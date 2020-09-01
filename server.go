package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
)

const AuthURL = "https://sessionserver.mojang.com/session/minecraft/hasJoined"

type Server struct {
	Description *ChatComponent
	Favicon     *PNGData

	PrivateKey *rsa.PrivateKey
	PublicKey  []byte
}

type Packet interface {
	PacketID() uint
}

type WritablePacket interface {
	Packet
	encoding.BinaryMarshaler
}

type ReadablePacket interface {
	Packet
	encoding.BinaryUnmarshaler
}

var ErrWrongPacket = errors.New("Wrong packet")
var ErrPacketTooShort = errors.New("Packet too short")

type RawPacket struct {
	ID   uint
	Data []byte
}

func (p RawPacket) PacketID() uint {
	return p.ID
}
func (p RawPacket) MarshalBinary() ([]byte, error) {
	return p.Data, nil
}
func (p RawPacket) UnmarshalInto(dest ReadablePacket) error {
	if dest.PacketID() != p.ID {
		return ErrWrongPacket
	}
	return dest.UnmarshalBinary(p.Data)
}

type PingPongPacket int64

func (p PingPongPacket) PacketID() uint {
	return 1
}
func (p PingPongPacket) MarshalBinary() ([]byte, error) {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, uint64(p))
	return data, nil
}
func (p *PingPongPacket) UnmarshalBinary(data []byte) error {
	if len(data) < 8 {
		// FIXME: probably not the right error to use here
		return ErrPacketTooShort
	}
	*p = PingPongPacket(binary.BigEndian.Uint64(data))
	return nil
}

type ProtocolVersion uint

var ErrInvalidProtocol = errors.New("Invalid protocol number")

type jsonVersion struct {
	Name string `json:"name"`
	V    uint   `json:"protocol"`
}

func (v ProtocolVersion) MarshalJSON() ([]byte, error) {
	var name string
	switch v {
	case V1_16_2:
		name = "1.16.2"
	default:
		return nil, ErrInvalidProtocol
	}
	return json.Marshal(jsonVersion{name, uint(v)})
}
func (v *ProtocolVersion) UnmarshalJSON(b []byte) error {
	var jsonV jsonVersion
	err := json.Unmarshal(b, &jsonV)
	*v = ProtocolVersion(jsonV.V)
	return err
}

const V1_16_2 ProtocolVersion = 751

type HandshakePacket struct {
	Version   ProtocolVersion
	Address   string
	Port      uint16
	NextState uint
}

func (p HandshakePacket) PacketID() uint {
	return 0
}
func (p *HandshakePacket) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)

	if vers, err := binary.ReadUvarint(buf); err == nil {
		p.Version = ProtocolVersion(vers)
	} else {
		return err
	}

	if addr, err := readString(buf); err == nil {
		p.Address = string(addr)
	} else {
		return err
	}

	if err := binary.Read(buf, binary.BigEndian, &p.Port); err != nil {
		return err
	}

	if next, err := binary.ReadUvarint(buf); err == nil {
		p.NextState = uint(next)
	} else {
		return err
	}

	return nil
}

type Player struct {
	Name string `json:"name"`
	UUID string `json:"id"`
}

type Players struct {
	Max    uint     `json:"max"`
	Online uint     `json:"online"`
	Sample []Player `json:"sample"`
}

type ChatComponent struct {
	Bold      bool   `json:"bold,omitempty"`
	Italic    bool   `json:"italic,omitempty"`
	Underline bool   `json:"underlined,omitempty"`
	Strike    bool   `json:"strikethrough,omitempty"`
	Obfuscate bool   `json:"obfuscated,omitempty"`
	Color     string `json:"color,omitempty"`

	Insert string `json:"insertion,omitempty"`
	//ClickEvent struct {} `json:"clickEvent,omitempty"`
	//HoverEvent struct {} `json:"hoverEvent,omitempty"`

	Extra []ChatComponent `json:"extra,omitempty"`

	Text       string `json:"text,omitempty"`
	Translatie string `json:"translate,omitempty"`
	Keybind    string `json:"keybind,omitempty"`
	Score      string `json:"score,omitempty"`
	Selector   string `json:"selector,omitempty"`
}

type PNGData []byte

func (d PNGData) MarshalText() ([]byte, error) {
	prefix := []byte("data:image/png;base64,")
	buf := make([]byte, len(prefix)+base64.StdEncoding.EncodedLen(len(d)))
	copy(buf, prefix)
	base64.StdEncoding.Encode(buf[len(prefix):], d)
	return buf, nil
}

type StatusResponsePacket struct {
	Version     ProtocolVersion `json:"version"`
	Players     Players         `json:"players"`
	Description *ChatComponent  `json:"description"`
	Favicon     *PNGData        `json:"favicon,omitempty"`
}

func (p StatusResponsePacket) PacketID() uint {
	return 0
}
func (p StatusResponsePacket) MarshalBinary() ([]byte, error) {
	if data, err := json.Marshal(p); err == nil {
		return encodeString(data), nil
	} else {
		return nil, err
	}
}

type StatusRequestPacket struct{}

func (p StatusRequestPacket) PacketID() uint {
	return 0
}
func (p StatusRequestPacket) UnmarshalBinary(buf []byte) error {
	return nil
}

type LoginStartPacket struct {
	Username string
}

func (p LoginStartPacket) PacketID() uint {
	return 0
}
func (p *LoginStartPacket) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	username, err := readString(buf)
	p.Username = string(username)
	return err
}

var ErrInvalidHexit = errors.New("Invalid hexadecimal digit")

type UUID struct {
	Low, High uint64
}

func (u UUID) MarshalText() ([]byte, error) {
	return []byte(fmt.Sprintf(
		"%08x-%04x-%04x-%04x-%012x",
		u.High>>32, u.High>>16&0xffff, u.High&0xffff,
		u.Low>>48, u.Low&0xffff_ffff_ffff,
	)), nil
}
func (u *UUID) UnmarshalText(data []byte) error {
	n := 0
	for _, ch := range data {
		if ch == '-' {
			continue
		}

		var nyb byte
		if '0' <= ch && ch <= '9' {
			nyb = ch - '0'
		} else if 'a' <= ch && ch <= 'f' {
			nyb = 10 + ch - 'a'
		} else if 'A' <= ch && ch <= 'F' {
			nyb = 10 + ch - 'A'
		} else {
			return ErrInvalidHexit
		}

		if n < 16 {
			u.High <<= 4
			u.High |= uint64(nyb)
		} else {
			u.Low <<= 4
			u.Low |= uint64(nyb)
		}
		n++
	}
	return nil
}
func (u UUID) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 16)
	binary.BigEndian.PutUint64(buf[0:], u.High)
	binary.BigEndian.PutUint64(buf[8:], u.Low)
	return buf, nil
}
func (u *UUID) UnmarshalBinary(buf []byte) error {
	u.High = binary.BigEndian.Uint64(buf)
	u.Low = binary.BigEndian.Uint64(buf[8:])
	return nil
}

type LoginDisconnectPacket struct {
	Reason ChatComponent
}

func (p LoginDisconnectPacket) PacketID() uint {
	return 0
}
func (p LoginDisconnectPacket) MarshalBinary() ([]byte, error) {
	if data, err := json.Marshal(p.Reason); err == nil {
		return encodeString(data), nil
	} else {
		return nil, err
	}
}

type LoginSuccessPacket struct {
	UUID     UUID   `json:"id"`
	Username string `json:"name"`
}

func (p LoginSuccessPacket) PacketID() uint {
	return 2
}
func (p LoginSuccessPacket) MarshalBinary() ([]byte, error) {
	uuid, _ := p.UUID.MarshalBinary()
	return append(uuid, encodeString([]byte(p.Username))...), nil
}

type LoginEncryptionRequestPacket struct {
	ServerID    string
	PublicKey   []byte
	VerifyToken []byte
}

func (p LoginEncryptionRequestPacket) PacketID() uint {
	return 1
}
func (p LoginEncryptionRequestPacket) MarshalBinary() ([]byte, error) {
	buf := encodeString([]byte(p.ServerID))
	buf = append(buf, encodeString(p.PublicKey)...)
	buf = append(buf, encodeString(p.VerifyToken)...)
	return buf, nil
}

type LoginEncryptionResponsePacket struct {
	SharedSecret []byte
	VerifyToken  []byte
}

func (p LoginEncryptionResponsePacket) PacketID() uint {
	return 1
}
func (p *LoginEncryptionResponsePacket) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	if secret, err := readString(buf); err == nil {
		p.SharedSecret = secret
	} else {
		return err
	}

	if token, err := readString(buf); err == nil {
		p.VerifyToken = token
	} else {
		return err
	}

	return nil
}

func writePacket(w io.Writer, p WritablePacket) error {
	// Len	VarInt
	// ID	VarInt
	// Data	ByteArray

	idBuf := make([]byte, binary.MaxVarintLen32)
	idLen := binary.PutUvarint(idBuf, uint64(p.PacketID()))

	data, err := p.MarshalBinary()
	if err != nil {
		return err
	}

	length := idLen + len(data)

	lenBuf := make([]byte, binary.MaxVarintLen32)
	lenLen := binary.PutUvarint(lenBuf, uint64(length))

	if _, err := w.Write(lenBuf[:lenLen]); err != nil {
		return err
	}
	if _, err := w.Write(idBuf[:idLen]); err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}

	return nil
}

func readRawPacket(r *bufio.Reader) (p RawPacket, err error) {
	length, err := binary.ReadUvarint(r)
	if err != nil {
		return
	}

	p.Data = make([]byte, length)
	if _, err = io.ReadFull(r, p.Data); err != nil {
		return
	}

	id64, off := binary.Uvarint(p.Data)
	p.ID = uint(id64)
	p.Data = p.Data[off:]

	return
}

func readPacket(r *bufio.Reader, p ReadablePacket) error {
	if raw, err := readRawPacket(r); err == nil {
		return raw.UnmarshalInto(p)
	} else {
		return err
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func encodeString(data []byte) []byte {
	lenBuf := make([]byte, binary.MaxVarintLen32)
	lenLen := binary.PutUvarint(lenBuf, uint64(len(data)))

	return append(lenBuf[:lenLen], data...)
}

func readString(buf *bytes.Buffer) ([]byte, error) {
	if length, err := binary.ReadUvarint(buf); err == nil {
		data := make([]byte, length)
		if _, err := io.ReadFull(buf, data); err != nil {
			return nil, err
		}
		return data, nil
	} else {
		return nil, err
	}
}

func (serv *Server) Handle(conn net.Conn) {
	defer func() {
		if err := recover(); err == nil {
			log.Println("Client disconnected:", conn.RemoteAddr())
		} else {
			log.Printf("Error in client handler: %v\n%s", err, debug.Stack())
		}
		conn.Close()
	}()

	log.Println("Client connected:", conn.RemoteAddr())

	r := bufio.NewReader(conn)
	w := io.Writer(conn)

	var hs HandshakePacket
	must(readPacket(r, &hs))

	switch hs.NextState {
	case 1: // Status
		var req StatusRequestPacket
		must(readPacket(r, &req))

		must(writePacket(w, StatusResponsePacket{
			Version:     V1_16_2,
			Players:     Players{420, 69, []Player{Player{"nice", "00000000-0000-0000-0000-000000000000"}}},
			Description: serv.Description,
			Favicon:     serv.Favicon,
		}))

		var pp PingPongPacket
		must(readPacket(r, &pp))
		must(writePacket(w, pp))

	case 2: // Login
		var start LoginStartPacket
		must(readPacket(r, &start))

		token := make([]byte, 4)
		_, err := io.ReadFull(rand.Reader, token)
		must(err)

		must(writePacket(w, LoginEncryptionRequestPacket{
			PublicKey:   serv.PublicKey,
			VerifyToken: token,
		}))

		var resp LoginEncryptionResponsePacket
		must(readPacket(r, &resp))

		respToken, err := serv.PrivateKey.Decrypt(rand.Reader, resp.VerifyToken, nil)
		must(err)

		if !bytes.Equal(token, respToken) {
			must(writePacket(w, LoginDisconnectPacket{
				ChatComponent{Text: "Incorrect token"},
			}))
			panic("Login: Incorrect token")
		}

		secret, err := serv.PrivateKey.Decrypt(rand.Reader, resp.SharedSecret, nil)
		must(err)

		aesCipher, err := aes.NewCipher(secret)
		must(err)

		if r.Buffered() > 0 {
			panic("Login: Unexpected bytes in buffer")
		}
		r.Reset(cipher.StreamReader{
			newCFB8Decrypter(aesCipher, secret),
			r,
		})
		w = cipher.StreamWriter{
			newCFB8Encrypter(aesCipher, secret),
			w,
			nil,
		}

		hash := sha1.New()
		hash.Write(nil)
		hash.Write(secret)
		hash.Write(serv.PublicKey)
		idStr := hexDigest(hash.Sum(nil))

		authURL, _ := url.Parse(AuthURL)
		params := authURL.Query()
		params.Set("username", start.Username)
		params.Set("serverId", idStr)
		// TODO: Add `ip` depending on config
		authURL.RawQuery = params.Encode()

		authResp, err := http.Get(authURL.String())
		if err != nil {
			panic(err)
		}

		if authResp.StatusCode != http.StatusOK {
			must(writePacket(w, LoginDisconnectPacket{
				ChatComponent{Text: fmt.Sprint("Authentication failed: ", authResp.Status)},
			}))
			panic("Login: Authentication failed")
		}

		var authData LoginSuccessPacket
		must(json.NewDecoder(authResp.Body).Decode(&authData))
		authResp.Body.Close()

		must(writePacket(w, authData))

	default:
		panic(fmt.Sprint("Handshake: Invalid next state: ", hs.NextState))
	}

}

func main() {
	favicon, err := ioutil.ReadFile("favicon.png")
	if err != nil {
		log.Fatal(err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatal(err)
	}

	publicKey, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		log.Fatal(err)
	}

	serv := &Server{
		&ChatComponent{Text: "Henlo"},
		(*PNGData)(&favicon),
		privateKey,
		publicKey,
	}

	sock, err := net.Listen("tcp", ":25565")
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Server started listening on", sock.Addr())

	for {
		conn, err := sock.Accept()
		if err != nil {
			log.Fatal(err)
		}
		serv.Handle(conn)
	}
}
