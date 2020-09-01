package main

import (
	"bufio"
	"encoding"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
)

type Server struct {
	Description *ChatComponent
	Favicon     *PNGData
}

type PacketID int32
type Packet interface {
	PacketID() PacketID
	encoding.BinaryMarshaler
}

type ReadablePacket interface {
	Packet
	encoding.BinaryUnmarshaler
}

var ErrWrongPacket = errors.New("Wrong packet")
var ErrPacketTooShort = errors.New("Packet too short")

type RawPacket struct {
	ID   PacketID
	Data []byte
}

func (p RawPacket) PacketID() PacketID {
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

func (p PingPongPacket) PacketID() PacketID {
	return PacketID(1)
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

type ServerListResponsePacket struct {
	Version     ProtocolVersion `json:"version"`
	Players     Players         `json:"players"`
	Description *ChatComponent  `json:"description"`
	Favicon     *PNGData        `json:"favicon,omitempty"`
}

func (p *ServerListResponsePacket) PacketID() PacketID {
	return PacketID(0)
}

func (p *ServerListResponsePacket) MarshalBinary() ([]byte, error) {
	if data, err := json.Marshal(p); err == nil {
		return encodeString(data), nil
	} else {
		return nil, err
	}
}

func writePacket(w io.Writer, p Packet) error {
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

func readPacket(r *bufio.Reader) (p RawPacket, err error) {
	length, err := binary.ReadUvarint(r)
	if err != nil {
		return
	}

	p.Data = make([]byte, length)
	if _, err = r.Read(p.Data); err != nil {
		return
	}

	id64, off := binary.Uvarint(p.Data)
	p.ID = PacketID(id64)
	p.Data = p.Data[off:]

	return
}

func encodeString(data []byte) []byte {
	lenBuf := make([]byte, binary.MaxVarintLen32)
	lenLen := binary.PutUvarint(lenBuf, uint64(len(data)))

	return append(lenBuf[:lenLen], data...)
}

func (serv *Server) Handle(conn net.Conn) {
	r := bufio.NewReader(conn)
	_, err := readPacket(r)
	if err != nil {
		fmt.Println(err)
		return
	}

	_, err = readPacket(r)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = writePacket(conn, &ServerListResponsePacket{
		Version:     V1_16_2,
		Players:     Players{420, 69, []Player{Player{"nice", "4566e69f-c907-48ee-8d71-d7ba5aa00d20"}}},
		Description: serv.Description,
		Favicon:     serv.Favicon,
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	p, err := readPacket(r)
	if err != nil {
		fmt.Println(err)
		return
	}

	var pp PingPongPacket
	err = p.UnmarshalInto(&pp)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = writePacket(conn, pp)
	if err != nil {
		fmt.Println(err)
		return
	}
}

func main() {
	sock, err := net.Listen("tcp", ":25565")
	if err != nil {
		panic(err)
	}

	favicon, err := ioutil.ReadFile("favicon.png")
	if err != nil {
		panic(err)
	}

	serv := &Server{
		&ChatComponent{Text: "Henlo"},
		(*PNGData)(&favicon),
	}

	for {
		conn, err := sock.Accept()
		if err != nil {
			panic(err)
		}
		fmt.Println("Client connected")
		serv.Handle(conn)
	}
}
