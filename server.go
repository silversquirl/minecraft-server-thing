package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

func writePacket(w io.Writer, id int32, data []byte) error {
	// Len	VarInt
	// ID	VarInt
	// Data	ByteArray

	idBuf := make([]byte, binary.MaxVarintLen32)
	idLen := binary.PutUvarint(idBuf, uint64(id))

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

func readPacket(r *bufio.Reader) (id int32, data []byte, err error) {
	length, err := binary.ReadUvarint(r)
	if err != nil {
		return
	}

	data = make([]byte, length)
	if _, err = r.Read(data); err != nil {
		return
	}

	id64, off := binary.Uvarint(data)
	id = int32(id64)
	data = data[off:]

	return
}

func encodeString(s string) []byte {
	data := []byte(s)

	lenBuf := make([]byte, binary.MaxVarintLen32)
	lenLen := binary.PutUvarint(lenBuf, uint64(len(data)))

	return append(lenBuf[:lenLen], data...)
}

func handle(conn net.Conn) {
	r := bufio.NewReader(conn)
	id, data, err := readPacket(r)
	if err != nil {
		fmt.Println(err)
		return
	}

	id, data, err = readPacket(r)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = writePacket(conn, 0, encodeString(`
	{
		"version": {
			"name": "1.16.2",
			"protocol": 751
		},
		"players": {
			"max": 0,
			"online": 0,
			"sample": []
		},
		"description": {
			"text": "yo what's up"
		}
	}
	`))

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

	for {
		conn, err := sock.Accept()
		if err != nil {
			panic(err)
		}
		fmt.Println("Client connected")
		handle(conn)
	}
}
