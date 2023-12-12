package proof

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
)

func setBit(data []byte, index int, bit int) {
	oct := index >> 3
	bitValue := byte((bit & 1))
	data[oct] |= bitValue << (7 - (index & 7))
}

func getBit(data []byte, index int) int {
	oct := index >> 3
	return int((data[oct] >> (7 - (index & 7))) & 1)
}

func hasBit(data []byte, index int) bool {
	return getBit(data, index) == 1
}

func writeByte(w io.Writer, b byte) error {
	_, err := w.Write([]byte{b})
	return err
}

func writeUint32(w io.Writer, n uint32) error {
	return binary.Write(w, binary.LittleEndian, n)
}

func readUint32(r io.Reader) (uint32, error) {
	var n uint32
	err := binary.Read(r, binary.LittleEndian, &n)
	return n, err
}

func writeUint16(w io.Writer, n uint16) error {
	var buf [2]byte
	binary.LittleEndian.PutUint16(buf[:], n)
	return writeBytesFull(w, buf[:])
}

func readUint16(r io.Reader) (uint16, error) {
	var n uint16
	var buf [2]byte

	if err := readBytesFull(r, buf[:]); err != nil {
		return 0, err
	}

	n = binary.LittleEndian.Uint16(buf[:])
	return n, nil
}

func writeBytes(w io.Writer, data []byte, n int) error {
	total := 0

	for total < n {
		written, err := w.Write(data[total:n])

		if err != nil {
			return err
		}

		total += written
	}

	return nil
}

func writeBytesFull(w io.Writer, data []byte) error {
	return writeBytes(w, data, len(data))
}

func readByte(r io.Reader) (byte, error) {
	var buf [1]byte

	if err := readBytes(r, buf[:], 1); err != nil {
		return 0, err
	}

	return buf[0], nil
}

func readBytes(r io.Reader, data []byte, n int) error {
	_, err := io.ReadAtLeast(r, data[:n], n)
	return err
}

func readBytesFull(r io.Reader, data []byte) error {
	return readBytes(r, data, len(data))
}

func decodeHashHex(s string) ([]byte, error) {
	if len(s) != 64 {
		return nil, errors.New("invalid hash length")
	}

	var b []byte
	var err error

	if b, err = hex.DecodeString(s); err != nil {
		return nil, err
	}

	if len(b) != 32 {
		return nil, errors.New("invalid hash length")
	}

	return b, nil
}
