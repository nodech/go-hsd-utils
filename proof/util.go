package proof

import (
	"encoding/binary"
	"io"
)

func setBit(data []byte, index uint, bit uint) {
	oct := index >> 3
	bitValue := byte((bit & 1))
	data[oct] |= bitValue << (7 - (index & 7))
}

func getBit(data []byte, index uint) uint {
	oct := index >> 3
	return uint((data[oct] >> (7 - (index & 7))) & 1)
}

func writeByte(w io.Writer, b byte) error {
	_, err := w.Write([]byte{b})
	return err
}

func writeUint32(w io.Writer, n int) error {
	return binary.Write(w, binary.LittleEndian, n)
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

func readByte(r io.Reader) (byte, error) {
	var buf [1]byte

	if err := readBytes(r, buf[:], 1); err != nil {
		return 0, err
	}

	return buf[0], nil
}

func readBytes(r io.Reader, data []byte, n int) error {
	_, err := io.ReadAtLeast(r, data, n)
	return err
}
