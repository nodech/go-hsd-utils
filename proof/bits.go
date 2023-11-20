package proof

import (
	"bytes"
	"errors"
	"io"
)

type Bits struct {
	// size is the number of bits in the bitfield.
	size int

	// data is the bitfield data.
	data [UrkelKeySize]byte
}

func (b *Bits) Size() int {
	return b.size
}

func (b *Bits) Data() []byte {
	return b.data[:]
}

func (b *Bits) SetBit(pos uint, bit uint) {
	setBit(b.data[:], pos, bit)
}

func (b *Bits) GetBit(pos uint) uint {
	return getBit(b.data[:], pos)
}

func (b *Bits) SerializeSize() int {
	size := 0

	if b.size >= 0x80 {
		size += 1
	}

	size += 1
	size += (b.size + 7) >> 3

	return size
}

func (b *Bits) Serialize(w io.Writer) error {
	if b.size >= 0x80 {
		if err := writeByte(w, byte(0x80|b.size>>8)); err != nil {
			return err
		}
	}

	if err := writeByte(w, byte(b.size&0xff)); err != nil {
		return err
	}

	size := (b.size + 7) >> 3
	return writeBytes(w, b.data[:], size)
}

func (b *Bits) Deserialize(r io.Reader) error {
	var size int

	sizeByte, err := readByte(r)

	if err != nil {
		return err
	}

	if sizeByte&0x80 != 0 {
		size = (int(sizeByte) - 0x80) << 8
		sizeByte, err = readByte(r)

		if err != nil {
			return err
		}
	}

	size |= int(sizeByte)

	if size > UrkelKeyBits {
		return errors.New("bitfield size too large")
	}

	b.size = size

	return readBytes(r, b.data[:], int((size+7)>>3))
}

func NewBits() (*Bits, error) {
	return &Bits{size: UrkelKeyBits}, nil
}

func NewBitsFromSize(size int) (*Bits, error) {
	if size > UrkelKeyBits {
		return nil, errors.New("bitfield size too large")
	}

	return &Bits{size: size}, nil
}

func NewBitsFromBytes(data []byte, size int) (*Bits, error) {
	return NewBitsFromReader(bytes.NewReader(data), size)
}

func NewBitsFromReader(r io.Reader, size int) (*Bits, error) {
	if size > UrkelKeyBits {
		return nil, errors.New("bitfield size too large")
	}

	bits := &Bits{size: size}
	err := bits.Deserialize(r)

	return bits, err
}
