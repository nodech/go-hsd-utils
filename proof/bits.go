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

func (b *Bits) DataByteSize() int {
	return (b.size + 7) >> 3
}

func (b *Bits) countFrom(index int, key UrkelHash, depth int) int {
	x := b.size - index
	y := UrkelKeySize - depth
	blen := x

	if y < x {
		blen = y
	}

	count := 0

	for i := 0; i < blen; i++ {
		if getBit(b.data[:], index) != getBit(key[:], depth) {
			break
		}

		count++
		index++
		depth++
	}

	return count
}

func (b *Bits) Count(key UrkelHash, depth int) int {
	return b.countFrom(0, key, depth)
}

func (b *Bits) Has(key UrkelHash, depth int) bool {
	return b.Count(key, depth) == b.size
}

func (b *Bits) SetBit(pos int, bit int) {
	setBit(b.data[:], pos, bit)
}

func (b *Bits) GetBit(pos int) int {
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

	size = int(sizeByte)

	if size&0x80 != 0 {
		size = (size - 0x80) << 8
		sizeByte, err = readByte(r)

		if err != nil {
			return err
		}

		size |= int(sizeByte)
	}

	if size > UrkelKeyBits {
		return errors.New("bitfield size too large")
	}

	b.size = size

	return readBytes(r, b.data[:], int((size+7)>>3))
}

func (p *Bits) String() string {
	// List all bits as 0 or 1.
	buf := make([]byte, p.size)

	for i := 0; i < p.size; i++ {
		if p.GetBit(i) == 1 {
			buf[i] = '1'
		} else {
			buf[i] = '0'
		}
	}

	return string(buf)
}

func (p *Bits) FromString(str string) error {
	if (len(str)+7)>>3 > UrkelKeySize {
		return errors.New("bitfield string too long")
	}

	p.size = len(str)

	for i := 0; i < p.size; i++ {
		if str[i] == '1' {
			p.SetBit(i, 1)
		} else if str[i] != '0' {
			return errors.New("invalid bitfield string")
		}
	}

	return nil
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

func NewBitsFromString(str string) (*Bits, error) {
	bits := &Bits{}
	err := bits.FromString(str)

	return bits, err
}
