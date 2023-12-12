package proof

import (
	"bytes"
	"testing"
)

var bitsAndBytes = []struct {
	setBits           []int
	expectedDataBytes [UrkelKeySize]byte
}{
	{
		[]int{0},
		[UrkelKeySize]byte{0x80},
	},
	{
		[]int{0, 1},
		[UrkelKeySize]byte{0xc0},
	},
	{
		[]int{0, 7},
		[UrkelKeySize]byte{0x81},
	},
	{
		[]int{0, 7, 8},
		[UrkelKeySize]byte{0x81, 0x80},
	},
	{
		[]int{0, 7, 8, 15, 16, 23, 24, 31},
		[UrkelKeySize]byte{0x81, 0x81, 0x81, 0x81},
	},
}

var prefixHas = []struct {
	size     int
	data     [UrkelKeySize]byte
	key      [UrkelKeySize]byte
	hasDepth int
}{
	{
		size:     1,
		data:     [UrkelKeySize]byte{0x80},
		key:      [UrkelKeySize]byte{0x80, 0xff},
		hasDepth: 0,
	},
	{
		size:     8,
		data:     [UrkelKeySize]byte{0xff},
		key:      [UrkelKeySize]byte{0xff, 0x00},
		hasDepth: 0,
	},
	{
		size:     16,
		data:     [UrkelKeySize]byte{0x80, 0xff},
		key:      [UrkelKeySize]byte{0x80, 0x80, 0xff},
		hasDepth: 8,
	},
}

func TestNewBits(t *testing.T) {
	size := 128

	bits, err := NewBitsFromSize(size)

	if err != nil {
		t.Error(err)
	}

	if bits.Size() != size {
		t.Errorf("expected size %d, got %d", size, bits.Size())
	}
}

func TestSetAndGetBit(t *testing.T) {
	for _, test := range bitsAndBytes {
		bits, err := NewBitsFromSize(128)

		if err != nil {
			t.Error(err)
		}

		for _, bit := range test.setBits {
			if bits.GetBit(bit) != 0 {
				t.Errorf("expected bit %d to be unset", bit)
			}

			bits.SetBit(bit, 1)

			if bits.GetBit(bit) != 1 {
				t.Errorf("expected bit %d to be set", bit)
			}
		}

		for i, b := range test.expectedDataBytes {
			if bits.data[i] != b {
				t.Errorf("expected byte %d to be %x, got %x", i, b, bits.data[i])
			}
		}
	}
}

func TestReserialize(t *testing.T) {
	sizes := []struct {
		size        int
		expectedLen int
	}{
		{64, 9},   // 64 bits / 8 bits per byte + 1 byte for size
		{128, 18}, // 128 bits / 8 bits per byte + 2 bytes for size
		{256, 34}, // 256 bits / 8 bits per byte + 2 bytes for size
	}

	for _, sizeVec := range sizes {
		for _, test := range bitsAndBytes {
			checkBits := func(bits *Bits) {
				for _, bit := range test.setBits {
					if bits.GetBit(bit) != 1 {
						t.Errorf("expected bit %d to be set", bit)
					}
				}

				for i, b := range test.expectedDataBytes {
					if bits.data[i] != b {
						t.Errorf("expected byte %d to be %x, got %x (size: %d)", i, b, bits.data[i], sizeVec.size)
					}
				}
			}

			bits, err := NewBitsFromSize(sizeVec.size)

			if err != nil {
				t.Error(err)
			}

			for _, bit := range test.setBits {
				bits.SetBit(bit, 1)
			}

			var serialized bytes.Buffer

			if err := bits.Serialize(&serialized); err != nil {
				t.Error(err)
			}

			serializedBytes := serialized.Bytes()

			if len(serializedBytes) != sizeVec.expectedLen {
				t.Errorf("expected serialized size %d, got %d", sizeVec.expectedLen, len(serializedBytes))
			}

			if len(serializedBytes) != bits.SerializeSize() {
				t.Errorf("expected serialized size %d, got %d", bits.SerializeSize(), len(serializedBytes))
			}

			// From bytes
			bits, err = NewBitsFromBytes(serializedBytes, sizeVec.size)

			if err != nil {
				t.Error(err)
			}

			checkBits(bits)

			// From reader
			bits, err = NewBitsFromReader(&serialized, sizeVec.size)

			if err != nil {
				t.Error(err)
			}

			checkBits(bits)
		}
	}
}

func TestHas(t *testing.T) {
	for _, test := range prefixHas {
		bits := Bits{
			data: test.data,
			size: test.size,
		}

		for i := 0; i < test.size; i++ {
			if i == test.hasDepth {
				if bits.Has(test.key, i) == false {
					t.Errorf("expected key %x to have depth %d", test.key, i)
				}

				continue
			}

			if bits.Has(test.key, i) == true {
				t.Errorf("expected key %x to not have depth %d", test.key, i)
			}
		}
	}
}
