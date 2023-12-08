package proof

import (
	"bytes"
	"errors"
	"io"
)

type ProofNode struct {
	prefix Bits
	hash   Hash
}

type Proof struct {
	ptype ProofType
	depth uint

	nodes []*ProofNode

	prefix Bits

	left  Hash
	right Hash

	hash      Hash
	key       UrkelKey
	value     UrkelValue
	valueSize uint16
}

func (p *Proof) Type() ProofType {
	return p.ptype
}

func (p *Proof) Value() []byte {
	return p.value[:p.valueSize]
}

func (p *Proof) IsSane() bool {
	if p.depth > UrkelKeyBits {
		return false
	}

	if len(p.nodes) > UrkelKeyBits {
		return false
	}

	for _, node := range p.nodes {
		if node.prefix.Size() > UrkelKeyBits {
			return false
		}
	}

	switch p.ptype {
	case ProofTypeDeadEnd:
		if p.prefix.size > 0 {
			return false
		}

		if p.valueSize > 0 {
			return false
		}

	case ProofTypeShort:
		if p.prefix.size == 0 {
			return false
		}

		if p.prefix.size > UrkelKeyBits {
			return false
		}

		if p.valueSize > 0 {
			return false
		}

	case ProofTypeCollision:
		if p.prefix.size > 0 {
			return false
		}

		if p.valueSize > 0 {
			return false
		}

	case ProofTypeExists:
		if p.prefix.size > 0 {
			return false
		}

		if p.valueSize > UrkelValueSize {
			return false
		}
	default:
		return false
	}

	return true
}

func (p *Proof) Push(prefix Bits, hash Hash) {
	p.nodes = append(p.nodes, newProofNode(prefix, hash))
}

func (p *Proof) Deserialize(r io.Reader) error {
	var field, count uint16
	var err error

	if field, err = readUint16(r); err != nil {
		return err
	}

	if count, err = readUint16(r); err != nil {
		return err
	}

	p.ptype = ProofType(field >> 14)
	p.depth = uint(field & (^(uint16(3) << uint16(14))))

	if p.depth > UrkelKeyBits {
		return errors.New("Invalid depth")
	}

	if count > UrkelKeyBits {
		return errors.New("Proof too large")
	}

	bsize := int(count+7) / 8
	bits := make([]byte, bsize)

	if err = readBytes(r, bits, bsize); err != nil {
		return err
	}

	for i := uint(0); i < uint(count); i++ {
		node := newProofNode(Bits{}, Hash{})

		if getBit(bits, i) == 1 {
			if err = node.prefix.Deserialize(r); err != nil {
				return err
			}

			if node.prefix.size == 0 {
				return errors.New("Invalid prefix size")
			}
		}

		if err = readBytesFull(r, node.hash[:]); err != nil {
			return err
		}

		p.nodes = append(p.nodes, node)
	}

	switch p.ptype {
	case ProofTypeDeadEnd:
		// Nothing.
	case ProofTypeShort:
		if err = p.prefix.Deserialize(r); err != nil {
			return err
		}

		if p.prefix.size == 0 {
			return errors.New("Invalid prefix size")
		}

		if err = readBytesFull(r, p.left[:]); err != nil {
			return err
		}

		if err = readBytesFull(r, p.right[:]); err != nil {
			return err
		}
	case ProofTypeCollision:
		if err = readBytesFull(r, p.key[:]); err != nil {
			return err
		}

		if err = readBytesFull(r, p.hash[:]); err != nil {
			return err
		}
	case ProofTypeExists:
		if p.valueSize, err = readUint16(r); err != nil {
			return err
		}

		if err = readBytes(r, p.value[:], int(p.valueSize)); err != nil {
			return err
		}
	}

	return nil
}

func (p *Proof) Serialize(w io.Writer) error {
	var err error

	count := len(p.nodes)
	bsize := (count + 7) / 8
	field := uint16(p.ptype<<14) | uint16(p.depth)
	bits := make([]byte, bsize)

	if err = writeUint16(w, field); err != nil {
		return err
	}

	if err = writeUint16(w, uint16(count)); err != nil {
		return err
	}

	for i, node := range p.nodes {
		if node.prefix.size > 0 {
			setBit(bits, uint(i), 1)
		}
	}

	writeBytesFull(w, bits)

	for _, node := range p.nodes {
		if node.prefix.size > 0 {
			if err = node.prefix.Serialize(w); err != nil {
				return err
			}
		}

		if err = writeBytesFull(w, node.hash[:]); err != nil {
			return err
		}
	}

	switch p.ptype {
	case ProofTypeDeadEnd:
		// Nothing.
	case ProofTypeShort:
		if err = p.prefix.Serialize(w); err != nil {
			return err
		}

		if err = writeBytesFull(w, p.left[:]); err != nil {
			return err
		}

		if err = writeBytesFull(w, p.right[:]); err != nil {
			return err
		}
	case ProofTypeCollision:
		if err = writeBytesFull(w, p.key[:]); err != nil {
			return err
		}

		if err = writeBytesFull(w, p.hash[:]); err != nil {
			return err
		}
	case ProofTypeExists:
		if err = writeUint16(w, p.valueSize); err != nil {
			return err
		}

		if err = writeBytes(w, p.value[:], int(p.valueSize)); err != nil {
			return err
		}
	}

	return nil
}

func newProofNode(prefix Bits, hash Hash) *ProofNode {
	return &ProofNode{
		prefix: prefix,
		hash:   hash,
	}
}

func New() *Proof {
	return &Proof{}
}

func NewFromReader(r io.Reader) (*Proof, error) {
	proof := New()

	err := proof.Deserialize(r)

	return proof, err
}

func NewFromBytes(b []byte) (*Proof, error) {
	return NewFromReader(bytes.NewReader(b))
}
