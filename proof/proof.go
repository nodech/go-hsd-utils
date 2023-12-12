package proof

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
)

type ProofNode struct {
	prefix Bits
	hash   UrkelHash
}

type Proof struct {
	ptype ProofType
	depth int

	nodes []*ProofNode

	prefix Bits

	left  UrkelHash
	right UrkelHash

	hash      UrkelHash
	key       UrkelHash
	value     UrkelValue
	valueSize uint16
}

type ProofJSON struct {
	Ptype  string       `json:"type"`
	Depth  int          `json:"depth"`
	Nodes  []*ProofNode `json:"nodes"`
	Prefix string       `json:"prefix,omitempty"`
	Left   string       `json:"left,omitempty"`
	Right  string       `json:"right,omitempty"`
	Key    string       `json:"key,omitempty"`
	Hash   string       `json:"hash,omitempty"`
	Value  string       `json:"value,omitempty"`
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

func (p *Proof) Push(prefix Bits, hash UrkelHash) {
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
	p.depth = int(field & (^(uint16(3) << uint16(14))))

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

	for i := 0; i < int(count); i++ {
		node := newProofNode(Bits{}, UrkelHash{})

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
			setBit(bits, i, 1)
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

func (p *Proof) Verify(root UrkelHash, key UrkelHash) (UrkelCode, []byte) {
	if p.IsSane() == false {
		return ProofInvalid, nil
	}

	var leaf UrkelHash
	var err error

	switch p.ptype {
	case ProofTypeDeadEnd:
		// Do nothing. Leaf is already zero.
	case ProofTypeShort:
		if p.prefix.Has(key, p.depth) {
			return ProofSamePath, nil
		}

		leaf, err = hashInternal(p.prefix, p.left, p.right)

	case ProofTypeCollision:
		if bytes.Compare(p.key[:], key[:]) == 0 {
			return ProofSameKey, nil
		}

		leaf, err = hashLeaf(p.key, p.hash)
	case ProofTypeExists:
		leaf, err = hashValue(key, p.value, p.valueSize)
	default:
		return ProofInvalid, nil
	}

	if err != nil {
		return ProofInvalid, nil
	}

	next := leaf
	depth := p.depth

	for i := len(p.nodes) - 1; i >= 0; i-- {
		node := p.nodes[i]

		if depth < node.prefix.size+1 {
			return ProofNegDepth, nil
		}

		depth -= 1

		if hasBit(key[:], depth) {
			next, err = hashInternal(node.prefix, node.hash, next)
		} else {
			next, err = hashInternal(node.prefix, next, node.hash)
		}

		depth -= node.prefix.size

		if err != nil {
			return ProofInvalid, nil
		}

		if !node.prefix.Has(key, depth) {
			return ProofPathMismatch, nil
		}
	}

	if depth != 0 {
		return ProofTooDeep, nil
	}

	if bytes.Compare(next[:], root[:]) != 0 {
		return ProofHashMismatch, nil
	}

	return ProofOk, p.value[:p.valueSize]
}

// MarshalJSON customizes the JSON serialization.
func (p *Proof) MarshalJSON() ([]byte, error) {
	var prefix string
	var left string
	var right string
	var key string
	var hash string
	var value string

	if p.Type() == ProofTypeShort {
		prefix = p.prefix.String()
		left = hex.EncodeToString(p.left[:])
		right = hex.EncodeToString(p.right[:])
	}

	if p.Type() == ProofTypeCollision {
		key = hex.EncodeToString(p.key[:])
		hash = hex.EncodeToString(p.hash[:])
	}

	if p.Type() == ProofTypeExists {
		value = hex.EncodeToString(p.value[:p.valueSize])
	}

	proofJSON := ProofJSON{
		Ptype: p.ptype.String(),
		Depth: p.depth,
		Nodes: p.nodes,

		Prefix: prefix,
		Left:   left,
		Right:  right,
		Key:    key,
		Hash:   hash,
		Value:  value,
	}

	return json.Marshal(proofJSON)
}

func (p *Proof) UnmarshalJSON(b []byte) error {
	var proofJSON ProofJSON

	if err := json.Unmarshal(b, &proofJSON); err != nil {
		return err
	}

	p.ptype = StringToProofType(proofJSON.Ptype)
	p.depth = proofJSON.Depth
	p.nodes = proofJSON.Nodes

	switch p.ptype {
	case ProofTypeDeadEnd:
		// Nothing.
	case ProofTypeShort:
		if err := p.prefix.FromString(proofJSON.Prefix); err != nil {
			return err
		}

		left, err := decodeHashHex(proofJSON.Left)

		if err != nil {
			return err
		}

		copy(p.left[:], left)

		right, err := decodeHashHex(proofJSON.Right)

		if err != nil {
			return err
		}

		copy(p.right[:], right)
	case ProofTypeCollision:
		key, err := decodeHashHex(proofJSON.Key)

		if err != nil {
			return err
		}

		copy(p.key[:], key)

		hash, err := decodeHashHex(proofJSON.Hash)

		if err != nil {
			return err
		}

		copy(p.hash[:], hash)
	case ProofTypeExists:
		value, err := hex.DecodeString(proofJSON.Value)

		if err != nil {
			return err
		}

		if len(value) > UrkelValueSize {
			return errors.New("value too long")
		}

		copy(p.value[:], value)
		p.valueSize = uint16(len(value))

	default:
		return errors.New("invalid proof type")
	}

	return nil
}

func (pn *ProofNode) MarshalJSON() ([]byte, error) {
	return json.Marshal([]string{
		pn.prefix.String(),
		hex.EncodeToString(pn.hash[:]),
	})
}

func (pn *ProofNode) UnmarshalJSON(data []byte) error {
	var parts []string

	if err := json.Unmarshal(data, &parts); err != nil {
		return err
	}

	if len(parts) != 2 {
		return errors.New("invalid proof node (length)")
	}

	if err := pn.prefix.FromString(parts[0]); err != nil {
		return err
	}

	hash, err := hex.DecodeString(parts[1])

	if err != nil {
		return err
	}

	if len(hash) != UrkelHashSize {
		return errors.New("invalid proof node (hash length)")
	}

	copy(pn.hash[:], hash)

	return nil
}

func newProofNode(prefix Bits, hash UrkelHash) *ProofNode {
	return &ProofNode{
		prefix: prefix,
		hash:   hash,
	}
}

func New() *Proof {
	return &Proof{
		nodes: []*ProofNode{},
	}
}

func NewFromReader(r io.Reader) (*Proof, error) {
	proof := New()

	err := proof.Deserialize(r)

	return proof, err
}

func NewFromBytes(b []byte) (*Proof, error) {
	return NewFromReader(bytes.NewReader(b))
}

func NewFromJSON(b []byte) (*Proof, error) {
	proof := New()
	err := json.Unmarshal(b, proof)
	return proof, err
}
