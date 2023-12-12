package proof

import (
	"errors"

	"golang.org/x/crypto/blake2b"
)

const (
	UrkelHashSize  = 32
	UrkelKeySize   = 32
	UrkelKeyBits   = 256
	UrkelValueSize = 1023

	// 2 + 2 + UrkelKeySize + UrkelKeyBits * (2 + 32 + 32) + 2 + UrkelValueSize
	UrkelProofSize = 17957
)

type UrkelHash [UrkelHashSize]byte
type UrkelValue [UrkelValueSize]byte
type ProofType int
type UrkelCode int

// Proof Node types
const (
	ProofTypeDeadEnd ProofType = iota
	ProofTypeShort
	ProofTypeCollision
	ProofTypeExists
	ProofTypeUnknown
)

// Proof error codes
const (
	ProofOk UrkelCode = iota
	ProofHashMismatch
	ProofSameKey
	ProofSamePath
	ProofNegDepth
	ProofPathMismatch
	ProofTooDeep
	ProofInvalid
)

var SkipPrefix = [1]byte{0x02}
var InternalPrefix = [1]byte{0x01}
var LeafPrefix = [1]byte{0x00}

func (pt ProofType) String() string {
	switch pt {
	case ProofTypeDeadEnd:
		return "TYPE_DEADEND"
	case ProofTypeShort:
		return "TYPE_SHORT"
	case ProofTypeCollision:
		return "TYPE_COLLISION"
	case ProofTypeExists:
		return "TYPE_EXISTS"
	case ProofTypeUnknown:
		return "TYPE_UNKNOWN"
	}

	return "TYPE_UNKNOWN"
}

func StringToProofType(s string) ProofType {
	switch s {
	case "TYPE_DEADEND":
		return ProofTypeDeadEnd
	case "TYPE_SHORT":
		return ProofTypeShort
	case "TYPE_COLLISION":
		return ProofTypeCollision
	case "TYPE_EXISTS":
		return ProofTypeExists
	case "TYPE_UNKNOWN":
		return ProofTypeUnknown
	}

	return ProofTypeUnknown
}

func hashInternal(prefix Bits, left UrkelHash, right UrkelHash) (UrkelHash, error) {
	var hash UrkelHash

	h, err := blake2b.New256(nil)

	if err != nil {
		return hash, err
	}

	if prefix.size == 0 {
		if err = writeBytesFull(h, InternalPrefix[:]); err != nil {
			return hash, err
		}
	} else {
		if err = writeBytesFull(h, SkipPrefix[:]); err != nil {
			return hash, err
		}

		if err = writeUint16(h, uint16(prefix.size)); err != nil {
			return hash, err
		}

		if err = writeBytes(h, prefix.data[:], prefix.DataByteSize()); err != nil {
			return hash, err
		}
	}

	if err = writeBytesFull(h, left[:]); err != nil {
		return hash, err
	}

	if err = writeBytesFull(h, right[:]); err != nil {
		return hash, err
	}

	sum := h.Sum(nil)

	if len(sum) != UrkelHashSize {
		return hash, errors.New("hash size mismatch")
	}

	copy(hash[:], sum)

	return hash, nil
}

func hashLeaf(key UrkelHash, valueHash UrkelHash) (UrkelHash, error) {
	var hash UrkelHash

	h, err := blake2b.New256(nil)

	if err != nil {
		return hash, err
	}

	if err = writeBytesFull(h, LeafPrefix[:]); err != nil {
		return hash, err
	}

	if err = writeBytesFull(h, key[:]); err != nil {
		return hash, err
	}

	if err = writeBytesFull(h, valueHash[:]); err != nil {
		return hash, err
	}

	sum := h.Sum(nil)

	if len(sum) != UrkelHashSize {
		return hash, errors.New("hash size mismatch")
	}

	copy(hash[:], sum)

	return hash, nil
}

func hashValue(key UrkelHash, value UrkelValue, size uint16) (UrkelHash, error) {
	var vhash UrkelHash

	h, err := blake2b.New256(nil)

	if err != nil {
		return vhash, err
	}

	if err = writeBytes(h, value[:], int(size)); err != nil {
		return vhash, err
	}

	sum := h.Sum(nil)

	if len(sum) != UrkelHashSize {
		return vhash, errors.New("hash size mismatch")
	}

	copy(vhash[:], sum)

	return hashLeaf(key, vhash)
}
