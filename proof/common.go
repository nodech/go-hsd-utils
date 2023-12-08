package proof

const (
	UrkelHashSize  = 32
	UrkelKeySize   = 32
	UrkelKeyBits   = 256
	UrkelValueSize = 1023

	// 2 + 2 + UrkelKeySize + UrkelKeyBits * (2 + 32 + 32) + 2 + UrkelValueSize
	UrkelProofSize = 17957
)

type Hash [UrkelHashSize]byte
type UrkelKey [UrkelKeySize]byte
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
	ProofUnknownError
)
