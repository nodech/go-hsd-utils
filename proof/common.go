package proof

const (
	UrkelKeySize = 32
	UrkelKeyBits = 256
)

// Hash is a 256 bit blake2b hash
type Hash [UrkelKeySize]byte
