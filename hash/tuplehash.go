package hash

import "github.com/AeonDave/cryptonite-go/internal/keccak"

// TupleHash128 returns the TupleHash-128 digest of the provided tuple, producing
// outLen bytes of output. The optional customization string may be nil.
func TupleHash128(tuple [][]byte, outLen int, customization []byte) ([]byte, error) {
	return keccak.TupleHash128(tuple, customization, outLen)
}

// TupleHash256 returns the TupleHash-256 digest of the provided tuple.
func TupleHash256(tuple [][]byte, outLen int, customization []byte) ([]byte, error) {
	return keccak.TupleHash256(tuple, customization, outLen)
}

// ParallelHash128 computes ParallelHash-128 over msg using the specified block
// size and produces outLen bytes of output. The customization string may be nil.
func ParallelHash128(msg []byte, blockSize int, outLen int, customization []byte) ([]byte, error) {
	return keccak.ParallelHash128(msg, blockSize, customization, outLen)
}

// ParallelHash256 computes ParallelHash-256 over msg using the provided block
// size and returns outLen bytes of output.
func ParallelHash256(msg []byte, blockSize int, outLen int, customization []byte) ([]byte, error) {
	return keccak.ParallelHash256(msg, blockSize, customization, outLen)
}
