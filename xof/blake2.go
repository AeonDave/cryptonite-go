package xof

import (
	"errors"
	"math"

	"github.com/AeonDave/cryptonite-go/internal/blake2b"
	"github.com/AeonDave/cryptonite-go/internal/blake2s"
)

// Blake2bUnknown indicates that the output length of a BLAKE2b XOF is
// unspecified in advance.
const Blake2bUnknown = blake2b.OutputLengthUnknown

// Blake2sUnknown indicates that the output length of a BLAKE2s XOF is
// unspecified in advance.
const Blake2sUnknown = uint32(blake2s.OutputLengthUnknown)

// Blake2b constructs a BLAKE2b extendable-output instance. Pass Blake2bUnknown
// when the desired output length is not known ahead of time.
func Blake2b(length uint32, key []byte) (XOF, error) {
	return blake2b.NewXOF(length, key)
}

// Blake2s constructs a BLAKE2s extendable-output instance. Pass Blake2sUnknown
// when the desired output length is not known ahead of time.
func Blake2s(length uint32, key []byte) (XOF, error) {
	if length != Blake2sUnknown && length > math.MaxUint16 {
		return nil, errors.New("xof: blake2s XOF length too large")
	}
	return blake2s.NewXOF(uint16(length), key)
}
