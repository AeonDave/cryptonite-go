package hash

import (
	"errors"
	"fmt"
	stdhash "hash"
	"math"

	"github.com/AeonDave/cryptonite-go/internal/blake2b"
	"github.com/AeonDave/cryptonite-go/internal/blake2s"
	"github.com/AeonDave/cryptonite-go/xof"
)

// Blake2bXOFUnknown indicates that the output length of a BLAKE2b XOF is
// unspecified in advance.
const Blake2bXOFUnknown = xof.Blake2bUnknown

// Blake2sXOFUnknown indicates that the output length of a BLAKE2s XOF is
// unspecified in advance.
const Blake2sXOFUnknown = xof.Blake2sUnknown

// Blake2bBuilder constructs keyed or unkeyed BLAKE2b hash and XOF instances.
type Blake2bBuilder struct {
	size int
	key  []byte
}

// NewBlake2bBuilder returns a builder configured for the default 64-byte
// BLAKE2b digest without a key.
func NewBlake2bBuilder() Blake2bBuilder { return Blake2bBuilder{size: blake2b.Size} }

// Size sets the desired digest length. The value must be between 1 and 64.
func (b Blake2bBuilder) Size(size int) Blake2bBuilder {
	b.size = size
	return b
}

// Key configures the secret key used for MAC mode. The key is copied so that
// subsequent modifications by the caller do not affect the builder.
func (b Blake2bBuilder) Key(key []byte) Blake2bBuilder {
	if len(key) == 0 {
		b.key = nil
		return b
	}
	dup := make([]byte, len(key))
	copy(dup, key)
	b.key = dup
	return b
}

// Hash returns a stateful hash.Hash instance implementing the configured
// BLAKE2b variant.
func (b Blake2bBuilder) Hash() (stdhash.Hash, error) {
	return blake2b.New(b.size, b.key)
}

// Hasher returns a stateless helper implementing hash.Hasher.
func (b Blake2bBuilder) Hasher() (Hasher, error) {
	return newBlake2Hasher(blake2b.New, blake2b.Size, b.size, b.key, "BLAKE2b")
}

// Sum computes a single-shot digest using the configured parameters.
func (b Blake2bBuilder) Sum(msg []byte) ([]byte, error) {
	h, err := b.Hasher()
	if err != nil {
		return nil, err
	}
	out := h.Hash(msg)
	return out, nil
}

// XOF returns an extendable-output function using the configured key and the
// requested output length. For unknown-length output use Blake2bXOFUnknown.
func (b Blake2bBuilder) XOF(length uint32) (xof.XOF, error) {
	return xof.Blake2b(length, b.key)
}

// NewBlake2b returns a streaming BLAKE2b hash.Hash with the specified digest
// length and key.
func NewBlake2b(size int, key []byte) (stdhash.Hash, error) {
	return blake2b.New(size, key)
}

// NewBlake2bHasher creates a stateless BLAKE2b helper with the given digest
// length and optional key.
func NewBlake2bHasher(size int, key []byte) (Hasher, error) {
	return newBlake2Hasher(blake2b.New, blake2b.Size, size, key, "BLAKE2b")
}

// NewBlake2bXOF constructs a BLAKE2b extendable-output instance.
// Deprecated: use xof.Blake2b.
func NewBlake2bXOF(length uint32, key []byte) (xof.XOF, error) {
	return xof.Blake2b(length, key)
}

// Blake2sBuilder constructs keyed or unkeyed BLAKE2s hash and XOF instances.
type Blake2sBuilder struct {
	size int
	key  []byte
}

// NewBlake2sBuilder returns a builder configured for the default 32-byte
// BLAKE2s digest without a key.
func NewBlake2sBuilder() Blake2sBuilder { return Blake2sBuilder{size: blake2s.Size} }

// Size sets the desired digest length. The value must be between 1 and 32.
func (b Blake2sBuilder) Size(size int) Blake2sBuilder {
	b.size = size
	return b
}

// Key configures the secret key used for MAC mode. The key is copied so that
// subsequent modifications by the caller do not affect the builder.
func (b Blake2sBuilder) Key(key []byte) Blake2sBuilder {
	if len(key) == 0 {
		b.key = nil
		return b
	}
	dup := make([]byte, len(key))
	copy(dup, key)
	b.key = dup
	return b
}

// Hash returns a stateful hash.Hash instance implementing the configured
// BLAKE2s variant.
func (b Blake2sBuilder) Hash() (stdhash.Hash, error) {
	return blake2s.New(b.size, b.key)
}

// Hasher returns a stateless helper implementing hash.Hasher.
func (b Blake2sBuilder) Hasher() (Hasher, error) {
	return newBlake2Hasher(blake2s.New, blake2s.Size, b.size, b.key, "BLAKE2s")
}

// Sum computes a single-shot digest using the configured parameters.
func (b Blake2sBuilder) Sum(msg []byte) ([]byte, error) {
	h, err := b.Hasher()
	if err != nil {
		return nil, err
	}
	return h.Hash(msg), nil
}

// XOF returns an extendable-output function using the configured key and the
// requested output length. For unknown-length output use Blake2sXOFUnknown.
func (b Blake2sBuilder) XOF(length uint32) (xof.XOF, error) {
	if length != Blake2sXOFUnknown && length >= math.MaxUint16 {
		return nil, errors.New("hash: blake2s XOF length too large")
	}
	return xof.Blake2s(length, b.key)
}

// NewBlake2s returns a streaming BLAKE2s hash.Hash with the specified digest
// length and key.
func NewBlake2s(size int, key []byte) (stdhash.Hash, error) {
	return blake2s.New(size, key)
}

// NewBlake2sHasher creates a stateless BLAKE2s helper with the given digest
// length and optional key.
func NewBlake2sHasher(size int, key []byte) (Hasher, error) {
	return newBlake2Hasher(blake2s.New, blake2s.Size, size, key, "BLAKE2s")
}

// Deprecated: use xof.Blake2s.
func NewBlake2sXOF(length uint32, key []byte) (xof.XOF, error) {
	if length != Blake2sXOFUnknown && length >= math.MaxUint16 {
		return nil, errors.New("hash: blake2s XOF length too large")
	}
	return xof.Blake2s(length, key)
}

type blake2Hasher struct {
	size    int
	key     []byte
	maxSize int
	newFunc func(int, []byte) (stdhash.Hash, error)
}

func newBlake2Hasher(newFunc func(int, []byte) (stdhash.Hash, error), maxSize, size int, key []byte, alg string) (Hasher, error) {
	if size <= 0 || size > maxSize {
		return nil, errors.New("hash: invalid BLAKE2 digest size")
	}
	if len(key) > maxSize {
		return nil, fmt.Errorf("hash: %s key too long (max %d bytes)", alg, maxSize)
	}
	dup := make([]byte, len(key))
	copy(dup, key)
	return blake2Hasher{size: size, key: dup, maxSize: maxSize, newFunc: newFunc}, nil
}

func (h blake2Hasher) Hash(msg []byte) []byte {
	hash, err := h.newFunc(h.size, h.key)
	if err != nil {
		panic(err)
	}
	if _, err := hash.Write(msg); err != nil {
		panic(err)
	}
	return hash.Sum(nil)
}

func (h blake2Hasher) Size() int { return h.size }
