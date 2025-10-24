package hash

import (
	"crypto/sha256"
	"crypto/sha512"
	stdhash "hash"
)

const (
	sha2Size224 = 28
	sha2Size256 = 32
	sha2Size384 = 48
	sha2Size512 = 64
)

type sha2Hasher struct {
	size int
	sum  func([]byte) []byte
}

func (h sha2Hasher) Hash(msg []byte) []byte { return h.sum(msg) }

func (h sha2Hasher) Size() int { return h.size }

type sha2Digest struct {
	state  stdhash.Hash
	hasher sha2Hasher
}

func newSHA2Digest(newState func() stdhash.Hash, hasher sha2Hasher) *sha2Digest {
	return &sha2Digest{
		state:  newState(),
		hasher: hasher,
	}
}

func (d *sha2Digest) Reset() { d.state.Reset() }

func (d *sha2Digest) Write(p []byte) (int, error) { return d.state.Write(p) }

func (d *sha2Digest) Sum(b []byte) []byte { return d.state.Sum(b) }

func (d *sha2Digest) Size() int { return d.state.Size() }

func (d *sha2Digest) BlockSize() int { return d.state.BlockSize() }

func (d *sha2Digest) Hash(msg []byte) []byte { return d.hasher.Hash(msg) }

func sha224Sum(msg []byte) []byte {
	sum := sha256.Sum224(msg)
	return append([]byte(nil), sum[:]...)
}

func sha256Sum(msg []byte) []byte {
	sum := sha256.Sum256(msg)
	return append([]byte(nil), sum[:]...)
}

func sha384Sum(msg []byte) []byte {
	sum := sha512.Sum384(msg)
	return append([]byte(nil), sum[:]...)
}

func sha512Sum(msg []byte) []byte {
	sum := sha512.Sum512(msg)
	return append([]byte(nil), sum[:]...)
}

var (
	sha2Variant224 = sha2Hasher{size: sha2Size224, sum: sha224Sum}
	sha2Variant256 = sha2Hasher{size: sha2Size256, sum: sha256Sum}
	sha2Variant384 = sha2Hasher{size: sha2Size384, sum: sha384Sum}
	sha2Variant512 = sha2Hasher{size: sha2Size512, sum: sha512Sum}
)

var (
	_ stdhash.Hash = (*sha2Digest)(nil)
	_ Hasher       = (*sha2Digest)(nil)
)

// NewSHA224 returns a hash computing the SHA-224 digest.
func NewSHA224() stdhash.Hash { return newSHA2Digest(sha256.New224, sha2Variant224) }

// NewSHA224Hasher returns a stateless SHA-224 helper implementing hash.Hasher.
func NewSHA224Hasher() Hasher { return sha2Variant224 }

// SumSHA224 returns the SHA-224 digest of the input.
func SumSHA224(data []byte) [sha2Size224]byte { return sha256.Sum224(data) }

// NewSHA256 returns a hash computing the SHA-256 digest.
func NewSHA256() stdhash.Hash { return newSHA2Digest(sha256.New, sha2Variant256) }

// NewSHA256Hasher returns a stateless SHA-256 helper implementing hash.Hasher.
func NewSHA256Hasher() Hasher { return sha2Variant256 }

// SumSHA256 returns the SHA-256 digest of the input.
func SumSHA256(data []byte) [sha2Size256]byte { return sha256.Sum256(data) }

// NewSHA384 returns a hash computing the SHA-384 digest.
func NewSHA384() stdhash.Hash { return newSHA2Digest(sha512.New384, sha2Variant384) }

// NewSHA384Hasher returns a stateless SHA-384 helper implementing hash.Hasher.
func NewSHA384Hasher() Hasher { return sha2Variant384 }

// SumSHA384 returns the SHA-384 digest of the input.
func SumSHA384(data []byte) [sha2Size384]byte { return sha512.Sum384(data) }

// NewSHA512 returns a hash computing the SHA-512 digest.
func NewSHA512() stdhash.Hash { return newSHA2Digest(sha512.New, sha2Variant512) }

// NewSHA512Hasher returns a stateless SHA-512 helper implementing hash.Hasher.
func NewSHA512Hasher() Hasher { return sha2Variant512 }

// SumSHA512 returns the SHA-512 digest of the input.
func SumSHA512(data []byte) [sha2Size512]byte { return sha512.Sum512(data) }
