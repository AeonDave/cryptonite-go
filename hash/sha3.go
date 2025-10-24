package hash

import (
	"crypto/sha3"
	stdhash "hash"
)

const (
	sha3Size224 = 28
	sha3Size256 = 32
	sha3Size384 = 48
	sha3Size512 = 64
)

type sha3Hasher struct {
	size int
	sum  func([]byte) []byte
}

func (h sha3Hasher) Hash(msg []byte) []byte {
	return h.sum(msg)
}

func (h sha3Hasher) Size() int { return h.size }

type sha3Digest struct {
	state  *sha3.SHA3
	hasher sha3Hasher
}

func newSHA3Digest(newState func() *sha3.SHA3, hasher sha3Hasher) *sha3Digest {
	return &sha3Digest{
		state:  newState(),
		hasher: hasher,
	}
}

func (d *sha3Digest) Reset() { d.state.Reset() }

func (d *sha3Digest) Write(p []byte) (int, error) { return d.state.Write(p) }

func (d *sha3Digest) Sum(b []byte) []byte { return d.state.Sum(b) }

func (d *sha3Digest) Size() int { return d.state.Size() }

func (d *sha3Digest) BlockSize() int { return d.state.BlockSize() }

func (d *sha3Digest) Hash(msg []byte) []byte { return d.hasher.Hash(msg) }

func sha3Sum224(msg []byte) []byte {
	sum := sha3.Sum224(msg)
	return append([]byte(nil), sum[:]...)
}

func sha3Sum256(msg []byte) []byte {
	sum := sha3.Sum256(msg)
	return append([]byte(nil), sum[:]...)
}

func sha3Sum384(msg []byte) []byte {
	sum := sha3.Sum384(msg)
	return append([]byte(nil), sum[:]...)
}

func sha3Sum512(msg []byte) []byte {
	sum := sha3.Sum512(msg)
	return append([]byte(nil), sum[:]...)
}

var (
	sha3Variant224 = sha3Hasher{size: sha3Size224, sum: sha3Sum224}
	sha3Variant256 = sha3Hasher{size: sha3Size256, sum: sha3Sum256}
	sha3Variant384 = sha3Hasher{size: sha3Size384, sum: sha3Sum384}
	sha3Variant512 = sha3Hasher{size: sha3Size512, sum: sha3Sum512}
)

var (
	_ stdhash.Hash = (*sha3Digest)(nil)
	_ Hasher       = (*sha3Digest)(nil)
)

// NewSHA3224 returns a hash computing the SHA3-224 digest.
func NewSHA3224() stdhash.Hash { return newSHA3Digest(sha3.New224, sha3Variant224) }

// NewSHA3224Hasher returns a stateless SHA3-224 helper implementing hash.Hasher.
func NewSHA3224Hasher() Hasher { return sha3Variant224 }

// Sum224 returns the SHA3-224 digest of the input.
func Sum224(data []byte) [sha3Size224]byte { return sha3.Sum224(data) }

// NewSHA3256 returns a hash computing the SHA3-256 digest.
func NewSHA3256() stdhash.Hash { return newSHA3Digest(sha3.New256, sha3Variant256) }

// NewSHA3256Hasher returns a stateless SHA3-256 helper implementing hash.Hasher.
func NewSHA3256Hasher() Hasher { return sha3Variant256 }

// Sum256 returns the SHA3-256 digest of the input.
func Sum256(data []byte) [sha3Size256]byte { return sha3.Sum256(data) }

// NewSHA3384 returns a hash computing the SHA3-384 digest.
func NewSHA3384() stdhash.Hash { return newSHA3Digest(sha3.New384, sha3Variant384) }

// NewSHA3384Hasher returns a stateless SHA3-384 helper implementing hash.Hasher.
func NewSHA3384Hasher() Hasher { return sha3Variant384 }

// Sum384 returns the SHA3-384 digest of the input.
func Sum384(data []byte) [sha3Size384]byte { return sha3.Sum384(data) }

// NewSHA3512 returns a hash computing the SHA3-512 digest.
func NewSHA3512() stdhash.Hash { return newSHA3Digest(sha3.New512, sha3Variant512) }

// NewSHA3512Hasher returns a stateless SHA3-512 helper implementing hash.Hasher.
func NewSHA3512Hasher() Hasher { return sha3Variant512 }

// Sum512 returns the SHA3-512 digest of the input.
func Sum512(data []byte) [sha3Size512]byte { return sha3.Sum512(data) }
