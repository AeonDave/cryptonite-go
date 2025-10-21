package sha3

import (
	"hash"

	"cryptonite-go/internal/keccak"
)

type digest struct {
	sponge     keccak.Sponge
	outputSize int
}

func newDigest(rate int, ds byte, out int) *digest {
	var d digest
	d.outputSize = out
	d.sponge.Init(rate, ds)
	return &d
}

func (d *digest) Reset() {
	d.sponge.Reset()
}

func (d *digest) Write(p []byte) (int, error) {
	d.sponge.Absorb(p)
	return len(p), nil
}

func (d *digest) Sum(b []byte) []byte {
	dup := *d
	out := make([]byte, d.outputSize)
	dup.sponge.Squeeze(out)
	return append(b, out...)
}

func (d *digest) Size() int      { return d.outputSize }
func (d *digest) BlockSize() int { return d.sponge.Rate() }

func sum(rate int, ds byte, out []byte, msg []byte) {
	var s keccak.Sponge
	s.Init(rate, ds)
	s.Absorb(msg)
	s.Squeeze(out)
}

// Newsha3224 returns a hash computing the SHA3-224 digest.
func Newsha3224() hash.Hash { return newDigest(144, 0x06, 28) }

// Sum224 returns the SHA3-224 digest of the input.
func Sum224(data []byte) [28]byte {
	var out [28]byte
	sum(144, 0x06, out[:], data)
	return out
}

// Newsha3256 returns a hash computing the SHA3-256 digest.
func Newsha3256() hash.Hash { return newDigest(136, 0x06, 32) }

// Sum256 returns the SHA3-256 digest of the input.
func Sum256(data []byte) [32]byte {
	var out [32]byte
	sum(136, 0x06, out[:], data)
	return out
}

// Newsha3384 returns a hash computing the SHA3-384 digest.
func Newsha3384() hash.Hash { return newDigest(104, 0x06, 48) }

// Sum384 returns the SHA3-384 digest of the input.
func Sum384(data []byte) [48]byte {
	var out [48]byte
	sum(104, 0x06, out[:], data)
	return out
}

// Newsha3512 returns a hash computing the SHA3-512 digest.
func Newsha3512() hash.Hash { return newDigest(72, 0x06, 64) }

// Sum512 returns the SHA3-512 digest of the input.
func Sum512(data []byte) [64]byte {
	var out [64]byte
	sum(72, 0x06, out[:], data)
	return out
}
