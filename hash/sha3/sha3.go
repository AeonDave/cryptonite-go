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

// Newsha3224 returns a hash computing the SHA3-224 digest.
func Newsha3224() hash.Hash { return newDigest(144, 0x06, 28) }

// Newsha3256 returns a hash computing the SHA3-256 digest.
func Newsha3256() hash.Hash { return newDigest(136, 0x06, 32) }

// Newsha3384 returns a hash computing the SHA3-384 digest.
func Newsha3384() hash.Hash { return newDigest(104, 0x06, 48) }

// Newsha3512 returns a hash computing the SHA3-512 digest.
func Newsha3512() hash.Hash { return newDigest(72, 0x06, 64) }
