package sha3

import (
	stdhash "hash"

	cryptohash "cryptonite-go/hash"
	"cryptonite-go/internal/keccak"
)

const (
	domainSHA3 = 0x06

	rate224 = 144
	rate256 = 136
	rate384 = 104
	rate512 = 72

	size224 = 28
	size256 = 32
	size384 = 48
	size512 = 64
)

type fixedHasher struct {
	rate   int
	domain byte
	size   int
}

func (h fixedHasher) Hash(msg []byte) []byte {
	out := make([]byte, h.size)
	keccak.SumFixed(h.rate, h.domain, out, msg)
	return out
}

func (h fixedHasher) Size() int { return h.size }

func (h fixedHasher) sumInto(out []byte, msg []byte) {
	keccak.SumFixed(h.rate, h.domain, out, msg)
}

var (
	sha3Variant224 = fixedHasher{rate: rate224, domain: domainSHA3, size: size224}
	sha3Variant256 = fixedHasher{rate: rate256, domain: domainSHA3, size: size256}
	sha3Variant384 = fixedHasher{rate: rate384, domain: domainSHA3, size: size384}
	sha3Variant512 = fixedHasher{rate: rate512, domain: domainSHA3, size: size512}
)

type digest struct {
	sponge keccak.Sponge
	params fixedHasher
}

func newDigest(cfg fixedHasher) *digest {
	var d digest
	d.params = cfg
	d.sponge.Init(cfg.rate, cfg.domain)
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
	out := make([]byte, d.params.size)
	dup.sponge.Squeeze(out)
	return append(b, out...)
}

func (d *digest) Size() int      { return d.params.size }
func (d *digest) BlockSize() int { return d.sponge.Rate() }

func (d *digest) Hash(msg []byte) []byte { return d.params.Hash(msg) }

// Newsha3224 returns a hash computing the SHA3-224 digest.
func Newsha3224() stdhash.Hash { return newDigest(sha3Variant224) }

// Newsha3224Hasher returns a stateless SHA3-224 helper implementing hash.Hasher.
func Newsha3224Hasher() cryptohash.Hasher { return sha3Variant224 }

// Sum224 returns the SHA3-224 digest of the input.
func Sum224(data []byte) [size224]byte {
	var out [size224]byte
	sha3Variant224.sumInto(out[:], data)
	return out
}

// Newsha3256 returns a hash computing the SHA3-256 digest.
func Newsha3256() stdhash.Hash { return newDigest(sha3Variant256) }

// Newsha3256Hasher returns a stateless SHA3-256 helper implementing hash.Hasher.
func Newsha3256Hasher() cryptohash.Hasher { return sha3Variant256 }

// Sum256 returns the SHA3-256 digest of the input.
func Sum256(data []byte) [size256]byte {
	var out [size256]byte
	sha3Variant256.sumInto(out[:], data)
	return out
}

// Newsha3384 returns a hash computing the SHA3-384 digest.
func Newsha3384() stdhash.Hash { return newDigest(sha3Variant384) }

// Newsha3384Hasher returns a stateless SHA3-384 helper implementing hash.Hasher.
func Newsha3384Hasher() cryptohash.Hasher { return sha3Variant384 }

// Sum384 returns the SHA3-384 digest of the input.
func Sum384(data []byte) [size384]byte {
	var out [size384]byte
	sha3Variant384.sumInto(out[:], data)
	return out
}

// Newsha3512 returns a hash computing the SHA3-512 digest.
func Newsha3512() stdhash.Hash { return newDigest(sha3Variant512) }

// Newsha3512Hasher returns a stateless SHA3-512 helper implementing hash.Hasher.
func Newsha3512Hasher() cryptohash.Hasher { return sha3Variant512 }

// Sum512 returns the SHA3-512 digest of the input.
func Sum512(data []byte) [size512]byte {
	var out [size512]byte
	sha3Variant512.sumInto(out[:], data)
	return out
}
