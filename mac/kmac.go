package mac

import (
	stdhash "hash"

	"github.com/AeonDave/cryptonite-go/internal/keccak"
)

const (
	domainKMAC  = 0x04
	kmac128Rate = 168
	kmac256Rate = 136
	kmac128Size = 32
	kmac256Size = 64
)

// KMAC implements the SP 800-185 KMAC construction backed by cSHAKE.
type KMAC struct {
	sponge keccak.Sponge
	rate   int
	outLen int
	prefix []byte
	keyPad []byte
}

// newKMAC initializes a KMAC instance with the provided parameters.
func newKMAC(rate int, key, customization []byte, outLen int) *KMAC {
	k := &KMAC{rate: rate, outLen: outLen}
	prefix := keccak.EncodeString([]byte("KMAC"))
	prefix = append(prefix, keccak.EncodeString(customization)...)
	k.prefix = keccak.Bytepad(prefix, rate)
	keyEnc := keccak.EncodeString(key)
	k.keyPad = keccak.Bytepad(keyEnc, rate)
	k.Reset()
	return k
}

// Reset restores the MAC to its initial state, ready to absorb a new message.
func (k *KMAC) Reset() {
	k.sponge.Init(k.rate, domainKMAC)
	k.sponge.Absorb(k.prefix)
	k.sponge.Absorb(k.keyPad)
}

// Write absorbs data into the MAC state.
func (k *KMAC) Write(p []byte) (int, error) {
	k.sponge.Absorb(p)
	return len(p), nil
}

// Sum finalises the computation and appends the resulting MAC to b.
func (k *KMAC) Sum(b []byte) []byte {
	dup := *k
	dup.sponge.Absorb(keccak.RightEncode(uint64(dup.outLen * 8)))
	out := make([]byte, dup.outLen)
	dup.sponge.Squeeze(out)
	return append(b, out...)
}

// Size reports the size in bytes of the final MAC output.
func (k *KMAC) Size() int { return k.outLen }

// BlockSize returns the rate of the underlying cSHAKE permutation.
func (k *KMAC) BlockSize() int { return k.rate }

// NewKMAC128 constructs a streaming KMAC128 instance producing a 32-byte MAC.
func NewKMAC128(key, customization []byte) stdhash.Hash {
	return newKMAC(kmac128Rate, cloneBytes(key), cloneBytes(customization), kmac128Size)
}

// NewKMAC256 constructs a streaming KMAC256 instance producing a 64-byte MAC.
func NewKMAC256(key, customization []byte) stdhash.Hash {
	return newKMAC(kmac256Rate, cloneBytes(key), cloneBytes(customization), kmac256Size)
}

// NewKMAC128WithSize constructs a streaming KMAC128 instance with a custom output length.
func NewKMAC128WithSize(key, customization []byte, outLen int) stdhash.Hash {
	return newKMAC(kmac128Rate, cloneBytes(key), cloneBytes(customization), outLen)
}

// NewKMAC256WithSize constructs a streaming KMAC256 instance with a custom output length.
func NewKMAC256WithSize(key, customization []byte, outLen int) stdhash.Hash {
	return newKMAC(kmac256Rate, cloneBytes(key), cloneBytes(customization), outLen)
}

// KMAC128 computes a single-shot KMAC128 MAC of the provided message.
func KMAC128(key, customization, msg []byte, outLen int) []byte {
	h := newKMAC(kmac128Rate, cloneBytes(key), cloneBytes(customization), outLen)
	h.Write(msg)
	return h.Sum(nil)
}

// KMAC256 computes a single-shot KMAC256 MAC of the provided message.
func KMAC256(key, customization, msg []byte, outLen int) []byte {
	h := newKMAC(kmac256Rate, cloneBytes(key), cloneBytes(customization), outLen)
	h.Write(msg)
	return h.Sum(nil)
}

func cloneBytes(in []byte) []byte {
	if len(in) == 0 {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}
