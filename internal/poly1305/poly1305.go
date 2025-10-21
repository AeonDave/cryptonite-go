package poly1305

import (
	"crypto/subtle"
	"encoding/binary"
)

// TagSize is the size, in bytes, of a Poly1305 authenticator.
const TagSize = 16

// Tag computes the Poly1305 authenticator over the ChaCha20-Poly1305 layout
// (AAD || padding || ciphertext || padding || len(AAD) || len(ciphertext)).
// The polyKey must be the one-time key derived from the cipher stream.
func Tag(polyKey [32]byte, ad, ciphertext []byte) [TagSize]byte {
	mac := New(&polyKey)
	writeWithPadding(mac, ad)
	writeWithPadding(mac, ciphertext)
	writeUint64(mac, len(ad))
	writeUint64(mac, len(ciphertext))
	var tag [TagSize]byte
	copy(tag[:], mac.Sum(nil))
	return tag
}

func writeWithPadding(mac *MAC, data []byte) {
	_, _ = mac.Write(data)
	if rem := len(data) % TagSize; rem != 0 {
		var zero [TagSize]byte
		_, _ = mac.Write(zero[:TagSize-rem])
	}
}

func writeUint64(mac *MAC, n int) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(n))
	_, _ = mac.Write(buf[:])
}

// Sum generates an authenticator for msg using a one-time key and puts the
// 16-byte result into out. Authenticating two different messages with the same
// key allows an attacker to forge messages at will.
func Sum(out *[TagSize]byte, m []byte, key *[32]byte) {
	h := New(key)
	_, _ = h.Write(m)
	h.Sum(out[:0])
}

// Verify returns true if mac is a valid authenticator for m with the given key.
func Verify(mac *[TagSize]byte, m []byte, key *[32]byte) bool {
	var tmp [TagSize]byte
	Sum(&tmp, m, key)
	return subtle.ConstantTimeCompare(tmp[:], mac[:]) == 1
}

// New returns a new MAC computing an authentication tag of all data written to
// it with the given key.
func New(key *[32]byte) *MAC {
	m := &MAC{}
	initialize(key, &m.macState)
	return m
}

// MAC is an io.Writer computing an authentication tag of the data written to it.
//
// MAC cannot be used like common hash.Hash implementations, because using a
// Poly1305 key twice breaks its security. Therefore writing data to a running MAC
// after calling Sum or Verify causes it to panic.
type MAC struct {
	mac // platform-dependent implementation

	finalized bool
}

// Size returns the number of bytes Sum will return.
func (h *MAC) Size() int { return TagSize }

// Write adds more data to the running message authentication code. It never
// returns an error. It must not be called after the first call of Sum or Verify.
func (h *MAC) Write(p []byte) (n int, err error) {
	if h.finalized {
		panic("poly1305: write to MAC after Sum or Verify")
	}
	return h.mac.Write(p)
}

// Sum computes the authenticator of all data written to the message
// authentication code.
func (h *MAC) Sum(b []byte) []byte {
	var mac [TagSize]byte
	h.mac.Sum(&mac)
	h.finalized = true
	return append(b, mac[:]...)
}

// Verify returns whether the authenticator of all data written to the message
// authentication code matches the expected value.
func (h *MAC) Verify(expected []byte) bool {
	var mac [TagSize]byte
	h.mac.Sum(&mac)
	h.finalized = true
	return subtle.ConstantTimeCompare(expected, mac[:]) == 1
}
