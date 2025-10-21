package mac

import (
	"errors"

	internal "github.com/AeonDave/cryptonite-go/internal/poly1305"
)

const (
	// Poly1305KeySize is the size in bytes of the one-time key accepted by Poly1305.
	Poly1305KeySize = 32
	// Poly1305TagSize is the size in bytes of the authenticator produced by Poly1305.
	Poly1305TagSize = internal.TagSize
)

// Poly1305 provides a minimal helper for computing standalone Poly1305 MACs.
//
// The helper wraps the internal Poly1305 implementation reused by the AEAD
// constructions. Callers must supply a unique one-time key for every message.
type Poly1305 struct {
	key [Poly1305KeySize]byte
	mac *internal.MAC
}

// NewPoly1305 initialises a Poly1305 helper with the provided one-time key.
// The key must be exactly 32 bytes as specified by RFC 7539.
func NewPoly1305(key []byte) (*Poly1305, error) {
	if len(key) != Poly1305KeySize {
		return nil, errors.New("mac: invalid Poly1305 key length")
	}
	var k [Poly1305KeySize]byte
	copy(k[:], key)
	return &Poly1305{key: k, mac: internal.New(&k)}, nil
}

// Write appends data to the running authenticator. It mirrors the semantics of
// hash.Hash Write but Poly1305 keys must never be reused across messages.
func (p *Poly1305) Write(data []byte) (int, error) {
	return p.mac.Write(data)
}

// Sum finalises the MAC and returns the authenticator. Further writes will
// panic, matching the behaviour of the underlying implementation.
func (p *Poly1305) Sum() []byte {
	return p.mac.Sum(nil)
}

// Verify finalises the MAC and compares it with expected in constant time.
func (p *Poly1305) Verify(expected []byte) bool {
	return p.mac.Verify(expected)
}

// SumPoly1305 computes a Poly1305 authenticator over msg with the provided
// one-time key and returns the 16-byte tag. The key must be used only once.
func SumPoly1305(key, msg []byte) ([]byte, error) {
	poly, err := NewPoly1305(key)
	if err != nil {
		return nil, err
	}
	_, _ = poly.Write(msg)
	tag := poly.Sum()
	out := make([]byte, len(tag))
	copy(out, tag)
	return out, nil
}

// VerifyPoly1305 recomputes the Poly1305 authenticator for msg and compares it
// to tag using constant-time comparison.
func VerifyPoly1305(key, msg, tag []byte) (bool, error) {
	poly, err := NewPoly1305(key)
	if err != nil {
		return false, err
	}
	_, _ = poly.Write(msg)
	return poly.Verify(tag), nil
}
