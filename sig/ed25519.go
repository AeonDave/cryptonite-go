package sig

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
)

// Expose standard ed25519 sizes so callers can allocate buffers without
// importing crypto/ed25519 directly.
const (
	PublicKeySize  = ed25519.PublicKeySize
	PrivateKeySize = ed25519.PrivateKeySize
	SeedSize       = ed25519.SeedSize
	SignatureSize  = ed25519.SignatureSize
)

type ed25519Scheme struct{}

// NewEd25519 returns a Signature backed by the Ed25519 helpers.
func NewEd25519() Signature { return ed25519Scheme{} }

// GenerateKey creates a new Ed25519 keypair using crypto/rand.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, p, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return append(ed25519.PublicKey(nil), pub...), append(ed25519.PrivateKey(nil), p...), nil
}

// FromSeed derives a deterministic keypair from a 32-byte seed.
func FromSeed(seed []byte) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if len(seed) != SeedSize {
		return nil, nil, errors.New("sig: invalid Ed25519 seed length")
	}
	p := ed25519.NewKeyFromSeed(seed)
	pub := p.Public().(ed25519.PublicKey)
	return append(ed25519.PublicKey(nil), pub...), append(ed25519.PrivateKey(nil), p...), nil
}

// Sign produces an Ed25519 signature of msg using priv.
func Sign(priv ed25519.PrivateKey, msg []byte) []byte {
	return ed25519.Sign(priv, msg)
}

// Verify reports whether sig is a valid Ed25519 signature of msg by pub.
func Verify(pub ed25519.PublicKey, msg, sig []byte) bool {
	return ed25519.Verify(pub, msg, sig)
}

func (ed25519Scheme) GenerateKey() ([]byte, []byte, error) {
	pub, p, err := GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return append([]byte(nil), pub...), append([]byte(nil), p...), nil
}

func (ed25519Scheme) Sign(private []byte, msg []byte) ([]byte, error) {
	if len(private) != PrivateKeySize {
		return nil, errors.New("sig: invalid Ed25519 private key length")
	}
	sig := ed25519.Sign(private, msg)
	return append([]byte(nil), sig...), nil
}

func (ed25519Scheme) Verify(public []byte, msg, signature []byte) bool {
	if len(public) != PublicKeySize || len(signature) != SignatureSize {
		return false
	}
	return ed25519.Verify(public, msg, signature)
}
