package x25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
)

const (
	PublicKeySize  = ed25519.PublicKeySize
	PrivateKeySize = ed25519.PrivateKeySize
	SeedSize       = ed25519.SeedSize
	SignatureSize  = ed25519.SignatureSize
)

type Scheme struct{}

// New returns a Scheme for EdDSA over Curve25519 (Ed25519).
func New() Scheme { return Scheme{} }

// GenerateKey creates a new EdDSA keypair using crypto/rand.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

// FromSeed derives a deterministic keypair from a 32-byte seed.
func FromSeed(seed []byte) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if len(seed) != SeedSize {
		return nil, nil, errors.New("x25519: invalid seed size")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv, nil
}

// Sign produces an EdDSA signature of msg using priv.
func Sign(priv ed25519.PrivateKey, msg []byte) []byte {
	return ed25519.Sign(priv, msg)
}

// Verify reports whether sig is a valid signature of msg by pub.
func Verify(pub ed25519.PublicKey, msg, sig []byte) bool {
	return ed25519.Verify(pub, msg, sig)
}

func (Scheme) GenerateKey() ([]byte, []byte, error) {
	pub, priv, err := GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return append([]byte(nil), pub...), append([]byte(nil), priv...), nil
}

func (Scheme) Sign(private []byte, msg []byte) ([]byte, error) {
	if len(private) != PrivateKeySize {
		return nil, errors.New("x25519: invalid private key length")
	}
	sig := ed25519.Sign(ed25519.PrivateKey(private), msg)
	return append([]byte(nil), sig...), nil
}

func (Scheme) Verify(public []byte, msg, signature []byte) bool {
	if len(public) != PublicKeySize || len(signature) != SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(public), msg, signature)
}
