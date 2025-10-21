package ed25519

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

// GenerateKey creates a new Ed25519 keypair using crypto/rand.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// FromSeed derives a deterministic keypair from a 32-byte seed.
func FromSeed(seed []byte) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if len(seed) != SeedSize {
		return nil, nil, errors.New("ed25519: invalid seed size")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv, nil
}

// Sign produces an Ed25519 signature of msg using priv.
func Sign(priv ed25519.PrivateKey, msg []byte) []byte {
	return ed25519.Sign(priv, msg)
}

// Verify reports whether sig is a valid Ed25519 signature of msg by pub.
func Verify(pub ed25519.PublicKey, msg, sig []byte) bool {
	return ed25519.Verify(pub, msg, sig)
}
