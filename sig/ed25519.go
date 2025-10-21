package sig

import (
	"crypto/ed25519"

	"cryptonite-go/sig/x25519"
)

const (
	PublicKeySize  = x25519.PublicKeySize
	PrivateKeySize = x25519.PrivateKeySize
	SeedSize       = x25519.SeedSize
	SignatureSize  = x25519.SignatureSize
)

// NewEd25519 returns a Scheme backed by the Ed25519 helpers.
func NewEd25519() Scheme { return x25519.New() }

// GenerateKey creates a new Ed25519 keypair using crypto/rand.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return x25519.GenerateKey()
}

// FromSeed derives a deterministic keypair from a 32-byte seed.
func FromSeed(seed []byte) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return x25519.FromSeed(seed)
}

// Sign produces an Ed25519 signature of msg using priv.
func Sign(priv ed25519.PrivateKey, msg []byte) []byte {
	return x25519.Sign(priv, msg)
}

// Verify reports whether sig is a valid Ed25519 signature of msg by pub.
func Verify(pub ed25519.PublicKey, msg, sig []byte) bool {
	return x25519.Verify(pub, msg, sig)
}
