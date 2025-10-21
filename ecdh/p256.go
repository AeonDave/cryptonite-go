package ecdh

import (
	"crypto/ecdh"
	"crypto/rand"
)

var curve = ecdh.P256()

// Curve returns the underlying P-256 curve instance.
func Curve() ecdh.Curve {
	return curve
}

// GenerateKey creates a new private key using crypto/rand.
func GenerateKey() (*ecdh.PrivateKey, error) {
	return curve.GenerateKey(rand.Reader)
}

// NewPrivateKey constructs a private key from scalar bytes.
func NewPrivateKey(d []byte) (*ecdh.PrivateKey, error) {
	return curve.NewPrivateKey(d)
}

// NewPublicKey parses an uncompressed public key.
func NewPublicKey(b []byte) (*ecdh.PublicKey, error) {
	return curve.NewPublicKey(b)
}

// SharedSecret performs the ECDH operation between priv and peer.
func SharedSecret(priv *ecdh.PrivateKey, peer *ecdh.PublicKey) ([]byte, error) {
	return priv.ECDH(peer)
}
