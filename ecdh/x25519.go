package ecdh

import (
	stdecdh "crypto/ecdh"
)

var (
	x25519Curve = stdecdh.X25519()
	x25519Impl  = NewKeyExchange(x25519Curve)
)

// CurveX25519 returns the underlying X25519 curve instance.
func CurveX25519() stdecdh.Curve { return x25519Curve }

// NewX25519 returns a KeyExchange helper bound to the X25519 curve.
func NewX25519() KeyExchange { return x25519Impl }

// GenerateKeyX25519 creates a new private key using crypto/rand.
func GenerateKeyX25519() (*stdecdh.PrivateKey, error) { return x25519Impl.GenerateKey() }

// NewPrivateKeyX25519 constructs a private key from scalar bytes.
func NewPrivateKeyX25519(d []byte) (*stdecdh.PrivateKey, error) { return x25519Impl.NewPrivateKey(d) }

// NewPublicKeyX25519 parses a 32-byte Montgomery u-coordinate public key.
func NewPublicKeyX25519(b []byte) (*stdecdh.PublicKey, error) { return x25519Impl.NewPublicKey(b) }

// SharedSecretX25519 performs the X25519 Diffie-Hellman operation between private and peer.
func SharedSecretX25519(p *stdecdh.PrivateKey, peer *stdecdh.PublicKey) ([]byte, error) {
	return x25519Impl.SharedSecret(p, peer)
}
