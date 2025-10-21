package ecdh

import (
	stdecdh "crypto/ecdh"
)

var (
	x25519Curve = stdecdh.X25519()
	x25519Impl  = NewKeyExchange(x25519Curve)
)

// Curve returns the underlying X25519 curve instance.
func Curve() stdecdh.Curve { return x25519Curve }

// New returns a KeyExchange helper bound to the X25519 curve.
func New() KeyExchange { return x25519Impl }

// GenerateKey creates a new private key using crypto/rand.
func GenerateKey() (*stdecdh.PrivateKey, error) { return x25519Impl.GenerateKey() }

// NewPrivateKey constructs a private key from scalar bytes.
func NewPrivateKey(d []byte) (*stdecdh.PrivateKey, error) { return x25519Impl.NewPrivateKey(d) }

// NewPublicKey parses a 32-byte Montgomery u-coordinate public key.
func NewPublicKey(b []byte) (*stdecdh.PublicKey, error) { return x25519Impl.NewPublicKey(b) }

// SharedSecret performs the X25519 Diffie-Hellman operation between private and peer.
func SharedSecret(p *stdecdh.PrivateKey, peer *stdecdh.PublicKey) ([]byte, error) {
	return x25519Impl.SharedSecret(p, peer)
}
