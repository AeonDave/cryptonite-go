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

// Curve returns the underlying X25519 curve instance.
//
// Deprecated: Use [CurveX25519] instead.
func Curve() stdecdh.Curve { return CurveX25519() }

// NewX25519 returns a KeyExchange helper bound to the X25519 curve.
func NewX25519() KeyExchange { return x25519Impl }

// New returns a KeyExchange helper bound to the X25519 curve.
//
// Deprecated: Use [NewX25519] instead.
func New() KeyExchange { return NewX25519() }

// GenerateKeyX25519 creates a new private key using crypto/rand.
func GenerateKeyX25519() (PrivateKey, error) { return x25519Impl.GenerateKey() }

// GenerateKey creates a new private key using crypto/rand.
//
// Deprecated: Use [GenerateKeyX25519] instead.
func GenerateKey() (PrivateKey, error) { return GenerateKeyX25519() }

// NewPrivateKeyX25519 constructs a private key from scalar bytes.
func NewPrivateKeyX25519(d []byte) (PrivateKey, error) { return x25519Impl.NewPrivateKey(d) }

// NewPrivateKey constructs a private key from scalar bytes.
//
// Deprecated: Use [NewPrivateKeyX25519] instead.
func NewPrivateKey(d []byte) (PrivateKey, error) { return NewPrivateKeyX25519(d) }

// NewPublicKeyX25519 parses a 32-byte Montgomery u-coordinate public key.
func NewPublicKeyX25519(b []byte) (PublicKey, error) { return x25519Impl.NewPublicKey(b) }

// NewPublicKey parses a 32-byte Montgomery u-coordinate public key.
//
// Deprecated: Use [NewPublicKeyX25519] instead.
func NewPublicKey(b []byte) (PublicKey, error) { return NewPublicKeyX25519(b) }

// SharedSecretX25519 performs the X25519 Diffie-Hellman operation between private and peer.
func SharedSecretX25519(p PrivateKey, peer PublicKey) ([]byte, error) {
	return x25519Impl.SharedSecret(p, peer)
}

// SharedSecret performs the X25519 Diffie-Hellman operation between private and peer.
//
// Deprecated: Use [SharedSecretX25519] instead.
func SharedSecret(p PrivateKey, peer PublicKey) ([]byte, error) {
	return SharedSecretX25519(p, peer)
}
