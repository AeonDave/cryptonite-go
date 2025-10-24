package ecdh

import (
	stdecdh "crypto/ecdh"
)

var (
	p256Curve = stdecdh.P256()
	p256Impl  = NewKeyExchange(p256Curve)
)

// CurveP256 returns the underlying P-256 curve instance.
func CurveP256() stdecdh.Curve { return p256Curve }

// NewP256 returns a KeyExchange helper bound to the P-256 curve.
func NewP256() KeyExchange { return p256Impl }

// GenerateKeyP256 creates a new private key using crypto/rand.
func GenerateKeyP256() (PrivateKey, error) { return p256Impl.GenerateKey() }

// NewPrivateKeyP256 constructs a private key from scalar bytes.
func NewPrivateKeyP256(d []byte) (PrivateKey, error) { return p256Impl.NewPrivateKey(d) }

// NewPublicKeyP256 parses an uncompressed public key.
func NewPublicKeyP256(b []byte) (PublicKey, error) { return p256Impl.NewPublicKey(b) }

// SharedSecretP256 performs the ECDH operation between private and peer.
func SharedSecretP256(p PrivateKey, peer PublicKey) ([]byte, error) {
	return p256Impl.SharedSecret(p, peer)
}
