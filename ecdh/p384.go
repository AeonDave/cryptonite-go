package ecdh

import (
	stdecdh "crypto/ecdh"
)

var (
	p384Curve = stdecdh.P384()
	p384Impl  = NewKeyExchange(p384Curve)
)

// CurveP384 returns the underlying P-384 curve instance.
func CurveP384() stdecdh.Curve { return p384Curve }

// NewP384 returns a KeyExchange helper bound to the P-384 curve.
func NewP384() KeyExchange { return p384Impl }

// GenerateKeyP384 creates a new private key using crypto/rand.
func GenerateKeyP384() (*stdecdh.PrivateKey, error) { return p384Impl.GenerateKey() }

// NewPrivateKeyP384 constructs a private key from scalar bytes.
func NewPrivateKeyP384(d []byte) (*stdecdh.PrivateKey, error) { return p384Impl.NewPrivateKey(d) }

// NewPublicKeyP384 parses an uncompressed public key.
func NewPublicKeyP384(b []byte) (*stdecdh.PublicKey, error) { return p384Impl.NewPublicKey(b) }

// SharedSecretP384 performs the ECDH operation between private and peer.
func SharedSecretP384(p *stdecdh.PrivateKey, peer *stdecdh.PublicKey) ([]byte, error) {
	return p384Impl.SharedSecret(p, peer)
}
