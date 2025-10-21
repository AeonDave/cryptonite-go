package x25519

import (
	stdecdh "crypto/ecdh"

	"cryptonite-go/ecdh"
)

var (
	curve = stdecdh.X25519()
	impl  = ecdh.NewKeyExchange(curve)
)

// Curve returns the underlying X25519 curve instance.
func Curve() stdecdh.Curve { return curve }

// New returns a KeyExchange helper bound to the X25519 curve.
func New() ecdh.KeyExchange { return impl }

// GenerateKey creates a new private key using crypto/rand.
func GenerateKey() (*stdecdh.PrivateKey, error) { return impl.GenerateKey() }

// NewPrivateKey constructs a private key from scalar bytes.
func NewPrivateKey(d []byte) (*stdecdh.PrivateKey, error) { return impl.NewPrivateKey(d) }

// NewPublicKey parses a 32-byte Montgomery u-coordinate public key.
func NewPublicKey(b []byte) (*stdecdh.PublicKey, error) { return impl.NewPublicKey(b) }

// SharedSecret performs the X25519 Diffie-Hellman operation between priv and peer.
func SharedSecret(priv *stdecdh.PrivateKey, peer *stdecdh.PublicKey) ([]byte, error) {
	return impl.SharedSecret(priv, peer)
}
