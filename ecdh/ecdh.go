package ecdh

import (
	stdecdh "crypto/ecdh"
	"crypto/rand"
)

// KeyExchange describes the minimal API shared by ECDH helpers exposed by the
// library. Implementations are thin wrappers around crypto/ecdh curves and
// provide uniform helpers for performing Diffie-Hellman operations without
// leaking the underlying curve-specific types to callers.
type KeyExchange interface {
	// Curve returns the underlying crypto/ecdh curve implementation.
	Curve() stdecdh.Curve
	// GenerateKey creates a new private key using crypto/rand.
	GenerateKey() (*stdecdh.PrivateKey, error)
	// NewPrivateKey constructs a private key from scalar bytes.
	NewPrivateKey(d []byte) (*stdecdh.PrivateKey, error)
	// NewPublicKey parses a peer public key in the format required by the curve.
	NewPublicKey(b []byte) (*stdecdh.PublicKey, error)
	// SharedSecret performs the ECDH operation between private and peer.
	SharedSecret(p *stdecdh.PrivateKey, peer *stdecdh.PublicKey) ([]byte, error)
}

type curveImpl struct {
	curve stdecdh.Curve
}

// NewKeyExchange wraps curve in a KeyExchange implementation.
func NewKeyExchange(curve stdecdh.Curve) KeyExchange {
	if curve == nil {
		panic("ecdh: nil curve")
	}
	return &curveImpl{curve: curve}
}

func (c *curveImpl) Curve() stdecdh.Curve { return c.curve }

func (c *curveImpl) GenerateKey() (*stdecdh.PrivateKey, error) {
	return c.curve.GenerateKey(rand.Reader)
}

func (c *curveImpl) NewPrivateKey(d []byte) (*stdecdh.PrivateKey, error) {
	return c.curve.NewPrivateKey(d)
}

func (c *curveImpl) NewPublicKey(b []byte) (*stdecdh.PublicKey, error) {
	return c.curve.NewPublicKey(b)
}

func (c *curveImpl) SharedSecret(p *stdecdh.PrivateKey, peer *stdecdh.PublicKey) ([]byte, error) {
	return p.ECDH(peer)
}
