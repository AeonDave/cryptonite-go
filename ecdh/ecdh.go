package ecdh

import (
	"crypto"
	stdecdh "crypto/ecdh"
	"crypto/rand"
	"errors"
)

// PrivateKey represents an ECDH private key backed either by the Go standard
// library implementation or by a custom curve implementation (such as X448).
//
// The interface intentionally mirrors the small subset of methods exposed by
// crypto/ecdh.PrivateKey that are required across the repository. This allows
// callers to operate on keys uniformly without leaking the concrete
// implementation details or exposing mutable internal buffers.
type PrivateKey interface {
	// Bytes returns the canonical encoding of the private key.
	Bytes() []byte
	// PublicKey returns the corresponding public key instance.
	PublicKey() PublicKey
	// ECDH computes the shared secret with the peer public key.
	ECDH(peer PublicKey) ([]byte, error)
	// Equal reports whether the provided key matches this private key.
	Equal(x crypto.PrivateKey) bool
}

// PublicKey represents an ECDH public key suitable for the associated
// PrivateKey type.
type PublicKey interface {
	// Bytes returns the canonical encoding of the public key.
	Bytes() []byte
	// Equal reports whether the provided key matches this public key.
	Equal(x crypto.PublicKey) bool
}

// KeyExchange describes the minimal API shared by ECDH helpers exposed by the
// library. Implementations may wrap crypto/ecdh curves or provide custom
// curve-specific logic while presenting a uniform surface to callers.
type KeyExchange interface {
	// Curve returns the underlying crypto/ecdh curve implementation when
	// available. For custom curves without a crypto/ecdh counterpart this may
	// return nil.
	Curve() stdecdh.Curve
	// GenerateKey creates a new private key using crypto/rand.
	GenerateKey() (PrivateKey, error)
	// NewPrivateKey constructs a private key from scalar bytes.
	NewPrivateKey(d []byte) (PrivateKey, error)
	// NewPublicKey parses a peer public key in the format required by the curve.
	NewPublicKey(b []byte) (PublicKey, error)
	// SharedSecret performs the ECDH operation between private and peer.
	SharedSecret(p PrivateKey, peer PublicKey) ([]byte, error)
}

var (
	errIncompatiblePrivate = errors.New("ecdh: incompatible private key type")
	errIncompatiblePublic  = errors.New("ecdh: incompatible public key type")
)

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

func (c *curveImpl) GenerateKey() (PrivateKey, error) {
	priv, err := c.curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &stdPrivateKey{key: priv}, nil
}

func (c *curveImpl) NewPrivateKey(d []byte) (PrivateKey, error) {
	priv, err := c.curve.NewPrivateKey(d)
	if err != nil {
		return nil, err
	}
	return &stdPrivateKey{key: priv}, nil
}

func (c *curveImpl) NewPublicKey(b []byte) (PublicKey, error) {
	pub, err := c.curve.NewPublicKey(b)
	if err != nil {
		return nil, err
	}
	return &stdPublicKey{key: pub}, nil
}

func (c *curveImpl) SharedSecret(p PrivateKey, peer PublicKey) ([]byte, error) {
	sp, ok := p.(*stdPrivateKey)
	if !ok {
		return nil, errIncompatiblePrivate
	}
	pp, ok := peer.(*stdPublicKey)
	if !ok {
		return nil, errIncompatiblePublic
	}
	return sp.key.ECDH(pp.key)
}

type stdPrivateKey struct {
	key *stdecdh.PrivateKey
}

func (k *stdPrivateKey) Bytes() []byte {
	if k == nil || k.key == nil {
		return nil
	}
	return k.key.Bytes()
}

func (k *stdPrivateKey) PublicKey() PublicKey {
	if k == nil || k.key == nil {
		return nil
	}
	return &stdPublicKey{key: k.key.PublicKey()}
}

func (k *stdPrivateKey) ECDH(peer PublicKey) ([]byte, error) {
	if k == nil || k.key == nil {
		return nil, errors.New("ecdh: nil private key")
	}
	pp, ok := peer.(*stdPublicKey)
	if !ok {
		return nil, errIncompatiblePublic
	}
	return k.key.ECDH(pp.key)
}

func (k *stdPrivateKey) Equal(x crypto.PrivateKey) bool {
	if k == nil || k.key == nil {
		return false
	}
	return k.key.Equal(x)
}

type stdPublicKey struct {
	key *stdecdh.PublicKey
}

func (k *stdPublicKey) Bytes() []byte {
	if k == nil || k.key == nil {
		return nil
	}
	return k.key.Bytes()
}

func (k *stdPublicKey) Equal(x crypto.PublicKey) bool {
	if k == nil || k.key == nil {
		return false
	}
	return k.key.Equal(x)
}
