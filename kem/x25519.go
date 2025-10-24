package kem

import (
	"errors"

	"github.com/AeonDave/cryptonite-go/ecdh"
	"github.com/AeonDave/cryptonite-go/secret"
)

const (
	// PublicSize is the length in bytes of an encoded X25519 public key.
	PublicSize = 32
	// PrivateSize is the length in bytes of an encoded X25519 private scalar.
	PrivateSize = 32
)

// Adapter exposes the classical X25519 ECDH primitive through the kem.KEM
// interface. The ciphertext returned by Encapsulate is the ephemeral X25519
// public key.
//
// The adapter intentionally lives in the kem package to highlight that it
// provides classical security. It can be composed with pq.Hybrid to build
// hybrid or future post-quantum deployments.
type Adapter struct {
	ke ecdh.KeyExchange
}

var _ KEM = (*Adapter)(nil)

// New returns a ready-to-use X25519-based kem.KEM implementation.
func New() KEM {
	return &Adapter{ke: ecdh.NewX25519()}
}

// GenerateKey creates a fresh X25519 key pair and returns the encoded public
// and private scalars.
func (a *Adapter) GenerateKey() ([]byte, []byte, error) {
	if a == nil || a.ke == nil {
		return nil, nil, errors.New("kem/x25519: nil adapter")
	}
	priv, err := a.ke.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	pubBytes := priv.PublicKey().Bytes()
	privBytes := priv.Bytes()
	return pubBytes, privBytes, nil
}

// Encapsulate performs an ephemeral-static X25519 exchange with the recipient
// public key and returns the ephemeral public key as the ciphertext together
// with the 32-byte shared secret.
func (a *Adapter) Encapsulate(public []byte) ([]byte, []byte, error) {
	if a == nil || a.ke == nil {
		return nil, nil, errors.New("kem/x25519: nil adapter")
	}
	if len(public) != PublicSize {
		return nil, nil, errors.New("kem/x25519: invalid public key length")
	}
	peer, err := a.ke.NewPublicKey(public)
	if err != nil {
		return nil, nil, err
	}
	eph, err := a.ke.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	shared, err := eph.ECDH(peer)
	if err != nil {
		return nil, nil, err
	}
	return eph.PublicKey().Bytes(), shared, nil
}

// Decapsulate recovers the shared secret using the recipient private key and
// the encapsulated ephemeral public key.
func (a *Adapter) Decapsulate(private, ciphertext []byte) ([]byte, error) {
	if a == nil || a.ke == nil {
		return nil, errors.New("kem/x25519: nil adapter")
	}
	if len(private) != PrivateSize {
		return nil, errors.New("kem/x25519: invalid private key length")
	}
	if len(ciphertext) != PublicSize {
		return nil, errors.New("kem/x25519: invalid ciphertext length")
	}
	privBytes := secret.CloneBytes(private)
	priv, err := a.ke.NewPrivateKey(privBytes)
	if err != nil {
		secret.WipeBytes(privBytes)
		return nil, err
	}
	secret.WipeBytes(privBytes)
	peer, err := a.ke.NewPublicKey(ciphertext)
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(peer)
	if err != nil {
		return nil, err
	}
	return shared, nil
}
