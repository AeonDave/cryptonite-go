package ecdh

import (
	"crypto"
	stdecdh "crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"

	"github.com/AeonDave/cryptonite-go/internal/x448"
)

const (
	x448ScalarSize = 56
	x448PointSize  = 56
)

var (
	x448BasePoint = func() [x448PointSize]byte {
		var bp [x448PointSize]byte
		bp[0] = 5
		return bp
	}()

	x448Impl = &x448KeyExchange{}

	errInvalidX448Scalar = errors.New("ecdh/x448: invalid private scalar length")
	errInvalidX448Public = errors.New("ecdh/x448: invalid public key length")
	errX448LowOrder      = errors.New("ecdh/x448: low-order input point")
)

// NewX448 returns a KeyExchange helper implementing the RFC 7748 X448 Diffie-Hellman
// primitive. The implementation is self-contained because crypto/ecdh currently
// does not expose Curve448.
func NewX448() KeyExchange { return x448Impl }

// GenerateKeyX448 creates a new X448 private key using crypto/rand.
func GenerateKeyX448() (PrivateKey, error) { return x448Impl.GenerateKey() }

// NewPrivateKeyX448 constructs an X448 private key from scalar bytes.
func NewPrivateKeyX448(d []byte) (PrivateKey, error) { return x448Impl.NewPrivateKey(d) }

// NewPublicKeyX448 parses a 56-byte X448 public key.
func NewPublicKeyX448(b []byte) (PublicKey, error) { return x448Impl.NewPublicKey(b) }

// SharedSecretX448 performs the X448 Diffie-Hellman operation between private and peer.
func SharedSecretX448(p PrivateKey, peer PublicKey) ([]byte, error) {
	return x448Impl.SharedSecret(p, peer)
}

type x448KeyExchange struct{}

func (x *x448KeyExchange) Curve() stdecdh.Curve { return nil }

func (x *x448KeyExchange) GenerateKey() (PrivateKey, error) {
	var scalar [x448ScalarSize]byte
	if _, err := io.ReadFull(rand.Reader, scalar[:]); err != nil {
		return nil, err
	}
	clampScalarX448(scalar[:])
	priv := &x448PrivateKey{scalar: scalar}
	return priv, nil
}

func (x *x448KeyExchange) NewPrivateKey(d []byte) (PrivateKey, error) {
	if len(d) != x448ScalarSize {
		return nil, errInvalidX448Scalar
	}
	var scalar [x448ScalarSize]byte
	copy(scalar[:], d)
	clampScalarX448(scalar[:])
	return &x448PrivateKey{scalar: scalar}, nil
}

func (x *x448KeyExchange) NewPublicKey(b []byte) (PublicKey, error) {
	if len(b) != x448PointSize {
		return nil, errInvalidX448Public
	}
	var pub [x448PointSize]byte
	copy(pub[:], b)
	return &x448PublicKey{u: pub}, nil
}

func (x *x448KeyExchange) SharedSecret(p PrivateKey, peer PublicKey) ([]byte, error) {
	priv, ok := p.(*x448PrivateKey)
	if !ok {
		return nil, errIncompatiblePrivate
	}
	pub, ok := peer.(*x448PublicKey)
	if !ok {
		return nil, errIncompatiblePublic
	}
	secret, err := priv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

type x448PrivateKey struct {
	scalar   [x448ScalarSize]byte
	public   [x448PointSize]byte
	computed bool
}

func (k *x448PrivateKey) Bytes() []byte {
	if k == nil {
		return nil
	}
	out := make([]byte, x448ScalarSize)
	copy(out, k.scalar[:])
	return out
}

func (k *x448PrivateKey) PublicKey() PublicKey {
	if k == nil {
		return nil
	}
	k.ensurePublic()
	return &x448PublicKey{u: k.public}
}

func (k *x448PrivateKey) ECDH(peer PublicKey) ([]byte, error) {
	if k == nil {
		return nil, errors.New("ecdh/x448: nil private key")
	}
	other, ok := peer.(*x448PublicKey)
	if !ok {
		return nil, errIncompatiblePublic
	}
	if x448.LowOrderPoint(&other.u) {
		return nil, errX448LowOrder
	}
	var scalarCopy [x448ScalarSize]byte
	copy(scalarCopy[:], k.scalar[:])
	var result [x448PointSize]byte
	scalarMultX448(&result, &scalarCopy, &other.u)
	if constantTimeAllZero(result[:]) == 1 {
		return nil, errX448LowOrder
	}
	secret := make([]byte, x448PointSize)
	copy(secret, result[:])
	return secret, nil
}

func (k *x448PrivateKey) Equal(x crypto.PrivateKey) bool {
	other, ok := x.(*x448PrivateKey)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(k.scalar[:], other.scalar[:]) == 1
}

func (k *x448PrivateKey) ensurePublic() {
	if k.computed {
		return
	}
	var result [x448PointSize]byte
	var scalarCopy [x448ScalarSize]byte
	copy(scalarCopy[:], k.scalar[:])
	scalarMultX448(&result, &scalarCopy, &x448BasePoint)
	copy(k.public[:], result[:])
	k.computed = true
}

type x448PublicKey struct {
	u [x448PointSize]byte
}

func (k *x448PublicKey) Bytes() []byte {
	if k == nil {
		return nil
	}
	out := make([]byte, x448PointSize)
	copy(out, k.u[:])
	return out
}

func (k *x448PublicKey) Equal(x crypto.PublicKey) bool {
	other, ok := x.(*x448PublicKey)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(k.u[:], other.u[:]) == 1
}

func clampScalarX448(k []byte) {
	k[0] &= 252
	k[55] |= 128
}

func scalarMultX448(out *[x448PointSize]byte, scalar *[x448ScalarSize]byte, point *[x448PointSize]byte) {
	x448.ScalarMult(out, scalar, point)
}

func constantTimeAllZero(b []byte) int {
	var acc byte
	for _, v := range b {
		acc |= v
	}
	return subtle.ConstantTimeByteEq(acc, 0)
}
