package p256

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"math/big"
)

const (
	// ScalarSize is the size in bytes of a P-256 private scalar.
	ScalarSize = 32
)

var (
	curve = elliptic.P256()
	order = curve.Params().N
)

type Scheme struct{}

// New returns a Scheme for deterministic ECDSA over P-256 using DER signatures.
func New() Scheme { return Scheme{} }

// GenerateKey creates a new ECDSA P-256 keypair using crypto/rand.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(curve, rand.Reader)
}

// NewPrivateKey constructs a private key from a scalar encoded as big-endian bytes.
func NewPrivateKey(d []byte) (*ecdsa.PrivateKey, error) {
	if len(d) != ScalarSize {
		return nil, errors.New("p256: invalid scalar length")
	}
	k := new(big.Int).SetBytes(d)
	if k.Sign() <= 0 || k.Cmp(order) >= 0 {
		return nil, errors.New("p256: scalar outside valid range")
	}
	priv := new(ecdsa.PrivateKey)
	priv.Curve = curve
	priv.D = k
	priv.X, priv.Y = curve.ScalarBaseMult(d)
	return priv, nil
}

// MarshalPrivateKey returns the 32-byte scalar for priv.
func MarshalPrivateKey(priv *ecdsa.PrivateKey) []byte {
	return priv.D.FillBytes(make([]byte, ScalarSize))
}

// MarshalPublicKey serialises pub as an uncompressed point.
func MarshalPublicKey(pub *ecdsa.PublicKey) []byte {
	return elliptic.Marshal(curve, pub.X, pub.Y)
}

// ParsePublicKey deserialises an uncompressed public key.
func ParsePublicKey(b []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(curve, b)
	if x == nil || y == nil {
		return nil, errors.New("p256: invalid public key")
	}
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("p256: point not on curve")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// SignASN1 generates an ECDSA signature over hash using priv, returning DER encoding.
func SignASN1(priv *ecdsa.PrivateKey, hash []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, priv, hash)
}

// VerifyASN1 reports whether sig is a valid DER-encoded ECDSA signature for hash.
func VerifyASN1(pub *ecdsa.PublicKey, hash, sig []byte) bool {
	return ecdsa.VerifyASN1(pub, hash, sig)
}

// ParseSignature decodes a DER-encoded ECDSA signature into r and s values.
func ParseSignature(sig []byte) (*big.Int, *big.Int, error) {
	var parsed struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(sig, &parsed); err != nil {
		return nil, nil, err
	}
	if parsed.R == nil || parsed.S == nil {
		return nil, nil, errors.New("p256: malformed signature")
	}
	return parsed.R, parsed.S, nil
}

func (Scheme) GenerateKey() ([]byte, []byte, error) {
	priv, err := GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	pubBytes := MarshalPublicKey(&priv.PublicKey)
	privBytes := MarshalPrivateKey(priv)
	return append([]byte(nil), pubBytes...), append([]byte(nil), privBytes...), nil
}

func (Scheme) Sign(private []byte, msg []byte) ([]byte, error) {
	priv, err := NewPrivateKey(private)
	if err != nil {
		return nil, err
	}
	sig, err := SignASN1(priv, msg)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), sig...), nil
}

func (Scheme) Verify(public []byte, msg, signature []byte) bool {
	pub, err := ParsePublicKey(public)
	if err != nil {
		return false
	}
	return VerifyASN1(pub, msg, signature)
}
