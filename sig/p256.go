package sig

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

type p256Scheme struct{}

// New returns a Signature for deterministic ECDSA over P-256 using DER signatures.
func New() Signature { return p256Scheme{} }

// GenerateKeyP256 creates a new ECDSA P-256 keypair using crypto/rand.
func GenerateKeyP256() (*ecdsa.PrivateKey, error) {
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
	p := new(ecdsa.PrivateKey)
	p.Curve = curve
	p.D = k
	p.X, p.Y = curve.ScalarBaseMult(d)
	return p, nil
}

// MarshalPrivateKey returns the 32-byte scalar for priv.
func MarshalPrivateKey(p *ecdsa.PrivateKey) []byte {
	return p.D.FillBytes(make([]byte, ScalarSize))
}

// MarshalPublicKey serialises pub as an uncompressed point.
func MarshalPublicKey(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.Curve != curve {
		return nil
	}
	size := (curve.Params().BitSize + 7) / 8
	out := make([]byte, 1+2*size)
	out[0] = 0x04 // uncompressed form tag
	pub.X.FillBytes(out[1 : 1+size])
	pub.Y.FillBytes(out[1+size:])
	return out
}

// ParsePublicKey deserializes an uncompressed public key.
func ParsePublicKey(b []byte) (*ecdsa.PublicKey, error) {
	size := (curve.Params().BitSize + 7) / 8
	if len(b) != 1+2*size || b[0] != 0x04 {
		return nil, errors.New("p256: invalid public key encoding")
	}
	x := new(big.Int).SetBytes(b[1 : 1+size])
	y := new(big.Int).SetBytes(b[1+size:])
	if x.Sign() == 0 && y.Sign() == 0 {
		return nil, errors.New("p256: invalid point at infinity")
	}
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("p256: point not on curve")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// SignASN1 generates an ECDSA signature over hash using priv, returning DER encoding.
func SignASN1(p *ecdsa.PrivateKey, hash []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, p, hash)
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

func (p256Scheme) GenerateKey() ([]byte, []byte, error) {
	p, err := GenerateKeyP256()
	if err != nil {
		return nil, nil, err
	}
	pubBytes := MarshalPublicKey(&p.PublicKey)
	pBytes := MarshalPrivateKey(p)
	return append([]byte(nil), pubBytes...), append([]byte(nil), pBytes...), nil
}

func (p256Scheme) Sign(private []byte, msg []byte) ([]byte, error) {
	p, err := NewPrivateKey(private)
	if err != nil {
		return nil, err
	}
	sig, err := SignASN1(p, msg)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), sig...), nil
}

func (p256Scheme) Verify(public []byte, msg, signature []byte) bool {
	pub, err := ParsePublicKey(public)
	if err != nil {
		return false
	}
	return VerifyASN1(pub, msg, signature)
}
