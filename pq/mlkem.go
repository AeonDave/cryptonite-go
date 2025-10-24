package pq

import (
	"errors"

	"github.com/AeonDave/cryptonite-go/internal/kyber"
	"github.com/AeonDave/cryptonite-go/kem"
)

type mlkem struct {
	name   string
	scheme *kyber.Kyber
}

var _ kem.KEM = (*mlkem)(nil)

// NewMLKEM512 returns a kem.KEM implementation for ML-KEM-512 (Kyber-512).
func NewMLKEM512() kem.KEM { return newMLKEM("ML-KEM-512", kyber.NewKyber512()) }

// NewMLKEM768 returns a kem.KEM implementation for ML-KEM-768 (Kyber-768).
func NewMLKEM768() kem.KEM { return newMLKEM("ML-KEM-768", kyber.NewKyber768()) }

// NewMLKEM1024 returns a kem.KEM implementation for ML-KEM-1024 (Kyber-1024).
func NewMLKEM1024() kem.KEM { return newMLKEM("ML-KEM-1024", kyber.NewKyber1024()) }

func newMLKEM(name string, scheme *kyber.Kyber) kem.KEM {
	return &mlkem{name: name, scheme: scheme}
}

func (m *mlkem) GenerateKey() ([]byte, []byte, error) {
	if m == nil || m.scheme == nil {
		return nil, nil, errors.New("pq/mlkem: nil scheme")
	}
	pub, priv := m.scheme.KeyGen(nil)
	if pub == nil || priv == nil {
		return nil, nil, errors.New("pq/mlkem: key generation failed")
	}
	return append([]byte(nil), pub...), append([]byte(nil), priv...), nil
}

func (m *mlkem) Encapsulate(public []byte) ([]byte, []byte, error) {
	if m == nil || m.scheme == nil {
		return nil, nil, errors.New("pq/mlkem: nil scheme")
	}
	if len(public) != m.scheme.SIZEPK() {
		return nil, nil, errors.New("pq/mlkem: invalid public key length")
	}
	ct, shared := m.scheme.Encaps(public, nil)
	if ct == nil || shared == nil {
		return nil, nil, errors.New("pq/mlkem: encapsulation failed")
	}
	return append([]byte(nil), ct...), append([]byte(nil), shared...), nil
}

func (m *mlkem) Decapsulate(private []byte, ciphertext []byte) ([]byte, error) {
	if m == nil || m.scheme == nil {
		return nil, errors.New("pq/mlkem: nil scheme")
	}
	if len(private) != m.scheme.SIZESK() {
		return nil, errors.New("pq/mlkem: invalid private key length")
	}
	if len(ciphertext) != m.scheme.SIZEC() {
		return nil, errors.New("pq/mlkem: invalid ciphertext length")
	}
	shared := m.scheme.Decaps(private, ciphertext)
	if shared == nil {
		return nil, errors.New("pq/mlkem: decapsulation failed")
	}
	return append([]byte(nil), shared...), nil
}
