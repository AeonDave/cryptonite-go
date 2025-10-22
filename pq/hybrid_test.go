package pq

import (
	"errors"
	"testing"

	"github.com/AeonDave/cryptonite-go/ecdh"
	"github.com/AeonDave/cryptonite-go/kem"
)

type stubKEM struct {
	kem.KEM
	decapsulateCalls int
}

func (s *stubKEM) GenerateKey() (public, private []byte, err error) {
	return []byte{0xA1, 0xB2}, []byte{0xC3, 0xD4}, nil
}

func (s *stubKEM) Encapsulate(public []byte) (ciphertext, sharedSecret []byte, err error) {
	return []byte{0xE5, 0xF6}, []byte{0x01, 0x23}, nil
}

func (s *stubKEM) Decapsulate(private []byte, ciphertext []byte) ([]byte, error) {
	s.decapsulateCalls++
	if len(private) == 0 || len(ciphertext) == 0 {
		return nil, errors.New("stub: empty input")
	}
	return []byte{0x45, 0x67}, nil
}

func TestHybridDecapsulateMissingPQComponents(t *testing.T) {
	stub := &stubKEM{}
	h, err := NewHybrid(ecdh.New(), stub)
	if err != nil {
		t.Fatalf("NewHybrid failed: %v", err)
	}

	public, private, err := h.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	ciphertext, _, err := h.Encapsulate(public)
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}

	keyComponents, err := parseHybridMaterial(private)
	if err != nil {
		t.Fatalf("parseHybridMaterial private: %v", err)
	}
	privateNoPQ := encodeHybridMaterial(keyComponents.classical, nil)
	if _, err := h.Decapsulate(privateNoPQ, ciphertext); !errors.Is(err, errMissingPQPrivate) {
		t.Fatalf("Decapsulate missing PQ private: expected %v, got %v", errMissingPQPrivate, err)
	}
	if stub.decapsulateCalls != 0 {
		t.Fatalf("Decapsulate should not be invoked when PQ private missing")
	}

	stub.decapsulateCalls = 0
	ctComponents, err := parseHybridMaterial(ciphertext)
	if err != nil {
		t.Fatalf("parseHybridMaterial ciphertext: %v", err)
	}
	ciphertextNoPQ := encodeHybridMaterial(ctComponents.classical, nil)
	if _, err := h.Decapsulate(private, ciphertextNoPQ); !errors.Is(err, errMissingPQCipher) {
		t.Fatalf("Decapsulate missing PQ ciphertext: expected %v, got %v", errMissingPQCipher, err)
	}
	if stub.decapsulateCalls != 0 {
		t.Fatalf("Decapsulate should not be invoked when PQ ciphertext missing")
	}
}
