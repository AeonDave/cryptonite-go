package pq_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/AeonDave/cryptonite-go/ecdh"
	"github.com/AeonDave/cryptonite-go/kdf"
	pq "github.com/AeonDave/cryptonite-go/pq"
)

const hybridSecretLen = 32

func TestHybridX25519RoundTrip(t *testing.T) {
	kem := pq.NewHybridX25519()
	pub, priv, err := kem.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if len(pub) == 0 || len(priv) == 0 {
		t.Fatal("empty key material")
	}
	ct, ssEnc, err := kem.Encapsulate(pub)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	if len(ct) == 0 {
		t.Fatal("empty ciphertext")
	}
	if len(ssEnc) != hybridSecretLen {
		t.Fatalf("unexpected shared secret length %d", len(ssEnc))
	}
	ssDec, err := kem.Decapsulate(priv, ct)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if !bytes.Equal(ssEnc, ssDec) {
		t.Fatal("shared secrets do not match")
	}
}

func TestHybridRejectsUnexpectedPQMaterial(t *testing.T) {
	kem := pq.NewHybridX25519()
	pub, priv, err := kem.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ct, _, err := kem.Encapsulate(pub)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	classicalPub, _, err := parseHybridForTest(pub)
	if err != nil {
		t.Fatalf("parseHybridForTest(pub): %v", err)
	}
	forgedPub := encodeHybridForTest(classicalPub, []byte{0x01})
	if _, _, err := kem.Encapsulate(forgedPub); err == nil {
		t.Fatal("Encapsulate accepted unexpected PQ key component")
	}
	classicalPriv, _, err := parseHybridForTest(priv)
	if err != nil {
		t.Fatalf("parseHybridForTest(priv): %v", err)
	}
	forgedPriv := encodeHybridForTest(classicalPriv, []byte{0x02})
	if _, err := kem.Decapsulate(forgedPriv, ct); err == nil {
		t.Fatal("Decapsulate accepted unexpected PQ key component")
	}
	classicalCT, _, err := parseHybridForTest(ct)
	if err != nil {
		t.Fatalf("parseHybridForTest(ct): %v", err)
	}
	forgedCT := encodeHybridForTest(classicalCT, []byte{0x03})
	if _, err := kem.Decapsulate(priv, forgedCT); err == nil {
		t.Fatal("Decapsulate accepted unexpected PQ ciphertext component")
	}
}

func TestHybridRejectsMissingPQMaterial(t *testing.T) {
	stub := &stubKEM{
		public:       []byte{0x01, 0x02, 0x03},
		private:      []byte{0x04, 0x05, 0x06, 0x07},
		ciphertext:   []byte{0xAA, 0xBB, 0xCC},
		sharedSecret: []byte("stub-mlkem-secret"),
	}
	hybrid, err := pq.NewHybrid(ecdh.NewX25519(), stub)
	if err != nil {
		t.Fatalf("NewHybrid: %v", err)
	}
	pub, priv, err := hybrid.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ct, _, err := hybrid.Encapsulate(pub)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}

	classicalPub, _, err := parseHybridForTest(pub)
	if err != nil {
		t.Fatalf("parseHybridForTest(pub): %v", err)
	}
	forgedPub := encodeHybridForTest(classicalPub, nil)
	if _, _, err := hybrid.Encapsulate(forgedPub); err == nil {
		t.Fatal("Encapsulate accepted missing PQ key component")
	}

	classicalPriv, _, err := parseHybridForTest(priv)
	if err != nil {
		t.Fatalf("parseHybridForTest(priv): %v", err)
	}
	forgedPriv := encodeHybridForTest(classicalPriv, nil)
	if _, err := hybrid.Decapsulate(forgedPriv, ct); err == nil {
		t.Fatal("Decapsulate accepted missing PQ key component")
	}

	classicalCT, _, err := parseHybridForTest(ct)
	if err != nil {
		t.Fatalf("parseHybridForTest(ct): %v", err)
	}
	forgedCT := encodeHybridForTest(classicalCT, nil)
	if _, err := hybrid.Decapsulate(priv, forgedCT); err == nil {
		t.Fatal("Decapsulate accepted missing PQ ciphertext component")
	}
}

func TestHybridDecapsulateMissingPQComponentsSkipsMLKEM(t *testing.T) {
	stub := &stubKEM{
		public:       []byte{0x01, 0x02},
		private:      []byte{0x03, 0x04, 0x05},
		ciphertext:   []byte{0xAA, 0xBB},
		sharedSecret: []byte("pq-secret"),
	}

	hybrid, err := pq.NewHybrid(ecdh.NewX25519(), stub)
	if err != nil {
		t.Fatalf("NewHybrid: %v", err)
	}

	pub, priv, err := hybrid.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	ct, _, err := hybrid.Encapsulate(pub)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}

	classicalPriv, _, err := parseHybridForTest(priv)
	if err != nil {
		t.Fatalf("parseHybridForTest(priv): %v", err)
	}

	truncatedPriv := encodeHybridForTest(classicalPriv, nil)
	if _, err := hybrid.Decapsulate(truncatedPriv, ct); err == nil {
		t.Fatal("Decapsulate succeeded with missing PQ private component")
	}
	if stub.decapsulateCalls != 0 {
		t.Fatal("ML-KEM decapsulate invoked when PQ private component missing")
	}

	stub.decapsulateCalls = 0

	classicalCT, _, err := parseHybridForTest(ct)
	if err != nil {
		t.Fatalf("parseHybridForTest(ct): %v", err)
	}

	truncatedCT := encodeHybridForTest(classicalCT, nil)
	if _, err := hybrid.Decapsulate(priv, truncatedCT); err == nil {
		t.Fatal("Decapsulate succeeded with missing PQ ciphertext component")
	}
	if stub.decapsulateCalls != 0 {
		t.Fatal("ML-KEM decapsulate invoked when PQ ciphertext component missing")
	}
}

func TestHybridWithPostQuantumStub(t *testing.T) {
	stub := &stubKEM{
		public:       []byte{0xAA, 0xBB},
		private:      []byte{0xCC, 0xDD, 0xEE},
		ciphertext:   []byte{0x10, 0x11, 0x12},
		sharedSecret: []byte("mlkem-shared-secret"),
	}
	base := ecdh.NewX25519()
	hybrid, err := pq.NewHybrid(base, stub)
	if err != nil {
		t.Fatalf("NewHybrid: %v", err)
	}
	pub, priv, err := hybrid.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ct, ssEnc, err := hybrid.Encapsulate(pub)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	ssDec, err := hybrid.Decapsulate(priv, ct)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if !bytes.Equal(ssEnc, ssDec) {
		t.Fatal("shared secrets mismatch")
	}
	classicalPriv, pqPriv, err := parseHybridForTest(priv)
	if err != nil {
		t.Fatalf("parseHybridForTest(priv): %v", err)
	}
	if !bytes.Equal(pqPriv, stub.private) {
		t.Fatalf("unexpected PQ private component: %x", pqPriv)
	}
	classicalCT, pqCT, err := parseHybridForTest(ct)
	if err != nil {
		t.Fatalf("parseHybridForTest(ct): %v", err)
	}
	if !bytes.Equal(pqCT, stub.ciphertext) {
		t.Fatalf("unexpected PQ ciphertext component: %x", pqCT)
	}
	privKey, err := base.NewPrivateKey(classicalPriv)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	peerKey, err := base.NewPublicKey(classicalCT)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	classicalSecret, err := privKey.ECDH(peerKey)
	if err != nil {
		t.Fatalf("ECDH: %v", err)
	}
	ikm := append([]byte{}, classicalSecret...)
	ikm = append(ikm, stub.sharedSecret...)
	expected, err := kdf.HKDFSHA256(ikm, nil, []byte("cryptonite-go/hybrid"), hybridSecretLen)
	if err != nil {
		t.Fatalf("HKDFSHA256: %v", err)
	}
	if !bytes.Equal(ssEnc, expected) {
		t.Fatal("derived secret does not match expected HKDF output")
	}
}

func TestHybridParseErrors(t *testing.T) {
	if _, _, err := parseHybridForTest(nil); err == nil {
		t.Fatal("expected error for nil input")
	}
	if _, _, err := parseHybridForTest([]byte{0x00}); err == nil {
		t.Fatal("expected error for wrong version")
	}
	if _, _, err := parseHybridForTest([]byte{0x01}); err == nil {
		t.Fatal("expected error for truncated payload")
	}
	if _, _, err := parseHybridForTest([]byte{0x01, 0x00}); err == nil {
		t.Fatal("expected error for truncated length")
	}
}

func encodeHybridForTest(classical, postQuantum []byte) []byte {
	out := make([]byte, 1+2+len(classical)+2+len(postQuantum))
	out[0] = 0x01
	binary.BigEndian.PutUint16(out[1:3], uint16(len(classical)))
	copy(out[3:], classical)
	offset := 3 + len(classical)
	binary.BigEndian.PutUint16(out[offset:offset+2], uint16(len(postQuantum)))
	copy(out[offset+2:], postQuantum)
	return out
}

func parseHybridForTest(b []byte) (classical, postQuantum []byte, err error) {
	if len(b) == 0 {
		return nil, nil, errors.New("empty")
	}
	if b[0] != 0x01 {
		return nil, nil, errors.New("version")
	}
	if len(b) < 3 {
		return nil, nil, errors.New("truncated")
	}
	classicalLen := int(binary.BigEndian.Uint16(b[1:3]))
	offset := 3
	if len(b) < offset+classicalLen+2 {
		return nil, nil, errors.New("length")
	}
	classical = append([]byte(nil), b[offset:offset+classicalLen]...)
	offset += classicalLen
	pqLen := int(binary.BigEndian.Uint16(b[offset : offset+2]))
	offset += 2
	if len(b) < offset+pqLen {
		return nil, nil, errors.New("length")
	}
	postQuantum = append([]byte(nil), b[offset:offset+pqLen]...)
	return classical, postQuantum, nil
}

type stubKEM struct {
	public           []byte
	private          []byte
	ciphertext       []byte
	sharedSecret     []byte
	decapsulateCalls int
}

func (s *stubKEM) GenerateKey() ([]byte, []byte, error) {
	return append([]byte(nil), s.public...), append([]byte(nil), s.private...), nil
}

func (s *stubKEM) Encapsulate([]byte) ([]byte, []byte, error) {
	return append([]byte(nil), s.ciphertext...), append([]byte(nil), s.sharedSecret...), nil
}

func (s *stubKEM) Decapsulate([]byte, []byte) ([]byte, error) {
	s.decapsulateCalls++
	return append([]byte(nil), s.sharedSecret...), nil
}
