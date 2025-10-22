package pq

import (
	"bytes"
	"io"
	"testing"

	"github.com/AeonDave/cryptonite-go/ecdh"
	"github.com/AeonDave/cryptonite-go/secret"
)

func TestHybridX25519RoundTrip(t *testing.T) {
	kem := NewHybridX25519()
	pub, priv, err := kem.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if len(pub) == 0 || len(priv) == 0 {
		t.Fatal("empty key material")
	}
	ct, ssEnc, err := kem.Encapsulate(nil, pub)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	if len(ct) == 0 {
		t.Fatal("empty ciphertext")
	}
	if len(ssEnc) != hybridSecretSize {
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
	kem := NewHybridX25519()
	pub, priv, err := kem.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ct, _, err := kem.Encapsulate(nil, pub)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	pubParts, err := parseHybridMaterial(pub)
	if err != nil {
		t.Fatalf("parseHybridMaterial: %v", err)
	}
	forgedPub := encodeHybridMaterial(pubParts.classical, []byte{0x01})
	if _, _, err := kem.Encapsulate(nil, forgedPub); err == nil {
		t.Fatal("Encapsulate accepted unexpected PQ key component")
	}
	forgedPriv := encodeHybridMaterial(parseHybrid(priv), []byte{0x02})
	if _, err := kem.Decapsulate(forgedPriv, ct); err == nil {
		t.Fatal("Decapsulate accepted unexpected PQ key component")
	}
	ctParts, err := parseHybridMaterial(ct)
	if err != nil {
		t.Fatalf("parseHybridMaterial(ciphertext): %v", err)
	}
	forgedCT := encodeHybridMaterial(ctParts.classical, []byte{0x03})
	if _, err := kem.Decapsulate(priv, forgedCT); err == nil {
		t.Fatal("Decapsulate accepted unexpected PQ ciphertext component")
	}
}

func TestHybridWithPostQuantumStub(t *testing.T) {
	stub := &stubKEM{
		public:       []byte{0xAA, 0xBB},
		private:      []byte{0xCC, 0xDD, 0xEE},
		ciphertext:   []byte{0x10, 0x11, 0x12},
		sharedSecret: []byte("mlkem-shared-secret"),
	}
	base := ecdh.New()
	kem, err := NewHybrid(base, stub)
	if err != nil {
		t.Fatalf("NewHybrid: %v", err)
	}
	pub, priv, err := kem.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ct, ssEnc, err := kem.Encapsulate(nil, pub)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	ssDec, err := kem.Decapsulate(priv, ct)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if !bytes.Equal(ssEnc, ssDec) {
		t.Fatal("shared secrets mismatch")
	}

	keyParts, err := parseHybridMaterial(priv)
	if err != nil {
		t.Fatalf("parseHybridMaterial(private): %v", err)
	}
	ctParts, err := parseHybridMaterial(ct)
	if err != nil {
		t.Fatalf("parseHybridMaterial(ciphertext): %v", err)
	}
	classicalPriv, err := base.Curve().NewPrivateKey(keyParts.classical)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	peerPub, err := base.NewPublicKey(ctParts.classical)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	classicalSecret, err := classicalPriv.ECDH(peerPub)
	if err != nil {
		t.Fatalf("ECDH: %v", err)
	}
	expected, err := combineSharedSecrets(classicalSecret, stub.sharedSecret)
	secret.WipeBytes(classicalSecret)
	if err != nil {
		t.Fatalf("combineSharedSecrets: %v", err)
	}
	if !bytes.Equal(ssEnc, expected) {
		t.Fatal("derived secret does not match expected HKDF output")
	}
}

func TestParseHybridMaterialErrors(t *testing.T) {
	if _, err := parseHybridMaterial(nil); err == nil {
		t.Fatal("expected error for nil input")
	}
	if _, err := parseHybridMaterial([]byte{0x00}); err == nil {
		t.Fatal("expected error for wrong version")
	}
	if _, err := parseHybridMaterial([]byte{hybridFormatVersion}); err == nil {
		t.Fatal("expected error for truncated payload")
	}
	if _, err := parseHybridMaterial([]byte{hybridFormatVersion, 0x00}); err == nil {
		t.Fatal("expected error for truncated length")
	}
}

func parseHybrid(b []byte) []byte {
	parts, err := parseHybridMaterial(b)
	if err != nil {
		panic(err)
	}
	return parts.classical
}

type stubKEM struct {
	public       []byte
	private      []byte
	ciphertext   []byte
	sharedSecret []byte
}

func (s *stubKEM) GenerateKey(io.Reader) ([]byte, []byte, error) {
	return append([]byte(nil), s.public...), append([]byte(nil), s.private...), nil
}

func (s *stubKEM) Encapsulate(io.Reader, []byte) ([]byte, []byte, error) {
	return append([]byte(nil), s.ciphertext...), append([]byte(nil), s.sharedSecret...), nil
}

func (s *stubKEM) Decapsulate([]byte, []byte) ([]byte, error) {
	return append([]byte(nil), s.sharedSecret...), nil
}
