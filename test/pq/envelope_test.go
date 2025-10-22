package pq_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/AeonDave/cryptonite-go/aead"
	kem "github.com/AeonDave/cryptonite-go/kem"
	pq "github.com/AeonDave/cryptonite-go/pq"
)

func TestEnvelopeChaCha20Poly1305(t *testing.T) {
	k := kem.New()
	pk, sk, err := k.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cipher := aead.NewChaCha20Poly1305()
	ad := []byte("associated data")
	pt := []byte("hybrid pq payload")
	blob, err := pq.Seal(k, cipher, pk, ad, pt)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(blob) < 1+2+kem.PublicSize+1 {
		t.Fatalf("envelope too short: %d", len(blob))
	}
	if blob[0] != 0x01 {
		t.Fatalf("unexpected envelope version %d", blob[0])
	}
	recovered, err := pq.Open(k, cipher, sk, ad, blob)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(pt, recovered) {
		t.Fatalf("plaintext mismatch: %x vs %x", pt, recovered)
	}
	if _, err := pq.Open(k, cipher, sk, []byte("wrong"), blob); err == nil {
		t.Fatal("Open succeeded with wrong associated data")
	}
}

func TestEnvelopeScheduleFallback(t *testing.T) {
	k := kem.New()
	pk, sk, err := k.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cipher := aead.NewAscon128()
	pt := []byte("post-quantum aware encryption")
	ad := []byte("envelope-ad")
	blob, err := pq.Seal(k, cipher, pk, ad, pt)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if blob[0] != 0x01 {
		t.Fatalf("unexpected envelope version %d", blob[0])
	}
	out, err := pq.Open(k, cipher, sk, ad, blob)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(pt, out) {
		t.Fatal("ascon plaintext mismatch")
	}
}

func TestEnvelopeRejectsMalformedBlob(t *testing.T) {
	k := kem.New()
	cipher := aead.NewChaCha20Poly1305()
	if _, err := pq.Seal(nil, cipher, nil, nil, nil); err == nil {
		t.Fatal("Seal accepted nil KEM")
	}
	if _, err := pq.Seal(k, nil, nil, nil, nil); err == nil {
		t.Fatal("Seal accepted nil AEAD")
	}
	pk, sk, err := k.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	blob, err := pq.Seal(k, cipher, pk, nil, []byte("pt"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := pq.Open(nil, cipher, sk, nil, blob); err == nil {
		t.Fatal("Open accepted nil KEM")
	}
	if _, err := pq.Open(k, nil, sk, nil, blob); err == nil {
		t.Fatal("Open accepted nil AEAD")
	}
	if _, err := pq.Open(k, cipher, sk, nil, []byte{0xFF}); err == nil {
		t.Fatal("Open accepted truncated blob")
	}
	forged := append([]byte(nil), blob...)
	forged[0] = 0xFF
	if _, err := pq.Open(k, cipher, sk, nil, forged); err == nil {
		t.Fatal("Open accepted unsupported version")
	}
	forged = append([]byte(nil), blob...)
	encLen := int(binary.BigEndian.Uint16(forged[1:3]))
	binary.BigEndian.PutUint16(forged[1:3], uint16(encLen+5))
	if _, err := pq.Open(k, cipher, sk, nil, forged); err == nil {
		t.Fatal("Open accepted inconsistent length")
	}
}
