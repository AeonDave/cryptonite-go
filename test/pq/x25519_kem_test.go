package pq_test

import (
	"bytes"
	"encoding/json"
	"testing"

	kemx25519 "github.com/AeonDave/cryptonite-go/kem/x25519"
	pq "github.com/AeonDave/cryptonite-go/pq"
	testutil "github.com/AeonDave/cryptonite-go/test/internal/testutil"

	_ "embed"
)

//go:embed testdata/x25519_kat.json
var x25519KATJSON []byte

type x25519KATCase struct {
	Name         string `json:"name"`
	Private      string `json:"private"`
	Ciphertext   string `json:"ciphertext"`
	SharedSecret string `json:"shared_secret"`
}

func loadX25519KAT(t *testing.T) []x25519KATCase {
	t.Helper()
	var cases []x25519KATCase
	if err := json.Unmarshal(x25519KATJSON, &cases); err != nil {
		t.Fatalf("failed to parse x25519 KAT: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("empty x25519 KAT")
	}
	return cases
}

func newX25519(t *testing.T) pq.KEM {
	t.Helper()
	kem := kemx25519.New()
	if kem == nil {
		t.Fatal("x25519.New returned nil")
	}
	return kem
}

func TestX25519KEMRoundTrip(t *testing.T) {
	kem := newX25519(t)
	pk, sk, err := kem.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	ct, ss, err := kem.Encapsulate(pk)
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}
	if len(ct) != kemx25519.PublicSize {
		t.Fatalf("unexpected ciphertext length %d", len(ct))
	}
	if len(ss) != kemx25519.PublicSize {
		t.Fatalf("unexpected shared secret length %d", len(ss))
	}
	recovered, err := kem.Decapsulate(sk, ct)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}
	if !bytes.Equal(ss, recovered) {
		t.Fatalf("shared secret mismatch")
	}
}

func TestX25519KEMKnownAnswer(t *testing.T) {
	cases := loadX25519KAT(t)
	kem := newX25519(t)
	for i, tc := range cases {
		sk := testutil.MustHex(t, tc.Private)
		ct := testutil.MustHex(t, tc.Ciphertext)
		want := testutil.MustHex(t, tc.SharedSecret)
		got, err := kem.Decapsulate(sk, ct)
		if err != nil {
			t.Fatalf("case %d (%s): Decapsulate failed: %v", i, tc.Name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("case %d (%s): shared secret mismatch", i, tc.Name)
		}
	}
}

func TestX25519KEMRejectsMalformedInputs(t *testing.T) {
	kem := newX25519(t)
	if _, _, err := kem.GenerateKey(); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if _, _, err := kem.Encapsulate([]byte("short")); err == nil {
		t.Fatal("Encapsulate accepted short public key")
	}
	if _, err := kem.Decapsulate(make([]byte, kemx25519.PrivateSize-1), make([]byte, kemx25519.PublicSize)); err == nil {
		t.Fatal("Decapsulate accepted short private key")
	}
	if _, err := kem.Decapsulate(make([]byte, kemx25519.PrivateSize), make([]byte, kemx25519.PublicSize-1)); err == nil {
		t.Fatal("Decapsulate accepted short ciphertext")
	}
}
