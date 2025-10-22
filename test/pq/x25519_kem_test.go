package pq_test

import (
	"bytes"
	"encoding/json"
	"testing"

	kem "github.com/AeonDave/cryptonite-go/kem"
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

func newX25519(t *testing.T) kem.KEM {
	t.Helper()
	k := kem.New()
	if k == nil {
		t.Fatal("x25519.New returned nil")
	}
	return k
}

func TestX25519KEMRoundTrip(t *testing.T) {
	k := newX25519(t)
	pk, sk, err := k.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	ct, ss, err := k.Encapsulate(pk)
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}
	if len(ct) != kem.PublicSize {
		t.Fatalf("unexpected ciphertext length %d", len(ct))
	}
	if len(ss) != kem.PublicSize {
		t.Fatalf("unexpected shared secret length %d", len(ss))
	}
	recovered, err := k.Decapsulate(sk, ct)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}
	if !bytes.Equal(ss, recovered) {
		t.Fatalf("shared secret mismatch")
	}
}

func TestX25519KEMKnownAnswer(t *testing.T) {
	cases := loadX25519KAT(t)
	k := newX25519(t)
	for i, tc := range cases {
		sk := testutil.MustHex(t, tc.Private)
		ct := testutil.MustHex(t, tc.Ciphertext)
		want := testutil.MustHex(t, tc.SharedSecret)
		got, err := k.Decapsulate(sk, ct)
		if err != nil {
			t.Fatalf("case %d (%s): Decapsulate failed: %v", i, tc.Name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("case %d (%s): shared secret mismatch", i, tc.Name)
		}
	}
}

func TestX25519KEMRejectsMalformedInputs(t *testing.T) {
	k := newX25519(t)
	if _, _, err := k.GenerateKey(); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if _, _, err := k.Encapsulate([]byte("short")); err == nil {
		t.Fatal("Encapsulate accepted short public key")
	}
	if _, err := k.Decapsulate(make([]byte, kem.PrivateSize-1), make([]byte, kem.PublicSize)); err == nil {
		t.Fatal("Decapsulate accepted short private key")
	}
	if _, err := k.Decapsulate(make([]byte, kem.PrivateSize), make([]byte, kem.PublicSize-1)); err == nil {
		t.Fatal("Decapsulate accepted short ciphertext")
	}
}
