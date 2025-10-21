package aead_test

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"testing"

	"cryptonite-go/aead"
	testutil "cryptonite-go/test/internal/testutil"
)

//go:embed testdata/deoxysii_kat.json
var deoxysIIKATData []byte

type deoxysVector struct {
	Name           string  `json:"Name"`
	Key            string  `json:"Key"`
	Nonce          string  `json:"Nonce"`
	AssociatedData *string `json:"AssociatedData"`
	Message        *string `json:"Message"`
	Sealed         string  `json:"Sealed"`
}

func TestDeoxysII_KAT(t *testing.T) {
	var vectors []deoxysVector
	if err := json.Unmarshal(deoxysIIKATData, &vectors); err != nil {
		t.Fatalf("failed to parse vectors: %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("no Deoxys-II vectors parsed")
	}
	cipher := aead.NewDeoxysII128()
	for idx, vec := range vectors {
		key := testutil.MustHex(t, vec.Key)
		nonce := testutil.MustHex(t, vec.Nonce)
		ad := testutil.OptionalHex(t, vec.AssociatedData)
		msg := testutil.OptionalHex(t, vec.Message)
		sealed := testutil.MustHex(t, vec.Sealed)

		got, err := cipher.Encrypt(key, nonce, ad, msg)
		if err != nil {
			t.Fatalf("encrypt failed case %d (%s): %v", idx+1, vec.Name, err)
		}
		if !bytes.Equal(got, sealed) {
			t.Fatalf("encrypt mismatch case %d (%s):\n got %x\nwant %x", idx+1, vec.Name, got, sealed)
		}
		dec, err := cipher.Decrypt(key, nonce, ad, sealed)
		if err != nil {
			t.Fatalf("decrypt failed case %d (%s): %v", idx+1, vec.Name, err)
		}
		if !bytes.Equal(dec, msg) {
			t.Fatalf("decrypt mismatch case %d (%s):\n got %x\nwant %x", idx+1, vec.Name, dec, msg)
		}
	}
}

func TestDeoxysII_InvalidSizes(t *testing.T) {
	cipher := aead.NewDeoxysII128()
	key := make([]byte, 31)
	nonce := make([]byte, 15)
	if _, err := cipher.Encrypt(key, nonce, nil, nil); err == nil {
		t.Fatalf("expected error for invalid key size")
	}
	key = make([]byte, 32)
	nonce = make([]byte, 14)
	if _, err := cipher.Encrypt(key, nonce, nil, nil); err == nil {
		t.Fatalf("expected error for invalid nonce size")
	}
	if _, err := cipher.Decrypt(key, make([]byte, 15), nil, []byte{1, 2, 3}); err == nil {
		t.Fatalf("expected error for short ciphertext")
	}
}

func TestDeoxysII_Tamper(t *testing.T) {
	cipher := aead.NewDeoxysII128()
	key := bytes.Repeat([]byte{0x11}, 32)
	nonce := bytes.Repeat([]byte{0x22}, 15)
	ad := []byte("associated data")
	pt := []byte("confidential payload")

	ct, err := cipher.Encrypt(key, nonce, ad, pt)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	tampered := append([]byte(nil), ct...)
	tampered[len(tampered)-1] ^= 0x80
	if _, err := cipher.Decrypt(key, nonce, ad, tampered); err == nil {
		t.Fatalf("decrypt succeeded on tampered data")
	}
}
