package aead_test

import (
	"bytes"
	_ "embed"
	"strings"
	"testing"

	"github.com/AeonDave/cryptonite-go/aead"
	testutil "github.com/AeonDave/cryptonite-go/test/internal/testutil"
)

//go:embed testdata/deoxysii_kat.txt
var deoxysIIKATData string

type deoxysKATCase struct {
	key, nonce, ad, pt, ct []byte
}

func parseDeoxysIIKAT(t *testing.T) []deoxysKATCase {
	t.Helper()
	lines := strings.Split(deoxysIIKATData, "\n")
	var cases []deoxysKATCase
	for i := 0; i < len(lines); {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			i++
			continue
		}
		if !strings.HasPrefix(line, "Count =") {
			t.Fatalf("unexpected format on line %d: %q", i+1, lines[i])
		}
		if i+5 >= len(lines) {
			t.Fatalf("incomplete block starting at line %d", i+1)
		}
		keyLine := strings.TrimSpace(lines[i+1])
		nonceLine := strings.TrimSpace(lines[i+2])
		ptLine := strings.TrimSpace(lines[i+3])
		adLine := strings.TrimSpace(lines[i+4])
		ctLine := strings.TrimSpace(lines[i+5])
		if !strings.HasPrefix(keyLine, "Key =") || !strings.HasPrefix(nonceLine, "Nonce =") ||
			!strings.HasPrefix(ptLine, "PT =") || !strings.HasPrefix(adLine, "AD =") ||
			!strings.HasPrefix(ctLine, "CT =") {
			t.Fatalf("unexpected block format around line %d", i+1)
		}
		key := testutil.MustHex(t, strings.TrimSpace(strings.TrimPrefix(keyLine, "Key =")))
		nonce := testutil.MustHex(t, strings.TrimSpace(strings.TrimPrefix(nonceLine, "Nonce =")))
		pt := testutil.MustHex(t, strings.TrimSpace(strings.TrimPrefix(ptLine, "PT =")))
		ad := testutil.MustHex(t, strings.TrimSpace(strings.TrimPrefix(adLine, "AD =")))
		ct := testutil.MustHex(t, strings.TrimSpace(strings.TrimPrefix(ctLine, "CT =")))
		cases = append(cases, deoxysKATCase{key: key, nonce: nonce, ad: ad, pt: pt, ct: ct})
		i += 6
		if i < len(lines) && strings.TrimSpace(lines[i]) == "" {
			i++
		}
	}
	return cases
}

func TestDeoxysII_KAT(t *testing.T) {
	cases := parseDeoxysIIKAT(t)
	if len(cases) == 0 {
		t.Fatal("no Deoxys-II vectors parsed")
	}
	cipher := aead.NewDeoxysII128()
	for idx, tc := range cases {
		got, err := cipher.Encrypt(tc.key, tc.nonce, tc.ad, tc.pt)
		if err != nil {
			t.Fatalf("encrypt failed case %d: %v", idx+1, err)
		}
		if !bytes.Equal(got, tc.ct) {
			t.Fatalf("encrypt mismatch case %d (|AD|=%d, |PT|=%d):\n got %x\nwant %x", idx+1, len(tc.ad), len(tc.pt), got, tc.ct)
		}
		dec, err := cipher.Decrypt(tc.key, tc.nonce, tc.ad, tc.ct)
		if err != nil {
			t.Fatalf("decrypt failed case %d: %v", idx+1, err)
		}
		if !bytes.Equal(dec, tc.pt) {
			t.Fatalf("decrypt mismatch case %d:\n got %x\nwant %x", idx+1, dec, tc.pt)
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
