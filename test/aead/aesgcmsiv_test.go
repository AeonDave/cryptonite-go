package aead_test

import (
	"bytes"
	_ "embed"
	"strings"
	"testing"

	"cryptonite-go/aead"
)

//go:embed testdata/aesgcmsiv_kat.txt
var aesgcmsivKATData string

type aesgcmsivKATCase struct {
	key, nonce, ad, pt, ct []byte
}

func parseAESGCMSIVKAT(t *testing.T) []aesgcmsivKATCase {
	t.Helper()

	lines := strings.Split(aesgcmsivKATData, "\n")
	var cases []aesgcmsivKATCase
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

		if !strings.HasPrefix(keyLine, "Key =") ||
			!strings.HasPrefix(nonceLine, "Nonce =") ||
			!strings.HasPrefix(ptLine, "PT =") ||
			!strings.HasPrefix(adLine, "AD =") ||
			!strings.HasPrefix(ctLine, "CT =") {
			t.Fatalf("unexpected block format around line %d", i+1)
		}

		key := mustHex(t, strings.TrimSpace(strings.TrimPrefix(keyLine, "Key =")))
		nonce := mustHex(t, strings.TrimSpace(strings.TrimPrefix(nonceLine, "Nonce =")))
		pt := mustHex(t, strings.TrimSpace(strings.TrimPrefix(ptLine, "PT =")))
		ad := mustHex(t, strings.TrimSpace(strings.TrimPrefix(adLine, "AD =")))
		ct := mustHex(t, strings.TrimSpace(strings.TrimPrefix(ctLine, "CT =")))
		cases = append(cases, aesgcmsivKATCase{
			key:   key,
			nonce: nonce,
			ad:    ad,
			pt:    pt,
			ct:    ct,
		})
		i += 6
	}
	return cases
}

func TestAESGCMSIV_KAT(t *testing.T) {
	cases := parseAESGCMSIVKAT(t)
	if len(cases) == 0 {
		t.Fatal("no AES-GCM-SIV vectors parsed")
	}
	cipher := aead.NewAesGcmSiv()
	for idx, tc := range cases {
		got, err := cipher.Encrypt(tc.key, tc.nonce, tc.ad, tc.pt)
		if err != nil {
			t.Fatalf("encrypt failed case %d: %v", idx+1, err)
		}
		if !bytes.Equal(got, tc.ct) {
			t.Fatalf("encrypt mismatch case %d:\n got %x\nwant %x", idx+1, got, tc.ct)
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

func TestAESGCMSIV_InvalidSizes(t *testing.T) {
	cipher := aead.NewAesGcmSiv()
	key := make([]byte, 15)
	nonce := make([]byte, 12)
	if _, err := cipher.Encrypt(key, nonce, nil, nil); err == nil {
		t.Fatalf("expected error for invalid key size")
	}
	key = make([]byte, 16)
	nonce = make([]byte, 11)
	if _, err := cipher.Encrypt(key, nonce, nil, nil); err == nil {
		t.Fatalf("expected error for invalid nonce size")
	}
	if _, err := cipher.Decrypt(key, make([]byte, 12), nil, []byte{1, 2, 3}); err == nil {
		t.Fatalf("expected error for short ciphertext")
	}
}

func TestAESGCMSIV_TagTamper(t *testing.T) {
	cipher := aead.NewAesGcmSiv()
	key := make([]byte, 16)
	nonce := make([]byte, 12)
	ad := []byte{0x01, 0x02}
	pt := []byte("hello world")

	ct, err := cipher.Encrypt(key, nonce, ad, pt)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	tampered := append([]byte(nil), ct...)
	tampered[len(tampered)-1] ^= 0x01

	if _, err := cipher.Decrypt(key, nonce, ad, tampered); err == nil {
		t.Fatalf("decrypt succeeded on tampered tag")
	}
}

func TestAESGCMSIV_CiphertextTamper(t *testing.T) {
	cipher := aead.NewAesGcmSiv()
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	ad := []byte{0xAA}
	pt := []byte("test message")

	ct, err := cipher.Encrypt(key, nonce, ad, pt)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	tampered := append([]byte(nil), ct...)
	tampered[0] ^= 0x80

	if _, err := cipher.Decrypt(key, nonce, ad, tampered); err == nil {
		t.Fatalf("decrypt succeeded on tampered ciphertext")
	}
}
