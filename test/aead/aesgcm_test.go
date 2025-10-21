package aead_test

import (
	"bytes"
	_ "embed"
	"strings"
	"testing"

	"github.com/AeonDave/cryptonite-go/aead"
	testutil "github.com/AeonDave/cryptonite-go/test/internal/testutil"
)

//go:embed testdata/aesgcm_kat.txt
var aesgcmKATData string

type aesgcmKATCase struct {
	key, nonce, ad, pt, ct []byte
}

func parseAESGCMKAT(t *testing.T) []aesgcmKATCase {
	lines := strings.Split(aesgcmKATData, "\n")
	var cases []aesgcmKATCase
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
		cases = append(cases, aesgcmKATCase{
			key:   key,
			nonce: nonce,
			ad:    ad,
			pt:    pt,
			ct:    ct,
		})
		i += 6
		if i < len(lines) && strings.TrimSpace(lines[i]) == "" {
			i++
		}
	}
	return cases
}

func TestAESGCM_EmptyInputs(t *testing.T) {
	cipher := aead.NewAESGCM()
	key := make([]byte, 16)
	nonce := make([]byte, 12)

	ct, err := cipher.Encrypt(key, nonce, nil, nil)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	if len(ct) != 16 { // tag only
		t.Fatalf("unexpected length for empty message: %d", len(ct))
	}
	pt, err := cipher.Decrypt(key, nonce, nil, ct)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if len(pt) != 0 {
		t.Fatalf("unexpected plaintext: %x", pt)
	}
}

func TestAESGCM_RoundTrip_VariousSizes(t *testing.T) {
	cipher := aead.NewAESGCM()
	keySizes := []int{16, 24, 32}
	adLens := []int{0, 1, 7, 16, 31}
	ptLens := []int{0, 1, 7, 16, 31, 64}
	nonce := make([]byte, 12)

	for _, kl := range keySizes {
		key := make([]byte, kl)
		for _, al := range adLens {
			ad := seqBytes(al)
			for _, pl := range ptLens {
				pt := seqBytes(pl)
				ct, err := cipher.Encrypt(key, nonce, ad, pt)
				if err != nil {
					t.Fatalf("encrypt failed (k=%d, ad=%d, pt=%d): %v", kl, al, pl, err)
				}
				if len(ct) != len(pt)+16 {
					t.Fatalf("unexpected ct length (k=%d, ad=%d, pt=%d): got %d want %d", kl, al, pl, len(ct), len(pt)+16)
				}
				dec, err := cipher.Decrypt(key, nonce, ad, ct)
				if err != nil {
					t.Fatalf("decrypt failed (k=%d, ad=%d, pt=%d): %v", kl, al, pl, err)
				}
				if !bytes.Equal(dec, pt) {
					t.Fatalf("roundtrip mismatch (k=%d, ad=%d, pt=%d)", kl, al, pl)
				}
			}
		}
	}
}

func TestAESGCM_TagTamper(t *testing.T) {
	cipher := aead.NewAESGCM()
	key := make([]byte, 16)
	nonce := make([]byte, 12)
	ad := []byte{0x01, 0x02}
	pt := []byte("hello")

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

func TestAESGCM_CiphertextTamper(t *testing.T) {
	cipher := aead.NewAESGCM()
	key := make([]byte, 16)
	nonce := make([]byte, 12)
	ad := []byte{0xAA}
	pt := seqBytes(32)

	ct, err := cipher.Encrypt(key, nonce, ad, pt)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	// Flip a bit in ciphertext portion (if there is ciphertext)
	if len(pt) == 0 {
		t.Skip("no ciphertext to tamper")
	}
	tampered := append([]byte(nil), ct...)
	tampered[len(pt)/2] ^= 0x01
	if _, err := cipher.Decrypt(key, nonce, ad, tampered); err == nil {
		t.Fatalf("decrypt succeeded on tampered ciphertext")
	}
}

func TestAESGCM_InvalidSizes(t *testing.T) {
	cipher := aead.NewAESGCM()
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
}

func seqBytes(n int) []byte {
	if n <= 0 {
		return nil
	}
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = byte(i)
	}
	return b
}

func TestAESGCM_KAT(t *testing.T) {
	cases := parseAESGCMKAT(t)
	if len(cases) == 0 {
		t.Fatal("no AES-GCM KAT cases parsed")
	}
	cipher := aead.NewAESGCM()
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
			t.Fatalf("decrypt reported failure case %d: %v", idx+1, err)
		}
		if !bytes.Equal(dec, tc.pt) {
			t.Fatalf("decrypt mismatch case %d: got %x want %x", idx+1, dec, tc.pt)
		}
	}
}
