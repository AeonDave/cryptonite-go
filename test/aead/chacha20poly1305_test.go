package aead_test

import (
	"bytes"
	_ "embed"
	"strings"
	"testing"

	"cryptonite-go/aead"
)

//go:embed testdata/chacha20poly1305_kat.txt
var chacha20Poly1305KATData string

type chacha20Poly1305KATCase struct {
	key, nonce, ad, pt, ct []byte
}

func parseChaCha20Poly1305KAT(t *testing.T) []chacha20Poly1305KATCase {
	lines := strings.Split(chacha20Poly1305KATData, "\n")
	var cases []chacha20Poly1305KATCase
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

		key := mustHex(t, strings.TrimSpace(strings.TrimPrefix(keyLine, "Key =")))
		nonce := mustHex(t, strings.TrimSpace(strings.TrimPrefix(nonceLine, "Nonce =")))
		pt := mustHex(t, strings.TrimSpace(strings.TrimPrefix(ptLine, "PT =")))
		ad := mustHex(t, strings.TrimSpace(strings.TrimPrefix(adLine, "AD =")))
		ct := mustHex(t, strings.TrimSpace(strings.TrimPrefix(ctLine, "CT =")))

		cases = append(cases, chacha20Poly1305KATCase{
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

func TestChaCha20Poly1305KAT(t *testing.T) {
	cases := parseChaCha20Poly1305KAT(t)
	if len(cases) == 0 {
		t.Fatal("no ChaCha20-Poly1305 KAT cases parsed")
	}

	cipher := aead.NewChaCha20Poly1305()
	adSeen := make(map[int]bool)
	ptSeen := make(map[int]bool)

	for idx, tc := range cases {
		ciphertext, err := cipher.Encrypt(tc.key, tc.nonce, tc.ad, tc.pt)
		if err != nil {
			t.Fatalf("encrypt failed case %d: %v", idx+1, err)
		}
		if !bytes.Equal(ciphertext, tc.ct) {
			t.Fatalf("encrypt mismatch case %d (|AD|=%d, |PT|=%d):\n got %x\nwant %x",
				idx+1, len(tc.ad), len(tc.pt), ciphertext, tc.ct)
		}
		pt, err := cipher.Decrypt(tc.key, tc.nonce, tc.ad, tc.ct)
		if err != nil {
			t.Fatalf("decrypt reported failure case %d: %v", idx+1, err)
		}
		if !bytes.Equal(pt, tc.pt) {
			t.Fatalf("decrypt mismatch case %d: got %x want %x", idx+1, pt, tc.pt)
		}
		adSeen[len(tc.ad)] = true
		ptSeen[len(tc.pt)] = true
	}
	if len(adSeen) == 0 || len(ptSeen) == 0 {
		t.Fatalf("unexpected empty coverage maps")
	}
}

func TestChaCha20Poly1305TagTamper(t *testing.T) {
	cases := parseChaCha20Poly1305KAT(t)
	if len(cases) == 0 {
		t.Fatal("no ChaCha20-Poly1305 KAT cases parsed")
	}
	cipher := aead.NewChaCha20Poly1305()
	base := cases[0]
	tampered := append([]byte(nil), base.ct...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := cipher.Decrypt(base.key, base.nonce, base.ad, tampered); err == nil {
		t.Fatalf("decrypt succeeded on tampered tag")
	}
}

func TestChaCha20Poly1305CiphertextTamper(t *testing.T) {
	cases := parseChaCha20Poly1305KAT(t)
	if len(cases) == 0 {
		t.Fatal("no ChaCha20-Poly1305 KAT cases parsed")
	}
	cipher := aead.NewChaCha20Poly1305()
	var tc *chacha20Poly1305KATCase
	for i := range cases {
		if len(cases[i].pt) > 0 {
			tc = &cases[i]
			break
		}
	}
	if tc == nil {
		t.Skip("no non-empty plaintext case available")
	}
	tampered := append([]byte(nil), tc.ct...)
	tampered[len(tc.pt)/2] ^= 0x01
	if _, err := cipher.Decrypt(tc.key, tc.nonce, tc.ad, tampered); err == nil {
		t.Fatalf("decrypt succeeded on tampered ciphertext")
	}
}

func TestChaCha20Poly1305EmptyInputs(t *testing.T) {
	cipher := aead.NewChaCha20Poly1305()

	key := make([]byte, 32)
	nonce := make([]byte, 12)

	ct, err := cipher.Encrypt(key, nonce, nil, nil)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	if len(ct) != 16 {
		t.Fatalf("unexpected length for empty message: %d", len(ct))
	}
	pt, err := cipher.Decrypt(key, nonce, nil, ct)
	if err != nil {
		t.Fatalf("decrypt failed on empty inputs: %v", err)
	}
	if len(pt) != 0 {
		t.Fatalf("unexpected plaintext: %x", pt)
	}
}
