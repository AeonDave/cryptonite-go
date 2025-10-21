package aead_test

import (
	"bytes"
	_ "embed"
	"strings"
	"testing"

	"github.com/AeonDave/cryptonite-go/aead"
	testutil "github.com/AeonDave/cryptonite-go/test/internal/testutil"
)

//go:embed testdata/xchacha20poly1305_kat.txt
var xChaChaKATData string

type xChaChaKATCase struct {
	key, nonce, ad, pt, ct []byte
}

func parseXChaChaKAT(t *testing.T) []xChaChaKATCase {
	lines := strings.Split(xChaChaKATData, "\n")
	var cases []xChaChaKATCase
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
		cases = append(cases, xChaChaKATCase{
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

func TestXChaCha20Poly1305_KAT(t *testing.T) {
	cases := parseXChaChaKAT(t)
	if len(cases) == 0 {
		t.Fatal("no XChaCha20-Poly1305 KAT cases parsed")
	}
	a := aead.NewXChaCha20Poly1305()
	for idx, tc := range cases {
		got, err := a.Encrypt(tc.key, tc.nonce, tc.ad, tc.pt)
		if err != nil {
			t.Fatalf("encrypt failed case %d: %v", idx+1, err)
		}
		if !bytes.Equal(got, tc.ct) {
			t.Fatalf("encrypt mismatch case %d (|AD|=%d, |PT|=%d):\n got %x\nwant %x", idx+1, len(tc.ad), len(tc.pt), got, tc.ct)
		}
		dec, err := a.Decrypt(tc.key, tc.nonce, tc.ad, tc.ct)
		if err != nil {
			t.Fatalf("decrypt failed case %d: %v", idx+1, err)
		}
		if !bytes.Equal(dec, tc.pt) {
			t.Fatalf("decrypt mismatch case %d: got %x want %x", idx+1, dec, tc.pt)
		}
	}
}

func TestXChaCha20Poly1305_Tamper(t *testing.T) {
	cases := parseXChaChaKAT(t)
	a := aead.NewXChaCha20Poly1305()
	tc := cases[0]
	tam := append([]byte(nil), tc.ct...)
	tam[len(tam)-1] ^= 0x01
	if _, err := a.Decrypt(tc.key, tc.nonce, tc.ad, tam); err == nil {
		t.Fatalf("decrypt succeeded on tampered tag")
	}
}
