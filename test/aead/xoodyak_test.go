package aead_test

import (
	"bytes"
	_ "embed"
	"strings"
	"testing"

	"github.com/AeonDave/cryptonite-go/aead"
	testutil "github.com/AeonDave/cryptonite-go/test/internal/testutil"
)

//go:embed testdata/xoodyak_kat.txt
var xoodyakKATData string

type xoodyakKATCase struct {
	key, nonce, ad, pt, ct []byte
}

func parseXoodyakKAT(t *testing.T) []xoodyakKATCase {
	lines := strings.Split(xoodyakKATData, "\n")
	var cases []xoodyakKATCase
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

		cases = append(cases, xoodyakKATCase{
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

func TestXoodyakKAT(t *testing.T) {
	cases := parseXoodyakKAT(t)
	if len(cases) != 65*65 {
		t.Fatalf("unexpected number of cases: %d", len(cases))
	}

	cipher := aead.NewXoodyak()
	adSeen := make(map[int]bool)
	ptSeen := make(map[int]bool)

	for idx, tc := range cases {
		got, err := cipher.Encrypt(tc.key, tc.nonce, tc.ad, tc.pt)
		if err != nil {
			t.Fatalf("encrypt mismatch case %d (|AD|=%d, |PT|=%d): %v", idx+1, len(tc.ad), len(tc.pt), err)
		}
		if !bytes.Equal(got, tc.ct) {
			t.Fatalf("encrypt mismatch case %d (|AD|=%d, |PT|=%d):\n got %x\nwant %x",
				idx+1, len(tc.ad), len(tc.pt), got, tc.ct)
		}
		pt, err := cipher.Decrypt(tc.key, tc.nonce, tc.ad, tc.ct)
		if err != nil {
			t.Fatalf("decrypt reported failure case %d: %v", idx+1, err)
		}
		if !bytes.Equal(pt, tc.pt) {
			t.Fatalf("decrypt mismatch case %d:\n got %x\nwant %x", idx+1, pt, tc.pt)
		}
		adSeen[len(tc.ad)] = true
		ptSeen[len(tc.pt)] = true
	}

	for l := 0; l <= 64; l++ {
		if !adSeen[l] {
			t.Fatalf("missing AD length %d in coverage", l)
		}
		if !ptSeen[l] {
			t.Fatalf("missing PT length %d in coverage", l)
		}
	}
}

func TestXoodyakTagTamper(t *testing.T) {
	cases := parseXoodyakKAT(t)
	cipher := aead.NewXoodyak()

	tc := cases[len(cases)/2]
	tampered := append([]byte(nil), tc.ct...)
	tampered[len(tampered)-1] ^= 0x01

	if _, err := cipher.Decrypt(tc.key, tc.nonce, tc.ad, tampered); err == nil {
		t.Fatalf("decrypt succeeded on tampered tag")
	}
}

func TestXoodyakCiphertextTamper(t *testing.T) {
	cases := parseXoodyakKAT(t)
	cipher := aead.NewXoodyak()

	var tc *xoodyakKATCase
	for i := range cases {
		if len(cases[i].ct) > len(cases[i].pt) { // ensure there is a ciphertext portion to flip
			tc = &cases[i]
			if len(cases[i].pt) > 0 {
				break
			}
		}
	}
	if tc == nil || len(tc.ct) == len(tc.pt) {
		t.Skip("no ciphertext+tag case available")
	}

	tampered := append([]byte(nil), tc.ct...)
	if len(tc.pt) == 0 {
		t.Skip("selected case has zero plaintext; cannot tamper ciphertext portion")
	}
	pos := len(tc.pt) / 2
	tampered[pos] ^= 0x01

	if _, err := cipher.Decrypt(tc.key, tc.nonce, tc.ad, tampered); err == nil {
		t.Fatalf("decrypt succeeded on tampered ciphertext")
	}
}
