package aead_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/AeonDave/cryptonite-go/aead"
	testutil "github.com/AeonDave/cryptonite-go/test/internal/testutil"

	_ "embed"
)

//go:embed testdata/giftcofb_kat.txt
var giftcofbKATData string

type giftcofbKATCase struct {
	key, nonce, ad, pt, ct []byte
}

func parseGiftcofbKAT(t *testing.T) []giftcofbKATCase {
	t.Helper()

	lines := strings.Split(giftcofbKATData, "\n")
	var cases []giftcofbKATCase
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

		if !strings.HasPrefix(keyLine, "Key =") || !strings.HasPrefix(nonceLine, "Nonce =") || !strings.HasPrefix(ptLine, "PT =") || !strings.HasPrefix(adLine, "AD =") || !strings.HasPrefix(ctLine, "CT =") {
			t.Fatalf("unexpected block format around line %d", i+1)
		}

		key := testutil.MustHex(t, strings.TrimSpace(strings.TrimPrefix(keyLine, "Key =")))
		nonce := testutil.MustHex(t, strings.TrimSpace(strings.TrimPrefix(nonceLine, "Nonce =")))
		pt := testutil.MustHex(t, strings.TrimSpace(strings.TrimPrefix(ptLine, "PT =")))
		ad := testutil.MustHex(t, strings.TrimSpace(strings.TrimPrefix(adLine, "AD =")))
		ct := testutil.MustHex(t, strings.TrimSpace(strings.TrimPrefix(ctLine, "CT =")))

		cases = append(cases, giftcofbKATCase{
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

var giftcofbVectors = []struct {
	name        string
	key, nonce  string
	ad, pt      string
	expectedHex string
}{
	{
		name:        "empty_ad_pt",
		key:         "000102030405060708090A0B0C0D0E0F",
		nonce:       "000102030405060708090A0B0C0D0E0F",
		ad:          "",
		pt:          "",
		expectedHex: "368965836D36614DE2FC24D0F801B9AF",
	},
	{
		name:        "ad_only",
		key:         "000102030405060708090A0B0C0D0E0F",
		nonce:       "000102030405060708090A0B0C0D0E0F",
		ad:          "00",
		pt:          "",
		expectedHex: "AE5DCDD1285D5177FE251DEB99D727DC",
	},
	{
		name:        "pt_only",
		key:         "000102030405060708090A0B0C0D0E0F",
		nonce:       "000102030405060708090A0B0C0D0E0F",
		ad:          "",
		pt:          "00",
		expectedHex: "5DF96DB329E92688242EF4E06F94FE1BD9",
	},
	{
		name:        "ad_and_pt",
		key:         "000102030405060708090A0B0C0D0E0F",
		nonce:       "000102030405060708090A0B0C0D0E0F",
		ad:          "00",
		pt:          "00",
		expectedHex: "2673FA1A8B8A87C239FA9122BE845864F9",
	},
	{
		name:        "multiblock_pt",
		key:         "000102030405060708090A0B0C0D0E0F",
		nonce:       "000102030405060708090A0B0C0D0E0F",
		ad:          "",
		pt:          "000102030405060708090A0B0C0D0E0F1011121314151617",
		expectedHex: "5D595FC00A309301719B30AD9E6D720F6F6F4759A224A9686D1B7570D00D2B8DE630017E7E780059",
	},
}

func TestGiftcofbKnownVectors(t *testing.T) {
	cipher := aead.NewGiftCofb()

	for _, vec := range giftcofbVectors {
		vec := vec
		t.Run(vec.name, func(t *testing.T) {
			key := testutil.MustHex(t, vec.key)
			nonce := testutil.MustHex(t, vec.nonce)
			ad := testutil.MustHex(t, vec.ad)
			pt := testutil.MustHex(t, vec.pt)

			want := testutil.MustHex(t, vec.expectedHex)
			got, err := cipher.Encrypt(key, nonce, ad, pt)
			if err != nil {
				t.Fatalf("encrypt failed: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("encrypt mismatch:\n got %x\nwant %x", got, want)
			}

			dec, err := cipher.Decrypt(key, nonce, ad, got)
			if err != nil {
				t.Fatalf("decrypt reported failure: %v", err)
			}
			if !bytes.Equal(dec, pt) {
				t.Fatalf("decrypt mismatch:\n got %x\nwant %x", dec, pt)
			}
		})
	}
}

func TestGiftcofbKAT(t *testing.T) {
	cipher := aead.NewGiftCofb()
	cases := parseGiftcofbKAT(t)

	for i, tc := range cases {
		got, err := cipher.Encrypt(tc.key, tc.nonce, tc.ad, tc.pt)
		if err != nil {
			t.Fatalf("encrypt failed on vector %d: %v", i, err)
		}
		if !bytes.Equal(got, tc.ct) {
			t.Fatalf("encrypt mismatch on vector %d:\n got %x\nwant %x", i, got, tc.ct)
		}

		pt, err := cipher.Decrypt(tc.key, tc.nonce, tc.ad, tc.ct)
		if err != nil {
			t.Fatalf("decrypt failed on vector %d: %v", i, err)
		}
		if !bytes.Equal(pt, tc.pt) {
			t.Fatalf("decrypt mismatch on vector %d:\n got %x\nwant %x", i, pt, tc.pt)
		}
	}
}

func TestGiftcofbTamper(t *testing.T) {
	cipher := aead.NewGiftCofb()
	vec := giftcofbVectors[3]

	key := testutil.MustHex(t, vec.key)
	nonce := testutil.MustHex(t, vec.nonce)
	ad := testutil.MustHex(t, vec.ad)
	msg := testutil.MustHex(t, vec.pt)

	ct, err := cipher.Encrypt(key, nonce, ad, msg)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	tampered := append([]byte{}, ct...)
	tampered[0] ^= 0x01
	if _, err := cipher.Decrypt(key, nonce, ad, tampered); err == nil {
		t.Fatalf("expected authentication failure")
	}
}
