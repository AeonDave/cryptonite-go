package aead_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/AeonDave/cryptonite-go/aead"
	testutil "github.com/AeonDave/cryptonite-go/test/internal/testutil"

	_ "embed"
)

//go:embed testdata/skinnyaead_kat.txt
var skinnyaeadKATData string

type skinnyaeadKATCase struct {
	key, nonce, ad, pt, ct []byte
}

func parseSkinnyKAT(t *testing.T) []skinnyaeadKATCase {
	t.Helper()

	lines := strings.Split(skinnyaeadKATData, "\n")
	var cases []skinnyaeadKATCase
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

		cases = append(cases, skinnyaeadKATCase{
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

var skinnyaeadVectors = []struct {
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
		expectedHex: "99CE68EF7B52AAD0E11C6E2FC722426D",
	},
	{
		name:        "ad_only",
		key:         "000102030405060708090A0B0C0D0E0F",
		nonce:       "000102030405060708090A0B0C0D0E0F",
		ad:          "00",
		pt:          "",
		expectedHex: "4720E8EA3682D9E9DC5C83563705F8F4",
	},
	{
		name:        "pt_only",
		key:         "000102030405060708090A0B0C0D0E0F",
		nonce:       "000102030405060708090A0B0C0D0E0F",
		ad:          "",
		pt:          "00",
		expectedHex: "85C6E991B30CC1479902E0E9736CA436F6",
	},
	{
		name:        "ad_and_pt",
		key:         "000102030405060708090A0B0C0D0E0F",
		nonce:       "000102030405060708090A0B0C0D0E0F",
		ad:          "00",
		pt:          "00",
		expectedHex: "85180711B6411134A03FA0040A9C838C6F",
	},
	{
		name:        "multiblock_pt",
		key:         "000102030405060708090A0B0C0D0E0F",
		nonce:       "000102030405060708090A0B0C0D0E0F",
		ad:          "",
		pt:          "000102030405060708090A0B0C0D0E0F1011121314151617",
		expectedHex: "241F0DAC2C5DDA488F0E68CADBF2CC9F9A1562B41DFC09AF6C940631F6A5A1A8E37CC7155D903810",
	},
}

func TestSkinnyAeadKnownVectors(t *testing.T) {
	cipher := aead.NewSkinnyAead()

	for _, vec := range skinnyaeadVectors {
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

func TestSkinnyAeadKAT(t *testing.T) {
	cipher := aead.NewSkinnyAead()
	cases := parseSkinnyKAT(t)

	for i, tc := range cases {
		got, err := cipher.Encrypt(tc.key, tc.nonce, tc.ad, tc.pt)
		if err != nil {
			t.Fatalf("encrypt failed on vector %d: %v", i, err)
		}
		if !bytes.Equal(got, tc.ct) {
			t.Fatalf("encrypt mismatch on vector %d:\n got %x\nwant %x", i, got, tc.ct)
		}

		dec, err := cipher.Decrypt(tc.key, tc.nonce, tc.ad, tc.ct)
		if err != nil {
			t.Fatalf("decrypt failed on vector %d: %v", i, err)
		}
		if !bytes.Equal(dec, tc.pt) {
			t.Fatalf("decrypt mismatch on vector %d:\n got %x\nwant %x", i, dec, tc.pt)
		}
	}
}

func TestSkinnyAeadRejectTampering(t *testing.T) {
	cipher := aead.NewSkinnyAead()
	key := testutil.MustHex(t, "000102030405060708090A0B0C0D0E0F")
	nonce := testutil.MustHex(t, "000102030405060708090A0B0C0D0E0F")
	ad := testutil.MustHex(t, "0102")
	pt := testutil.MustHex(t, "00010203")

	ct, err := cipher.Encrypt(key, nonce, ad, pt)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	for i := range ct {
		tweaked := make([]byte, len(ct))
		copy(tweaked, ct)
		tweaked[i] ^= 0x01
		if _, err := cipher.Decrypt(key, nonce, ad, tweaked); err == nil {
			t.Fatalf("tampering at byte %d was not detected", i)
		}
	}
}
