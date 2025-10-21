package aead_test

import (
	"bytes"
	"strings"
	"testing"

	"cryptonite-go/aead"
	testutil "cryptonite-go/test/internal/testutil"

	_ "embed"
)

//go:embed testdata/ascon128a_kat.txt
var asconKATData string

type asconKATCase struct {
	key, nonce, ad, pt, ct []byte
}

func parseAsconKAT(t *testing.T) []asconKATCase {
	lines := strings.Split(asconKATData, "\n")
	var cases []asconKATCase
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
		cases = append(cases, asconKATCase{
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

var asconVectors = []struct {
	name               string
	key, nonce, ad, pt string
	expectedHex        string
}{
	{
		name:        "empty_pt_ad",
		key:         "000102030405060708090A0B0C0D0E0F",
		nonce:       "101112131415161718191A1B1C1D1E1F",
		pt:          "",
		ad:          "",
		expectedHex: "4F9C278211BEC9316BF68F46EE8B2EC6",
	},
	{
		name:        "ad_only",
		key:         "000102030405060708090A0B0C0D0E0F",
		nonce:       "101112131415161718191A1B1C1D1E1F",
		pt:          "",
		ad:          "303132333435363738393A3B3C3D3E3F404142434445464748",
		expectedHex: "0A0BB58CE4513C2CFB950CCDF7C5DBFC",
	},
	{
		name:        "pt_only",
		key:         "000102030405060708090A0B0C0D0E0F",
		nonce:       "101112131415161718191A1B1C1D1E1F",
		pt:          "20",
		ad:          "",
		expectedHex: "E8DD576ABA1CD3E6FC704DE02AEDB79588",
	},
	{
		name:        "pt_and_ad",
		key:         "000102030405060708090A0B0C0D0E0F",
		nonce:       "101112131415161718191A1B1C1D1E1F",
		pt:          "20",
		ad:          "30",
		expectedHex: "962B8016836C75A7D86866588CA245D886",
	},
	{
		name:        "multi_block_pt",
		key:         "000102030405060708090A0B0C0D0E0F",
		nonce:       "101112131415161718191A1B1C1D1E1F",
		pt:          "202122232425262728292A2B2C2D2E2F",
		ad:          "",
		expectedHex: "E8C3DEEE246CC5EAE3E872313897A2BB9EAA915C9DD3245D77048F24D46D27A7",
	},
	{
		name:        "multi_block_pt_ad",
		key:         "000102030405060708090A0B0C0D0E0F",
		nonce:       "101112131415161718191A1B1C1D1E1F",
		pt:          "202122232425262728292A2B2C2D2E2F",
		ad:          "30",
		expectedHex: "96107D8A29A7529A7941BDC7DF1FE3C6B48691673A22DA04BCC261FEE0FD6A4D",
	},
}

func TestAsconKnownVectors(t *testing.T) {
	cipher := aead.NewAscon128()

	for _, vec := range asconVectors {
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

func TestAsconTamper(t *testing.T) {
	cipher := aead.NewAscon128()

	vec := asconVectors[3] // pt_and_ad
	key := testutil.MustHex(t, vec.key)
	nonce := testutil.MustHex(t, vec.nonce)
	ad := testutil.MustHex(t, vec.ad)
	ciphertext, err := cipher.Encrypt(key, nonce, ad, testutil.MustHex(t, vec.pt))
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-1] ^= 0x01

	if _, err := cipher.Decrypt(key, nonce, ad, tampered); err == nil {
		t.Fatalf("decrypt succeeded on tampered tag")
	}
}

func TestAsconKATGrid(t *testing.T) {
	cases := parseAsconKAT(t)
	if len(cases) != 32*32 {
		t.Fatalf("unexpected number of cases: %d", len(cases))
	}

	cipher := aead.NewAscon128()
	adSeen := make(map[int]bool)
	ptSeen := make(map[int]bool)

	for idx, tc := range cases {
		got, err := cipher.Encrypt(tc.key, tc.nonce, tc.ad, tc.pt)
		if err != nil {
			t.Fatalf("encrypt failed for case %d: %v", idx+1, err)
		}
		if !bytes.Equal(got, tc.ct) {
			t.Fatalf("encrypt mismatch for case %d (|AD|=%d, |PT|=%d):\n got %x\nwant %x", idx+1, len(tc.ad), len(tc.pt), got, tc.ct)
		}

		dec, err := cipher.Decrypt(tc.key, tc.nonce, tc.ad, tc.ct)
		if err != nil {
			t.Fatalf("decrypt reported failure for case %d: %v", idx+1, err)
		}
		if !bytes.Equal(dec, tc.pt) {
			t.Fatalf("decrypt mismatch for case %d: got %x want %x", idx+1, dec, tc.pt)
		}

		adSeen[len(tc.ad)] = true
		ptSeen[len(tc.pt)] = true
	}

	for i := 0; i < 32; i++ {
		if !adSeen[i] {
			t.Fatalf("missing AD length %d in KAT coverage", i)
		}
		if !ptSeen[i] {
			t.Fatalf("missing PT length %d in KAT coverage", i)
		}
	}
}
