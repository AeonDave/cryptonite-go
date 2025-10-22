package aead_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/AeonDave/cryptonite-go/aead"
	testutil "github.com/AeonDave/cryptonite-go/test/internal/testutil"

	_ "embed"
)

//go:embed testdata/ascon80pq_kat.txt
var ascon80pqKATData string

type ascon80pqKATCase struct {
	key, nonce, ad, pt, ct []byte
}

func parseAscon80pqKAT(t *testing.T) []ascon80pqKATCase {
	lines := strings.Split(ascon80pqKATData, "\n")
	var cases []ascon80pqKATCase
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
		cases = append(cases, ascon80pqKATCase{
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

var ascon80pqVectors = []struct {
	name               string
	key, nonce, ad, pt string
	expectedHex        string
}{
	{
		name:        "empty_pt_ad",
		key:         "000102030405060708090A0B0C0D0E0F10111213",
		nonce:       "101112131415161718191A1B1C1D1E1F",
		pt:          "",
		ad:          "",
		expectedHex: "D36D9BF38D7B05DFB24212BCE7C500AC",
	},
        {
                name:        "ad_only",
                key:         "000102030405060708090A0B0C0D0E0F10111213",
                nonce:       "101112131415161718191A1B1C1D1E1F",
                pt:          "",
                ad:          "303132333435363738393A3B3C3D3E3F404142434445464748",
                expectedHex: "3F9206022315184B58A37B4704719C11",
        },
	{
		name:        "pt_only",
		key:         "000102030405060708090A0B0C0D0E0F10111213",
		nonce:       "101112131415161718191A1B1C1D1E1F",
		pt:          "20",
		ad:          "",
		expectedHex: "48019AA3FAC9E6F8335DF128F8D88F2CD1",
	},
	{
		name:        "pt_and_ad",
		key:         "000102030405060708090A0B0C0D0E0F10111213",
		nonce:       "101112131415161718191A1B1C1D1E1F",
		pt:          "20",
		ad:          "30",
		expectedHex: "1555B8BCDB1D8F251ED8656BEB064F89B9",
	},
	{
		name:        "multi_block_pt",
		key:         "000102030405060708090A0B0C0D0E0F10111213",
		nonce:       "101112131415161718191A1B1C1D1E1F",
		pt:          "202122232425262728292A2B2C2D2E2F",
		ad:          "",
		expectedHex: "482B76513832B80ECDC03756D855F0A0E9003082D77C1A95E147C51DC5B52F42",
	},
	{
		name:        "multi_block_pt_ad",
		key:         "000102030405060708090A0B0C0D0E0F10111213",
		nonce:       "101112131415161718191A1B1C1D1E1F",
		pt:          "202122232425262728292A2B2C2D2E2F",
		ad:          "30",
		expectedHex: "15CF4AFFA562E812871B57F959A6770DA9CE1A1DC184CED8250EA45E37FF58CE",
	},
}

func TestAscon80pqKnownVectors(t *testing.T) {
	cipher := aead.NewAscon80pq()

	for _, vec := range ascon80pqVectors {
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

func TestAscon80pqTamper(t *testing.T) {
	cipher := aead.NewAscon80pq()

	vec := ascon80pqVectors[3]
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

func TestAscon80pqKATGrid(t *testing.T) {
	cases := parseAscon80pqKAT(t)
	if len(cases) != 32*32 {
		t.Fatalf("unexpected number of cases: %d", len(cases))
	}

	cipher := aead.NewAscon80pq()
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
			t.Fatalf("missing associated data length %d", i)
		}
		if !ptSeen[i] {
			t.Fatalf("missing plaintext length %d", i)
		}
	}
}
