package block_test

import (
	"bytes"
	_ "embed"
	"strings"
	"testing"

	"cryptonite-go/block"
	testutil "cryptonite-go/test/internal/testutil"
)

//go:embed testdata/aes_kat.txt
var aesKAT string

type aesCase struct {
	variant    string
	key        []byte
	plaintext  []byte
	ciphertext []byte
	is256      bool
}

func parseAESKAT(t *testing.T) []aesCase {
	t.Helper()
	lines := strings.Split(aesKAT, "\n")
	var cases []aesCase
	for i := 0; i < len(lines); {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			i++
			continue
		}
		if !strings.HasPrefix(line, "Variant =") {
			t.Fatalf("unexpected label on line %d: %q", i+1, lines[i])
		}
		variant := strings.TrimSpace(strings.TrimPrefix(line, "Variant ="))
		i++
		var key, plaintext, ciphertext []byte
		for i < len(lines) {
			l := strings.TrimSpace(lines[i])
			if l == "" {
				i++
				break
			}
			switch {
			case strings.HasPrefix(l, "Key ="):
				key = testutil.MustHex(t, strings.TrimSpace(strings.TrimPrefix(l, "Key =")))
			case strings.HasPrefix(l, "Plaintext ="):
				plaintext = testutil.MustHex(t, strings.TrimSpace(strings.TrimPrefix(l, "Plaintext =")))
			case strings.HasPrefix(l, "Ciphertext ="):
				ciphertext = testutil.MustHex(t, strings.TrimSpace(strings.TrimPrefix(l, "Ciphertext =")))
			default:
				t.Fatalf("variant %q: unexpected attribute on line %d: %q", variant, i+1, lines[i])
			}
			i++
		}
		cases = append(cases, aesCase{
			variant:    variant,
			key:        key,
			plaintext:  plaintext,
			ciphertext: ciphertext,
			is256:      strings.Contains(variant, "256"),
		})
	}
	return cases
}

func TestAESKAT(t *testing.T) {
	cases := parseAESKAT(t)
	if len(cases) == 0 {
		t.Fatal("no AES cases parsed")
	}
	for _, tc := range cases {
		if tc.is256 {
			testAES256Case(t, tc)
		} else {
			testAES128Case(t, tc)
		}
	}
}

func testAES128Case(t *testing.T, tc aesCase) {
	c, err := block.NewAES128(tc.key)
	if err != nil {
		t.Fatalf("%s: constructor failed: %v", tc.variant, err)
	}
	if got := c.BlockSize(); got != 16 {
		t.Fatalf("%s: unexpected block size %d", tc.variant, got)
	}
	dst := make([]byte, len(tc.plaintext))
	c.Encrypt(dst, tc.plaintext)
	if !bytes.Equal(dst, tc.ciphertext) {
		t.Fatalf("%s: encrypt mismatch\n got %x\nwant %x", tc.variant, dst, tc.ciphertext)
	}
	pt := make([]byte, len(tc.ciphertext))
	c.Decrypt(pt, tc.ciphertext)
	if !bytes.Equal(pt, tc.plaintext) {
		t.Fatalf("%s: decrypt mismatch\n got %x\nwant %x", tc.variant, pt, tc.plaintext)
	}
}

func testAES256Case(t *testing.T, tc aesCase) {
	c, err := block.NewAES256(tc.key)
	if err != nil {
		t.Fatalf("%s: constructor failed: %v", tc.variant, err)
	}
	if got := c.BlockSize(); got != 16 {
		t.Fatalf("%s: unexpected block size %d", tc.variant, got)
	}
	dst := make([]byte, len(tc.plaintext))
	c.Encrypt(dst, tc.plaintext)
	if !bytes.Equal(dst, tc.ciphertext) {
		t.Fatalf("%s: encrypt mismatch\n got %x\nwant %x", tc.variant, dst, tc.ciphertext)
	}
	pt := make([]byte, len(tc.ciphertext))
	c.Decrypt(pt, tc.ciphertext)
	if !bytes.Equal(pt, tc.plaintext) {
		t.Fatalf("%s: decrypt mismatch\n got %x\nwant %x", tc.variant, pt, tc.plaintext)
	}
}

func TestAESInvalidParameters(t *testing.T) {
	if _, err := block.NewAES128(make([]byte, 15)); err == nil {
		t.Fatal("expected error for short AES-128 key")
	}
	if _, err := block.NewAES256(make([]byte, 31)); err == nil {
		t.Fatal("expected error for short AES-256 key")
	}
}
