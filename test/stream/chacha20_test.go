package stream_test

import (
	"bytes"
	_ "embed"
	"strconv"
	"strings"
	"testing"

	"cryptonite-go/stream"
	testutil "cryptonite-go/test/internal/testutil"
)

//go:embed testdata/chacha20_kat.txt
var chachaKAT string

type chachaCase struct {
	variant    string
	key        []byte
	nonce      []byte
	counter    uint32
	keystream  []byte
	plaintext  []byte
	ciphertext []byte
	isX        bool
}

func parseChaChaKAT(t *testing.T) []chachaCase {
	t.Helper()
	lines := strings.Split(chachaKAT, "\n")
	var cases []chachaCase
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
		var (
			key, nonce, keystream, plaintext, ciphertext []byte
			counter                                      uint32
			haveCounter                                  bool
		)
		for i < len(lines) {
			l := strings.TrimSpace(lines[i])
			if l == "" {
				i++
				break
			}
			switch {
			case strings.HasPrefix(l, "Key ="):
				key = testutil.MustHex(t, strings.TrimSpace(strings.TrimPrefix(l, "Key =")))
			case strings.HasPrefix(l, "Nonce ="):
				nonce = testutil.MustHex(t, strings.TrimSpace(strings.TrimPrefix(l, "Nonce =")))
			case strings.HasPrefix(l, "Counter ="):
				value := strings.TrimSpace(strings.TrimPrefix(l, "Counter ="))
				n, err := strconv.ParseUint(value, 10, 32)
				if err != nil {
					t.Fatalf("variant %q: invalid counter %q: %v", variant, value, err)
				}
				counter = uint32(n)
				haveCounter = true
			case strings.HasPrefix(l, "Keystream ="):
				keystream = testutil.MustHex(t, strings.TrimSpace(strings.TrimPrefix(l, "Keystream =")))
			case strings.HasPrefix(l, "Plaintext ="):
				plaintext = testutil.MustHex(t, strings.TrimSpace(strings.TrimPrefix(l, "Plaintext =")))
			case strings.HasPrefix(l, "Ciphertext ="):
				ciphertext = testutil.MustHex(t, strings.TrimSpace(strings.TrimPrefix(l, "Ciphertext =")))
			default:
				t.Fatalf("variant %q: unexpected attribute on line %d: %q", variant, i+1, lines[i])
			}
			i++
		}
		if !haveCounter {
			t.Fatalf("variant %q missing counter", variant)
		}
		cases = append(cases, chachaCase{
			variant:    variant,
			key:        key,
			nonce:      nonce,
			counter:    counter,
			keystream:  keystream,
			plaintext:  plaintext,
			ciphertext: ciphertext,
			isX:        strings.HasPrefix(strings.ToUpper(variant), "XCHACHA20"),
		})
	}
	return cases
}

func TestChaChaKAT(t *testing.T) {
	cases := parseChaChaKAT(t)
	if len(cases) == 0 {
		t.Fatal("no ChaCha cases parsed")
	}
	for _, tc := range cases {
		if tc.isX {
			testXChaChaCase(t, tc)
		} else {
			testChaChaCase(t, tc)
		}
	}
}

func testChaChaCase(t *testing.T, tc chachaCase) {
	c, err := stream.NewChaCha20(tc.key, tc.nonce, tc.counter)
	if err != nil {
		t.Fatalf("%s: constructor failed: %v", tc.variant, err)
	}
	if len(tc.keystream) > 0 {
		got := make([]byte, len(tc.keystream))
		c.KeyStream(got)
		if !bytes.Equal(got, tc.keystream) {
			t.Fatalf("%s: keystream mismatch\n got %x\nwant %x", tc.variant, got, tc.keystream)
		}
		c.Reset(tc.counter)
	}
	switch {
	case len(tc.plaintext) > 0 && len(tc.ciphertext) > 0:
		dst := make([]byte, len(tc.plaintext))
		copy(dst, tc.plaintext)
		c.XORKeyStream(dst, tc.plaintext)
		if !bytes.Equal(dst, tc.ciphertext) {
			t.Fatalf("%s: ciphertext mismatch\n got %x\nwant %x", tc.variant, dst, tc.ciphertext)
		}
		// Verify we can recover plaintext in place.
		c.Reset(tc.counter)
		copy(dst, tc.ciphertext)
		c.XORKeyStream(dst, dst)
		if !bytes.Equal(dst, tc.plaintext) {
			t.Fatalf("%s: decrypt mismatch\n got %x\nwant %x", tc.variant, dst, tc.plaintext)
		}
		// Verify KeyStream matches ciphertext XOR plaintext.
		keystream := make([]byte, len(tc.plaintext))
		for i := range keystream {
			keystream[i] = tc.plaintext[i] ^ tc.ciphertext[i]
		}
		c.Reset(tc.counter)
		got := make([]byte, len(keystream))
		c.KeyStream(got)
		if !bytes.Equal(got, keystream) {
			t.Fatalf("%s: derived keystream mismatch\n got %x\nwant %x", tc.variant, got, keystream)
		}
	case len(tc.keystream) > 0:
		zero := make([]byte, len(tc.keystream))
		dst := make([]byte, len(tc.keystream))
		c.Reset(tc.counter)
		c.XORKeyStream(dst, zero)
		if !bytes.Equal(dst, tc.keystream) {
			t.Fatalf("%s: XOR keystream mismatch\n got %x\nwant %x", tc.variant, dst, tc.keystream)
		}
	default:
		t.Fatalf("%s: no validation data present", tc.variant)
	}
}

func testXChaChaCase(t *testing.T, tc chachaCase) {
	c, err := stream.NewXChaCha20(tc.key, tc.nonce, tc.counter)
	if err != nil {
		t.Fatalf("%s: constructor failed: %v", tc.variant, err)
	}
	if len(tc.keystream) == 0 {
		t.Fatalf("%s: expected keystream for XChaCha20 case", tc.variant)
	}
	got := make([]byte, len(tc.keystream))
	c.KeyStream(got)
	if !bytes.Equal(got, tc.keystream) {
		t.Fatalf("%s: keystream mismatch\n got %x\nwant %x", tc.variant, got, tc.keystream)
	}
	// Verify we can XOR in place.
	c.Reset(tc.counter)
	buf := make([]byte, len(tc.keystream))
	copy(buf, tc.keystream)
	c.XORKeyStream(buf, buf)
	if !bytes.Equal(buf, make([]byte, len(buf))) {
		t.Fatalf("%s: XORing keystream with itself did not zero buffer", tc.variant)
	}
}

func TestChaChaInvalidParameters(t *testing.T) {
	if _, err := stream.NewChaCha20(make([]byte, 31), make([]byte, 12), 0); err == nil {
		t.Fatal("expected error for short key")
	}
	if _, err := stream.NewChaCha20(make([]byte, 32), make([]byte, 11), 0); err == nil {
		t.Fatal("expected error for short nonce")
	}
	if _, err := stream.NewXChaCha20(make([]byte, 31), make([]byte, 24), 0); err == nil {
		t.Fatal("expected error for short XChaCha key")
	}
	if _, err := stream.NewXChaCha20(make([]byte, 32), make([]byte, 23), 0); err == nil {
		t.Fatal("expected error for short XChaCha nonce")
	}
}
