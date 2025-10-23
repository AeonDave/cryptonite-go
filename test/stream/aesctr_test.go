package stream_test

import (
	"bytes"
	_ "embed"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/AeonDave/cryptonite-go/stream"
	testutil "github.com/AeonDave/cryptonite-go/test/internal/testutil"
)

//go:embed testdata/aesctr_kat.txt
var aesctrKAT string

type aesctrCase struct {
	variant    string
	key        []byte
	nonce      []byte
	counter    uint32
	plaintext  []byte
	ciphertext []byte
}

func parseAESCTRKAT(t *testing.T) []aesctrCase {
	t.Helper()
	lines := strings.Split(aesctrKAT, "\n")
	var cases []aesctrCase
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
			key, nonce, plaintext, ciphertext []byte
			counter                           uint32
			haveCounter                       bool
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
		cases = append(cases, aesctrCase{
			variant:    variant,
			key:        key,
			nonce:      nonce,
			counter:    counter,
			plaintext:  plaintext,
			ciphertext: ciphertext,
		})
	}
	return cases
}

func TestAESCTRKAT(t *testing.T) {
	cases := parseAESCTRKAT(t)
	if len(cases) == 0 {
		t.Fatal("no AES-CTR cases parsed")
	}
	for _, tc := range cases {
		c, err := stream.NewAESCTR(tc.key, tc.nonce, tc.counter)
		if err != nil {
			t.Fatalf("%s: constructor failed: %v", tc.variant, err)
		}
		if len(tc.plaintext) == 0 || len(tc.ciphertext) == 0 {
			t.Fatalf("%s: missing plaintext or ciphertext", tc.variant)
		}
		dst := make([]byte, len(tc.plaintext))
		c.XORKeyStream(dst, tc.plaintext)
		if !bytes.Equal(dst, tc.ciphertext) {
			t.Fatalf("%s: ciphertext mismatch\n got %x\nwant %x", tc.variant, dst, tc.ciphertext)
		}
		c.Reset(tc.counter)
		copy(dst, tc.ciphertext)
		c.XORKeyStream(dst, dst)
		if !bytes.Equal(dst, tc.plaintext) {
			t.Fatalf("%s: decrypt mismatch\n got %x\nwant %x", tc.variant, dst, tc.plaintext)
		}
		keystream := make([]byte, len(tc.plaintext))
		for i := range keystream {
			keystream[i] = tc.plaintext[i] ^ tc.ciphertext[i]
		}
		c.Reset(tc.counter)
		got := make([]byte, len(keystream))
		c.KeyStream(got)
		if !bytes.Equal(got, keystream) {
			t.Fatalf("%s: keystream mismatch\n got %x\nwant %x", tc.variant, got, keystream)
		}
	}
}

func TestAESCTRInvalidParameters(t *testing.T) {
	if _, err := stream.NewAESCTR(make([]byte, 15), make([]byte, stream.AESCTRNonceSize()), 0); err == nil {
		t.Fatal("expected error for short key")
	}
	if _, err := stream.NewAESCTR(make([]byte, 16), make([]byte, stream.AESCTRNonceSize()-1), 0); err == nil {
		t.Fatal("expected error for short nonce")
	}
}

func TestAESCTRKeystreamExhaustion(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, stream.AESCTRNonceSize())
	c, err := stream.NewAESCTR(key, nonce, math.MaxUint32)
	if err != nil {
		t.Fatalf("NewAESCTR failed: %v", err)
	}

	block := make([]byte, 16)
	c.KeyStream(block)

	var panicked bool
	func() {
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("expected keystream exhaustion panic")
			}
			if s, ok := r.(string); ok && s != "aesctr: keystream exhausted" {
				t.Fatalf("unexpected panic message: %v", r)
			}
			panicked = true
		}()

		tmp := make([]byte, 1)
		c.KeyStream(tmp)
	}()
	if !panicked {
		t.Fatal("expected keystream exhaustion panic")
	}

	c.Reset(math.MaxUint32)
	got := make([]byte, len(block))
	c.KeyStream(got)
	if !bytes.Equal(got, block) {
		t.Fatalf("keystream mismatch after reset\n got %x\nwant %x", got, block)
	}
}
