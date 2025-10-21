package xoodyak_test

import (
	"bytes"
	_ "embed"
	"hash"
	"strings"
	"testing"

	"cryptonite-go/hash/sha3"
)

//go:embed testdata/sha3_kat.txt
var sha3KAT string

type sha3Case struct {
	variant string
	msg     []byte
	md      []byte
}

func parseSHA3KAT(t *testing.T) []sha3Case {
	t.Helper()
	lines := strings.Split(sha3KAT, "\n")
	var cases []sha3Case
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
		if i+2 >= len(lines) {
			t.Fatalf("incomplete block starting line %d", i+1)
		}
		msgLine := strings.TrimSpace(lines[i+1])
		mdLine := strings.TrimSpace(lines[i+2])
		if !strings.HasPrefix(msgLine, "Msg =") || !strings.HasPrefix(mdLine, "MD =") {
			t.Fatalf("unexpected block around line %d", i+1)
		}
		msgHex := strings.TrimSpace(strings.TrimPrefix(msgLine, "Msg ="))
		mdHex := strings.TrimSpace(strings.TrimPrefix(mdLine, "MD ="))
		msg := mustHex(t, msgHex)
		md := mustHex(t, mdHex)
		cases = append(cases, sha3Case{variant: variant, msg: msg, md: md})
		i += 3
		if i < len(lines) && strings.TrimSpace(lines[i]) == "" {
			i++
		}
	}
	return cases
}

func TestSHA3KAT(t *testing.T) {
	cases := parseSHA3KAT(t)
	if len(cases) == 0 {
		t.Fatal("no SHA3 cases parsed")
	}
	constructors := map[string]func() hash.Hash{
		"SHA3-224": sha3.Newsha3224,
		"SHA3-256": sha3.Newsha3256,
		"SHA3-384": sha3.Newsha3384,
		"SHA3-512": sha3.Newsha3512,
	}
	for idx, tc := range cases {
		newHash, ok := constructors[tc.variant]
		if !ok {
			t.Fatalf("unknown variant %q", tc.variant)
		}
		h := newHash()
		if _, err := h.Write(tc.msg); err != nil {
			t.Fatalf("write failed for case %d: %v", idx+1, err)
		}
		got := h.Sum(nil)
		if !bytes.Equal(got, tc.md) {
			t.Fatalf("digest mismatch for case %d (%s)\n got %x\nwant %x", idx+1, tc.variant, got, tc.md)
		}
		h.Reset()
		if len(tc.msg) > 0 {
			half := len(tc.msg) / 2
			if half == 0 {
				half = len(tc.msg)
			}
			if _, err := h.Write(tc.msg[:half]); err != nil {
				t.Fatalf("write1 failed case %d: %v", idx+1, err)
			}
			if _, err := h.Write(tc.msg[half:]); err != nil {
				t.Fatalf("write2 failed case %d: %v", idx+1, err)
			}
		}
		got = h.Sum(nil)
		if !bytes.Equal(got, tc.md) {
			t.Fatalf("digest mismatch after reset for case %d (%s)", idx+1, tc.variant)
		}

		switch tc.variant {
		case "SHA3-224":
			if got := sha3.Sum224(tc.msg); !bytes.Equal(got[:], tc.md) {
				t.Fatalf("Sum224 mismatch case %d", idx+1)
			}
		case "SHA3-256":
			if got := sha3.Sum256(tc.msg); !bytes.Equal(got[:], tc.md) {
				t.Fatalf("Sum256 mismatch case %d", idx+1)
			}
		case "SHA3-384":
			if got := sha3.Sum384(tc.msg); !bytes.Equal(got[:], tc.md) {
				t.Fatalf("Sum384 mismatch case %d", idx+1)
			}
		case "SHA3-512":
			if got := sha3.Sum512(tc.msg); !bytes.Equal(got[:], tc.md) {
				t.Fatalf("Sum512 mismatch case %d", idx+1)
			}
		}
	}
}
