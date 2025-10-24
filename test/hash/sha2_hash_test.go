package xoodyak_test

import (
	"bytes"
	_ "embed"
	stdhash "hash"
	"strings"
	"testing"

	cryptohash "github.com/AeonDave/cryptonite-go/hash"
	testutil "github.com/AeonDave/cryptonite-go/test/internal/testutil"
)

//go:embed testdata/sha2_kat.txt
var sha2KAT string

type sha2Case struct {
	variant string
	msg     []byte
	md      []byte
}

func parseSHA2KAT(t *testing.T) []sha2Case {
	t.Helper()
	lines := strings.Split(sha2KAT, "\n")
	var cases []sha2Case
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
		msg := testutil.MustHex(t, msgHex)
		md := testutil.MustHex(t, mdHex)
		cases = append(cases, sha2Case{variant: variant, msg: msg, md: md})
		i += 3
		if i < len(lines) && strings.TrimSpace(lines[i]) == "" {
			i++
		}
	}
	return cases
}

func TestSHA2KAT(t *testing.T) {
	cases := parseSHA2KAT(t)
	if len(cases) == 0 {
		t.Fatal("no SHA-2 cases parsed")
	}
	constructors := map[string]func() stdhash.Hash{
		"SHA-224": cryptohash.NewSHA224,
		"SHA-256": cryptohash.NewSHA256,
		"SHA-384": cryptohash.NewSHA384,
		"SHA-512": cryptohash.NewSHA512,
	}
	stateless := map[string]func() cryptohash.Hasher{
		"SHA-224": cryptohash.NewSHA224Hasher,
		"SHA-256": cryptohash.NewSHA256Hasher,
		"SHA-384": cryptohash.NewSHA384Hasher,
		"SHA-512": cryptohash.NewSHA512Hasher,
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
		case "SHA-224":
			if got := cryptohash.SumSHA224(tc.msg); !bytes.Equal(got[:], tc.md) {
				t.Fatalf("SumSHA224 mismatch case %d", idx+1)
			}
		case "SHA-256":
			if got := cryptohash.SumSHA256(tc.msg); !bytes.Equal(got[:], tc.md) {
				t.Fatalf("SumSHA256 mismatch case %d", idx+1)
			}
		case "SHA-384":
			if got := cryptohash.SumSHA384(tc.msg); !bytes.Equal(got[:], tc.md) {
				t.Fatalf("SumSHA384 mismatch case %d", idx+1)
			}
		case "SHA-512":
			if got := cryptohash.SumSHA512(tc.msg); !bytes.Equal(got[:], tc.md) {
				t.Fatalf("SumSHA512 mismatch case %d", idx+1)
			}
		}

		streaming, ok := h.(cryptohash.Hasher)
		if !ok {
			t.Fatalf("streaming digest missing hash.Hasher for %s", tc.variant)
		}
		if streaming.Size() != len(tc.md) {
			t.Fatalf("streaming Size mismatch for %s", tc.variant)
		}
		if got := streaming.Hash(tc.msg); !bytes.Equal(got, tc.md) {
			t.Fatalf("streaming Hash mismatch case %d (%s)", idx+1, tc.variant)
		}

		statelessNew, ok := stateless[tc.variant]
		if !ok {
			t.Fatalf("missing stateless constructor for %s", tc.variant)
		}
		s := statelessNew()
		if s.Size() != len(tc.md) {
			t.Fatalf("Size mismatch for %s", tc.variant)
		}
		if got := s.Hash(tc.msg); !bytes.Equal(got, tc.md) {
			t.Fatalf("Hasher mismatch case %d (%s)", idx+1, tc.variant)
		}
	}
}
