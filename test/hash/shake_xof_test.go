package xoodyak_test

import (
	"bytes"
	"cryptonite-go/hash"
	_ "embed"
	"strconv"
	"strings"
	"testing"
)

//go:embed testdata/shake_kat.txt
var shakeKAT string

type shakeCase struct {
	variant string
	msg     []byte
	outLen  int
	xof     []byte
}

func parseSHAKEKAT(t *testing.T) []shakeCase {
	t.Helper()
	lines := strings.Split(shakeKAT, "\n")
	var cases []shakeCase
	for i := 0; i < len(lines); {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			i++
			continue
		}
		if !strings.HasPrefix(line, "Variant =") {
			t.Fatalf("unexpected label at line %d: %q", i+1, lines[i])
		}
		variant := strings.TrimSpace(strings.TrimPrefix(line, "Variant ="))
		if i+3 >= len(lines) {
			t.Fatalf("incomplete block at line %d", i+1)
		}
		msgLine := strings.TrimSpace(lines[i+1])
		lenLine := strings.TrimSpace(lines[i+2])
		xofLine := strings.TrimSpace(lines[i+3])
		if !strings.HasPrefix(msgLine, "Msg =") || !strings.HasPrefix(lenLine, "Len =") || !strings.HasPrefix(xofLine, "XOF =") {
			t.Fatalf("unexpected block structure near line %d", i+1)
		}
		msgHex := strings.TrimSpace(strings.TrimPrefix(msgLine, "Msg ="))
		msg := mustHex(t, msgHex)
		bitLenStr := strings.TrimSpace(strings.TrimPrefix(lenLine, "Len ="))
		bitLen, err := strconv.Atoi(bitLenStr)
		if err != nil {
			t.Fatalf("invalid length %q: %v", bitLenStr, err)
		}
		if bitLen%8 != 0 {
			t.Fatalf("non-byte-aligned length %d", bitLen)
		}
		xofHex := strings.TrimSpace(strings.TrimPrefix(xofLine, "XOF ="))
		xof := mustHex(t, xofHex)
		cases = append(cases, shakeCase{variant: variant, msg: msg, outLen: bitLen / 8, xof: xof})
		i += 4
		if i < len(lines) && strings.TrimSpace(lines[i]) == "" {
			i++
		}
	}
	return cases
}

func TestSHAKEXOF(t *testing.T) {
	cases := parseSHAKEKAT(t)
	if len(cases) == 0 {
		t.Fatal("no SHAKE cases parsed")
	}
	constructors := map[string]func() *hash.XOF{
		"SHAKE128": hash.NewSHAKE128,
		"SHAKE256": hash.NewSHAKE256,
	}
	for idx, tc := range cases {
		newXOF, ok := constructors[tc.variant]
		if !ok {
			t.Fatalf("unknown variant %q", tc.variant)
		}
		x := newXOF()
		if _, err := x.Write(tc.msg); err != nil {
			t.Fatalf("write failed case %d: %v", idx+1, err)
		}
		out := make([]byte, tc.outLen)
		if n, err := x.Read(out); err != nil || n != len(out) {
			t.Fatalf("read failed case %d: n=%d err=%v", idx+1, n, err)
		}
		if !bytes.Equal(out, tc.xof) {
			t.Fatalf("xof mismatch case %d (%s)", idx+1, tc.variant)
		}

		// Multi-read behaviour
		x2 := newXOF()
		_, _ = x2.Write(tc.msg)
		first := make([]byte, len(out)/2)
		second := make([]byte, len(out)-len(first))
		_, _ = x2.Read(first)
		_, _ = x2.Read(second)
		if !bytes.Equal(append(first, second...), tc.xof) {
			t.Fatalf("xof split mismatch case %d (%s)", idx+1, tc.variant)
		}

		// Reset should allow reuse.
		x.Reset()
		if _, err := x.Write(tc.msg); err != nil {
			t.Fatalf("write after reset failed case %d: %v", idx+1, err)
		}
		out2 := make([]byte, tc.outLen)
		_, _ = x.Read(out2)
		if !bytes.Equal(out2, tc.xof) {
			t.Fatalf("xof mismatch after reset case %d (%s)", idx+1, tc.variant)
		}
	}
}
