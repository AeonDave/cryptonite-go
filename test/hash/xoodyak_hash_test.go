package xoodyak_test

import (
	"bytes"
	_ "embed"
	"strings"
	"testing"

	cryptohash "cryptonite-go/hash"
	"cryptonite-go/hash/xoodyak"
)

//go:embed testdata/xoodyak_hash_kat.txt
var xoodyakHashKAT string

type xoodyakHashCase struct {
	msg, md, xof []byte
}

func parseXoodyakHashKAT(t *testing.T) []xoodyakHashCase {
	lines := strings.Split(xoodyakHashKAT, "\n")
	var cases []xoodyakHashCase
	for i := 0; i < len(lines); {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			i++
			continue
		}
		if !strings.HasPrefix(line, "Count =") {
			t.Fatalf("unexpected format on line %d: %q", i+1, lines[i])
		}
		if i+3 >= len(lines) {
			t.Fatalf("incomplete block at line %d", i+1)
		}
		msgLine := strings.TrimSpace(lines[i+1])
		mdLine := strings.TrimSpace(lines[i+2])
		xofLine := strings.TrimSpace(lines[i+3])
		if !strings.HasPrefix(msgLine, "Msg =") || !strings.HasPrefix(mdLine, "MD =") || !strings.HasPrefix(xofLine, "XOF =") {
			t.Fatalf("unexpected block labels around line %d", i+1)
		}
		msg := mustHex(t, strings.TrimSpace(strings.TrimPrefix(msgLine, "Msg =")))
		md := mustHex(t, strings.TrimSpace(strings.TrimPrefix(mdLine, "MD =")))
		xof := mustHex(t, strings.TrimSpace(strings.TrimPrefix(xofLine, "XOF =")))
		cases = append(cases, xoodyakHashCase{msg: msg, md: md, xof: xof})
		i += 4
		if i < len(lines) && strings.TrimSpace(lines[i]) == "" {
			i++
		}
	}
	return cases
}

func TestXoodyak_Hash_XOF_KAT(t *testing.T) {
	cases := parseXoodyakHashKAT(t)
	if len(cases) == 0 {
		t.Fatal("no Xoodyak hash KAT cases parsed")
	}
	for idx, tc := range cases {
		// Hash
		h := xoodyak.New()
		if _, err := h.Write(tc.msg); err != nil {
			t.Fatalf("hash write failed case %d: %v", idx+1, err)
		}
		got := h.Sum(nil)
		if !bytes.Equal(got, tc.md) {
			t.Fatalf("hash mismatch case %d:\n got %x\nwant %x", idx+1, got, tc.md)
		}
		sum := xoodyak.Sum(tc.msg)
		if !bytes.Equal(sum[:], tc.md) {
			t.Fatalf("Sum mismatch case %d:\n got %x\nwant %x", idx+1, sum, tc.md)
		}
		streaming, ok := h.(cryptohash.Hasher)
		if !ok {
			t.Fatalf("xoodyak.Hash missing hash.Hasher implementation")
		}
		if streaming.Size() != len(tc.md) {
			t.Fatalf("streaming Size mismatch case %d", idx+1)
		}
		if got := streaming.Hash(tc.msg); !bytes.Equal(got, tc.md) {
			t.Fatalf("streaming Hash mismatch case %d", idx+1)
		}
		hasher := xoodyak.NewHasher()
		if hasher.Size() != len(tc.md) {
			t.Fatalf("Hasher size mismatch case %d", idx+1)
		}
		if got := hasher.Hash(tc.msg); !bytes.Equal(got, tc.md) {
			t.Fatalf("Hasher digest mismatch case %d", idx+1)
		}
		// XOF (64 bytes)
		x := xoodyak.NewXOF()
		if _, err := x.Write(tc.msg); err != nil {
			t.Fatalf("xof write failed case %d: %v", idx+1, err)
		}
		out := make([]byte, len(tc.xof))
		if n, err := x.Read(out); err != nil || n != len(out) {
			t.Fatalf("xof read failed case %d: n=%d err=%v", idx+1, n, err)
		}
		if !bytes.Equal(out, tc.xof) {
			t.Fatalf("xof mismatch case %d:\n got %x\nwant %x", idx+1, out, tc.xof)
		}
		// Multiple reads should continue the stream
		x2 := xoodyak.NewXOF()
		_, _ = x2.Write(tc.msg)
		outA := make([]byte, 32)
		outB := make([]byte, len(tc.xof)-32)
		_, _ = x2.Read(outA)
		_, _ = x2.Read(outB)
		if !bytes.Equal(append(outA, outB...), tc.xof) {
			t.Fatalf("xof split read mismatch case %d", idx+1)
		}
	}
}
