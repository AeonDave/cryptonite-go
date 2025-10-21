package kdf_test

import (
	"bytes"
	_ "embed"
	"strconv"
	"strings"
	"testing"

	"cryptonite-go/kdf"
)

//go:embed testdata/hkdf_sha256_kat.txt
var hkdfVectors string

type hkdfCase struct {
	count       int
	ikm, salt   []byte
	info        []byte
	prk, okm    []byte
	lengthBytes int
}

func parseHKDF(t *testing.T) []hkdfCase {
	t.Helper()
	lines := strings.Split(hkdfVectors, "\n")
	var cases []hkdfCase
	for i := 0; i < len(lines); {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			i++
			continue
		}
		if !strings.HasPrefix(line, "Count =") {
			t.Fatalf("unexpected line %d: %q", i+1, lines[i])
		}
		num, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "Count =")))
		if err != nil {
			t.Fatalf("bad count on line %d: %v", i+1, err)
		}
		if i+5 >= len(lines) {
			t.Fatalf("incomplete block starting at line %d", i+1)
		}
		ikm := strings.TrimSpace(strings.TrimPrefix(lines[i+1], "IKM ="))
		salt := strings.TrimSpace(strings.TrimPrefix(lines[i+2], "Salt ="))
		info := strings.TrimSpace(strings.TrimPrefix(lines[i+3], "Info ="))
		lStr := strings.TrimSpace(strings.TrimPrefix(lines[i+4], "L ="))
		prk := strings.TrimSpace(strings.TrimPrefix(lines[i+5], "PRK ="))
		okm := strings.TrimSpace(strings.TrimPrefix(lines[i+6], "OKM ="))
		length, err := strconv.Atoi(lStr)
		if err != nil {
			t.Fatalf("invalid length on line %d: %v", i+5, err)
		}
		cases = append(cases, hkdfCase{
			count:       num,
			ikm:         mustHex(t, strings.ReplaceAll(ikm, " ", "")),
			salt:        mustHex(t, strings.ReplaceAll(salt, " ", "")),
			info:        mustHex(t, strings.ReplaceAll(info, " ", "")),
			prk:         mustHex(t, strings.ReplaceAll(prk, " ", "")),
			okm:         mustHex(t, strings.ReplaceAll(okm, " ", "")),
			lengthBytes: length,
		})
		i += 7
	}
	return cases
}

func TestHKDFSHA256_KAT(t *testing.T) {
	cases := parseHKDF(t)
	for _, tc := range cases {
		prk := kdf.HKDFSHA256Extract(tc.salt, tc.ikm)
		if !bytes.Equal(prk, tc.prk) {
			t.Fatalf("count %d: extract mismatch", tc.count)
		}
		okm, err := kdf.HKDFSHA256(tc.ikm, tc.salt, tc.info, tc.lengthBytes)
		if err != nil {
			t.Fatalf("count %d: hkdf failed: %v", tc.count, err)
		}
		if !bytes.Equal(okm, tc.okm) {
			t.Fatalf("count %d: okm mismatch", tc.count)
		}
		expanded, err := kdf.HKDFSHA256Expand(prk, tc.info, tc.lengthBytes)
		if err != nil {
			t.Fatalf("count %d: expand failed: %v", tc.count, err)
		}
		if !bytes.Equal(expanded, tc.okm) {
			t.Fatalf("count %d: expand result mismatch", tc.count)
		}
	}
}
