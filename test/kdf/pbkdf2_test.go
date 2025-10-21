package kdf_test

import (
	"bytes"
	_ "embed"
	"strconv"
	"strings"
	"testing"

	"cryptonite-go/kdf"
)

//go:embed testdata/pbkdf2_kat.txt
var pbkdf2Vectors string

type pbkdf2Case struct {
	count                  int
	algo                   string
	password, salt, expect []byte
	iterations             int
	dkLen                  int
}

func parsePBKDF2(t *testing.T) []pbkdf2Case {
	t.Helper()
	lines := strings.Split(pbkdf2Vectors, "\n")
	var cases []pbkdf2Case
	for i := 0; i < len(lines); {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			i++
			continue
		}
		if !strings.HasPrefix(line, "Count =") {
			t.Fatalf("unexpected line %d: %q", i+1, lines[i])
		}
		count, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "Count =")))
		if err != nil {
			t.Fatalf("invalid count on line %d: %v", i+1, err)
		}
		if i+5 >= len(lines) {
			t.Fatalf("incomplete block at line %d", i+1)
		}
		algo := strings.TrimSpace(strings.TrimPrefix(lines[i+1], "Algo ="))
		password := strings.TrimSpace(strings.TrimPrefix(lines[i+2], "Password ="))
		salt := strings.TrimSpace(strings.TrimPrefix(lines[i+3], "Salt ="))
		iterStr := strings.TrimSpace(strings.TrimPrefix(lines[i+4], "Iterations ="))
		dkLenStr := strings.TrimSpace(strings.TrimPrefix(lines[i+5], "DKLen ="))
		dk := strings.TrimSpace(strings.TrimPrefix(lines[i+6], "DK ="))
		iters, err := strconv.Atoi(iterStr)
		if err != nil {
			t.Fatalf("invalid iterations on line %d: %v", i+5, err)
		}
		dkLen, err := strconv.Atoi(dkLenStr)
		if err != nil {
			t.Fatalf("invalid dkLen on line %d: %v", i+6, err)
		}
		cases = append(cases, pbkdf2Case{
			count:      count,
			algo:       strings.ToUpper(algo),
			password:   mustHex(t, password),
			salt:       mustHex(t, salt),
			iterations: iters,
			dkLen:      dkLen,
			expect:     mustHex(t, strings.ReplaceAll(dk, " ", "")),
		})
		i += 7
	}
	return cases
}

func TestPBKDF2_KAT(t *testing.T) {
	cases := parsePBKDF2(t)
	for _, tc := range cases {
		var (
			dk  []byte
			err error
		)
		switch tc.algo {
		case "SHA1":
			dk, err = kdf.PBKDF2SHA1(tc.password, tc.salt, tc.iterations, tc.dkLen)
		case "SHA256":
			dk, err = kdf.PBKDF2SHA256(tc.password, tc.salt, tc.iterations, tc.dkLen)
		default:
			t.Fatalf("count %d: unsupported algo %q", tc.count, tc.algo)
		}
		if err != nil {
			t.Fatalf("count %d: pbkdf2 returned error: %v", tc.count, err)
		}
		if !bytes.Equal(dk, tc.expect) {
			t.Fatalf("count %d: derived key mismatch", tc.count)
		}
	}
}
