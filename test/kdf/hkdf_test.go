package kdf_test

import (
	"bytes"
	_ "embed"
	stdhash "hash"
	"strconv"
	"strings"
	"testing"

	cryptohash "cryptonite-go/hash"
	"cryptonite-go/kdf"
	testutil "cryptonite-go/test/internal/testutil"
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
			ikm:         testutil.MustHex(t, strings.ReplaceAll(ikm, " ", "")),
			salt:        testutil.MustHex(t, strings.ReplaceAll(salt, " ", "")),
			info:        testutil.MustHex(t, strings.ReplaceAll(info, " ", "")),
			prk:         testutil.MustHex(t, strings.ReplaceAll(prk, " ", "")),
			okm:         testutil.MustHex(t, strings.ReplaceAll(okm, " ", "")),
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

func TestHKDFInterface(t *testing.T) {
	deriver := kdf.NewHKDFSHA256()
	params := kdf.DeriveParams{
		Secret: []byte("secret"),
		Salt:   []byte("salt"),
		Info:   []byte("info"),
		Length: 42,
	}
	out, err := deriver.Derive(params)
	if err != nil {
		t.Fatalf("Derive failed: %v", err)
	}
	if len(out) != params.Length {
		t.Fatalf("unexpected output length: got %d want %d", len(out), params.Length)
	}
}

func TestHKDFGeneric(t *testing.T) {
	ikm := []byte("ikm")
	salt := []byte("salt")
	info := []byte("info")
	const outLen = 32

	okm, err := kdf.HKDF(newBlake2sHash, ikm, salt, info, outLen)
	if err != nil {
		t.Fatalf("HKDF returned error: %v", err)
	}
	if len(okm) != outLen {
		t.Fatalf("unexpected length: got %d", len(okm))
	}

	deriver := kdf.NewHKDF(newBlake2sHash)
	params := kdf.DeriveParams{Secret: ikm, Salt: salt, Info: info, Length: outLen}
	viaDeriver, err := deriver.Derive(params)
	if err != nil {
		t.Fatalf("Derive failed: %v", err)
	}
	if !bytes.Equal(okm, viaDeriver) {
		t.Fatalf("Derive output mismatch")
	}
}

func TestHKDFBlake2b(t *testing.T) {
	ikm := []byte("BLAKE2b IKM")
	salt := []byte("BLAKE2b salt")
	info := []byte("ctx")
	const outLen = 64

	okm1, err := kdf.HKDFBlake2b(ikm, salt, info, outLen)
	if err != nil {
		t.Fatalf("HKDFBlake2b failed: %v", err)
	}
	okm2, err := kdf.HKDF(newBlake2bHash, ikm, salt, info, outLen)
	if err != nil {
		t.Fatalf("HKDF generic failed: %v", err)
	}
	if !bytes.Equal(okm1, okm2) {
		t.Fatalf("HKDFBlake2b mismatch")
	}

	prk := kdf.HKDFExtractWith(newBlake2bHash, salt, ikm)
	expanded, err := kdf.HKDFExpandWith(newBlake2bHash, prk, info, outLen)
	if err != nil {
		t.Fatalf("HKDFExpandWith failed: %v", err)
	}
	if !bytes.Equal(expanded, okm1) {
		t.Fatalf("HKDFExpandWith mismatch")
	}

	deriver := kdf.NewHKDFBlake2b()
	params := kdf.DeriveParams{Secret: ikm, Salt: salt, Info: info, Length: outLen}
	viaDeriver, err := deriver.Derive(params)
	if err != nil {
		t.Fatalf("HKDFBlake2b deriver failed: %v", err)
	}
	if !bytes.Equal(viaDeriver, okm1) {
		t.Fatalf("HKDFBlake2b deriver mismatch")
	}
}

func TestHKDFGenericMaxLength(t *testing.T) {
	_, err := kdf.HKDF(newBlake2sHash, []byte("ikm"), []byte("salt"), nil, 255*32+1)
	if err == nil {
		t.Fatalf("expected HKDF length error")
	}
}

func newBlake2bHash() stdhash.Hash {
	h, err := cryptohash.NewBlake2b(64, nil)
	if err != nil {
		panic(err)
	}
	return h
}

func newBlake2sHash() stdhash.Hash {
	h, err := cryptohash.NewBlake2s(32, nil)
	if err != nil {
		panic(err)
	}
	return h
}
