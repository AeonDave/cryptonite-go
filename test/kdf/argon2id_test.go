package kdf_test

import (
	"bytes"
	_ "embed"
	"strconv"
	"strings"
	"testing"

	"github.com/AeonDave/cryptonite-go/kdf"
	testutil "github.com/AeonDave/cryptonite-go/test/internal/testutil"
)

//go:embed testdata/argon2id_kat.txt
var argon2idKAT string

type argon2idCase struct {
	time, memory, threads uint32
	password, salt        []byte
	expected              []byte
}

func parseArgon2idKAT(t *testing.T) []argon2idCase {
	t.Helper()
	lines := strings.Split(argon2idKAT, "\n")
	var cases []argon2idCase
	for i := 0; i < len(lines); {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "#") {
			i++
			continue
		}
		if !strings.HasPrefix(line, "Time =") {
			t.Fatalf("argon2id kat: unexpected line %d: %q", i+1, lines[i])
		}
		timeVal := mustUint32(t, strings.TrimSpace(strings.TrimPrefix(line, "Time =")))
		if i+5 >= len(lines) {
			t.Fatalf("argon2id kat: incomplete record starting at line %d", i+1)
		}
		memoryLine := strings.TrimSpace(lines[i+1])
		threadsLine := strings.TrimSpace(lines[i+2])
		passwordLine := strings.TrimSpace(lines[i+3])
		saltLine := strings.TrimSpace(lines[i+4])
		hashLine := strings.TrimSpace(lines[i+5])

		if !strings.HasPrefix(memoryLine, "MemoryKiB =") || !strings.HasPrefix(threadsLine, "Threads =") ||
			!strings.HasPrefix(passwordLine, "Password =") || !strings.HasPrefix(saltLine, "Salt =") ||
			!strings.HasPrefix(hashLine, "Hash =") {
			t.Fatalf("argon2id kat: malformed record around line %d", i+2)
		}

		memory := mustUint32(t, strings.TrimSpace(strings.TrimPrefix(memoryLine, "MemoryKiB =")))
		threads := mustUint32(t, strings.TrimSpace(strings.TrimPrefix(threadsLine, "Threads =")))
		password := decodeHex(t, strings.TrimSpace(strings.TrimPrefix(passwordLine, "Password =")))
		salt := decodeHex(t, strings.TrimSpace(strings.TrimPrefix(saltLine, "Salt =")))
		hash := decodeHex(t, strings.TrimSpace(strings.TrimPrefix(hashLine, "Hash =")))

		cases = append(cases, argon2idCase{
			time:     timeVal,
			memory:   memory,
			threads:  threads,
			password: password,
			salt:     salt,
			expected: hash,
		})
		i += 6
	}
	return cases
}

func mustUint32(t *testing.T, s string) uint32 {
	t.Helper()
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		t.Fatalf("failed parsing %q as uint32: %v", s, err)
	}
	return uint32(v)
}

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	return testutil.MustHex(t, strings.ReplaceAll(s, " ", ""))
}

func TestArgon2idKnownAnswers(t *testing.T) {
	cases := parseArgon2idKAT(t)
	for _, tc := range cases {
		got, err := kdf.Argon2id(tc.password, tc.salt, tc.time, tc.memory, tc.threads, len(tc.expected))
		if err != nil {
			t.Fatalf("Argon2id returned error: %v", err)
		}
		if !bytes.Equal(got, tc.expected) {
			t.Fatalf("Argon2id mismatch for time=%d memory=%d threads=%d\n got %x\nwant %x",
				tc.time, tc.memory, tc.threads, got, tc.expected)
		}

		deriver := kdf.NewArgon2idWithParams(tc.time, tc.memory, tc.threads)
		viaDeriver, err := deriver.Derive(kdf.DeriveParams{
			Secret: tc.password,
			Salt:   tc.salt,
			Length: len(tc.expected),
		})
		if err != nil {
			t.Fatalf("Deriver returned error: %v", err)
		}
		if !bytes.Equal(viaDeriver, tc.expected) {
			t.Fatalf("Deriver mismatch for time=%d memory=%d threads=%d", tc.time, tc.memory, tc.threads)
		}
	}
}

func TestArgon2idValidation(t *testing.T) {
	deriver := kdf.NewArgon2id()

	if _, err := deriver.Derive(kdf.DeriveParams{Salt: []byte("12345678"), Length: 16}); err == nil {
		t.Fatal("expected error for missing secret")
	}
	if _, err := deriver.Derive(kdf.DeriveParams{Secret: []byte("pwd"), Salt: []byte("short"), Length: 16}); err == nil {
		t.Fatal("expected error for short salt")
	}
	if _, err := deriver.Derive(kdf.DeriveParams{Secret: []byte("pwd"), Salt: []byte("adequatesalt"), Length: 0}); err == nil {
		t.Fatal("expected error for zero length")
	}
}
