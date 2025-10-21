package testutil

import (
	"encoding/hex"
	"testing"
)

// MustHex decodes the hexadecimal string s or fails the test immediately.
//
// It accepts testing.TB to support both *testing.T and *testing.B callers
// without forcing packages to duplicate helper shims.
func MustHex(t testing.TB, s string) []byte {
	t.Helper()
	if s == "" {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("failed to decode %q: %v", s, err)
	}
	return b
}

// OptionalHex decodes the pointed-to string if present, otherwise returning nil.
func OptionalHex(t testing.TB, s *string) []byte {
	if s == nil {
		return nil
	}
	return MustHex(t, *s)
}
