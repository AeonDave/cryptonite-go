package hash

import (
	"bytes"
	"testing"

	"github.com/AeonDave/cryptonite-go/internal/blake2b"
	"github.com/AeonDave/cryptonite-go/internal/blake2s"
)

func TestNewBlake2bHasherRejectsOversizedKey(t *testing.T) {
	oversized := bytes.Repeat([]byte{0x42}, blake2b.Size+1)

	if _, err := NewBlake2bHasher(blake2b.Size, oversized); err == nil {
		t.Fatalf("expected error for oversized key")
	}
}

func TestNewBlake2sHasherRejectsOversizedKey(t *testing.T) {
	oversized := bytes.Repeat([]byte{0x42}, blake2s.Size+1)

	if _, err := NewBlake2sHasher(blake2s.Size, oversized); err == nil {
		t.Fatalf("expected error for oversized key")
	}
}
