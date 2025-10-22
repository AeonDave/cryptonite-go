package secret_test

import (
	"bytes"
	"testing"

	"github.com/AeonDave/cryptonite-go/secret"
)

func TestSymmetricKeyBasic(t *testing.T) {
	src := []byte{1, 2, 3, 4}
	key := secret.SymmetricKeyFrom(src)
	if key.Len() != len(src) {
		t.Fatalf("unexpected key length: got %d want %d", key.Len(), len(src))
	}
	src[0] = 0xFF
	dup, err := key.Bytes()
	if err != nil {
		t.Fatalf("Bytes failed: %v", err)
	}
	if !bytes.Equal(dup, []byte{1, 2, 3, 4}) {
		t.Fatalf("key copy mutated: %x", dup)
	}
	if err := key.Use(func(b []byte) error {
		if !bytes.Equal(b, []byte{1, 2, 3, 4}) {
			t.Fatalf("Use data mismatch: %x", b)
		}
		b[0] = 9
		return nil
	}); err != nil {
		t.Fatalf("Use failed: %v", err)
	}
	clone, _ := key.Bytes()
	if clone[0] != 9 {
		t.Fatalf("mutation via Use not reflected")
	}
	key.Destroy()
	if _, err := key.Bytes(); err == nil {
		t.Fatalf("expected error after Destroy")
	}
	if err := key.Use(func([]byte) error { return nil }); err == nil {
		t.Fatalf("expected Use error after Destroy")
	}
}

func TestNonceBasic(t *testing.T) {
	n := secret.NonceFrom([]byte{0xAA, 0xBB})
	if n.Len() != 2 {
		t.Fatalf("unexpected nonce length")
	}
	b, err := n.Bytes()
	if err != nil {
		t.Fatalf("Bytes failed: %v", err)
	}
	if !bytes.Equal(b, []byte{0xAA, 0xBB}) {
		t.Fatalf("unexpected nonce contents: %x", b)
	}
	if err := n.Use(func(buf []byte) error {
		buf[1] = 0
		return nil
	}); err != nil {
		t.Fatalf("Use failed: %v", err)
	}
	updated, _ := n.Bytes()
	if !bytes.Equal(updated, []byte{0xAA, 0}) {
		t.Fatalf("nonce mutation missing: %x", updated)
	}
	n.Destroy()
	if _, err := n.Bytes(); err == nil {
		t.Fatalf("expected error after Destroy")
	}
}

func TestWipeBytes(t *testing.T) {
	buf := []byte{1, 2, 3, 4}
	secret.WipeBytes(buf)
	if got := bytes.Count(buf, []byte{0}); got != len(buf) {
		t.Fatalf("wipe failed: %x", buf)
	}
}
