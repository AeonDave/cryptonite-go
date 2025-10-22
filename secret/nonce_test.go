package secret_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/AeonDave/cryptonite-go/secret"
)

func TestCounter96Sequence(t *testing.T) {
	initial := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	ctr, err := secret.NewCounter96(initial)
	if err != nil {
		t.Fatalf("NewCounter96 failed: %v", err)
	}
	first, err := ctr.Next()
	if err != nil {
		t.Fatalf("Next failed: %v", err)
	}
	if !bytes.Equal(first, initial) {
		t.Fatalf("unexpected first nonce %x", first)
	}
	second, err := ctr.Next()
	if err != nil {
		t.Fatalf("Next failed: %v", err)
	}
	expected := append([]byte{}, initial...)
	expected[len(expected)-1]++
	if !bytes.Equal(second, expected) {
		t.Fatalf("unexpected second nonce %x", second)
	}
	peek, err := ctr.Peek()
	if err != nil {
		t.Fatalf("Peek failed: %v", err)
	}
	third := append([]byte{}, expected...)
	third[len(third)-1]++
	if !bytes.Equal(peek, third) {
		t.Fatalf("peek mismatch: got %x want %x", peek, third)
	}
}

func TestCounter96Exhaustion(t *testing.T) {
	initial := bytes.Repeat([]byte{0xFF}, 12)
	ctr, err := secret.NewCounter96(initial)
	if err != nil {
		t.Fatalf("NewCounter96 failed: %v", err)
	}
	if _, err := ctr.Next(); err != nil {
		t.Fatalf("first Next failed: %v", err)
	}
	if _, err := ctr.Next(); !errors.Is(err, secret.ErrNonceExhausted) {
		t.Fatalf("expected exhaustion, got %v", err)
	}
}

func TestCounter192(t *testing.T) {
	initial := make([]byte, 24)
	initial[len(initial)-1] = 1
	ctr, err := secret.NewCounter192(initial)
	if err != nil {
		t.Fatalf("NewCounter192 failed: %v", err)
	}
	val, err := ctr.Next()
	if err != nil {
		t.Fatalf("Next failed: %v", err)
	}
	if !bytes.Equal(val, initial) {
		t.Fatalf("unexpected value: %x", val)
	}
	ctr.Destroy()
	if _, err := ctr.Next(); !errors.Is(err, secret.ErrNonceExhausted) {
		t.Fatalf("expected exhaustion after destroy, got %v", err)
	}
}
