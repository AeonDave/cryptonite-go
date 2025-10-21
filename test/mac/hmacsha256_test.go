package mac_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"cryptonite-go/mac"
	"encoding/hex"
	"testing"
)

func TestHMACSHA256Sum(t *testing.T) {
	key := []byte("key material")
	msg := []byte("data to authenticate")
	expected := hmac.New(sha256.New, key)
	expected.Write(msg)
	want := expected.Sum(nil)

	got := mac.Sum(key, msg)
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("unexpected MAC\n got %x\nwant %x", got, want)
	}
}

func TestHMACSHA256Verify(t *testing.T) {
	key := []byte("another key")
	msg := []byte("payload")
	tag := mac.Sum(key, msg)
	if !mac.Verify(key, msg, tag) {
		t.Fatal("Verify returned false for valid MAC")
	}
	if mac.Verify(key, msg, tag[:len(tag)-1]) {
		t.Fatal("Verify accepted truncated MAC")
	}
	if mac.Verify(key, append([]byte(nil), msg...), append([]byte(nil), tag...)) != true {
		t.Fatal("Verify should succeed with separate buffers")
	}
	tampered := append([]byte(nil), tag...)
	tampered[0] ^= 0xff
	if mac.Verify(key, msg, tampered) {
		t.Fatal("Verify accepted tampered MAC")
	}
}
