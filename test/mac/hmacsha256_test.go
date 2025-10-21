package mac_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"cryptonite-go/mac/hmacsha256"
)

func TestHMACSHA256Sum(t *testing.T) {
	key := []byte("key material")
	msg := []byte("data to authenticate")
	expected := hmac.New(sha256.New, key)
	expected.Write(msg)
	want := expected.Sum(nil)

	got := hmacsha256.Sum(key, msg)
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("unexpected MAC\n got %x\nwant %x", got, want)
	}
}

func TestHMACSHA256Verify(t *testing.T) {
	key := []byte("another key")
	msg := []byte("payload")
	mac := hmacsha256.Sum(key, msg)
	if !hmacsha256.Verify(key, msg, mac) {
		t.Fatal("Verify returned false for valid MAC")
	}
	if hmacsha256.Verify(key, msg, mac[:len(mac)-1]) {
		t.Fatal("Verify accepted truncated MAC")
	}
	if hmacsha256.Verify(key, append([]byte(nil), msg...), append([]byte(nil), mac...)) != true {
		t.Fatal("Verify should succeed with separate buffers")
	}
	tampered := append([]byte(nil), mac...)
	tampered[0] ^= 0xff
	if hmacsha256.Verify(key, msg, tampered) {
		t.Fatal("Verify accepted tampered MAC")
	}
}
