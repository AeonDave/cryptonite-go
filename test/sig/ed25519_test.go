package sig_test

import (
	"bytes"
	ed "cryptonite-go/sig"
	"encoding/hex"
	"testing"
)

func decodeHex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("failed to decode hex %q: %v", s, err)
	}
	return b
}

func TestEd25519RFC8032Vector(t *testing.T) {
	seed := decodeHex(t, "9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60")
	pubExp := decodeHex(t, "D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A")
	sigExp := decodeHex(t, "E5564300C360AC729086E2CC806E828A84877F1EB8E5D974D873E065224901555FB8821590A33BACC61E39701CF9B46BD25BF5F0595BBE24655141438E7A100B")
	msg := []byte{}

	pub, priv, err := ed.FromSeed(seed)
	if err != nil {
		t.Fatalf("FromSeed failed: %v", err)
	}
	if !bytes.Equal(pub, pubExp) {
		t.Fatalf("public key mismatch\n got %x\nwant %x", pub, pubExp)
	}

	sig := ed.Sign(priv, msg)
	if !bytes.Equal(sig, sigExp) {
		t.Fatalf("signature mismatch\n got %x\nwant %x", sig, sigExp)
	}
	if !ed.Verify(pub, msg, sig) {
		t.Fatalf("verification failed for valid signature")
	}
	if ed.Verify(pub, []byte{0x01}, sig) {
		t.Fatalf("verification succeeded on tampered message")
	}
}

func TestEd25519GenerateKey(t *testing.T) {
	pub, priv, err := ed.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	msg := []byte("hello")
	sig := ed.Sign(priv, msg)
	if !ed.Verify(pub, msg, sig) {
		t.Fatalf("generated key verify failed")
	}
}
