package sig_test

import (
	"bytes"
	sig "cryptonite-go/sig"
	xsig "cryptonite-go/sig/x25519"
	"cryptonite-go/test/internal/testutil"
	"testing"
)

func TestX25519RFC8032Vector(t *testing.T) {
	seed := testutil.MustHex(t, "9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60")
	pubExp := testutil.MustHex(t, "D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A")
	sigExp := testutil.MustHex(t, "E5564300C360AC729086E2CC806E828A84877F1EB8E5D974D873E065224901555FB8821590A33BACC61E39701CF9B46BD25BF5F0595BBE24655141438E7A100B")
	msg := []byte{}

	pub, priv, err := xsig.FromSeed(seed)
	if err != nil {
		t.Fatalf("FromSeed failed: %v", err)
	}
	if !bytes.Equal(pub, pubExp) {
		t.Fatalf("public key mismatch\n got %x\nwant %x", pub, pubExp)
	}

	sigBytes := xsig.Sign(priv, msg)
	if !bytes.Equal(sigBytes, sigExp) {
		t.Fatalf("signature mismatch\n got %x\nwant %x", sigBytes, sigExp)
	}
	if !xsig.Verify(pub, msg, sigBytes) {
		t.Fatalf("verification failed for valid signature")
	}
	if xsig.Verify(pub, []byte{0x01}, sigBytes) {
		t.Fatalf("verification succeeded on tampered message")
	}
}

func TestX25519GenerateKey(t *testing.T) {
	pub, priv, err := xsig.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	msg := []byte("hello")
	sigBytes := sig.Sign(priv, msg)
	if !sig.Verify(pub, msg, sigBytes) {
		t.Fatalf("generated key verify failed")
	}
}

func TestSigPackageAliases(t *testing.T) {
	pub, priv, err := sig.GenerateKey()
	if err != nil {
		t.Fatalf("sig.GenerateKey failed: %v", err)
	}
	if len(pub) != sig.PublicKeySize || len(priv) != sig.PrivateKeySize {
		t.Fatalf("unexpected key sizes")
	}
	msg := []byte("alias")
	sigBytes := sig.Sign(priv, msg)
	if !sig.Verify(pub, msg, sigBytes) {
		t.Fatalf("sig package alias verify failed")
	}
	if _, _, err := sig.FromSeed(make([]byte, sig.SeedSize+1)); err == nil {
		t.Fatalf("expected FromSeed to reject invalid length")
	}
}

func TestEd25519SchemeInterface(t *testing.T) {
	scheme := sig.NewEd25519()
	pub, priv, err := scheme.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	msg := []byte("interface")
	signature, err := scheme.Sign(priv, msg)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if !scheme.Verify(pub, msg, signature) {
		t.Fatalf("Verify failed for valid signature")
	}
	if scheme.Verify(pub, []byte("tamper"), signature) {
		t.Fatalf("Verify succeeded for tampered message")
	}
}
