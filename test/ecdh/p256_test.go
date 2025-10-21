package ecdh_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"cryptonite-go/ecdh/p256"
)

func mustDecodeHex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("failed to decode hex %q: %v", s, err)
	}
	return b
}

func TestP256KnownVector(t *testing.T) {
	privBytes := mustDecodeHex(t, "7D7DC5F71EB29DDAF80D6214632EEAE03D9058AF1FB6D22ED80BADB62BC1A534")
	pubBytes := mustDecodeHex(t, "04EAD218590119E8876B29146FF89CA61770C4EDBBF97D38CE385ED281D8A6B23028AF61281FD35E2FA7002523ACC85A429CB06EE6648325389F59EDFCE1405141")
	peerBytes := mustDecodeHex(t, "04700C48F77F56584C5CC632CA65640DB91B6BACCE3A4DF6B42CE7CC838833D287DB71E509E3FD9B060DDB20BA5C51DCC5948D46FBF640DFE0441782CAB85FA4AC")
	secretExp := mustDecodeHex(t, "46FC62106420FF012E54A434FBDD2D25CCC5852060561E68040DD7778997BD7B")

	priv, err := p256.NewPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("NewPrivateKey failed: %v", err)
	}
	if got := priv.PublicKey().Bytes(); !bytes.Equal(got, pubBytes) {
		t.Fatalf("public key mismatch\n got %X\nwant %X", got, pubBytes)
	}
	peer, err := p256.NewPublicKey(peerBytes)
	if err != nil {
		t.Fatalf("NewPublicKey failed: %v", err)
	}
	secret, err := p256.SharedSecret(priv, peer)
	if err != nil {
		t.Fatalf("SharedSecret failed: %v", err)
	}
	if !bytes.Equal(secret, secretExp) {
		t.Fatalf("shared secret mismatch\n got %X\nwant %X", secret, secretExp)
	}
}

func TestP256GenerateKey(t *testing.T) {
	privA, err := p256.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey A failed: %v", err)
	}
	privB, err := p256.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey B failed: %v", err)
	}
	secretA, err := p256.SharedSecret(privA, privB.PublicKey())
	if err != nil {
		t.Fatalf("SharedSecret A failed: %v", err)
	}
	secretB, err := p256.SharedSecret(privB, privA.PublicKey())
	if err != nil {
		t.Fatalf("SharedSecret B failed: %v", err)
	}
	if !bytes.Equal(secretA, secretB) {
		t.Fatalf("generated shared secrets differ")
	}
}
