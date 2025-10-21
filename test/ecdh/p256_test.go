package ecdh_test

import (
	"bytes"
	p256 "github.com/AeonDave/cryptonite-go/ecdh"
	"github.com/AeonDave/cryptonite-go/test/internal/testutil"
	"testing"
)

func TestP256KnownVector(t *testing.T) {
	privBytes := testutil.MustHex(t, "7D7DC5F71EB29DDAF80D6214632EEAE03D9058AF1FB6D22ED80BADB62BC1A534")
	pubBytes := testutil.MustHex(t, "04EAD218590119E8876B29146FF89CA61770C4EDBBF97D38CE385ED281D8A6B23028AF61281FD35E2FA7002523ACC85A429CB06EE6648325389F59EDFCE1405141")
	peerBytes := testutil.MustHex(t, "04700C48F77F56584C5CC632CA65640DB91B6BACCE3A4DF6B42CE7CC838833D287DB71E509E3FD9B060DDB20BA5C51DCC5948D46FBF640DFE0441782CAB85FA4AC")
	secretExp := testutil.MustHex(t, "46FC62106420FF012E54A434FBDD2D25CCC5852060561E68040DD7778997BD7B")

	priv, err := p256.NewPrivateKeyP256(privBytes)
	if err != nil {
		t.Fatalf("NewPrivateKey failed: %v", err)
	}
	if got := priv.PublicKey().Bytes(); !bytes.Equal(got, pubBytes) {
		t.Fatalf("public key mismatch\n got %X\nwant %X", got, pubBytes)
	}
	peer, err := p256.NewPublicKeyP256(peerBytes)
	if err != nil {
		t.Fatalf("NewPublicKey failed: %v", err)
	}
	secret, err := p256.SharedSecretP256(priv, peer)
	if err != nil {
		t.Fatalf("SharedSecret failed: %v", err)
	}
	if !bytes.Equal(secret, secretExp) {
		t.Fatalf("shared secret mismatch\n got %X\nwant %X", secret, secretExp)
	}
}

func TestP256GenerateKey(t *testing.T) {
	privA, err := p256.GenerateKeyP256()
	if err != nil {
		t.Fatalf("GenerateKeyP256 A failed: %v", err)
	}
	privB, err := p256.GenerateKeyP256()
	if err != nil {
		t.Fatalf("GenerateKeyP256 B failed: %v", err)
	}
	secretA, err := p256.SharedSecretP256(privA, privB.PublicKey())
	if err != nil {
		t.Fatalf("SharedSecret A failed: %v", err)
	}
	secretB, err := p256.SharedSecretP256(privB, privA.PublicKey())
	if err != nil {
		t.Fatalf("SharedSecret B failed: %v", err)
	}
	if !bytes.Equal(secretA, secretB) {
		t.Fatalf("generated shared secrets differ")
	}
}

func TestP256Interface(t *testing.T) {
	ke := p256.NewP256()
	priv, err := ke.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey via interface failed: %v", err)
	}
	peer, err := ke.GenerateKey()
	if err != nil {
		t.Fatalf("peer GenerateKey failed: %v", err)
	}
	secretA, err := ke.SharedSecret(priv, peer.PublicKey())
	if err != nil {
		t.Fatalf("SharedSecret failed: %v", err)
	}
	secretB, err := ke.SharedSecret(peer, priv.PublicKey())
	if err != nil {
		t.Fatalf("SharedSecret peer failed: %v", err)
	}
	if !bytes.Equal(secretA, secretB) {
		t.Fatalf("shared secrets via interface mismatch")
	}
}
