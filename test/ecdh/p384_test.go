package ecdh_test

import (
	"bytes"
	p384 "github.com/AeonDave/cryptonite-go/ecdh"
	"github.com/AeonDave/cryptonite-go/test/internal/testutil"
	"testing"
)

func TestP384KnownVector(t *testing.T) {
	privBytes := testutil.MustHex(t, "6B9D5D9A5A5AA5ADAF676905FA5C14C3D30C232D0BAF7DFFF9F6C52FCECDB24970FF9F4A26A95E5A9DF0C6068F36B5A8")
	pubBytes := testutil.MustHex(t, "04A5C400DC867CAF6B6A4C4151DEEA5FFF54CCCA0E2C59E1BBCDEB84886431D779BABEAF9660EFF49B023CBB935A2DE847B351598E1F14E217361BB42A87E4FEC5F9655EF721213BE59AAB1D3D9D999ABA534C4DAFDAE7FD62AD8E49FBBA02257F")
	peerBytes := testutil.MustHex(t, "04645E4ABDA6C153BC4D5F3DE0C2B1885CCAC80D1047E134C8760B229486CCCFA7331B30AE57D9308D14C37A36754D5E13E6F9F397199E433A7F161E0886F8FC9B5BBC698FD133628B503466AAA57D4795E03546861F76E33704C73C58CCE0C65A")
	secretExp := testutil.MustHex(t, "84899D3E0A01D2BA5AD458C240C89FADC0F85C2C32A15FAF1D325C6132AC7B2B42D31F1D5C6D4619C9C17A7C5D62B243")

	priv, err := p384.NewPrivateKeyP384(privBytes)
	if err != nil {
		t.Fatalf("NewPrivateKey failed: %v", err)
	}
	if got := priv.PublicKey().Bytes(); !bytes.Equal(got, pubBytes) {
		t.Fatalf("public key mismatch\n got %X\nwant %X", got, pubBytes)
	}
	peer, err := p384.NewPublicKeyP384(peerBytes)
	if err != nil {
		t.Fatalf("NewPublicKey failed: %v", err)
	}
	secret, err := p384.SharedSecretP384(priv, peer)
	if err != nil {
		t.Fatalf("SharedSecret failed: %v", err)
	}
	if !bytes.Equal(secret, secretExp) {
		t.Fatalf("shared secret mismatch\n got %X\nwant %X", secret, secretExp)
	}
}

func TestP384GenerateKey(t *testing.T) {
	privA, err := p384.GenerateKeyP384()
	if err != nil {
		t.Fatalf("GenerateKeyP384 A failed: %v", err)
	}
	privB, err := p384.GenerateKeyP384()
	if err != nil {
		t.Fatalf("GenerateKeyP384 B failed: %v", err)
	}
	secretA, err := p384.SharedSecretP384(privA, privB.PublicKey())
	if err != nil {
		t.Fatalf("SharedSecret A failed: %v", err)
	}
	secretB, err := p384.SharedSecretP384(privB, privA.PublicKey())
	if err != nil {
		t.Fatalf("SharedSecret B failed: %v", err)
	}
	if !bytes.Equal(secretA, secretB) {
		t.Fatalf("generated shared secrets differ")
	}
}

func TestP384Interface(t *testing.T) {
	ke := p384.NewP384()
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
