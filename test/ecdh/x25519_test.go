package ecdh_test

import (
	"bytes"
	xdh "cryptonite-go/ecdh/x25519"
	"cryptonite-go/test/internal/testutil"
	"testing"
)

func TestX25519RFC7748Vectors(t *testing.T) {
	cases := []struct {
		scalar string
		u      string
		out    string
	}{
		{
			scalar: "A546E36BF0527C9D3B16154B82465EDD62144C0AC1FC5A18506A2244BA449AC4",
			u:      "E6DB6867583030DB3594C1A424B15F7C726624EC26B3353B10A903A6D0AB1C4C",
			out:    "C3DA55379DE9C6908E94EA4DF28D084F32ECCF03491C71F754B4075577A28552",
		},
		{
			scalar: "4B66E9D4D1B4673C5AD22691957D6AF5C11B6421E0EA01D42CA4169E7918BA0D",
			u:      "E5210F12786811D3F4B7959D0538AE2C31DBE7106FC03C3EFC4CD549C715A493",
			out:    "95CBDE9476E8907D7AADE45CB4B873F88B595A68799FA152E6F8F7647AAC7957",
		},
	}

	for i, tc := range cases {
		priv, err := xdh.NewPrivateKey(testutil.MustHex(t, tc.scalar))
		if err != nil {
			t.Fatalf("case %d: NewPrivateKey failed: %v", i, err)
		}
		pub, err := xdh.NewPublicKey(testutil.MustHex(t, tc.u))
		if err != nil {
			t.Fatalf("case %d: NewPublicKey failed: %v", i, err)
		}
		out, err := xdh.SharedSecret(priv, pub)
		if err != nil {
			t.Fatalf("case %d: SharedSecret failed: %v", i, err)
		}
		if !bytes.Equal(out, testutil.MustHex(t, tc.out)) {
			t.Fatalf("case %d: mismatch\n got %X\nwant %s", i, out, tc.out)
		}
	}
}

func TestX25519GenerateKey(t *testing.T) {
	privA, err := xdh.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey A failed: %v", err)
	}
	privB, err := xdh.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey B failed: %v", err)
	}
	secretA, err := xdh.SharedSecret(privA, privB.PublicKey())
	if err != nil {
		t.Fatalf("SharedSecret A failed: %v", err)
	}
	secretB, err := xdh.SharedSecret(privB, privA.PublicKey())
	if err != nil {
		t.Fatalf("SharedSecret B failed: %v", err)
	}
	if !bytes.Equal(secretA, secretB) {
		t.Fatalf("generated shared secrets differ")
	}
}

func TestX25519Interface(t *testing.T) {
	ke := xdh.New()
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
