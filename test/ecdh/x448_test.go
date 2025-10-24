package ecdh_test

import (
	"bytes"
	"encoding/json"
	"testing"

	xdh "github.com/AeonDave/cryptonite-go/ecdh"
	"github.com/AeonDave/cryptonite-go/test/internal/testutil"

	_ "embed"
)

//go:embed testdata/x448_kat.json
var x448KATJSON []byte

type x448KATCase struct {
	Name         string `json:"name"`
	Scalar       string `json:"scalar"`
	U            string `json:"u"`
	SharedSecret string `json:"shared_secret"`
}

func loadX448KAT(t *testing.T) []x448KATCase {
	t.Helper()
	var cases []x448KATCase
	if err := json.Unmarshal(x448KATJSON, &cases); err != nil {
		t.Fatalf("failed to parse x448 KAT: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("empty x448 KAT")
	}
	return cases
}

func TestX448RFC7748Vectors(t *testing.T) {
	cases := loadX448KAT(t)

	for i, tc := range cases {
		priv, err := xdh.NewPrivateKeyX448(testutil.MustHex(t, tc.Scalar))
		if err != nil {
			t.Fatalf("case %d (%s): NewPrivateKey failed: %v", i, tc.Name, err)
		}
		pub, err := xdh.NewPublicKeyX448(testutil.MustHex(t, tc.U))
		if err != nil {
			t.Fatalf("case %d (%s): NewPublicKey failed: %v", i, tc.Name, err)
		}
		out, err := xdh.SharedSecretX448(priv, pub)
		if err != nil {
			t.Fatalf("case %d (%s): SharedSecret failed: %v", i, tc.Name, err)
		}
		if !bytes.Equal(out, testutil.MustHex(t, tc.SharedSecret)) {
			t.Fatalf("case %d (%s): mismatch\n got %X\nwant %s", i, tc.Name, out, tc.SharedSecret)
		}
	}
}

func TestX448IteratedVectors(t *testing.T) {
	type iteration struct {
		loops int
		out   string
	}

	cases := []iteration{
		{loops: 1, out: "3F482C8A9F19B01E6C46EE9711D9DC14FD4BF67AF30765C2AE2B846A4D23A8CD0DB897086239492CAF350B51F833868B9BC2B3BCA9CF4113"},
		{loops: 1000, out: "AA3B4749D55B9DAF1E5B00288826C467274CE3EBBDD5C17B975E09D4AF6C67CF10D087202DB88286E2B79FCEEA3EC353EF54FAA26E219F38"},
	}

	seed := testutil.MustHex(t, "0500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

	for _, tc := range cases {
		k := append([]byte(nil), seed...)
		u := append([]byte(nil), seed...)
		for i := 0; i < tc.loops; i++ {
			prevK := append([]byte(nil), k...)
			priv, err := xdh.NewPrivateKeyX448(k)
			if err != nil {
				t.Fatalf("loops=%d: NewPrivateKey failed: %v", tc.loops, err)
			}
			pub, err := xdh.NewPublicKeyX448(u)
			if err != nil {
				t.Fatalf("loops=%d: NewPublicKey failed: %v", tc.loops, err)
			}
			shared, err := xdh.SharedSecretX448(priv, pub)
			if err != nil {
				t.Fatalf("loops=%d: SharedSecret failed: %v", tc.loops, err)
			}
			u = prevK
			k = shared
		}
		if !bytes.Equal(k, testutil.MustHex(t, tc.out)) {
			t.Fatalf("loops=%d: mismatch\n got %X\nwant %s", tc.loops, k, tc.out)
		}
	}
}

func TestX448DiffieHellmanVector(t *testing.T) {
	privA, err := xdh.NewPrivateKeyX448(testutil.MustHex(t, "9A8F4925D1519F5775CF46B04B5800D4EE9EE8BAE8BC5565D498C28DD9C9BAF574A9419744897391006382A6F127AB1D9AC2D8C0A598726B"))
	if err != nil {
		t.Fatalf("NewPrivateKey A failed: %v", err)
	}
	pubB, err := xdh.NewPublicKeyX448(testutil.MustHex(t, "3EB7A829B0CD20F5BCFC0B599B6FECCF6DA4627107BDB0D4F345B43027D8B972FC3E34FB4232A13CA706DCB57AEC3DAE07BDC1C67BF33609"))
	if err != nil {
		t.Fatalf("NewPublicKey B failed: %v", err)
	}
	secret, err := xdh.SharedSecretX448(privA, pubB)
	if err != nil {
		t.Fatalf("SharedSecret failed: %v", err)
	}
	if !bytes.Equal(secret, testutil.MustHex(t, "07FFF4181AC6CC95EC1C16A94A0F74D12DA232CE40A77552281D282BB60C0B56FD2464C335543936521C24403085D59A449A5037514A879D")) {
		t.Fatalf("shared secret mismatch")
	}
}

func TestX448GenerateKey(t *testing.T) {
	privA, err := xdh.GenerateKeyX448()
	if err != nil {
		t.Fatalf("GenerateKey A failed: %v", err)
	}
	privB, err := xdh.GenerateKeyX448()
	if err != nil {
		t.Fatalf("GenerateKey B failed: %v", err)
	}
	secretA, err := xdh.SharedSecretX448(privA, privB.PublicKey())
	if err != nil {
		t.Fatalf("SharedSecret A failed: %v", err)
	}
	secretB, err := xdh.SharedSecretX448(privB, privA.PublicKey())
	if err != nil {
		t.Fatalf("SharedSecret B failed: %v", err)
	}
	if !bytes.Equal(secretA, secretB) {
		t.Fatalf("generated shared secrets differ")
	}
}

func TestX448Interface(t *testing.T) {
	ke := xdh.NewX448()
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
