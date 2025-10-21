package sig_test

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"testing"

	sig "cryptonite-go/sig"
	"cryptonite-go/test/internal/testutil"
)

func TestP256RFC6979Vector(t *testing.T) {
	privBytes := testutil.MustHex(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721")
	msg := []byte("sample")
	hash := sha256.Sum256(msg)
	sigDER := testutil.MustHex(t, "3046022100EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716022100F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8")
	rExp := testutil.MustHex(t, "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716")
	sExp := testutil.MustHex(t, "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8")

	priv, err := sig.NewPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("NewPrivateKey failed: %v", err)
	}
	pubBytes := sig.MarshalPublicKey(&priv.PublicKey)
	pub, err := sig.ParsePublicKey(pubBytes)
	if err != nil {
		t.Fatalf("ParsePublicKey failed: %v", err)
	}
	if !sig.VerifyASN1(pub, hash[:], sigDER) {
		t.Fatalf("VerifyASN1 rejected known signature")
	}
	r, s, err := sig.ParseSignature(sigDER)
	if err != nil {
		t.Fatalf("ParseSignature failed: %v", err)
	}
	if r.Cmp(new(big.Int).SetBytes(rExp)) != 0 || s.Cmp(new(big.Int).SetBytes(sExp)) != 0 {
		t.Fatalf("parsed r/s mismatch")
	}
}

func TestP256SignAndVerify(t *testing.T) {
	priv, err := sig.GenerateKeyP256()
	if err != nil {
		t.Fatalf("GenerateKeyP256 failed: %v", err)
	}
	hash := sha256.Sum256([]byte("hello world"))
	sigDER, err := sig.SignASN1(priv, hash[:])
	if err != nil {
		t.Fatalf("SignASN1 failed: %v", err)
	}
	if !sig.VerifyASN1(&priv.PublicKey, hash[:], sigDER) {
		t.Fatalf("VerifyASN1 failed for generated signature")
	}
	tampered := append([]byte{}, sigDER...)
	tampered[len(tampered)-1] ^= 0x01
	if sig.VerifyASN1(&priv.PublicKey, hash[:], tampered) {
		t.Fatalf("VerifyASN1 accepted tampered signature")
	}
}

func TestP256MarshalRoundTrip(t *testing.T) {
	priv, err := sig.GenerateKeyP256()
	if err != nil {
		t.Fatalf("GenerateKeyP256 failed: %v", err)
	}
	scalar := sig.MarshalPrivateKey(priv)
	if len(scalar) != sig.ScalarSize {
		t.Fatalf("unexpected scalar length")
	}
	priv2, err := sig.NewPrivateKey(scalar)
	if err != nil {
		t.Fatalf("NewPrivateKey failed: %v", err)
	}
	if !bytes.Equal(sig.MarshalPublicKey(&priv.PublicKey), sig.MarshalPublicKey(&priv2.PublicKey)) {
		t.Fatalf("public key mismatch after round trip")
	}
}

func TestP256SchemeInterface(t *testing.T) {
	var scheme sig.Signature = sig.New()
	pub, priv, err := scheme.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	hash := sha256.Sum256([]byte("interface"))
	signature, err := scheme.Sign(priv, hash[:])
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if !scheme.Verify(pub, hash[:], signature) {
		t.Fatalf("Verify failed for valid signature")
	}
	tampered := append([]byte{}, signature...)
	tampered[len(tampered)-1] ^= 0x02
	if scheme.Verify(pub, hash[:], tampered) {
		t.Fatalf("Verify succeeded for tampered signature")
	}
}
