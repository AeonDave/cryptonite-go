package sig_test

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"

	"crypto/ed25519"
	"crypto/elliptic"

	cryptosig "github.com/AeonDave/cryptonite-go/sig"
	wycheproof "github.com/AeonDave/cryptonite-go/test/wycheproof"
)

type ecdsaCase struct {
	TCID    int    `json:"tcId"`
	Comment string `json:"comment"`
	Msg     string `json:"msg"`
	Qx      string `json:"qx"`
	Qy      string `json:"qy"`
	Sig     string `json:"sig"`
	Result  string `json:"result"`
}

type ed25519Case struct {
	TCID    int    `json:"tcId"`
	Comment string `json:"comment"`
	Msg     string `json:"msg"`
	Public  string `json:"public"`
	Sig     string `json:"sig"`
	Result  string `json:"result"`
}

type wycheproofSigVectors struct {
	ECDSA   []ecdsaCase   `json:"ecdsa_p256"`
	Ed25519 []ed25519Case `json:"ed25519"`
}

func TestECDSAP256Wycheproof(t *testing.T) {
	var vectors wycheproofSigVectors
	if err := json.Unmarshal(wycheproof.JSON, &vectors); err != nil {
		t.Fatalf("failed to parse wycheproof data: %v", err)
	}
	curve := elliptic.P256()
	for _, tc := range vectors.ECDSA {
		msg := mustHex(t, tc.Msg)
		sigBytes := mustHex(t, tc.Sig)
		qx := new(big.Int)
		qy := new(big.Int)
		if _, ok := qx.SetString(tc.Qx, 16); !ok {
			t.Fatalf("invalid qx in tc %d", tc.TCID)
		}
		if _, ok := qy.SetString(tc.Qy, 16); !ok {
			t.Fatalf("invalid qy in tc %d", tc.TCID)
		}
		// Build uncompressed encoding (0x04 || X || Y) instead of using
		// deprecated elliptic.Marshal. This matches sig.MarshalPublicKey and
		// sig.ParsePublicKey expectations.
		size := (curve.Params().BitSize + 7) / 8
		encoded := make([]byte, 1+2*size)
		encoded[0] = 0x04
		qx.FillBytes(encoded[1 : 1+size])
		qy.FillBytes(encoded[1+size:])
		pub, err := cryptosig.ParsePublicKey(encoded)
		if err != nil {
			t.Fatalf("failed to reconstruct public key for tc %d: %v", tc.TCID, err)
		}
		valid := cryptosig.VerifyASN1(pub, msg, sigBytes)
		if tc.Result == "valid" && !valid {
			t.Fatalf("ECDSA tc %d expected success", tc.TCID)
		}
		if tc.Result != "valid" && valid {
			t.Fatalf("ECDSA tc %d expected failure", tc.TCID)
		}
	}
}

func TestEd25519Wycheproof(t *testing.T) {
	var vectors wycheproofSigVectors
	if err := json.Unmarshal(wycheproof.JSON, &vectors); err != nil {
		t.Fatalf("failed to parse wycheproof data: %v", err)
	}
	for _, tc := range vectors.Ed25519 {
		msg := mustHex(t, tc.Msg)
		pub := mustHex(t, tc.Public)
		sig := mustHex(t, tc.Sig)
		valid := cryptosig.Verify(ed25519.PublicKey(pub), msg, sig)
		if tc.Result == "valid" && !valid {
			t.Fatalf("Ed25519 tc %d expected success", tc.TCID)
		}
		if tc.Result != "valid" && valid {
			t.Fatalf("Ed25519 tc %d expected failure", tc.TCID)
		}
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	if s == "" {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid hex %q: %v", s, err)
	}
	return b
}
