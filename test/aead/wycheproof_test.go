package aead_test

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/AeonDave/cryptonite-go/aead"
	wycheproof "github.com/AeonDave/cryptonite-go/test/wycheproof"
)

type aeadCase struct {
	TCID    int    `json:"tcId"`
	Comment string `json:"comment"`
	Key     string `json:"key"`
	Iv      string `json:"iv"`
	Aad     string `json:"aad"`
	Msg     string `json:"msg"`
	Ct      string `json:"ct"`
	Tag     string `json:"tag"`
	Result  string `json:"result"`
}

type wycheproofAEADVectors struct {
	AESGCM           []aeadCase `json:"aes_gcm"`
	ChaCha20Poly1305 []aeadCase `json:"chacha20_poly1305"`
}

func TestAESGCMAgainstWycheproof(t *testing.T) {
	var vectors wycheproofAEADVectors
	if err := json.Unmarshal(wycheproof.JSON, &vectors); err != nil {
		t.Fatalf("failed to parse wycheproof vectors: %v", err)
	}
	cipher := aead.NewAESGCM()
	for _, tc := range vectors.AESGCM {
		key := mustHex(t, tc.Key)
		iv := mustHex(t, tc.Iv)
		aad := mustHex(t, tc.Aad)
		msg := mustHex(t, tc.Msg)
		ct := mustHex(t, tc.Ct)
		tag := mustHex(t, tc.Tag)
		combined := append(append([]byte{}, ct...), tag...)
		plaintext, err := cipher.Decrypt(key, iv, aad, combined)
		if tc.Result == "valid" {
			if err != nil {
				t.Fatalf("AES-GCM tc %d expected success: %v", tc.TCID, err)
			}
			if !bytesEqual(plaintext, msg) {
				t.Fatalf("AES-GCM tc %d plaintext mismatch", tc.TCID)
			}
			enc, err := cipher.Encrypt(key, iv, aad, msg)
			if err != nil {
				t.Fatalf("AES-GCM tc %d encrypt failed: %v", tc.TCID, err)
			}
			if !bytesEqual(enc, combined) {
				t.Fatalf("AES-GCM tc %d encrypt mismatch", tc.TCID)
			}
		} else {
			if err == nil {
				t.Fatalf("AES-GCM tc %d expected failure", tc.TCID)
			}
		}
	}
}

func TestChaCha20Poly1305AgainstWycheproof(t *testing.T) {
	var vectors wycheproofAEADVectors
	if err := json.Unmarshal(wycheproof.JSON, &vectors); err != nil {
		t.Fatalf("failed to parse wycheproof vectors: %v", err)
	}
	cipher := aead.NewChaCha20Poly1305()
	for _, tc := range vectors.ChaCha20Poly1305 {
		key := mustHex(t, tc.Key)
		nonce := mustHex(t, tc.Iv)
		aad := mustHex(t, tc.Aad)
		msg := mustHex(t, tc.Msg)
		ct := mustHex(t, tc.Ct)
		tag := mustHex(t, tc.Tag)
		combined := append(append([]byte{}, ct...), tag...)
		plaintext, err := cipher.Decrypt(key, nonce, aad, combined)
		if tc.Result == "valid" {
			if err != nil {
				t.Fatalf("ChaCha20-Poly1305 tc %d expected success: %v", tc.TCID, err)
			}
			if !bytesEqual(plaintext, msg) {
				t.Fatalf("ChaCha20-Poly1305 tc %d plaintext mismatch", tc.TCID)
			}
			enc, err := cipher.Encrypt(key, nonce, aad, msg)
			if err != nil {
				t.Fatalf("ChaCha20-Poly1305 tc %d encrypt failed: %v", tc.TCID, err)
			}
			if !bytesEqual(enc, combined) {
				t.Fatalf("ChaCha20-Poly1305 tc %d encrypt mismatch", tc.TCID)
			}
		} else if err == nil {
			t.Fatalf("ChaCha20-Poly1305 tc %d expected failure", tc.TCID)
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

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
