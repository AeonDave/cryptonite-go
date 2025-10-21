package aead

import (
	"crypto/subtle"
	"errors"

	xo "cryptonite-go/internal/xoodyak"
)

const (
	xoodyakKeySize   = xo.KeySize
	xoodyakNonceSize = xo.NonceSize
	xoodyakTagSize   = xo.TagSize
)

// xoodyak implements the Aead interface using the xoodyak-Encrypt mode.
type xoodyak struct{}

// NewXoodyak returns a zero-allocation AEAD cipher instance.
func NewXoodyak() Aead { return xoodyak{} }

func (xoodyak) Encrypt(key, nonce, ad, plaintext []byte) ([]byte, error) {
	if len(key) != xoodyakKeySize {
		return nil, errors.New("xoodyak: invalid key size")
	}
	if len(nonce) != xoodyakNonceSize {
		return nil, errors.New("xoodyak: invalid nonce size")
	}

	var inst xo.Instance
	if err := inst.Initialize(key, nil, nil); err != nil {
		return nil, err
	}
	inst.Absorb(nonce)
	inst.Absorb(ad)

	ciphertext := make([]byte, len(plaintext))
	inst.Crypt(plaintext, ciphertext, false)

	tag := make([]byte, xoodyakTagSize)
	inst.Squeeze(tag)

	result := make([]byte, len(ciphertext)+xoodyakTagSize)
	copy(result, ciphertext)
	copy(result[len(ciphertext):], tag)

	for i := range tag {
		tag[i] = 0
	}
	inst.Clear()
	return result, nil
}

func (xoodyak) Decrypt(key, nonce, ad, ciphertextAndTag []byte) ([]byte, error) {
	if len(key) != xoodyakKeySize {
		return nil, errors.New("xoodyak: invalid key size")
	}
	if len(nonce) != xoodyakNonceSize {
		return nil, errors.New("xoodyak: invalid nonce size")
	}
	if len(ciphertextAndTag) < xoodyakTagSize {
		return nil, errors.New("xoodyak: ciphertext too short")
	}

	ct := ciphertextAndTag[:len(ciphertextAndTag)-xoodyakTagSize]
	tag := ciphertextAndTag[len(ciphertextAndTag)-xoodyakTagSize:]

	var inst xo.Instance
	if err := inst.Initialize(key, nil, nil); err != nil {
		return nil, err
	}
	inst.Absorb(nonce)
	inst.Absorb(ad)

	plaintext := make([]byte, len(ct))
	inst.Crypt(ct, plaintext, true)

	expectedTag := make([]byte, xoodyakTagSize)
	inst.Squeeze(expectedTag)
	if subtle.ConstantTimeCompare(tag, expectedTag) != 1 {
		for i := range plaintext {
			plaintext[i] = 0
		}
		for i := range expectedTag {
			expectedTag[i] = 0
		}
		inst.Clear()
		return nil, errors.New("xoodyak: authentication failed")
	}
	for i := range expectedTag {
		expectedTag[i] = 0
	}
	inst.Clear()
	return plaintext, nil
}
