package aead

type Aead interface {
	Encrypt(key, nonce, ad, plaintext []byte) ([]byte, error)
	Decrypt(key, nonce, ad, ciphertextAndTag []byte) ([]byte, error)
}
