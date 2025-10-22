package pq

import "io"

// KEM defines the minimal interface implemented by post-quantum key
// encapsulation mechanisms exposed by the pq package.
type KEM interface {
	// GenerateKey returns the public and private key material using entropy
	// from rand. Implementations must read the exact amount of bytes needed
	// for the private key and may derive the public key deterministically
	// from it. Callers may pass a nil reader to use crypto/rand.Reader.
	GenerateKey(rand io.Reader) (public, private []byte, err error)
	// Encapsulate produces a ciphertext and the shared secret using the
	// recipient's public key. Implementations should derive any additional
	// randomness from rand. Callers may pass a nil reader to use
	// crypto/rand.Reader.
	Encapsulate(rand io.Reader, public []byte) (ciphertext, sharedSecret []byte, err error)
	// Decapsulate recovers the shared secret from the provided ciphertext
	// using the recipient's private key.
	Decapsulate(private []byte, ciphertext []byte) ([]byte, error)
}
