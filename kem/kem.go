package kem

// KEM defines the minimal interface implemented by key encapsulation
// mechanisms exposed by the kem package. Implementations are responsible for
// sourcing entropy via crypto/rand and therefore expose deterministic method
// signatures that do not require callers to pass a randomness source.
type KEM interface {
	// GenerateKey returns the public and private key material. The public
	// key must be derived deterministically from the freshly generated
	// private key material.
	GenerateKey() (public, private []byte, err error)
	// Encapsulate produces a ciphertext and the shared secret using the
	// recipient's public key.
	Encapsulate(public []byte) (ciphertext, sharedSecret []byte, err error)
	// Decapsulate recovers the shared secret from the provided ciphertext
	// using the recipient's private key.
	Decapsulate(private []byte, ciphertext []byte) ([]byte, error)
}
