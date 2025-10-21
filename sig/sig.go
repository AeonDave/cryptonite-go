package sig

// Scheme defines the minimal single-shot signing API implemented by the
// signature helpers exposed under sig/.
type Scheme interface {
	// GenerateKey returns the encoded public and private key material.
	GenerateKey() (public []byte, private []byte, err error)
	// Sign produces a signature over msg using the encoded private key.
	Sign(private []byte, msg []byte) ([]byte, error)
	// Verify reports whether signature is valid for msg under the encoded public key.
	Verify(public []byte, msg, signature []byte) bool
}
