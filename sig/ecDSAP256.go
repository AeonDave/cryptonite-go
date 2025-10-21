package sig

// NewECDSAP256 returns a Signature implementation backed by the helpers in
// p256.go. It exposes the P-256 ECDSA functionality under an explicit name
// without duplicating the underlying logic.
func NewECDSAP256() Signature { return p256Scheme{} }

// GenerateKeyECDSAP256 produces a fresh ECDSA P-256 keypair using crypto/rand
// and returns the encoded public/private material suitable for use with the
// Signature interface.
func GenerateKeyECDSAP256() (public []byte, private []byte, err error) {
	impl := p256Scheme{}
	return impl.GenerateKey()
}

// SignECDSAP256 signs msg using the provided encoded private scalar. The
// signature is returned in ASN.1 DER format matching crypto/ecdsa.SignASN1.
func SignECDSAP256(private, msg []byte) ([]byte, error) {
	impl := p256Scheme{}
	return impl.Sign(private, msg)
}

// VerifyECDSAP256 checks whether signature is a valid ASN.1 DER encoded ECDSA
// signature over msg under the encoded uncompressed public key.
func VerifyECDSAP256(public, msg, signature []byte) bool {
	impl := p256Scheme{}
	return impl.Verify(public, msg, signature)
}
