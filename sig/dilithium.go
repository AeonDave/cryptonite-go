package sig

import "github.com/AeonDave/cryptonite-go/internal/dilithium"

// Public, secret, and signature sizes for the Dilithium / ML-DSA variants.
const (
	MLDSA44PublicKeySize = dilithium.PublicKeySize44
	MLDSA44SecretKeySize = dilithium.SecretKeySize44
	MLDSA44SignatureSize = dilithium.SignatureSize44
	MLDSA65PublicKeySize = dilithium.PublicKeySize65
	MLDSA65SecretKeySize = dilithium.SecretKeySize65
	MLDSA65SignatureSize = dilithium.SignatureSize65
	MLDSA87PublicKeySize = dilithium.PublicKeySize87
	MLDSA87SecretKeySize = dilithium.SecretKeySize87
	MLDSA87SignatureSize = dilithium.SignatureSize87
)

type dilithiumScheme struct {
	impl *dilithium.Scheme
}

// NewMLDSA44 returns a Signature implementation for ML-DSA-44 (Dilithium-2).
func NewMLDSA44() Signature { return &dilithiumScheme{impl: dilithium.NewMLDSA44()} }

// NewMLDSA65 returns a Signature implementation for ML-DSA-65 (Dilithium-3).
func NewMLDSA65() Signature { return &dilithiumScheme{impl: dilithium.NewMLDSA65()} }

// NewMLDSA87 returns a Signature implementation for ML-DSA-87 (Dilithium-5).
func NewMLDSA87() Signature { return &dilithiumScheme{impl: dilithium.NewMLDSA87()} }

// NewDeterministicMLDSA44 returns ML-DSA-44 operating in deterministic mode.
func NewDeterministicMLDSA44() Signature {
	return &dilithiumScheme{impl: dilithium.NewMLDSA44(false)}
}

// NewDeterministicMLDSA65 returns ML-DSA-65 operating in deterministic mode.
func NewDeterministicMLDSA65() Signature {
	return &dilithiumScheme{impl: dilithium.NewMLDSA65(false)}
}

// NewDeterministicMLDSA87 returns ML-DSA-87 operating in deterministic mode.
func NewDeterministicMLDSA87() Signature {
	return &dilithiumScheme{impl: dilithium.NewMLDSA87(false)}
}

func (d *dilithiumScheme) GenerateKey() ([]byte, []byte, error) {
	return d.impl.GenerateKey(nil)
}

func (d *dilithiumScheme) Sign(private []byte, msg []byte) ([]byte, error) {
	return d.impl.Sign(private, msg)
}

func (d *dilithiumScheme) Verify(public []byte, msg, signature []byte) bool {
	return d.impl.Verify(public, msg, signature)
}

// GenerateKeyMLDSA44 creates a randomized key pair for ML-DSA-44.
func GenerateKeyMLDSA44() ([]byte, []byte, error) { return dilithium.NewMLDSA44().GenerateKey(nil) }

// GenerateKeyMLDSA65 creates a randomized key pair for ML-DSA-65.
func GenerateKeyMLDSA65() ([]byte, []byte, error) { return dilithium.NewMLDSA65().GenerateKey(nil) }

// GenerateKeyMLDSA87 creates a randomized key pair for ML-DSA-87.
func GenerateKeyMLDSA87() ([]byte, []byte, error) { return dilithium.NewMLDSA87().GenerateKey(nil) }

// GenerateDeterministicKeyMLDSA44 derives a deterministic ML-DSA-44 key pair from seed.
func GenerateDeterministicKeyMLDSA44(seed []byte) ([]byte, []byte, error) {
	return dilithium.NewMLDSA44(false).GenerateKey(seed)
}

// GenerateDeterministicKeyMLDSA65 derives a deterministic ML-DSA-65 key pair from seed.
func GenerateDeterministicKeyMLDSA65(seed []byte) ([]byte, []byte, error) {
	return dilithium.NewMLDSA65(false).GenerateKey(seed)
}

// GenerateDeterministicKeyMLDSA87 derives a deterministic ML-DSA-87 key pair from seed.
func GenerateDeterministicKeyMLDSA87(seed []byte) ([]byte, []byte, error) {
	return dilithium.NewMLDSA87(false).GenerateKey(seed)
}
