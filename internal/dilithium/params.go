package dilithium

// Internal Dilithium constants shared across all parameter sets.
const (
	n            = 256
	q            = 8380417  // 2^23 - 2^13 + 1
	qInv         = 58728449 // -q^{-1} mod 2^32
	d            = 13
	polySizeT1   = 320
	polySizeT0   = 416
	shake128Rate = 168
	shake256Rate = 136

	// SeedSize is the number of bytes required for Dilithium seed material.
	SeedSize = 32

	// Public/secret key and signature sizes for the NIST-standardised ML-DSA
	// (Dilithium) parameter sets. These values mirror the definitions in
	// FIPS 204 / ML-DSA round 3.
	PublicKeySize44 = 1312
	SecretKeySize44 = 2528
	SignatureSize44 = 2420
	PublicKeySize65 = 1952
	SecretKeySize65 = 4000
	SignatureSize65 = 3293
	PublicKeySize87 = 2592
	SecretKeySize87 = 4864
	SignatureSize87 = 4595
)

// Scheme captures a concrete Dilithium / ML-DSA parameter set together with
// whether the signer operates in deterministic (false) or randomized (true)
// mode as defined in FIPS 204.
type Scheme struct {
	name       string
	params     parameters
	randomized bool
}

// parameters holds all per-mode constants used throughout the implementation.
type parameters struct {
	tau        int
	k          int
	l          int
	gamma1     int32
	gamma2     int32
	eta        int32
	beta       int32
	omega      int
	polySizeS  int
	polySizeZ  int
	polySizeW1 int
	publicKey  int
	secretKey  int
	signature  int
}

// NewMLDSA44 returns the ML-DSA-44 (Dilithium-2) parameter set. By default the
// signer operates in randomized mode; pass randomized=false to force the
// deterministic variant.
func NewMLDSA44(randomized ...bool) *Scheme {
	useRandomized := true
	if len(randomized) == 1 && !randomized[0] {
		useRandomized = false
	}
	return &Scheme{
		name:       "ML-DSA-44",
		randomized: useRandomized,
		params: parameters{
			tau:        39,
			k:          4,
			l:          4,
			gamma1:     131072,
			gamma2:     (q - 1) / 88,
			eta:        2,
			beta:       78,
			omega:      80,
			polySizeS:  96,
			polySizeZ:  576,
			polySizeW1: 192,
			publicKey:  SeedSize + 4*polySizeT1,
			secretKey:  SeedSize + SeedSize + SeedSize + 4*polySizeT0 + (4+4)*96,
			signature:  SeedSize + 4*576 + 4 + 80,
		},
	}
}

// NewMLDSA65 returns the ML-DSA-65 (Dilithium-3) parameter set.
func NewMLDSA65(randomized ...bool) *Scheme {
	useRandomized := true
	if len(randomized) == 1 && !randomized[0] {
		useRandomized = false
	}
	return &Scheme{
		name:       "ML-DSA-65",
		randomized: useRandomized,
		params: parameters{
			tau:        49,
			k:          6,
			l:          5,
			gamma1:     524288,
			gamma2:     (q - 1) / 32,
			eta:        4,
			beta:       196,
			omega:      55,
			polySizeS:  128,
			polySizeZ:  640,
			polySizeW1: 128,
			publicKey:  SeedSize + 6*polySizeT1,
			secretKey:  SeedSize + SeedSize + SeedSize + 6*polySizeT0 + (5+6)*128,
			signature:  SeedSize + 5*640 + 6 + 55,
		},
	}
}

// NewMLDSA87 returns the ML-DSA-87 (Dilithium-5) parameter set.
func NewMLDSA87(randomized ...bool) *Scheme {
	useRandomized := true
	if len(randomized) == 1 && !randomized[0] {
		useRandomized = false
	}
	return &Scheme{
		name:       "ML-DSA-87",
		randomized: useRandomized,
		params: parameters{
			tau:        60,
			k:          8,
			l:          7,
			gamma1:     524288,
			gamma2:     (q - 1) / 32,
			eta:        2,
			beta:       120,
			omega:      75,
			polySizeS:  96,
			polySizeZ:  640,
			polySizeW1: 128,
			publicKey:  SeedSize + 8*polySizeT1,
			secretKey:  SeedSize + SeedSize + SeedSize + 8*polySizeT0 + (8+7)*96,
			signature:  SeedSize + 7*640 + 8 + 75,
		},
	}
}

// Name returns the human-readable identifier for the scheme (ML-DSA-XX).
func (s *Scheme) Name() string { return s.name }

// PublicKeySize returns the packed public key length in bytes.
func (s *Scheme) PublicKeySize() int { return s.params.publicKey }

// SecretKeySize returns the packed secret key length in bytes.
func (s *Scheme) SecretKeySize() int { return s.params.secretKey }

// SignatureSize returns the packed signature length in bytes.
func (s *Scheme) SignatureSize() int { return s.params.signature }

// Randomized returns true if the signer operates in randomized mode.
func (s *Scheme) Randomized() bool { return s.randomized }

// WithRandomized toggles the signing mode for the receiver and returns the
// mutated scheme for convenience.
func (s *Scheme) WithRandomized(randomized bool) *Scheme {
	s.randomized = randomized
	return s
}

// NewDilithium2, NewDilithium3 and NewDilithium5 keep parity with the legacy
// naming used by the original reference implementations.
func NewDilithium2(randomized ...bool) *Scheme { return NewMLDSA44(randomized...) }
func NewDilithium3(randomized ...bool) *Scheme { return NewMLDSA65(randomized...) }
func NewDilithium5(randomized ...bool) *Scheme { return NewMLDSA87(randomized...) }
