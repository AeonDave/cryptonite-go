package kdf

// DeriveParams captures the inputs required by the various key-derivation
// helpers exposed by the library. Individual schemes may interpret fields
// differently and ignore those they do not require.
type DeriveParams struct {
	// Secret holds the primary secret/input keying material (IKM/password).
	Secret []byte
	// Salt supplies optional diversification data.
	Salt []byte
	// Info carries optional context for HKDF-style constructions.
	Info []byte
	// Iterations controls the number of rounds for iterative KDFs such as PBKDF2.
	Iterations int
	// Length specifies how many bytes of key material to output.
	Length int
}

// Deriver defines the minimal API implemented by each KDF helper in the
// package, offering a consistent single-shot derivation entrypoint.
type Deriver interface {
	Derive(params DeriveParams) ([]byte, error)
}
