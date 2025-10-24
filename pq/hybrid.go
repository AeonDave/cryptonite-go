package pq

import (
	"encoding/binary"
	"errors"

	"github.com/AeonDave/cryptonite-go/ecdh"
	"github.com/AeonDave/cryptonite-go/kdf"
	"github.com/AeonDave/cryptonite-go/kem"
	"github.com/AeonDave/cryptonite-go/secret"
)

const (
	hybridFormatVersion = 0x01
	hybridSecretSize    = 32
)

var (
	errInvalidKeyMaterial = errors.New("pq: invalid hybrid key material")
	errUnsupportedVersion = errors.New("pq: unsupported hybrid key version")
	errMissingPQPublic    = errors.New("pq: missing post-quantum public key component")
	errMissingPQPrivate   = errors.New("pq: missing post-quantum private key component")
	errMissingPQCipher    = errors.New("pq: missing post-quantum ciphertext component")
)

// Hybrid implements a deployable hybrid key encapsulation mechanism that
// combines a classical ECDH exchange with an optional post-quantum KEM. The
// classical component is required to ensure callers can rely on the
// construction even before a post-quantum primitive is available. When a PQ
// KEM is supplied, Hybrid derives the final shared secret from both inputs
// using HKDF-SHA256 as described in draft-ietf-tls-hybrid-design-05.
//
// The encoded public/private keys and ciphertexts follow a simple tagged
// format: version byte followed by 2-byte big-endian length prefixes for the
// classical and post-quantum components.
type Hybrid struct {
	classical ecdh.KeyExchange
	mlkem     kem.KEM
}

// NewHybrid constructs a Hybrid KEM using the provided classical ECDH exchange
// and optional post-quantum KEM. The classical exchange must be non-nil.
func NewHybrid(classical ecdh.KeyExchange, mlkem kem.KEM) (*Hybrid, error) {
	if classical == nil {
		return nil, errors.New("pq: nil classical exchange")
	}
	return &Hybrid{classical: classical, mlkem: mlkem}, nil
}

// NewHybridX25519 returns a Hybrid instance backed by X25519 and without a
// post-quantum component. It is intended as an immediate, deployable hybrid
// construction until a vetted ML-KEM implementation is available.
func NewHybridX25519() *Hybrid {
	h, _ := NewHybrid(ecdh.NewX25519(), nil)
	return h
}

// GenerateKey creates a hybrid public/private key pair. When mlkem is nil only
// the classical component is produced, resulting in a format that still allows
// hybrid ciphertexts to be processed in the future.
func (h *Hybrid) GenerateKey() (public, private []byte, err error) {
	if h == nil {
		return nil, nil, errors.New("pq: nil hybrid")
	}
	classicalPriv, err := h.classical.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	classicalPub := classicalPriv.PublicKey().Bytes()
	classicalPrivBytes := classicalPriv.Bytes()

	var mlkemPub, mlkemPriv []byte
	if h.mlkem != nil {
		mlkemPub, mlkemPriv, err = h.mlkem.GenerateKey()
		if err != nil {
			secret.WipeBytes(classicalPrivBytes)
			secret.WipeBytes(classicalPub)
			return nil, nil, err
		}
	}

	public = encodeHybridMaterial(classicalPub, mlkemPub)
	private = encodeHybridMaterial(classicalPrivBytes, mlkemPriv)
	secret.WipeBytes(classicalPrivBytes)
	secret.WipeBytes(mlkemPriv)
	return public, private, nil
}

// Encapsulate performs hybrid encapsulation using the recipient's public key.
// The returned ciphertext embeds the ephemeral classical public key and, when
// available, the post-quantum ciphertext. The shared secret is derived from the
// concatenation of the classical and PQ secrets using HKDF-SHA256.
func (h *Hybrid) Encapsulate(public []byte) (ciphertext, sharedSecret []byte, err error) {
	if h == nil {
		return nil, nil, errors.New("pq: nil hybrid")
	}
	components, err := parseHybridMaterial(public)
	if err != nil {
		return nil, nil, err
	}
	if len(components.extraPayload) != 0 {
		return nil, nil, errInvalidKeyMaterial
	}
	if len(components.classical) == 0 {
		return nil, nil, errors.New("pq: missing classical public key")
	}
	if len(components.postQuantum) > 0 && h.mlkem == nil {
		return nil, nil, errors.New("pq: unexpected post-quantum key component")
	}
	if h.mlkem != nil && len(components.postQuantum) == 0 {
		return nil, nil, errMissingPQPublic
	}

	classicalPriv, err := h.classical.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	classicalPub := classicalPriv.PublicKey().Bytes()
	peerPub, err := h.classical.NewPublicKey(components.classical)
	if err != nil {
		return nil, nil, err
	}
	classicalSecret, err := classicalPriv.ECDH(peerPub)
	if err != nil {
		return nil, nil, err
	}

	var pqCiphertext, pqSecret []byte
	if h.mlkem != nil {
		pqCiphertext, pqSecret, err = h.mlkem.Encapsulate(components.postQuantum)
		if err != nil {
			secret.WipeBytes(classicalSecret)
			return nil, nil, err
		}
	}

	derivedSecret, err := combineSharedSecrets(classicalSecret, pqSecret)
	if err != nil {
		secret.WipeBytes(classicalSecret)
		secret.WipeBytes(pqSecret)
		return nil, nil, err
	}

	ciphertext = encodeHybridMaterial(classicalPub, pqCiphertext)
	secret.WipeBytes(classicalSecret)
	secret.WipeBytes(pqSecret)
	return ciphertext, derivedSecret, nil
}

// Decapsulate recovers the shared secret from ciphertext using the provided
// private key. It validates the key/ciphertext format and combines the
// classical and post-quantum secrets using HKDF-SHA256.
func (h *Hybrid) Decapsulate(private, ciphertext []byte) ([]byte, error) {
	if h == nil {
		return nil, errors.New("pq: nil hybrid")
	}
	keyComponents, err := parseHybridMaterial(private)
	if err != nil {
		return nil, err
	}
	if len(keyComponents.extraPayload) != 0 {
		return nil, errInvalidKeyMaterial
	}
	if len(keyComponents.classical) == 0 {
		return nil, errors.New("pq: missing classical private key")
	}
	ctComponents, err := parseHybridMaterial(ciphertext)
	if err != nil {
		return nil, err
	}
	if len(ctComponents.extraPayload) != 0 {
		return nil, errInvalidKeyMaterial
	}
	if len(ctComponents.classical) == 0 {
		return nil, errors.New("pq: missing classical ciphertext component")
	}
	requirePQ := h.mlkem != nil
	if len(keyComponents.postQuantum) > 0 && !requirePQ {
		return nil, errors.New("pq: unexpected post-quantum key component")
	}
	if len(ctComponents.postQuantum) > 0 && !requirePQ {
		return nil, errors.New("pq: unexpected post-quantum ciphertext component")
	}
	if requirePQ {
		if len(keyComponents.postQuantum) == 0 {
			return nil, errMissingPQPrivate
		}
		if len(ctComponents.postQuantum) == 0 {
			return nil, errMissingPQCipher
		}
	}

	classicalPriv, err := h.classical.NewPrivateKey(keyComponents.classical)
	if err != nil {
		return nil, err
	}
	peerPub, err := h.classical.NewPublicKey(ctComponents.classical)
	if err != nil {
		return nil, err
	}
	classicalSecret, err := classicalPriv.ECDH(peerPub)
	if err != nil {
		return nil, err
	}

	var pqSecret []byte
	if requirePQ {
		pqSecret, err = h.mlkem.Decapsulate(keyComponents.postQuantum, ctComponents.postQuantum)
		if err != nil {
			secret.WipeBytes(classicalSecret)
			return nil, err
		}
	}

	derivedSecret, err := combineSharedSecrets(classicalSecret, pqSecret)
	secret.WipeBytes(classicalSecret)
	secret.WipeBytes(pqSecret)
	if err != nil {
		return nil, err
	}
	return derivedSecret, nil
}

type hybridComponents struct {
	classical    []byte
	postQuantum  []byte
	extraPayload []byte
}

func parseHybridMaterial(b []byte) (hybridComponents, error) {
	if len(b) == 0 {
		return hybridComponents{}, errInvalidKeyMaterial
	}
	if b[0] != hybridFormatVersion {
		return hybridComponents{}, errUnsupportedVersion
	}
	if len(b) < 3 {
		return hybridComponents{}, errInvalidKeyMaterial
	}
	classicalLen := int(binary.BigEndian.Uint16(b[1:3]))
	offset := 3
	if classicalLen < 0 || len(b) < offset+classicalLen+2 {
		return hybridComponents{}, errInvalidKeyMaterial
	}
	classical := b[offset : offset+classicalLen]
	offset += classicalLen
	pqLen := int(binary.BigEndian.Uint16(b[offset : offset+2]))
	offset += 2
	if pqLen < 0 || len(b) < offset+pqLen {
		return hybridComponents{}, errInvalidKeyMaterial
	}
	postQuantum := b[offset : offset+pqLen]
	offset += pqLen
	extra := b[offset:]
	return hybridComponents{classical: classical, postQuantum: postQuantum, extraPayload: extra}, nil
}

func encodeHybridMaterial(classical, postQuantum []byte) []byte {
	totalLen := 1 + 2 + len(classical) + 2 + len(postQuantum)
	out := make([]byte, totalLen)
	out[0] = hybridFormatVersion
	binary.BigEndian.PutUint16(out[1:3], uint16(len(classical)))
	copy(out[3:], classical)
	offset := 3 + len(classical)
	binary.BigEndian.PutUint16(out[offset:offset+2], uint16(len(postQuantum)))
	copy(out[offset+2:], postQuantum)
	return out
}

func combineSharedSecrets(classical, postQuantum []byte) ([]byte, error) {
	ikm := make([]byte, 0, len(classical)+len(postQuantum))
	ikm = append(ikm, classical...)
	ikm = append(ikm, postQuantum...)
	out, err := kdf.HKDFSHA256(ikm, nil, []byte("cryptonite-go/hybrid"), hybridSecretSize)
	secret.WipeBytes(ikm)
	return out, err
}
