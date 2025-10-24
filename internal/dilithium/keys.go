package dilithium

import (
	"crypto/subtle"
	"errors"
)

var (
	errInvalidSeed   = errors.New("dilithium: invalid seed length")
	errInvalidPublic = errors.New("dilithium: invalid public key length")
	errInvalidSecret = errors.New("dilithium: invalid secret key length")
)

// PublicKey holds the expanded public key components (t1, rho).
type PublicKey struct {
	T1  Vec
	Rho [SeedSize]byte
}

// PrivateKey represents the packed secret key structure.
type PrivateKey struct {
	S1  Vec
	S2  Vec
	Rho [SeedSize]byte
	Key [SeedSize]byte
	Tr  [SeedSize]byte
	T0  Vec
}

func (s *Scheme) packPublicKey(pk PublicKey) []byte {
	out := make([]byte, s.params.publicKey)
	copy(out[:SeedSize], pk.Rho[:])
	copy(out[SeedSize:], packT1(pk.T1, s.params.k))
	return out
}

func (s *Scheme) unpackPublicKey(data []byte) (PublicKey, error) {
	if len(data) != s.params.publicKey {
		return PublicKey{}, errInvalidPublic
	}
	var pk PublicKey
	copy(pk.Rho[:], data[:SeedSize])
	pk.T1 = unpackT1(data[SeedSize:], s.params.k)
	return pk, nil
}

func (s *Scheme) packSecretKey(sk PrivateKey) []byte {
	out := make([]byte, s.params.secretKey)
	offset := 0

	subtle.ConstantTimeCopy(1, out[offset:offset+SeedSize], sk.Rho[:])
	offset += SeedSize
	subtle.ConstantTimeCopy(1, out[offset:offset+SeedSize], sk.Key[:])
	offset += SeedSize
	subtle.ConstantTimeCopy(1, out[offset:offset+SeedSize], sk.Tr[:])
	offset += SeedSize

	l := s.params.l
	k := s.params.k
	subtle.ConstantTimeCopy(1, out[offset:offset+l*s.params.polySizeS], packS(sk.S1, l, s.params.polySizeS, s.params.eta))
	offset += l * s.params.polySizeS
	subtle.ConstantTimeCopy(1, out[offset:offset+k*s.params.polySizeS], packS(sk.S2, k, s.params.polySizeS, s.params.eta))
	offset += k * s.params.polySizeS
	subtle.ConstantTimeCopy(1, out[offset:], packT0(sk.T0, k))
	return out
}

func (s *Scheme) unpackSecretKey(data []byte) (PrivateKey, error) {
	if len(data) != s.params.secretKey {
		return PrivateKey{}, errInvalidSecret
	}
	var sk PrivateKey
	offset := 0

	subtle.ConstantTimeCopy(1, sk.Rho[:], data[:SeedSize])
	offset += SeedSize
	subtle.ConstantTimeCopy(1, sk.Key[:], data[offset:offset+SeedSize])
	offset += SeedSize
	subtle.ConstantTimeCopy(1, sk.Tr[:], data[offset:offset+SeedSize])
	offset += SeedSize

	l := s.params.l
	k := s.params.k
	sk.S1 = unpackS(data[offset:offset+l*s.params.polySizeS], l, s.params.polySizeS, s.params.eta)
	offset += l * s.params.polySizeS
	sk.S2 = unpackS(data[offset:offset+k*s.params.polySizeS], k, s.params.polySizeS, s.params.eta)
	offset += k * s.params.polySizeS
	sk.T0 = unpackT0(data[offset:], k)
	return sk, nil
}
