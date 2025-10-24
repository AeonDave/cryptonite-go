package dilithium

import (
	"bytes"
	"crypto/rand"
	"crypto/sha3"
	"crypto/subtle"
	"errors"
)

var (
	errNonceExhausted = errors.New("dilithium: rejection sampling failed")
	errTagCollision   = errors.New("dilithium: challenge collision")
)

// GenerateKey returns packed public/secret key material. When seed is nil a
// fresh SeedSize-byte seed is sampled from crypto/rand. Providing a custom
// seed is primarily useful for deterministic test vectors.
func (s *Scheme) GenerateKey(seed []byte) ([]byte, []byte, error) {
	switch {
	case seed == nil:
		seed = make([]byte, SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, nil, err
		}
	case len(seed) != SeedSize:
		return nil, nil, errInvalidSeed
	default:
		seed = append([]byte(nil), seed...)
	}

	var (
		tr, rho, key [SeedSize]byte
		rhoPrime     [2 * SeedSize]byte
	)
	state := sha3.NewSHAKE256()
	state.Write(seed)
	state.Read(rho[:])
	state.Read(rhoPrime[:])
	state.Read(key[:])
	state.Reset()

	k := s.params.k
	l := s.params.l
	eta := s.params.eta

	aHat := expandSeed(rho, k, l)

	s1 := make(Vec, l)
	for i := 0; i < l; i++ {
		s1[i] = polyUniformEta(rhoPrime, uint16(i), eta)
	}
	s2 := make(Vec, k)
	for i := 0; i < k; i++ {
		s2[i] = polyUniformEta(rhoPrime, uint16(i+l), eta)
	}

	s1Hat := s1.copy()
	s1Hat.ntt(l)
	s2Hat := s2.copy()
	s2Hat.ntt(k)

	t, t1, t0 := make(Vec, k), make(Vec, k), make(Vec, k)
	for i := 0; i < k; i++ {
		t[i] = vecAccPointWise(aHat[i], s1Hat, l)
		s2Hat[i].tomont()
		t[i] = add(t[i], s2Hat[i])
		t[i].invntt()
		t[i].addQ()
		t1[i], t0[i] = polyPower2Round(t[i])
	}
	state.Write(append(rho[:], packT1(t1, k)...))
	state.Read(tr[:])

	pub := s.packPublicKey(PublicKey{T1: t1, Rho: rho})
	sec := s.packSecretKey(PrivateKey{
		Rho: rho,
		Key: key,
		Tr:  tr,
		S1:  s1,
		S2:  s2,
		T0:  t0,
	})
	return pub, sec, nil
}

// Sign produces a packed Dilithium signature over msg using the packed secret
// key encoded in sk.
func (s *Scheme) Sign(sk []byte, msg []byte) ([]byte, error) {
	if len(sk) != s.params.secretKey {
		return nil, errInvalidSecret
	}

	key, err := s.unpackSecretKey(sk)
	if err != nil {
		return nil, err
	}

	k := s.params.k
	l := s.params.l
	beta := s.params.beta

	aHat := expandSeed(key.Rho, k, l)

	var (
		mu    [2 * SeedSize]byte
		rhoP  [2 * SeedSize]byte
		randR [2 * SeedSize]byte
	)

	state := sha3.NewSHAKE256()
	state.Write(key.Tr[:])
	state.Write(msg)
	state.Read(mu[:])
	state.Reset()

	state.Write(append(key.Key[:], mu[:]...))
	state.Read(rhoP[:])
	state.Reset()

	if _, err := rand.Read(randR[:]); err != nil {
		return nil, err
	}
	mask := 0
	if s.randomized {
		mask = 1
	}
	subtle.ConstantTimeCopy(mask, rhoP[:], randR[:])

	s1Hat := key.S1.copy()
	s2Hat := key.S2.copy()
	t0Hat := key.T0.copy()
	s1Hat.ntt(l)
	s2Hat.ntt(k)
	t0Hat.ntt(k)

	var (
		nonce uint16
		y     = make(Vec, l)
		z     = make(Vec, l)
		c     Poly
	)

	for {
		if nonce > 500 {
			return nil, errNonceExhausted
		}

		for i := 0; i < l; i++ {
			y[i] = polyUniformGamma1(rhoP, nonce, s.params.gamma1)
			nonce++
		}

		yHat := y.copy()
		yHat.ntt(l)

		w, w1, w0 := make(Vec, k), make(Vec, k), make(Vec, k)
		for i := 0; i < k; i++ {
			w[i] = vecAccPointWise(aHat[i], yHat, l)
			w[i].reduce()
			w[i].invntt()
			w[i].addQ()
			w1[i], w0[i] = polyDecompose(w[i], s.params.gamma2)
		}

		var (
			hc   [SeedSize]byte
			zero [SeedSize]byte
		)
		state.Write(mu[:])
		state.Write(packW1(w1, k, s.params.polySizeW1, s.params.gamma2))
		state.Read(hc[:])
		state.Reset()

		state.Write(mu[:])
		state.Write(packW1(w0, k, s.params.polySizeW1, s.params.gamma2))
		state.Read(zero[:])
		state.Reset()
		if bytes.Equal(hc[:], zero[:]) {
			return nil, errTagCollision
		}

		c = challenge(hc[:], s.params.tau)
		chat := c
		chat.ntt()

		for i := 0; i < l; i++ {
			yHat[i].tomont()
			z[i] = montMul(chat, s1Hat[i])
			z[i] = add(z[i], yHat[i])
			z[i].invntt()
			z[i].reduce()
		}
		if !z.vecIsBelow(s.params.gamma1-beta, l) {
			continue
		}

		wcs2 := make(Vec, k)
		for i := 0; i < k; i++ {
			wcs2[i] = montMul(chat, s2Hat[i])
			wcs2[i].invntt()
			wcs2[i] = sub(w0[i], wcs2[i])
			wcs2[i].reduce()
		}
		if !wcs2.vecIsBelow(s.params.gamma2-beta, k) {
			continue
		}

		ct0 := make(Vec, k)
		for i := 0; i < k; i++ {
			ct0[i] = montMul(chat, t0Hat[i])
			ct0[i].invntt()
			ct0[i].reduce()
		}
		if !ct0.vecIsBelow(s.params.gamma2, k) {
			continue
		}

		wcs2 = vecAdd(wcs2, ct0, k)
		h, count := vecMakeHint(w1, wcs2, k, s.params.gamma2)
		if count > s.params.omega {
			continue
		}
		return s.PackSig(z, h, hc[:]), nil
	}
}

// Verify reports whether sig is a valid Dilithium signature on msg under the
// packed public key pk.
func (s *Scheme) Verify(pk []byte, msg []byte, sig []byte) bool {
	if len(sig) != s.params.signature || len(pk) != s.params.publicKey {
		return false
	}

	pub, err := s.unpackPublicKey(pk)
	if err != nil {
		return false
	}
	z, h, hc := s.UnpackSig(sig)
	if z == nil {
		return false
	}

	c := challenge(hc, s.params.tau)
	aHat := expandSeed(pub.Rho, s.params.k, s.params.l)

	var (
		tr [SeedSize]byte
		mu [2 * SeedSize]byte
	)
	state := sha3.NewSHAKE256()
	state.Write(append(pub.Rho[:], packT1(pub.T1, s.params.k)...))
	state.Read(tr[:])
	state.Reset()

	state.Write(tr[:])
	state.Write(msg)
	state.Read(mu[:])
	state.Reset()

	zHat := z.copy()
	zHat.ntt(s.params.l)

	chat := c
	chat.ntt()

	t1Hat := pub.T1.copy()

	w1 := make(Vec, s.params.k)
	for i := 0; i < s.params.k; i++ {
		w1[i] = vecAccPointWise(aHat[i], zHat, s.params.l)

		t1Hat[i].shift()
		t1Hat[i].ntt()
		t1Hat[i] = montMul(chat, t1Hat[i])

		w1[i] = sub(w1[i], t1Hat[i])
		w1[i].reduce()
		w1[i].invntt()
		w1[i].addQ()
		w1[i] = polyUseHint(w1[i], h[i], s.params.gamma2)
	}

	var hc2 [SeedSize]byte
	state.Write(mu[:])
	state.Write(packW1(w1, s.params.k, s.params.polySizeW1, s.params.gamma2))
	state.Read(hc2[:])

	return z.vecIsBelow(s.params.gamma1-s.params.beta, s.params.l) &&
		bytes.Equal(hc, hc2[:]) &&
		h.sum(s.params.k) <= s.params.omega
}
