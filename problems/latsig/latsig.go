// Package latsig implements the lattice component of the kMOSAIC signature.
//
// The scheme is CRYSTALS-Dilithium (FIPS 204, ML-DSA) instantiated over
// unstructured matrices in Z_q rather than polynomial rings. With A ∈ Z_q^{M×N}
// expanded from ρ and S1, S2 small, T = A·S1 + S2 mod q is split by
// Power2Round into (T1, T0); the public key is (ρ, T1) and the secret key
// keeps T0. A signature on message M is (c̃, z, h) with
//
//	μ   = H(tr || M),             tr = H(pk)
//	y   ← uniform in (-γ1, γ1]^N
//	w   = A·y,  w1 = HighBits(w)
//	c̃   = H(μ || w1),             c = SampleInBall(c̃)
//	z   = y + S1·c,               restart unless ||z||∞ < γ1 - β,
//	                              ||LowBits(w - S2·c)||∞ < γ2 - β and
//	                              ||T0·c||∞ < γ2
//	h   = MakeHint(-T0·c, w - S2·c + T0·c), restart if more than ω hints
//
// and verification recomputes w1 as UseHint(h, A·z - T1·c·2^d) and checks c̃.
// Security reduces to unstructured LWE (key recovery) and SIS (forgery) with
// the parameters of ML-DSA-65 / ML-DSA-87.
package latsig

import (
	"errors"
	"fmt"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

const (
	// DomainKeyGen separates the key-generation seed expansion.
	DomainKeyGen = "kmosaic-latsig-keygen-v4"

	// SeedSize is the size of the public matrix seed ρ and the PRF key K.
	SeedSize = 32
	// TrSize is the size of tr = H(pk) and of μ = H(tr || M).
	TrSize = 64

	// MaxComponentSize is retained for API compatibility. The v4 encodings
	// have fixed sizes per level; the only length prefix (the level string)
	// is bounded by 32 bytes.
	MaxComponentSize = 64 * 1024 * 1024

	// maxSignAttempts bounds the rejection-sampling loop. The expected number
	// of attempts is about 5 (ML-DSA-65 shape) or 4 (ML-DSA-87 shape), so
	// hitting this bound means a broken key or RNG.
	maxSignAttempts = 1024
)

// GenerateKeyPair generates a signature key pair for the given security level.
func GenerateKeyPair(level kmosaic.SecurityLevel) (result *kmosaic.LatticeSignKeyPair, err error) {
	defer func() {
		if r := recover(); r != nil {
			result = nil
			err = fmt.Errorf("signature key generation panic: %v", r)
		}
	}()

	params, err := core.GetLatticeSignParams(level)
	if err != nil {
		return nil, err
	}

	seed, err := utils.SecureRandomBytes(SeedSize)
	if err != nil {
		return nil, err
	}
	defer utils.Zeroize(seed)

	return GenerateKeyPairFromSeed(params, seed)
}

// checkParams requires a valid parameter set that matches a known level.
func checkParams(p kmosaic.LatticeSignParams) error {
	if err := core.ValidateLatticeSignParams(p); err != nil {
		return err
	}
	_, err := core.LatticeLevelFromParams(p)
	return err
}

// GenerateKeyPairFromSeed deterministically generates a signature key pair.
func GenerateKeyPairFromSeed(params kmosaic.LatticeSignParams, seed []byte) (*kmosaic.LatticeSignKeyPair, error) {
	if len(seed) < SeedSize {
		return nil, errors.New("seed must be at least 32 bytes")
	}
	if err := utils.ValidateSeedEntropy(seed); err != nil {
		return nil, err
	}
	if err := checkParams(params); err != nil {
		return nil, err
	}

	n, m, l, eta := params.N, params.M, params.L, params.Eta

	// (ρ, ρ', K) = H(seed || N || M || L)
	input := make([]byte, 0, len(seed)+12)
	input = append(input, seed...)
	input = append(input, uint32LE(uint32(n))...)
	input = append(input, uint32LE(uint32(m))...)
	input = append(input, uint32LE(uint32(l))...)
	expanded := utils.Shake256WithDomain(DomainKeyGen, input, SeedSize+TrSize+SeedSize)
	utils.Zeroize(input)
	defer utils.Zeroize(expanded)
	rho := append([]byte{}, expanded[:SeedSize]...)
	rhoPrime := expanded[SeedSize : SeedSize+TrSize]
	K := append([]byte{}, expanded[SeedSize+TrSize:]...)

	A := expandA(rho, m, n)
	S1 := sampleEta(rhoPrime, 0, n*l, eta)
	S2 := sampleEta(rhoPrime, 1, m*l, eta)
	T := computeT(A, S1, S2, m, n)
	T1 := make([]int32, len(T))
	T0 := make([]int32, len(T))
	for i, t := range T {
		T1[i], T0[i] = power2Round(t)
	}
	utils.ZeroizeInt32(T)

	publicKey := kmosaic.LatticeSignPublicKey{Params: params, Rho: rho, T1: T1, A: A}
	publicKey.Tr = shake(TrSize, SerializePublicKey(&publicKey))

	secretKey := kmosaic.LatticeSignSecretKey{
		Params: params,
		Rho:    append([]byte{}, rho...),
		K:      K,
		Tr:     append([]byte{}, publicKey.Tr...),
		S1:     S1,
		S2:     S2,
		T0:     T0,
		A:      A,
	}
	return &kmosaic.LatticeSignKeyPair{PublicKey: publicKey, SecretKey: secretKey}, nil
}

// checkSecretKey validates the parameters and shape of a secret key. Entry
// ranges are checked by DeserializeSecretKey, not on every signature.
func checkSecretKey(sk *kmosaic.LatticeSignSecretKey) error {
	p := sk.Params
	if err := checkParams(p); err != nil {
		return err
	}
	if len(sk.Rho) != SeedSize || len(sk.K) != SeedSize || len(sk.Tr) != TrSize {
		return errors.New("invalid secret key: wrong seed or hash length")
	}
	if len(sk.S1) != p.N*chalLen || len(sk.S2) != p.M*chalLen || len(sk.T0) != p.M*chalLen {
		return errors.New("invalid secret key: wrong matrix dimensions")
	}
	return nil
}

// checkPublicKey validates the parameters and shape of a public key.
func checkPublicKey(pk *kmosaic.LatticeSignPublicKey) error {
	p := pk.Params
	if err := checkParams(p); err != nil {
		return err
	}
	if len(pk.Rho) != SeedSize {
		return errors.New("invalid public key: wrong seed length")
	}
	if len(pk.T1) != p.M*chalLen {
		return errors.New("invalid public key: wrong T1 dimensions")
	}
	return nil
}

// publicKeyHash returns pk.Tr when it is cached and SHAKE256(pk, 64) otherwise
// (nil if pk cannot be serialized).
func publicKeyHash(pk *kmosaic.LatticeSignPublicKey) []byte {
	if len(pk.Tr) == TrSize {
		return pk.Tr
	}
	enc := SerializePublicKey(pk)
	if enc == nil {
		return nil
	}
	return shake(TrSize, enc)
}

// Sign creates a signature on message with sk. pk, if non-nil, must be the
// matching public key; its hash is compared with the one stored in sk.
// Signing is hedged: fresh randomness is mixed into the mask derivation so
// that a faulty RNG degrades to deterministic (still secure) signing.
func Sign(sk *kmosaic.LatticeSignSecretKey, pk *kmosaic.LatticeSignPublicKey, message []byte) (result *kmosaic.LatticeSignature, err error) {
	defer func() {
		if r := recover(); r != nil {
			result = nil
			err = fmt.Errorf("signature creation panic: %v", r)
		}
	}()

	if sk == nil {
		return nil, errors.New("nil secret key")
	}
	if err := checkSecretKey(sk); err != nil {
		return nil, err
	}
	if pk != nil {
		if pk.Params != sk.Params {
			return nil, errors.New("public key does not match secret key")
		}
		if err := checkPublicKey(pk); err != nil {
			return nil, err
		}
		tr := publicKeyHash(pk)
		if tr == nil || !utils.ConstantTimeEqual(sk.Tr, tr) {
			return nil, errors.New("public key does not match secret key")
		}
	}

	rnd, err := utils.SecureRandomBytes(SeedSize)
	if err != nil {
		return nil, err
	}
	defer utils.Zeroize(rnd)

	sig, _, err := signInternal(sk, message, rnd, signLane)
	return sig, err
}

// signScratch holds every per-signature buffer so that all of them, secret
// or not, are zeroized on every exit path of Sign.
type signScratch struct {
	ys  []int32           // signLane masks, interleaved
	w   [signLane][]int32 // A·y for each lane
	w1  []int32           // HighBits(w) of the current attempt
	w1p []byte            // packed w1
	z   []int32           // y + S1·c
	cs2 []int32           // S2·c
	r   []int32           // w - S2·c mod q
	ct0 []int32           // T0·c
}

func newSignScratch(n, m int) *signScratch {
	s := &signScratch{
		ys:  make([]int32, signLane*n),
		w1:  make([]int32, m),
		w1p: make([]byte, m*w1Bits/8),
		z:   make([]int32, n),
		cs2: make([]int32, m),
		r:   make([]int32, m),
		ct0: make([]int32, m),
	}
	for j := range s.w {
		s.w[j] = make([]int32, m)
	}
	return s
}

func (s *signScratch) wipe() {
	utils.ZeroizeInt32(s.ys)
	for j := range s.w {
		utils.ZeroizeInt32(s.w[j])
	}
	utils.ZeroizeInt32(s.w1)
	utils.Zeroize(s.w1p)
	utils.ZeroizeInt32(s.z)
	utils.ZeroizeInt32(s.cs2)
	utils.ZeroizeInt32(s.r)
	utils.ZeroizeInt32(s.ct0)
}

// signInternal runs the rejection-sampling loop with hedging randomness rnd.
// Masks are derived for attempts κ = 0, 1, 2, ... exactly as in sequential
// signing; batch (1..signLane) of them are expanded per pass over A and the
// attempts are then tried in κ order, so the first accepted attempt, and
// hence the output, does not depend on batch. It also returns the number of
// attempts consumed (for tests).
func signInternal(sk *kmosaic.LatticeSignSecretKey, message, rnd []byte, batch int) (*kmosaic.LatticeSignature, int, error) {
	p := sk.Params
	n, m := p.N, p.M
	A := sk.A
	if len(A) != m*n {
		A = expandA(sk.Rho, m, n)
	}

	mu := shake(TrSize, sk.Tr, message)
	rhoPrime := shake(TrSize, sk.K, rnd, mu)
	defer utils.Zeroize(rhoPrime)

	s := newSignScratch(n, m)
	defer s.wipe()

	for base := 0; base < maxSignAttempts; base += batch {
		for j := 0; j < batch; j++ {
			expandMaskLane(rhoPrime, uint16(base+j), n, s.ys, j)
		}
		matVec4(A, s.ys, m, n, &s.w)
		for j := 0; j < batch; j++ {
			if sig := s.attempt(sk, mu, j); sig != nil {
				return sig, base + j + 1, nil
			}
		}
	}
	return nil, maxSignAttempts, errors.New("signing failed: rejection sampling did not terminate")
}

// attempt runs one signing attempt on lane j of the scratch space and
// returns the signature, or nil if the attempt is rejected.
func (s *signScratch) attempt(sk *kmosaic.LatticeSignSecretKey, mu []byte, j int) *kmosaic.LatticeSignature {
	p := sk.Params
	n, m := p.N, p.M
	w := s.w[j]

	for i, v := range w {
		s.w1[i] = highBits(v)
	}
	packW1(s.w1, s.w1p)
	ctilde := shake(p.CTildeSize, mu, s.w1p)
	_, c := sampleInBall(ctilde, p.Tau)

	// z = y + S1·c
	mulSparse8(sk.S1, &c, n, s.z)
	for k := range s.z {
		s.z[k] += s.ys[signLane*k+j]
	}
	if normU(s.z) >= uint32(p.Gamma1-p.Beta) {
		return nil
	}

	// r = w - S2·c; reject unless ||LowBits(r)||∞ < γ2 - β.
	mulSparse8(sk.S2, &c, m, s.cs2)
	var r0Norm uint32
	for i, v := range w {
		r := freeze(v - s.cs2[i])
		s.r[i] = r
		_, r0 := decompose(r)
		a := absU(r0)
		mask := -uint32((uint64(r0Norm) - uint64(a)) >> 63)
		r0Norm = (r0Norm &^ mask) | (a & mask)
	}
	if r0Norm >= uint32(p.Gamma2-p.Beta) {
		return nil
	}

	// T0·c must be below γ2 so that the hints recover HighBits(w).
	mulSparse32(sk.T0, &c, m, s.ct0)
	if normU(s.ct0) >= uint32(p.Gamma2) {
		return nil
	}

	// h = MakeHint(-T0·c, w - S2·c + T0·c): h_i = 1 iff
	// HighBits(r_i + ct0_i) != HighBits(r_i).
	var count int32
	for i, r := range s.r {
		count += makeHint(-s.ct0[i], freeze(r+s.ct0[i]))
	}
	if int(count) > p.Omega {
		return nil
	}
	hint := make([]uint16, 0, count)
	for i, r := range s.r {
		if makeHint(-s.ct0[i], freeze(r+s.ct0[i])) != 0 {
			hint = append(hint, uint16(i))
		}
	}
	return &kmosaic.LatticeSignature{Challenge: ctilde, Z: append([]int32{}, s.z...), Hint: hint}
}

// recoverW1 computes UseHint(h, A·z - T1·c·2^d) for a well-formed signature
// on a well-formed public key.
func recoverW1(pk *kmosaic.LatticeSignPublicKey, sig *kmosaic.LatticeSignature, c *challenge) []int32 {
	p := pk.Params
	n, m := p.N, p.M
	A := pk.A
	if len(A) != m*n {
		A = expandA(pk.Rho, m, n)
	}
	ct1 := make([]int32, m)
	mulSparse32(pk.T1, c, m, ct1)
	w := make([]int32, m)
	matVec(A, sig.Z, ct1, m, n, w)
	hi := 0
	for i, v := range w {
		var h int32
		if hi < len(sig.Hint) && int(sig.Hint[hi]) == i {
			h = 1
			hi++
		}
		w[i] = useHint(h, v)
	}
	return w
}

// Verify reports whether sig is a valid signature on message under pk.
func Verify(pk *kmosaic.LatticeSignPublicKey, message []byte, sig *kmosaic.LatticeSignature) (isValid bool) {
	defer func() {
		if r := recover(); r != nil {
			isValid = false
		}
	}()

	if pk == nil || sig == nil {
		return false
	}
	if err := checkPublicKey(pk); err != nil {
		return false
	}
	p := pk.Params
	if len(sig.Challenge) != p.CTildeSize || len(sig.Z) != p.N || !checkHints(sig.Hint, p) {
		return false
	}
	if normU(sig.Z) >= uint32(p.Gamma1-p.Beta) {
		return false
	}

	tr := publicKeyHash(pk)
	if tr == nil {
		return false
	}
	mu := shake(TrSize, tr, message)
	_, c := sampleInBall(sig.Challenge, p.Tau)

	w1 := recoverW1(pk, sig, &c)
	w1p := make([]byte, p.M*w1Bits/8)
	packW1(w1, w1p)
	expected := shake(p.CTildeSize, mu, w1p)
	return utils.ConstantTimeEqual(sig.Challenge, expected)
}
