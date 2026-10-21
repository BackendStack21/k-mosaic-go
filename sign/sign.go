// Package sign implements the kMOSAIC digital signature scheme.
//
// The scheme is a Fiat-Shamir-with-aborts lattice signature: the construction
// of CRYSTALS-Dilithium (FIPS 204, ML-DSA) instantiated over unstructured
// matrices in Z_q rather than polynomial rings. The public key is
// (ρ, T = A·S1 + S2 mod q) with A ∈ Z_q^{M×N} expanded from ρ and S1, S2 small;
// a signature on message M is (c̃, z) with
//
//	y   ← uniform in (-γ1, γ1]^N
//	w1  = HighBits(A·y)
//	c̃   = H(H(tr || M) || w1),   c = SampleInBall(c̃)
//	z   = y + S1·c,               restart unless ||z||∞ < γ1 - β
//	                              and ||LowBits(A·y - S2·c)||∞ < γ2 - β
//
// and verification recomputes w1 as HighBits(A·z - T·c) and checks c̃.
// Security reduces to unstructured LWE (key recovery) and SIS (forgery) with
// the parameters of ML-DSA-65 / ML-DSA-87.
//
// The previous kMOSAIC signature derived its "response" as a hash of the
// secret key that the verifier never checked, so anyone holding the public key
// could forge signatures on arbitrary messages. That construction is gone.
package sign

import (
	"encoding/binary"
	"errors"
	"fmt"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

const (
	// DomainKeyGen separates the key-generation seed expansion.
	DomainKeyGen = "kmosaic-sign-keygen-v2"

	// SeedSize is the size of the public matrix seed ρ and the PRF key K.
	SeedSize = 32
	// TrSize is the size of tr = H(pk) and of μ = H(tr || M).
	TrSize = 64

	// MaxComponentSize bounds any length prefix read during deserialization.
	MaxComponentSize = 64 * 1024 * 1024

	// maxSignAttempts bounds the rejection-sampling loop. The acceptance rate
	// is about 1/4 per attempt, so hitting this bound is a broken key or RNG.
	maxSignAttempts = 1024

	// zBytes is the packed size of one response coefficient (20 bits + γ1 offset).
	zBytes = 3
	// tBytes is the packed size of one public-key coefficient (23 bits).
	tBytes = 3
)

// GenerateKeyPair generates a signature key pair for the given security level.
func GenerateKeyPair(level kmosaic.SecurityLevel) (result *kmosaic.MOSAICSignKeyPair, err error) {
	defer func() {
		if r := recover(); r != nil {
			result = nil
			err = fmt.Errorf("signature key generation panic: %v", r)
		}
	}()

	params, err := core.GetSignParams(level)
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

// GenerateKeyPairFromSeed deterministically generates a signature key pair.
func GenerateKeyPairFromSeed(params kmosaic.SignParams, seed []byte) (*kmosaic.MOSAICSignKeyPair, error) {
	if len(seed) < SeedSize {
		return nil, errors.New("seed must be at least 32 bytes")
	}
	if err := utils.ValidateSeedEntropy(seed); err != nil {
		return nil, err
	}
	if err := core.ValidateSignParams(params); err != nil {
		return nil, err
	}
	if _, err := core.SignLevelFromParams(params); err != nil {
		return nil, err
	}

	n, m, l, q, eta := params.N, params.M, params.L, params.Q, params.Eta

	// (ρ, ρ', K) = H(seed || N || M || L)
	expanded := utils.Shake256WithDomain(DomainKeyGen,
		append(append(append(append([]byte{}, seed...), uint32LE(uint32(n))...), uint32LE(uint32(m))...), uint32LE(uint32(l))...),
		SeedSize+TrSize+SeedSize)
	rho := append([]byte{}, expanded[:SeedSize]...)
	rhoPrime := expanded[SeedSize : SeedSize+TrSize]
	K := append([]byte{}, expanded[SeedSize+TrSize:]...)
	defer utils.Zeroize(expanded)

	A := expandA(rho, m, n, q)
	S1 := sampleEta(rhoPrime, 0, n*l, eta)
	S2 := sampleEta(rhoPrime, 1, m*l, eta)
	T := computeT(A, S1, S2, m, n, l, q)

	publicKey := kmosaic.MOSAICSignPublicKey{Params: params, Rho: rho, T: T, A: A}
	tr := shake(TrSize, SerializePublicKey(&publicKey))

	secretKey := kmosaic.MOSAICSignSecretKey{
		Params: params,
		Rho:    append([]byte{}, rho...),
		K:      K,
		Tr:     tr,
		S1:     S1,
		S2:     S2,
		A:      A,
	}
	return &kmosaic.MOSAICSignKeyPair{PublicKey: publicKey, SecretKey: secretKey}, nil
}

// checkSecretKey validates the shape of a secret key.
func checkSecretKey(sk *kmosaic.MOSAICSignSecretKey) error {
	p := sk.Params
	if err := core.ValidateSignParams(p); err != nil {
		return err
	}
	if len(sk.Rho) != SeedSize || len(sk.K) != SeedSize || len(sk.Tr) != TrSize {
		return errors.New("invalid secret key: wrong seed or hash length")
	}
	if len(sk.S1) != p.N*p.L || len(sk.S2) != p.M*p.L {
		return errors.New("invalid secret key: wrong matrix dimensions")
	}
	for _, s := range sk.S1 {
		if int(s) > p.Eta || int(s) < -p.Eta {
			return errors.New("invalid secret key: S1 entry out of range")
		}
	}
	for _, s := range sk.S2 {
		if int(s) > p.Eta || int(s) < -p.Eta {
			return errors.New("invalid secret key: S2 entry out of range")
		}
	}
	return nil
}

// checkPublicKey validates the shape of a public key.
func checkPublicKey(pk *kmosaic.MOSAICSignPublicKey) error {
	p := pk.Params
	if err := core.ValidateSignParams(p); err != nil {
		return err
	}
	if len(pk.Rho) != SeedSize {
		return errors.New("invalid public key: wrong seed length")
	}
	if len(pk.T) != p.M*p.L {
		return errors.New("invalid public key: wrong T dimensions")
	}
	return nil
}

// Sign creates a signature on message with sk. pk, if non-nil, must be the
// matching public key; it is checked against the hash stored in sk.
// Signing is hedged: fresh randomness is mixed into the mask derivation so
// that a faulty RNG degrades to deterministic (still secure) signing.
func Sign(sk *kmosaic.MOSAICSignSecretKey, pk *kmosaic.MOSAICSignPublicKey, message []byte) (result *kmosaic.MOSAICSignature, err error) {
	defer func() {
		if r := recover(); r != nil {
			result = nil
			err = fmt.Errorf("signature creation panic: %v", r)
		}
	}()

	if err := checkSecretKey(sk); err != nil {
		return nil, err
	}
	if pk != nil {
		if err := checkPublicKey(pk); err != nil {
			return nil, err
		}
		if !utils.ConstantTimeEqual(sk.Tr, shake(TrSize, SerializePublicKey(pk))) {
			return nil, errors.New("public key does not match secret key")
		}
	}

	p := sk.Params
	n, m, l, q := p.N, p.M, p.L, p.Q
	A := sk.A
	if len(A) != m*n {
		A = expandA(sk.Rho, m, n, q)
	}

	rnd, err := utils.SecureRandomBytes(SeedSize)
	if err != nil {
		return nil, err
	}
	defer utils.Zeroize(rnd)

	mu := shake(TrSize, sk.Tr, message)
	rhoPrime := shake(TrSize, sk.K, rnd, mu)
	defer utils.Zeroize(rhoPrime)

	zBound := int32(p.Gamma1 - p.Beta)
	r0Bound := int32(p.Gamma2 - p.Beta)

	for kappa := 0; kappa < maxSignAttempts; kappa++ {
		y := expandMask(rhoPrime, uint16(kappa), n, p.Gamma1)
		w := matVec(A, y, m, n, q)
		w1 := highBits(w, q, p.Gamma2)
		ctilde := shake(p.CTildeSize, mu, packW1(w1))
		c := sampleInBall(ctilde, p.Tau, l)

		z := mulSmall(sk.S1, c, n, l)
		for i := range z {
			z[i] += y[i]
		}
		utils.ZeroizeInt32(y)
		if infNorm(z) >= zBound {
			utils.ZeroizeInt32(z)
			continue
		}

		s2c := mulSmall(sk.S2, c, m, l)
		for i := range s2c {
			s2c[i] = modQ(int64(w[i])-int64(s2c[i]), q)
		}
		r0 := lowBits(s2c, q, p.Gamma2)
		utils.ZeroizeInt32(s2c)
		if infNorm(r0) >= r0Bound {
			utils.ZeroizeInt32(z)
			continue
		}

		return &kmosaic.MOSAICSignature{Challenge: ctilde, Z: z}, nil
	}
	return nil, errors.New("signing failed: rejection sampling did not terminate")
}

// Verify reports whether sig is a valid signature on message under pk.
func Verify(pk *kmosaic.MOSAICSignPublicKey, message []byte, sig *kmosaic.MOSAICSignature) (isValid bool) {
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
	n, m, l, q := p.N, p.M, p.L, p.Q

	if len(sig.Challenge) != p.CTildeSize || len(sig.Z) != n {
		return false
	}
	if infNorm(sig.Z) >= int32(p.Gamma1-p.Beta) {
		return false
	}

	A := pk.A
	if len(A) != m*n {
		A = expandA(pk.Rho, m, n, q)
	}

	tr := shake(TrSize, SerializePublicKey(pk))
	mu := shake(TrSize, tr, message)
	c := sampleInBall(sig.Challenge, p.Tau, l)

	// w' = A·z - T·c = A·y - S2·c, whose HighBits equal HighBits(A·y) by construction.
	w := matVec(A, sig.Z, m, n, q)
	tc := mulT(pk.T, c, m, l, q)
	for i := range w {
		w[i] = modQ(int64(w[i])-int64(tc[i]), q)
	}
	w1 := highBits(w, q, p.Gamma2)
	expected := shake(p.CTildeSize, mu, packW1(w1))

	return utils.ConstantTimeEqual(sig.Challenge, expected)
}

// -----------------------------------------------------------------------------
// Serialization
// -----------------------------------------------------------------------------

func levelBytes(params kmosaic.SignParams) []byte {
	level, err := core.SignLevelFromParams(params)
	if err != nil {
		return nil
	}
	return []byte(level)
}

func put3(buf []byte, v uint32) {
	buf[0] = byte(v)
	buf[1] = byte(v >> 8)
	buf[2] = byte(v >> 16)
}

func get3(buf []byte) uint32 {
	return uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16
}

// SerializePublicKey serializes a signature public key as
// [level_len:4][level][rho:32][t_count:4][T entries, 3 bytes each].
func SerializePublicKey(pk *kmosaic.MOSAICSignPublicKey) []byte {
	lvl := levelBytes(pk.Params)
	result := make([]byte, 0, 4+len(lvl)+SeedSize+4+tBytes*len(pk.T))
	result = append(result, uint32LE(uint32(len(lvl)))...)
	result = append(result, lvl...)
	result = append(result, pk.Rho...)
	result = append(result, uint32LE(uint32(len(pk.T)))...)
	buf := make([]byte, tBytes)
	for _, v := range pk.T {
		put3(buf, uint32(v))
		result = append(result, buf...)
	}
	return result
}

// DeserializePublicKey parses a public key written by SerializePublicKey and
// expands the matrix A.
func DeserializePublicKey(data []byte) (*kmosaic.MOSAICSignPublicKey, error) {
	off := 0
	if off+4 > len(data) {
		return nil, errors.New("invalid public key data: too short")
	}
	lvlLen := int(binary.LittleEndian.Uint32(data[off:]))
	off += 4
	if lvlLen > MaxComponentSize || off+lvlLen > len(data) {
		return nil, errors.New("invalid public key: security level truncated")
	}
	params, err := core.GetSignParams(kmosaic.SecurityLevel(data[off : off+lvlLen]))
	if err != nil {
		return nil, err
	}
	off += lvlLen

	if off+SeedSize+4 > len(data) {
		return nil, errors.New("invalid public key: truncated")
	}
	rho := append([]byte{}, data[off:off+SeedSize]...)
	off += SeedSize
	tCount := int(binary.LittleEndian.Uint32(data[off:]))
	off += 4
	if tCount != params.M*params.L {
		return nil, errors.New("invalid public key: T dimension mismatch with params")
	}
	if len(data) != off+tBytes*tCount {
		return nil, errors.New("invalid public key: wrong length")
	}
	T := make([]int32, tCount)
	for i := 0; i < tCount; i++ {
		v := get3(data[off+tBytes*i:])
		if int(v) >= params.Q {
			return nil, errors.New("invalid public key: T entry out of range")
		}
		T[i] = int32(v)
	}

	pk := &kmosaic.MOSAICSignPublicKey{Params: params, Rho: rho, T: T}
	pk.A = expandA(rho, params.M, params.N, params.Q)
	return pk, nil
}

// SerializeSecretKey serializes a signature secret key as
// [level_len:4][level][rho:32][K:32][tr:64][s1_count:4][S1 bytes][s2_count:4][S2 bytes].
func SerializeSecretKey(sk *kmosaic.MOSAICSignSecretKey) []byte {
	lvl := levelBytes(sk.Params)
	result := make([]byte, 0, 4+len(lvl)+SeedSize+SeedSize+TrSize+8+len(sk.S1)+len(sk.S2))
	result = append(result, uint32LE(uint32(len(lvl)))...)
	result = append(result, lvl...)
	result = append(result, sk.Rho...)
	result = append(result, sk.K...)
	result = append(result, sk.Tr...)
	result = append(result, uint32LE(uint32(len(sk.S1)))...)
	for _, s := range sk.S1 {
		result = append(result, byte(s))
	}
	result = append(result, uint32LE(uint32(len(sk.S2)))...)
	for _, s := range sk.S2 {
		result = append(result, byte(s))
	}
	return result
}

// DeserializeSecretKey parses a secret key written by SerializeSecretKey.
func DeserializeSecretKey(data []byte) (*kmosaic.MOSAICSignSecretKey, error) {
	off := 0
	if off+4 > len(data) {
		return nil, errors.New("invalid secret key data: too short")
	}
	lvlLen := int(binary.LittleEndian.Uint32(data[off:]))
	off += 4
	if lvlLen > MaxComponentSize || off+lvlLen > len(data) {
		return nil, errors.New("invalid secret key: security level truncated")
	}
	params, err := core.GetSignParams(kmosaic.SecurityLevel(data[off : off+lvlLen]))
	if err != nil {
		return nil, err
	}
	off += lvlLen

	if off+SeedSize+SeedSize+TrSize+4 > len(data) {
		return nil, errors.New("invalid secret key: truncated")
	}
	sk := &kmosaic.MOSAICSignSecretKey{Params: params}
	sk.Rho = append([]byte{}, data[off:off+SeedSize]...)
	off += SeedSize
	sk.K = append([]byte{}, data[off:off+SeedSize]...)
	off += SeedSize
	sk.Tr = append([]byte{}, data[off:off+TrSize]...)
	off += TrSize

	readSmall := func(expected int) ([]int8, error) {
		if off+4 > len(data) {
			return nil, errors.New("invalid secret key: missing matrix length")
		}
		count := int(binary.LittleEndian.Uint32(data[off:]))
		off += 4
		if count != expected {
			return nil, errors.New("invalid secret key: matrix dimension mismatch with params")
		}
		if off+count > len(data) {
			return nil, errors.New("invalid secret key: matrix truncated")
		}
		out := make([]int8, count)
		for i := 0; i < count; i++ {
			v := int8(data[off+i])
			if int(v) > params.Eta || int(v) < -params.Eta {
				return nil, errors.New("invalid secret key: entry out of range")
			}
			out[i] = v
		}
		off += count
		return out, nil
	}
	if sk.S1, err = readSmall(params.N * params.L); err != nil {
		return nil, err
	}
	if sk.S2, err = readSmall(params.M * params.L); err != nil {
		return nil, err
	}
	if off != len(data) {
		return nil, errors.New("invalid secret key: trailing data")
	}
	sk.A = expandA(sk.Rho, params.M, params.N, params.Q)
	return sk, nil
}

// SerializeSignature serializes a signature as
// [ctilde_len:4][ctilde][z_count:4][z entries + gamma1, 3 bytes each].
func SerializeSignature(sig *kmosaic.MOSAICSignature) []byte {
	result := make([]byte, 0, 8+len(sig.Challenge)+zBytes*len(sig.Z))
	result = append(result, uint32LE(uint32(len(sig.Challenge)))...)
	result = append(result, sig.Challenge...)
	result = append(result, uint32LE(uint32(len(sig.Z)))...)
	buf := make([]byte, zBytes)
	gamma1 := int32(1 << 19)
	for _, z := range sig.Z {
		put3(buf, uint32(z+gamma1))
		result = append(result, buf...)
	}
	return result
}

// DeserializeSignature parses a signature written by SerializeSignature.
// Range checks on z are performed by Verify.
func DeserializeSignature(data []byte) (*kmosaic.MOSAICSignature, error) {
	off := 0
	if off+4 > len(data) {
		return nil, errors.New("invalid signature data: too short")
	}
	cLen := int(binary.LittleEndian.Uint32(data[off:]))
	off += 4
	if cLen < 32 || cLen > 64 {
		return nil, errors.New("invalid signature: challenge length out of range")
	}
	if off+cLen > len(data) {
		return nil, errors.New("invalid signature: challenge truncated")
	}
	sig := &kmosaic.MOSAICSignature{Challenge: append([]byte{}, data[off:off+cLen]...)}
	off += cLen

	if off+4 > len(data) {
		return nil, errors.New("invalid signature: missing response length")
	}
	zCount := int(binary.LittleEndian.Uint32(data[off:]))
	off += 4
	if zCount > utils.MaxVectorLength {
		return nil, errors.New("invalid signature: response length exceeds limit")
	}
	if len(data) != off+zBytes*zCount {
		return nil, errors.New("invalid signature: wrong length")
	}
	gamma1 := int32(1 << 19)
	sig.Z = make([]int32, zCount)
	for i := 0; i < zCount; i++ {
		sig.Z[i] = int32(get3(data[off+zBytes*i:])) - gamma1
	}
	return sig, nil
}
