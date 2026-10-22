// Package core provides parameter sets and validation for kMOSAIC.
package core

import (
	"errors"
	"fmt"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
)

// LatticeSignQ is the modulus of the lattice signature component (2^23 - 2^13 + 1).
const LatticeSignQ = 8380417

// SLSSQ is the modulus of the SLSS component.
const SLSSQ = 12289

// CodeHQC256 is the quasi-cyclic syndrome-decoding parameter set, identical
// to NIST's hqc-256 (level 5): ring length 57637, Reed-Solomon [90,32] with
// correction capability 29, Reed-Muller RM(1,7) duplicated 5 times, secret
// weight 131, ephemeral weights 149. Its decryption failure rate is below
// 2^-256 per the HQC specification. It encodes exactly 32 bytes, the size of
// a KEM share, which is why it is used at both levels.
var CodeHQC256 = kmosaic.CodeParams{
	N:     57637,
	N1:    90,
	K:     32,
	Delta: 29,
	Mult:  5,
	W:     131,
	WR:    149,
	WE:    149,
}

// MOS128Params is the KEM parameter set for the MOS-128 level.
//
// SLSS: n = m = 768, q = 12289, σ = 3.19, sparse ternary secrets of weight 192
// estimate at roughly 2^160 classical / 2^145 quantum core-SVP (primal uSVP
// model) for both the key and ciphertext LWE instances.
var MOS128Params = kmosaic.MOSAICParams{
	Level: kmosaic.MOS128,
	SLSS: kmosaic.SLSSParams{
		N:   768,
		M:   768,
		Q:   SLSSQ,
		W:   192,
		Eta: 20,
		L:   256,
		DU:  11,
		DV:  5,
	},
	Code: CodeHQC256,
}

// MOS256Params is the KEM parameter set for the MOS-256 level.
//
// SLSS: n = m = 1152, w = 288 estimate at roughly 2^260 classical / 2^236
// quantum core-SVP.
var MOS256Params = kmosaic.MOSAICParams{
	Level: kmosaic.MOS256,
	SLSS: kmosaic.SLSSParams{
		N:   1152,
		M:   1152,
		Q:   SLSSQ,
		W:   288,
		Eta: 20,
		L:   256,
		DU:  11,
		DV:  5,
	},
	Code: CodeHQC256,
}

// Lattice128Params transplants the ML-DSA-65 (Dilithium3, NIST level 3)
// parameters to unstructured matrices: A is 1536 x 1280 over Z_q, secrets
// have entries in [-4, 4], the challenge has 49 non-zero entries among 256.
// Module structure plays no role in the published core-SVP estimates
// (about 2^182 classical / 2^165 quantum for LWE, 2^174 / 2^158 for SIS).
var Lattice128Params = kmosaic.LatticeSignParams{
	N:          1280,
	M:          1536,
	L:          256,
	Q:          LatticeSignQ,
	Eta:        4,
	Tau:        49,
	Gamma1:     1 << 19,
	Gamma2:     (LatticeSignQ - 1) / 32,
	Beta:       49 * 4,
	D:          13,
	Omega:      55,
	CTildeSize: 48,
}

// Lattice256Params transplants the ML-DSA-87 (Dilithium5, NIST level 5)
// parameters: A is 2048 x 1792, secrets in [-2, 2], 60 non-zero challenge
// entries (about 2^252 classical / 2^229 quantum core-SVP).
var Lattice256Params = kmosaic.LatticeSignParams{
	N:          1792,
	M:          2048,
	L:          256,
	Q:          LatticeSignQ,
	Eta:        2,
	Tau:        60,
	Gamma1:     1 << 19,
	Gamma2:     (LatticeSignQ - 1) / 32,
	Beta:       60 * 2,
	D:          13,
	Omega:      75,
	CTildeSize: 64,
}

// MQ128Params is the uov-Ip parameter set (NIST level 1): 112 variables,
// 44 equations over F_256.
var MQ128Params = kmosaic.MQParams{N: 112, M: 44}

// MQ256Params is the uov-V parameter set (NIST level 5): 244 variables,
// 96 equations over F_256.
var MQ256Params = kmosaic.MQParams{N: 244, M: 96}

// Hash128Params is SLH-DSA-SHAKE-128f (FIPS 205, NIST level 1).
var Hash128Params = kmosaic.HashSignParams{N: 16, H: 66, D: 22, A: 6, K: 33, LgW: 4, M: 34}

// Hash256Params is SLH-DSA-SHAKE-256f (FIPS 205, NIST level 5).
var Hash256Params = kmosaic.HashSignParams{N: 32, H: 68, D: 17, A: 9, K: 35, LgW: 4, M: 49}

// Sign128Params is the composite signature parameter set for MOS-128.
var Sign128Params = kmosaic.SignParams{
	Level:   kmosaic.MOS128,
	Lattice: Lattice128Params,
	MQ:      MQ128Params,
	Hash:    Hash128Params,
}

// Sign256Params is the composite signature parameter set for MOS-256.
var Sign256Params = kmosaic.SignParams{
	Level:   kmosaic.MOS256,
	Lattice: Lattice256Params,
	MQ:      MQ256Params,
	Hash:    Hash256Params,
}

// GetParams returns the KEM parameter set for the given security level.
func GetParams(level kmosaic.SecurityLevel) (kmosaic.MOSAICParams, error) {
	switch level {
	case kmosaic.MOS128:
		return MOS128Params, nil
	case kmosaic.MOS256:
		return MOS256Params, nil
	default:
		return kmosaic.MOSAICParams{}, fmt.Errorf("unknown security level: %s", level)
	}
}

// GetSignParams returns the composite signature parameter set for the given level.
func GetSignParams(level kmosaic.SecurityLevel) (kmosaic.SignParams, error) {
	switch level {
	case kmosaic.MOS128:
		return Sign128Params, nil
	case kmosaic.MOS256:
		return Sign256Params, nil
	default:
		return kmosaic.SignParams{}, fmt.Errorf("unknown security level: %s", level)
	}
}

// GetLatticeSignParams returns the lattice signature parameter set for the given level.
func GetLatticeSignParams(level kmosaic.SecurityLevel) (kmosaic.LatticeSignParams, error) {
	switch level {
	case kmosaic.MOS128:
		return Lattice128Params, nil
	case kmosaic.MOS256:
		return Lattice256Params, nil
	default:
		return kmosaic.LatticeSignParams{}, fmt.Errorf("unknown security level: %s", level)
	}
}

// LatticeLevelFromParams returns the security level whose lattice signature
// parameter set equals params, or an error if it matches none.
func LatticeLevelFromParams(params kmosaic.LatticeSignParams) (kmosaic.SecurityLevel, error) {
	switch params {
	case Lattice128Params:
		return kmosaic.MOS128, nil
	case Lattice256Params:
		return kmosaic.MOS256, nil
	default:
		return "", errors.New("lattice signature parameters do not match a known security level")
	}
}

// ValidateParams validates the KEM parameter set for security and consistency.
func ValidateParams(params kmosaic.MOSAICParams) error {
	if params.SLSS.N <= 0 || params.SLSS.M <= 0 {
		return errors.New("SLSS dimensions must be positive")
	}
	if params.SLSS.W <= 0 || params.SLSS.W > params.SLSS.N {
		return errors.New("SLSS sparsity must be in (0, n]")
	}
	if params.SLSS.Q != SLSSQ {
		return errors.New("SLSS modulus must be 12289")
	}
	if params.SLSS.M < params.SLSS.N {
		return errors.New("SLSS m must be at least n: the ciphertext LWE instance has dimension m")
	}
	if params.SLSS.Eta < 16 || params.SLSS.Eta > 64 {
		return errors.New("SLSS eta must be in [16, 64]")
	}
	if params.SLSS.L <= 0 || params.SLSS.L%8 != 0 {
		return errors.New("SLSS L must be a positive multiple of 8")
	}
	if params.SLSS.DU < 10 || params.SLSS.DU > 14 || params.SLSS.DV < 4 || params.SLSS.DV > 14 {
		return errors.New("SLSS compression bits out of range")
	}
	if err := ValidateCodeParams(params.Code); err != nil {
		return err
	}
	if params.SLSS.L/8 != params.Code.K {
		return errors.New("SLSS and code components must encrypt the same message size")
	}
	return nil
}

// ValidateCodeParams validates the code-based component parameters.
func ValidateCodeParams(p kmosaic.CodeParams) error {
	if p.N <= 0 || p.N1 <= 0 || p.K <= 0 || p.Delta <= 0 || p.Mult <= 0 {
		return errors.New("code parameters must be positive")
	}
	if !isPrime(p.N) {
		return errors.New("code ring length must be prime")
	}
	if p.N1 > 255 || p.K >= p.N1 || p.N1-p.K != 2*p.Delta {
		return errors.New("Reed-Solomon parameters inconsistent: need N1 <= 255 and N1 - K = 2*Delta")
	}
	if p.N1*128*p.Mult > p.N {
		return errors.New("code: N1*N2 must not exceed N")
	}
	if p.W <= 0 || p.WR <= 0 || p.WE <= 0 || p.W > p.N || p.WR > p.N || p.WE > p.N {
		return errors.New("code weights must be in (0, N]")
	}
	return nil
}

// ValidateLatticeSignParams validates a lattice signature parameter set.
func ValidateLatticeSignParams(p kmosaic.LatticeSignParams) error {
	if p.N <= 0 || p.M <= 0 || p.N%256 != 0 || p.M%256 != 0 {
		return errors.New("lattice signature dimensions must be positive multiples of 256")
	}
	if p.L != 256 {
		return errors.New("lattice signature challenge length must be 256")
	}
	if p.Q != LatticeSignQ {
		return errors.New("lattice signature modulus must be 8380417")
	}
	if p.Eta != 2 && p.Eta != 4 {
		return errors.New("eta must be 2 or 4")
	}
	if p.Tau <= 0 || p.Tau > 64 {
		return errors.New("tau must be in (0, 64]")
	}
	if p.Beta != p.Tau*p.Eta {
		return errors.New("beta must equal tau*eta")
	}
	if p.Gamma1 != 1<<19 {
		return errors.New("gamma1 must be 2^19")
	}
	if p.Gamma2 != (LatticeSignQ-1)/32 {
		return errors.New("gamma2 must be (q-1)/32")
	}
	if p.D != 13 {
		return errors.New("d must be 13")
	}
	if p.Omega <= 0 || p.Omega > p.M {
		return errors.New("omega out of range")
	}
	if p.CTildeSize < 32 || p.CTildeSize > 64 {
		return errors.New("challenge hash must be between 32 and 64 bytes")
	}
	return nil
}

// ValidateMQParams validates a UOV parameter set.
func ValidateMQParams(p kmosaic.MQParams) error {
	if p.M <= 0 || p.N <= 2*p.M {
		return errors.New("UOV requires 0 < m and n > 2m")
	}
	return nil
}

// ValidateHashSignParams validates an SLH-DSA parameter set.
func ValidateHashSignParams(p kmosaic.HashSignParams) error {
	if p.N != 16 && p.N != 24 && p.N != 32 {
		return errors.New("SLH-DSA n must be 16, 24 or 32")
	}
	if p.D <= 0 || p.H <= 0 || p.H%p.D != 0 || p.H/p.D > 32 {
		return errors.New("SLH-DSA requires d | h with h/d <= 32")
	}
	if p.H-p.H/p.D > 64 {
		return errors.New("SLH-DSA tree index must fit in 64 bits")
	}
	if p.A <= 0 || p.A > 32 || p.K <= 0 {
		return errors.New("SLH-DSA FORS parameters out of range")
	}
	if p.LgW != 4 {
		return errors.New("SLH-DSA lg_w must be 4")
	}
	expectedM := (p.K*p.A+7)/8 + (p.H-p.H/p.D+7)/8 + (p.H/p.D+7)/8
	if p.M != expectedM {
		return fmt.Errorf("SLH-DSA m must be %d", expectedM)
	}
	return nil
}

// ValidateSignParams validates a composite signature parameter set.
func ValidateSignParams(p kmosaic.SignParams) error {
	if err := ValidateLatticeSignParams(p.Lattice); err != nil {
		return err
	}
	if err := ValidateMQParams(p.MQ); err != nil {
		return err
	}
	return ValidateHashSignParams(p.Hash)
}

// isPrime checks if a number is prime using optimized trial division.
// Uses the 6k±1 optimization since all primes > 3 are of the form 6k±1.
// This is used for validating parameters, not for generating large primes.
func isPrime(n int) bool {
	if n < 2 {
		return false
	}
	if n == 2 || n == 3 {
		return true
	}
	if n%2 == 0 || n%3 == 0 {
		return false
	}
	// Check divisibility by numbers of the form 6k±1
	for i := 5; i*i <= n; i += 6 {
		if n%i == 0 || n%(i+2) == 0 {
			return false
		}
	}
	return true
}
