// Package core provides parameter sets and validation for kMOSAIC.
package core

import (
	"errors"
	"fmt"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
)

// Modulus of the signature scheme (same as CRYSTALS-Dilithium: 2^23 - 2^13 + 1).
const SignQ = 8380417

// MOS128Params is the parameter set for the MOS-128 level.
//
// SLSS (KEM) parameters were chosen with a core-SVP primal (uSVP) estimate:
// n = m = 768, q = 12289, σ = 3.19, sparse ternary secrets of weight 192 give
// roughly 2^160 classical / 2^145 quantum core-SVP for both the key and the
// ciphertext LWE instances, leaving margin for hybrid attacks on the sparse
// secret. (The original n=512, m=384, w=64 set estimated at about 2^65
// classical for the ciphertext instance.)
var MOS128Params = kmosaic.MOSAICParams{
	Level: kmosaic.MOS128,
	SLSS: kmosaic.SLSSParams{
		N:     768,
		M:     768,
		Q:     12289,
		W:     192,
		Sigma: 3.19,
		L:     256,
	},
	TDD: kmosaic.TDDParams{
		N:     24,
		R:     6,
		Q:     7681,
		Sigma: 2.0,
	},
	EGRW: kmosaic.EGRWParams{
		P: 1021,
		K: 128,
	},
}

// MOS256Params is the parameter set for the MOS-256 level.
//
// n = m = 1152, w = 288 estimate at roughly 2^260 classical / 2^236 quantum
// core-SVP, comparable to NIST level 5 lattice KEMs.
var MOS256Params = kmosaic.MOSAICParams{
	Level: kmosaic.MOS256,
	SLSS: kmosaic.SLSSParams{
		N:     1152,
		M:     1152,
		Q:     12289,
		W:     288,
		Sigma: 3.19,
		L:     256,
	},
	TDD: kmosaic.TDDParams{
		N:     36,
		R:     9,
		Q:     7681,
		Sigma: 2.0,
	},
	EGRW: kmosaic.EGRWParams{
		P: 2039,
		K: 256,
	},
}

// Sign128Params is the signature parameter set for MOS-128.
//
// It transplants the ML-DSA-65 (Dilithium3, NIST level 3) parameters to
// unstructured matrices: A is 1536 x 1280 over Z_q, secrets have entries in
// [-4, 4], the challenge has 49 non-zero entries among 256. The module
// structure of Dilithium plays no role in the published core-SVP estimates
// (about 2^182 classical / 2^165 quantum for LWE, 2^174 / 2^158 for SIS), so
// those estimates carry over.
var Sign128Params = kmosaic.SignParams{
	N:          1280,
	M:          1536,
	L:          256,
	Q:          SignQ,
	Eta:        4,
	Tau:        49,
	Gamma1:     1 << 19,
	Gamma2:     (SignQ - 1) / 32,
	Beta:       49 * 4,
	CTildeSize: 48,
}

// Sign256Params is the signature parameter set for MOS-256.
//
// It transplants the ML-DSA-87 (Dilithium5, NIST level 5) parameters:
// A is 2048 x 1792, secrets in [-2, 2], 60 non-zero challenge entries
// (about 2^252 classical / 2^229 quantum core-SVP).
var Sign256Params = kmosaic.SignParams{
	N:          1792,
	M:          2048,
	L:          256,
	Q:          SignQ,
	Eta:        2,
	Tau:        60,
	Gamma1:     1 << 19,
	Gamma2:     (SignQ - 1) / 32,
	Beta:       60 * 2,
	CTildeSize: 64,
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

// GetSignParams returns the signature parameter set for the given security level.
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

// SignLevelFromParams returns the security level whose signature parameter
// set equals params, or an error if it matches none.
func SignLevelFromParams(params kmosaic.SignParams) (kmosaic.SecurityLevel, error) {
	switch params {
	case Sign128Params:
		return kmosaic.MOS128, nil
	case Sign256Params:
		return kmosaic.MOS256, nil
	default:
		return "", errors.New("signature parameters do not match a known security level")
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
	if !isPrime(params.SLSS.Q) {
		return errors.New("SLSS modulus must be prime")
	}
	if params.SLSS.M < params.SLSS.N {
		return errors.New("SLSS m must be at least n: the ciphertext LWE instance has dimension m")
	}
	if params.SLSS.Sigma < 3.0 {
		return errors.New("SLSS sigma should be at least 3.0")
	}
	if params.SLSS.L <= 0 || params.SLSS.L%8 != 0 {
		return errors.New("SLSS L must be a positive multiple of 8")
	}
	if params.TDD.N <= 0 || params.TDD.R <= 0 {
		return errors.New("TDD dimensions must be positive")
	}
	if params.TDD.R > params.TDD.N {
		return errors.New("TDD rank cannot exceed dimension")
	}
	if !isPrime(params.EGRW.P) {
		return errors.New("EGRW prime must be prime")
	}
	if params.EGRW.K < 64 {
		return errors.New("EGRW walk length should be at least 64")
	}
	return nil
}

// ValidateSignParams validates a signature parameter set for consistency.
func ValidateSignParams(p kmosaic.SignParams) error {
	if p.N <= 0 || p.M <= 0 || p.L <= 0 {
		return errors.New("signature dimensions must be positive")
	}
	if p.Q != SignQ {
		return errors.New("signature modulus must be 8380417")
	}
	if p.Eta <= 0 || p.Tau <= 0 || p.Tau > p.L {
		return errors.New("invalid eta or tau")
	}
	if p.Beta != p.Tau*p.Eta {
		return errors.New("beta must equal tau*eta")
	}
	if p.Gamma1 != 1<<19 {
		return errors.New("gamma1 must be 2^19")
	}
	if p.Gamma2 <= p.Beta || (p.Q-1)%(2*p.Gamma2) != 0 {
		return errors.New("gamma2 must exceed beta and 2*gamma2 must divide q-1")
	}
	if p.CTildeSize < 32 {
		return errors.New("challenge hash must be at least 32 bytes")
	}
	return nil
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
