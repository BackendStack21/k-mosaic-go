// Package core provides parameter sets and validation for kMOSAIC.
package core

import (
	"errors"
	"fmt"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
)

// MOS128Params is the parameter set for 128-bit post-quantum security.
var MOS128Params = kmosaic.MOSAICParams{
	Level: kmosaic.MOS128,
	SLSS: kmosaic.SLSSParams{
		N:     512,
		M:     384,
		Q:     12289,
		W:     64,
		Sigma: 3.19,
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

// MOS256Params is the parameter set for 256-bit post-quantum security.
var MOS256Params = kmosaic.MOSAICParams{
	Level: kmosaic.MOS256,
	SLSS: kmosaic.SLSSParams{
		N:     1024,
		M:     768,
		Q:     12289,
		W:     128,
		Sigma: 3.19,
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

// GetParams returns the parameter set for the given security level.
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

// ValidateParams validates the parameter set for security and consistency.
func ValidateParams(params kmosaic.MOSAICParams) error {
	if params.SLSS.N <= 0 || params.SLSS.M <= 0 {
		return errors.New("SLSS dimensions must be positive")
	}
	if params.SLSS.W > params.SLSS.N {
		return errors.New("SLSS sparsity cannot exceed dimension")
	}
	if !isPrime(params.SLSS.Q) {
		return errors.New("SLSS modulus must be prime")
	}
	if params.SLSS.M < params.SLSS.N/2 {
		return errors.New("SLSS m should be at least n/2 for security")
	}
	if params.SLSS.Sigma < 3.0 {
		return errors.New("SLSS sigma should be at least 3.0")
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

// isPrime checks if a number is prime using a simple trial division.
// This is used for validating parameters, not for generating large primes.
func isPrime(n int) bool {
	if n < 2 {
		return false
	}
	if n == 2 {
		return true
	}
	if n%2 == 0 {
		return false
	}
	for i := 3; i*i <= n; i += 2 {
		if n%i == 0 {
			return false
		}
	}
	return true
}
