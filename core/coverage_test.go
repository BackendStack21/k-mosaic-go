package core

import (
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
)

func TestValidateParams_Coverage(t *testing.T) {
	base := MOS128Params

	// SLSS.N <= 0
	p := base
	p.SLSS.N = 0
	if err := ValidateParams(p); err == nil {
		t.Error("expected error for SLSS.N <= 0")
	}

	// SLSS.W > SLSS.N
	p = base
	p.SLSS.W = p.SLSS.N + 1
	if err := ValidateParams(p); err == nil {
		t.Error("expected error for SLSS.W > SLSS.N")
	}

	// !isPrime(SLSS.Q)
	p = base
	p.SLSS.Q = 4
	if err := ValidateParams(p); err == nil {
		t.Error("expected error for non-prime SLSS.Q")
	}

	// SLSS.M < SLSS.N/2
	p = base
	p.SLSS.M = p.SLSS.N/2 - 1
	if err := ValidateParams(p); err == nil {
		t.Error("expected error for small SLSS.M")
	}

	// SLSS.Sigma < 3.0
	p = base
	p.SLSS.Sigma = 2.0
	if err := ValidateParams(p); err == nil {
		t.Error("expected error for small SLSS.Sigma")
	}

	// TDD.N <= 0
	p = base
	p.TDD.N = 0
	if err := ValidateParams(p); err == nil {
		t.Error("expected error for TDD.N <= 0")
	}

	// TDD.R > TDD.N
	p = base
	p.TDD.R = p.TDD.N + 1
	if err := ValidateParams(p); err == nil {
		t.Error("expected error for TDD.R > TDD.N")
	}

	// !isPrime(EGRW.P)
	p = base
	p.EGRW.P = 4
	if err := ValidateParams(p); err == nil {
		t.Error("expected error for non-prime EGRW.P")
	}

	// EGRW.K < 64
	p = base
	p.EGRW.K = 63
	if err := ValidateParams(p); err == nil {
		t.Error("expected error for small EGRW.K")
	}

	// Unknown security level
	_, err := GetParams(kmosaic.SecurityLevel("UNKNOWN"))
	if err == nil {
		t.Error("expected error for unknown security level")
	}
}
