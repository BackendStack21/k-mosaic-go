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

	// SLSS.Eta out of range
	p = base
	p.SLSS.Eta = 2
	if err := ValidateParams(p); err == nil {
		t.Error("expected error for small SLSS.Eta")
	}

	// SLSS compression bits out of range
	p = base
	p.SLSS.DV = 2
	if err := ValidateParams(p); err == nil {
		t.Error("expected error for too few DV bits")
	}

	// code: non-prime ring length
	p = base
	p.Code.N = 57636
	if err := ValidateParams(p); err == nil {
		t.Error("expected error for non-prime code ring length")
	}

	// code: Reed-Solomon parameters inconsistent
	p = base
	p.Code.Delta = 10
	if err := ValidateParams(p); err == nil {
		t.Error("expected error for inconsistent Reed-Solomon parameters")
	}

	// code: N1*N2 exceeds N
	p = base
	p.Code.Mult = 6
	if err := ValidateParams(p); err == nil {
		t.Error("expected error for code longer than ring")
	}

	// Unknown security level
	_, err := GetParams(kmosaic.SecurityLevel("UNKNOWN"))
	if err == nil {
		t.Error("expected error for unknown security level")
	}
}
