package core

import (
	"math"
	"testing"
	"time"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
)

// TestValidateCodeParams_HugeN pins the fix for the primality loop whose
// i*i overflowed for N near MaxInt (it used to hang on amd64 and answer
// wrongly on 32-bit platforms).
func TestValidateCodeParams_HugeN(t *testing.T) {
	for _, n := range []int{math.MaxInt, math.MaxInt - 24, 1<<24 + 1, 2147483647} {
		p := CodeHQC256
		p.N = n
		done := make(chan error, 1)
		go func() { done <- ValidateCodeParams(p) }()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("N=%d accepted", n)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("ValidateCodeParams hung for N=%d", n)
		}
	}
	if !isPrime(57637) || isPrime(57639) || !isPrime(2147483647) || isPrime(1<<30) || isPrime(math.MaxInt) {
		t.Fatal("isPrime wrong on known values")
	}
}

// TestValidationBoundsMatchComponents checks that the limits enforced here
// are at least as strict as the ones the component packages rely on.
func TestValidationBoundsMatchComponents(t *testing.T) {
	mq := MQ256Params
	mq.N, mq.M = 513, 96
	if ValidateMQParams(mq) == nil {
		t.Error("UOV n > 512 accepted")
	}
	h := Hash256Params
	h.A = 17
	h.M = (h.K*h.A+7)/8 + (h.H-h.H/h.D+7)/8 + (h.H/h.D+7)/8
	if ValidateHashSignParams(h) == nil {
		t.Error("SLH-DSA a > 16 accepted")
	}
	h = Hash256Params
	h.K = 65
	h.M = (h.K*h.A+7)/8 + (h.H-h.H/h.D+7)/8 + (h.H/h.D+7)/8
	if ValidateHashSignParams(h) == nil {
		t.Error("SLH-DSA k > 64 accepted")
	}
	lat := Lattice256Params
	lat.Omega = 256
	if ValidateLatticeSignParams(lat) == nil {
		t.Error("lattice omega > 255 accepted (hint counts are bytes)")
	}
	for _, p := range []kmosaic.MQParams{MQ128Params, MQ256Params} {
		if err := ValidateMQParams(p); err != nil {
			t.Errorf("published UOV set rejected: %v", err)
		}
	}
	for _, p := range []kmosaic.HashSignParams{Hash128Params, Hash256Params} {
		if err := ValidateHashSignParams(p); err != nil {
			t.Errorf("published SLH-DSA set rejected: %v", err)
		}
	}
}
