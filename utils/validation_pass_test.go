package utils

import (
	"math"
	"testing"
)

func TestSafeReadLength_Bounds(t *testing.T) {
	data := []byte{0xff, 0xff, 0xff, 0x7f}
	if _, _, err := SafeReadLength(data, 0, -1); err == nil {
		t.Error("negative maxAllowed accepted")
	}
	if _, _, err := SafeReadLength(data, math.MaxInt-2, 10); err == nil {
		t.Error("offset near MaxInt accepted (offset+4 overflow)")
	}
	if n, off, err := SafeReadLength(data, 0, math.MaxInt); err != nil || n != 0x7fffffff || off != 4 {
		t.Errorf("large maxAllowed: got %d %d %v", n, off, err)
	}
	if n, _, err := SafeReadLength([]byte{7, 0, 0, 0}, 0, math.MaxInt/2+1); err != nil || n != 7 {
		t.Errorf("large maxAllowed rejected a valid length: %d %v", n, err)
	}
	if _, _, err := SafeReadLength(data, 0, 0x7ffffffe); err == nil {
		t.Error("length above maxAllowed accepted")
	}
	if _, _, err := SafeReadLength([]byte{1, 2, 3}, 0, 100); err == nil {
		t.Error("truncated field accepted")
	}
}

func TestSamplersRejectBadArguments(t *testing.T) {
	seed := make([]byte, 32)
	if SampleVectorZq(seed, 4, 0) != nil || SampleVectorZq(seed, -1, 7) != nil || SampleVectorZq(seed, 4, -7) != nil {
		t.Error("SampleVectorZq accepted a non-positive modulus or negative length")
	}
	if SampleGaussianVector(seed, -1, 3.0) != nil {
		t.Error("SampleGaussianVector accepted a negative length")
	}
	if Shake256(seed, -1) != nil || Shake256WithDomain("d", seed, -1) != nil {
		t.Error("negative SHAKE output length accepted")
	}
	if len(Shake256(seed, 0)) != 0 {
		t.Error("zero-length SHAKE output wrong")
	}
}
