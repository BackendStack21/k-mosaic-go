package utils

import (
	"bytes"
	"testing"
)

func TestRandomInt(t *testing.T) {
	// Test edge cases
	_, err := RandomInt(0)
	if err == nil {
		t.Error("RandomInt(0) should fail")
	}

	val, err := RandomInt(1)
	if err != nil {
		t.Errorf("RandomInt(1) failed: %v", err)
	}
	if val != 0 {
		t.Errorf("RandomInt(1) should return 0, got %d", val)
	}

	// Test range
	max := 100
	for i := 0; i < 1000; i++ {
		val, err := RandomInt(max)
		if err != nil {
			t.Fatalf("RandomInt failed: %v", err)
		}
		if val < 0 || val >= max {
			t.Errorf("RandomInt returned value out of range: %d", val)
		}
	}
}

func TestValidateSeedEntropy(t *testing.T) {
	// Test all zeros
	zeros := make([]byte, 32)
	if err := ValidateSeedEntropy(zeros); err == nil {
		t.Error("ValidateSeedEntropy should reject all zeros")
	}

	// Test sequential
	seq := make([]byte, 32)
	for i := range seq {
		seq[i] = byte(i)
	}
	if err := ValidateSeedEntropy(seq); err == nil {
		t.Error("ValidateSeedEntropy should reject sequential bytes")
	}

	// Test good seed
	good, _ := SecureRandomBytes(32)
	if err := ValidateSeedEntropy(good); err != nil {
		t.Errorf("ValidateSeedEntropy rejected good seed: %v", err)
	}
}

func TestConstantTime(t *testing.T) {
	a := []byte{1, 2, 3}
	b := []byte{1, 2, 3}
	c := []byte{1, 2, 4}

	if !ConstantTimeEqual(a, b) {
		t.Error("ConstantTimeEqual failed for equal slices")
	}
	if ConstantTimeEqual(a, c) {
		t.Error("ConstantTimeEqual passed for unequal slices")
	}

	res := ConstantTimeSelect(1, a, c)
	if !bytes.Equal(res, a) {
		t.Error("ConstantTimeSelect(1) failed")
	}
	res = ConstantTimeSelect(0, a, c)
	if !bytes.Equal(res, c) {
		t.Error("ConstantTimeSelect(0) failed")
	}
}

func TestSecureRandomBytes(t *testing.T) {
	b, err := SecureRandomBytes(32)
	if err != nil {
		t.Fatalf("SecureRandomBytes failed: %v", err)
	}
	if len(b) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(b))
	}

	b2, _ := SecureRandomBytes(32)
	if bytes.Equal(b, b2) {
		t.Error("SecureRandomBytes returned duplicate values")
	}
}

func TestSampleGaussianVector(t *testing.T) {
	n := 100
	sigma := 3.0
	seed := make([]byte, 32)
	vec := SampleGaussianVector(seed, n, sigma)

	if len(vec) != n {
		t.Errorf("Expected length %d, got %d", n, len(vec))
	}
	// Basic statistical check (very loose)
	mean := 0.0
	for _, v := range vec {
		mean += float64(v)
	}
	mean /= float64(n)
	if mean < -3*sigma || mean > 3*sigma {
		t.Errorf("Mean %f is too far from 0", mean)
	}
}

func TestSampleVectorZq(t *testing.T) {
	n := 100
	q := 17
	seed := make([]byte, 32)
	vec := SampleVectorZq(seed, n, q)

	if len(vec) != n {
		t.Errorf("Expected length %d, got %d", n, len(vec))
	}
	for _, v := range vec {
		if v < 0 || v >= int32(q) {
			t.Errorf("Value %d out of range [0, %d)", v, q)
		}
	}
}

func TestZeroize(t *testing.T) {
	b := []byte{1, 2, 3}
	Zeroize(b)
	for _, v := range b {
		if v != 0 {
			t.Error("Zeroize failed")
		}
	}

	i := []int32{1, 2, 3}
	ZeroizeInt32(i)
	for _, v := range i {
		if v != 0 {
			t.Error("ZeroizeInt32 failed")
		}
	}
}

func TestShake(t *testing.T) {
	data := []byte("test")
	out := Shake256(data, 32)

	out2 := Shake256(data, 32)

	if !bytes.Equal(out, out2) {
		t.Error("Shake256 not deterministic")
	}

	hash := SHA3256(data)
	if len(hash) != 32 {
		t.Errorf("SHA3256 returned wrong length: %d", len(hash))
	}

	domain := "domain"
	dHash := HashWithDomain(domain, data)
	if bytes.Equal(dHash, hash) {
		t.Error("HashWithDomain should differ from raw hash")
	}

	concat := HashConcat(data, data)
	if len(concat) != 32 {
		t.Errorf("HashConcat returned wrong length: %d", len(concat))
	}
}
