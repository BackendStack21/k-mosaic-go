package utils

import (
	"errors"
	"testing"
)

func TestSecureRandomBytes_Coverage(t *testing.T) {
	bytes, err := SecureRandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	if len(bytes) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(bytes))
	}
}

func TestSecureRandomBytes_Zero(t *testing.T) {
	bytes, err := SecureRandomBytes(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(bytes) != 0 {
		t.Error("expected empty slice")
	}
}

func TestSecureRandomBytes_RandError(t *testing.T) {
	old := RandReader
	RandReader = &errorReader{}
	defer func() { RandReader = old }()

	_, err := SecureRandomBytes(32)
	if err == nil {
		t.Error("expected error from rand failure")
	}
}

func TestRandomInt_Coverage(t *testing.T) {
	for i := 0; i < 100; i++ {
		val, err := RandomInt(100)
		if err != nil {
			t.Fatal(err)
		}
		if val < 0 || val >= 100 {
			t.Errorf("value %d out of range [0, 100)", val)
		}
	}
}

func TestRandomInt_One(t *testing.T) {
	val, err := RandomInt(1)
	if err != nil {
		t.Fatal(err)
	}
	if val != 0 {
		t.Errorf("expected 0, got %d", val)
	}
}

func TestRandomInt_EdgeCases(t *testing.T) {
	// Test max=0 should return error
	_, err := RandomInt(0)
	if err == nil {
		t.Error("RandomInt(0) should return error")
	}

	// Test negative should return error
	_, err = RandomInt(-5)
	if err == nil {
		t.Error("RandomInt(-5) should return error")
	}
}

func TestSampleVectorZq_Coverage(t *testing.T) {
	seed := make([]byte, 32)
	vec := SampleVectorZq(seed, 10, 100)
	if len(vec) != 10 {
		t.Errorf("expected length 10, got %d", len(vec))
	}
	for i, v := range vec {
		if v < 0 || v >= 100 {
			t.Errorf("element %d: value %d out of range [0, 100)", i, v)
		}
	}
}

func TestSampleVectorZq_Empty(t *testing.T) {
	seed := make([]byte, 32)
	vec := SampleVectorZq(seed, 0, 100)
	if len(vec) != 0 {
		t.Error("expected empty vector")
	}
}

func TestSampleVectorZq_LargeVector(t *testing.T) {
	seed := make([]byte, 32)
	// Large vector to force extension
	vec := SampleVectorZq(seed, 10000, 3329)
	if len(vec) != 10000 {
		t.Errorf("expected length 10000, got %d", len(vec))
	}
}

func TestSampleVectorZq_SmallQ(t *testing.T) {
	seed := make([]byte, 32)
	// Small q to test modular reduction
	vec := SampleVectorZq(seed, 100, 3)
	for i, v := range vec {
		if v < 0 || v >= 3 {
			t.Errorf("element %d: value %d out of range [0, 3)", i, v)
		}
	}
}

type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("simulated rand error")
}
