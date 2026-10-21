package tdd

import (
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

// TestKeyGen_PublicTensorReduced verifies every public tensor entry lies in
// [0, q). Negative Gaussian noise used to leak through an unsigned-only
// reduction, producing out-of-range (negative) public key entries.
func TestKeyGen_PublicTensorReduced(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS_128)
	for trial := 0; trial < 8; trial++ {
		seed, _ := utils.SecureRandomBytes(32)
		kp, err := KeyGen(params.TDD, seed)
		if err != nil {
			t.Fatalf("KeyGen failed: %v", err)
		}
		for i, v := range kp.PublicKey.T {
			if v < 0 || int(v) >= params.TDD.Q {
				t.Fatalf("trial %d: T[%d] = %d is outside [0, %d)", trial, i, v, params.TDD.Q)
			}
		}
	}
}

// TestTensorAdd_NegativeEntries verifies tensorAdd reduces negative sums into [0, q).
func TestTensorAdd_NegativeEntries(t *testing.T) {
	result := tensorAdd([]int32{0, 1, 5}, []int32{-3, -1, -9}, 10)
	expected := []int32{7, 0, 6}
	for i := range expected {
		if result[i] != expected[i] {
			t.Errorf("index %d: expected %d, got %d", i, expected[i], result[i])
		}
	}
}

// TestDecrypt_WrongLength verifies that a ciphertext with the wrong number of
// words is rejected (nil) instead of panicking.
func TestDecrypt_WrongLength(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS_128)
	seed, _ := utils.SecureRandomBytes(32)
	kp, err := KeyGen(params.TDD, seed)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}
	for _, n := range []int{0, 3, 8, params.TDD.N*params.TDD.N + EncryptedMessageWords - 1} {
		ct := &kmosaic.TDDCiphertext{Data: make([]int32, n)}
		if got := Decrypt(ct, kp.SecretKey, kp.PublicKey, params.TDD); got != nil {
			t.Errorf("Decrypt of %d-word ciphertext returned %d bytes, want nil", n, len(got))
		}
	}
}
