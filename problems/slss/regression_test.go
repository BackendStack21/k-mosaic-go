package slss

import (
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go/v4"
	"github.com/BackendStack21/k-mosaic-go/v4/core"
	"github.com/BackendStack21/k-mosaic-go/v4/utils"
)

// TestDecrypt_MismatchedShape verifies that a ciphertext or key whose
// dimensions do not match the parameters is rejected (nil) instead of
// panicking, and that well-shaped garbage decrypts without error.
func TestDecrypt_MismatchedShape(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS_128)
	seed, _ := utils.SecureRandomBytes(32)
	kp, err := KeyGen(params.SLSS, seed)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}
	n, l := params.SLSS.N, params.SLSS.L
	cases := []*kmosaic.SLSSCiphertext{
		nil,
		{U: make([]int32, 0), V: make([]int32, l)},
		{U: make([]int32, n-1), V: make([]int32, l)},
		{U: make([]int32, n+1), V: make([]int32, l)},
		{U: make([]int32, 4*n), V: make([]int32, l)},
		{U: make([]int32, n), V: make([]int32, l-8)},
		{U: make([]int32, n), V: make([]int32, 0)},
	}
	for i, ct := range cases {
		if got := Decrypt(ct, kp.SecretKey, params.SLSS); got != nil {
			t.Errorf("case %d: Decrypt returned %d bytes, want nil", i, len(got))
		}
	}
	good := &kmosaic.SLSSCiphertext{U: make([]int32, n), V: make([]int32, l)}
	if Decrypt(good, kmosaic.SLSSSecretKey{S: kp.SecretKey.S[1:]}, params.SLSS) != nil {
		t.Error("Decrypt accepted a truncated secret key")
	}
	for i := range good.U {
		good.U[i] = int32(i) * -7919 // out of range: masked, must not panic
	}
	if got := Decrypt(good, kp.SecretKey, params.SLSS); len(got) != l/8 {
		t.Errorf("Decrypt of out-of-range coefficients returned %d bytes", len(got))
	}
}
