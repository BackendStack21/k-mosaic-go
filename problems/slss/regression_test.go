package slss

import (
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

// TestDecrypt_MismatchedShape verifies that a ciphertext whose dimensions do
// not match the parameters is rejected (nil) instead of panicking.
func TestDecrypt_MismatchedShape(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS_128)
	seed, _ := utils.SecureRandomBytes(32)
	kp, err := KeyGen(params.SLSS, seed)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}
	n, l := params.SLSS.N, params.SLSS.L
	cases := []*kmosaic.SLSSCiphertext{
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
}
