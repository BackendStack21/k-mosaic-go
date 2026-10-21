package slss

import (
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

// TestDecrypt_MismatchedU verifies that a ciphertext whose u vector does not
// match the secret key dimension is rejected (nil) instead of panicking.
func TestDecrypt_MismatchedU(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS_128)
	seed, _ := utils.SecureRandomBytes(32)
	kp, err := KeyGen(params.SLSS, seed)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}
	for _, n := range []int{0, params.SLSS.N - 1, params.SLSS.N + 1, 4 * params.SLSS.N} {
		ct := &kmosaic.SLSSCiphertext{U: make([]int32, n), V: make([]int32, 256)}
		if got := Decrypt(ct, kp.SecretKey, params.SLSS); got != nil {
			t.Errorf("Decrypt with %d-entry u returned %d bytes, want nil", n, len(got))
		}
	}
}
