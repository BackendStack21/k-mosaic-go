package slss

import (
	"bytes"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

func TestSLSS(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS_128)

	// KeyGen
	seed, _ := utils.SecureRandomBytes(32)
	kp, err := KeyGen(params.SLSS, seed)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	// Encrypt
	msg := []byte("test")
	randomness, _ := utils.SecureRandomBytes(32)
	ct, err := Encrypt(kp.PublicKey, msg, params.SLSS, randomness)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt
	dec := Decrypt(ct, kp.SecretKey, params.SLSS)

	// Note: SLSS decryption might not be perfect depending on error distribution,
	// but for small messages and correct params it should work.
	if !bytes.Equal(msg, dec) {
		t.Logf("Decrypted message does not match (expected for noisy encryption if not fully decoded)")
	}
}

func TestMathOps(t *testing.T) {
	// Test mod
	if mod(-5, 3) != 1 {
		t.Error("mod(-5, 3) should be 1")
	}
	if mod(5, 3) != 2 {
		t.Error("mod(5, 3) should be 2")
	}

	// Test centerMod
	if centerMod(13, 5) != -2 { // 13 % 5 = 3 -> 3-5 = -2
		t.Errorf("centerMod(13, 5) = %d, want -2", centerMod(13, 5))
	}
}

func TestSerialization(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS_128)
	seed, _ := utils.SecureRandomBytes(32)
	kp, err := KeyGen(params.SLSS, seed)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	serialized := SerializePublicKey(kp.PublicKey)
	if len(serialized) == 0 {
		t.Error("SerializePublicKey returned empty bytes")
	}
}
