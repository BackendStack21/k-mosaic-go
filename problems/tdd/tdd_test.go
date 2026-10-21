package tdd

import (
	"bytes"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

func TestTDD(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS_128)

	// KeyGen
	seed, _ := utils.SecureRandomBytes(32)
	kp, err := KeyGen(params.TDD, seed)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	// Encrypt a full 32-byte block (Decrypt always returns 32 bytes).
	msg := make([]byte, 32)
	for i := range msg {
		msg[i] = byte(i * 7)
	}
	randomness, _ := utils.SecureRandomBytes(32)
	ct, err := Encrypt(kp.PublicKey, msg, params.TDD, randomness)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt
	dec := Decrypt(ct, kp.SecretKey, kp.PublicKey, params.TDD)

	if !bytes.Equal(msg, dec) {
		t.Errorf("Decrypted message does not match: got %x, want %x", dec, msg)
	}
}

func TestTensorOps(t *testing.T) {
	// Basic tensor operations test
}

func TestSerialization(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS_128)
	seed, _ := utils.SecureRandomBytes(32)
	kp, err := KeyGen(params.TDD, seed)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	serialized := SerializePublicKey(kp.PublicKey)
	if len(serialized) == 0 {
		t.Error("SerializePublicKey returned empty bytes")
	}
}
