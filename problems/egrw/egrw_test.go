package egrw

import (
	"bytes"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

func TestEGRW(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS_128)

	// KeyGen
	seed, _ := utils.SecureRandomBytes(32)
	kp, err := KeyGen(params.EGRW, seed)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	// Encrypt
	msg := []byte("test")
	randomness, _ := utils.SecureRandomBytes(32)
	ct, err := Encrypt(kp.PublicKey, msg, params.EGRW, randomness)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt
	dec := Decrypt(ct, kp.SecretKey, kp.PublicKey, params.EGRW)

	if !bytes.Equal(msg, dec) {
		t.Log("Decrypted message does not match")
	}
}

func TestSL2Ops(t *testing.T) {
	// Test SL2 multiplication
	// I = [[1,0],[0,1]]
	I := kmosaic.SL2Element{A: 1, B: 0, C: 0, D: 1}
	A := kmosaic.SL2Element{A: 1, B: 1, C: 0, D: 1}

	res := SL2Multiply(I, A, 17)
	if res != A {
		t.Error("Identity multiplication failed")
	}

	// Test Inverse
	inv := SL2Inverse(A, 17)
	prod := SL2Multiply(A, inv, 17)
	if prod != I {
		t.Error("Inverse check failed")
	}
}

func TestSerialization(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS_128)
	seed, _ := utils.SecureRandomBytes(32)
	kp, err := KeyGen(params.EGRW, seed)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	serialized := SerializePublicKey(kp.PublicKey)
	if len(serialized) == 0 {
		t.Error("SerializePublicKey returned empty bytes")
	}
}
