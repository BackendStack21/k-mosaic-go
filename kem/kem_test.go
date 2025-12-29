package kem

import (
	"bytes"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

func TestKEM_Failures(t *testing.T) {
	kp, _ := GenerateKeyPair(kmosaic.MOS_128)
	res, _ := Encapsulate(&kp.PublicKey)

	// Test modified ciphertext (should implicitly reject)
	badCT := res.Ciphertext
	badCT.C1.U[0] ^= 1 // Modify SLSS ciphertext

	ss, err := Decapsulate(&kp.SecretKey, &kp.PublicKey, &badCT)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}
	if bytes.Equal(ss, res.SharedSecret) {
		t.Error("Decapsulate should return different shared secret for modified ciphertext")
	}

	// Test modified proof
	badCT = res.Ciphertext
	badCT.Proof[0] ^= 1
	ss, err = Decapsulate(&kp.SecretKey, &kp.PublicKey, &badCT)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}
	if bytes.Equal(ss, res.SharedSecret) {
		t.Error("Decapsulate should return different shared secret for modified proof")
	}
}

func TestKEM_Encryption(t *testing.T) {
	kp, _ := GenerateKeyPair(kmosaic.MOS_128)
	msg := []byte("test message")

	// Encrypt
	enc, err := Encrypt(&kp.PublicKey, msg)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt
	dec, err := Decrypt(&kp.SecretKey, &kp.PublicKey, enc)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(msg, dec) {
		t.Error("Decrypted message does not match")
	}

	// Test tampering
	enc.Encrypted[0] ^= 1
	_, err = Decrypt(&kp.SecretKey, &kp.PublicKey, enc)
	if err == nil {
		t.Error("Decrypt should fail with tampered ciphertext")
	}
}

func TestKEM_Deterministic(t *testing.T) {
	seed, _ := utils.SecureRandomBytes(32)
	params, _ := core.GetParams(kmosaic.MOS_128)

	kp1, err := GenerateKeyPairFromSeed(params, seed)
	if err != nil {
		t.Fatalf("GenerateKeyPairFromSeed failed: %v", err)
	}

	kp2, err := GenerateKeyPairFromSeed(params, seed)
	if err != nil {
		t.Fatalf("GenerateKeyPairFromSeed failed: %v", err)
	}

	// Check public keys match (deep check needed or serialization)
	pk1 := SerializePublicKey(&kp1.PublicKey)
	pk2 := SerializePublicKey(&kp2.PublicKey)
	if !bytes.Equal(pk1, pk2) {
		t.Error("GenerateKeyPairFromSeed not deterministic")
	}
}

func TestSerialization(t *testing.T) {
	kp, _ := GenerateKeyPair(kmosaic.MOS_128)

	pkBytes := SerializePublicKey(&kp.PublicKey)
	if len(pkBytes) == 0 {
		t.Error("SerializePublicKey returned empty bytes")
	}

	res, _ := Encapsulate(&kp.PublicKey)
	ctBytes := SerializeCiphertext(&res.Ciphertext)
	if len(ctBytes) == 0 {
		t.Error("SerializeCiphertext returned empty bytes")
	}
}
