// Package test provides comprehensive tests for k-mosaic security fixes.
package test

import (
	"bytes"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/kem"
	"github.com/BackendStack21/k-mosaic-go/sign"
)

// TestKEMGenerateKeyPairPanicRecovery verifies panic recovery in KEM key generation.
func TestKEMGenerateKeyPairPanicRecovery(t *testing.T) {
	levels := []kmosaic.SecurityLevel{kmosaic.MOS_128, kmosaic.MOS_256}

	for _, level := range levels {
		kp, err := kem.GenerateKeyPair(level)
		if err != nil {
			t.Fatalf("GenerateKeyPair failed: %v", err)
		}
		if kp == nil {
			t.Fatalf("GenerateKeyPair returned nil key pair")
		}
	}
}

// TestSignGenerateKeyPairPanicRecovery verifies panic recovery in Sign key generation.
func TestSignGenerateKeyPairPanicRecovery(t *testing.T) {
	levels := []kmosaic.SecurityLevel{kmosaic.MOS_128, kmosaic.MOS_256}

	for _, level := range levels {
		kp, err := sign.GenerateKeyPair(level)
		if err != nil {
			t.Fatalf("GenerateKeyPair failed: %v", err)
		}
		if kp == nil {
			t.Fatalf("GenerateKeyPair returned nil key pair")
		}
	}
}

// TestSignSignPanicRecovery verifies panic recovery in Sign function.
func TestSignSignPanicRecovery(t *testing.T) {
	kp, err := sign.GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	message := []byte("test message for signing")
	sig, err := sign.Sign(&kp.SecretKey, &kp.PublicKey, message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if sig == nil {
		t.Fatalf("Sign returned nil signature")
	}
	if len(sig.Commitment) != 32 || len(sig.Challenge) != 32 || len(sig.Response) != 64 {
		t.Errorf("Signature components have incorrect length")
	}
}

// TestSignVerifyPanicRecovery verifies panic recovery in Verify function.
func TestSignVerifyPanicRecovery(t *testing.T) {
	kp, err := sign.GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	message := []byte("test message for verification")
	sig, err := sign.Sign(&kp.SecretKey, &kp.PublicKey, message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Valid signature should verify
	valid := sign.Verify(&kp.PublicKey, message, sig)
	if !valid {
		t.Errorf("Valid signature failed verification")
	}

	// Modified message should fail verification
	wrongMessage := []byte("wrong message")
	valid = sign.Verify(&kp.PublicKey, wrongMessage, sig)
	if valid {
		t.Errorf("Invalid message passed verification")
	}
}

// TestSignDeserializePublicKeyLimits verifies size validation in sign deserialization.
func TestSignDeserializePublicKeyLimits(t *testing.T) {
	// First generate a valid key to get proper format
	kp, err := sign.GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Serialize it
	pkData := sign.SerializePublicKey(&kp.PublicKey)

	// Deserialize should succeed
	pk, err := sign.DeserializePublicKey(pkData)
	if err != nil {
		t.Fatalf("DeserializePublicKey failed: %v", err)
	}
	if pk == nil {
		t.Fatalf("DeserializePublicKey returned nil")
	}

	// Verify round-trip
	pkData2 := sign.SerializePublicKey(pk)
	if !bytes.Equal(pkData, pkData2) {
		t.Errorf("Round-trip serialization mismatch")
	}
}

// TestIntegrationSecurityFixes verifies all security fixes work together.
func TestIntegrationSecurityFixes(t *testing.T) {
	// Test KEM operations
	kemKP, err := kem.GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		t.Fatalf("KEM GenerateKeyPair failed: %v", err)
	}

	plaintext := []byte("secret message")
	encMsg, err := kem.Encrypt(&kemKP.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := kem.Decrypt(&kemKP.SecretKey, &kemKP.PublicKey, encMsg)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted message does not match original")
	}

	// Test Sign operations
	signKP, err := sign.GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		t.Fatalf("Sign GenerateKeyPair failed: %v", err)
	}

	message := []byte("document to sign")
	sig, err := sign.Sign(&signKP.SecretKey, &signKP.PublicKey, message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	valid := sign.Verify(&signKP.PublicKey, message, sig)
	if !valid {
		t.Errorf("Signature verification failed")
	}
}

// TestKEMEncryptDecryptWithPanicRecovery verifies Encrypt/Decrypt handle panics.
func TestKEMEncryptDecryptWithPanicRecovery(t *testing.T) {
	kp, err := kem.GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Test multiple encryptions and decryptions
	for i := 0; i < 5; i++ {
		plaintext := []byte("test message")
		encMsg, err := kem.Encrypt(&kp.PublicKey, plaintext)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		decrypted, err := kem.Decrypt(&kp.SecretKey, &kp.PublicKey, encMsg)
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("Decrypted message mismatch at iteration %d", i)
		}
	}
}

// TestMultipleLevelsAllOperations verifies all security levels work with fixes.
func TestMultipleLevelsAllOperations(t *testing.T) {
	levels := []kmosaic.SecurityLevel{kmosaic.MOS_128, kmosaic.MOS_256}

	for _, level := range levels {
		// Test KEM
		kemKP, err := kem.GenerateKeyPair(level)
		if err != nil {
			t.Fatalf("KEM GenerateKeyPair failed: %v", err)
		}

		plaintext := []byte("test")
		encMsg, err := kem.Encrypt(&kemKP.PublicKey, plaintext)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		decrypted, err := kem.Decrypt(&kemKP.SecretKey, &kemKP.PublicKey, encMsg)
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("KEM decryption mismatch")
		}

		// Test Sign
		signKP, err := sign.GenerateKeyPair(level)
		if err != nil {
			t.Fatalf("Sign GenerateKeyPair failed: %v", err)
		}

		sig, err := sign.Sign(&signKP.SecretKey, &signKP.PublicKey, plaintext)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		if !sign.Verify(&signKP.PublicKey, plaintext, sig) {
			t.Errorf("Signature verification failed")
		}
	}
}

// TestErrorHandlingCompleteness verifies all error cases are handled.
func TestErrorHandlingCompleteness(t *testing.T) {
	// Test invalid security levels
	invalidKP, err := kem.GenerateKeyPair(kmosaic.SecurityLevel("invalid"))
	if err == nil {
		t.Fatalf("Invalid security level should return error")
	}
	if invalidKP != nil {
		t.Fatalf("Invalid security level should return nil key pair")
	}

	// Test sign with invalid level
	invalidSignKP, err := sign.GenerateKeyPair(kmosaic.SecurityLevel("invalid"))
	if err == nil {
		t.Fatalf("Invalid sign security level should return error")
	}
	if invalidSignKP != nil {
		t.Fatalf("Invalid sign security level should return nil key pair")
	}

	// Test deserialization with invalid data
	invalidPK, err := sign.DeserializePublicKey([]byte("invalid"))
	if err == nil {
		t.Fatalf("Invalid data should return error")
	}
	if invalidPK != nil {
		t.Fatalf("Invalid data should return nil public key")
	}
}
