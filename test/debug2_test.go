package test

import (
	"bytes"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/entanglement"
	"github.com/BackendStack21/k-mosaic-go/kem"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

func TestKEMCiphertextDeterminism(t *testing.T) {
	kp, err := kem.GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Test with deterministic ephemeral secret
	ephemeralSecret := make([]byte, 32)
	for i := range ephemeralSecret {
		ephemeralSecret[i] = byte(i + 1)
	}

	// Encapsulate twice with same ephemeral secret
	result1, err := kem.EncapsulateDeterministic(&kp.PublicKey, ephemeralSecret)
	if err != nil {
		t.Fatalf("EncapsulateDeterministic 1 failed: %v", err)
	}

	result2, err := kem.EncapsulateDeterministic(&kp.PublicKey, ephemeralSecret)
	if err != nil {
		t.Fatalf("EncapsulateDeterministic 2 failed: %v", err)
	}

	ct1 := kem.SerializeCiphertext(&result1.Ciphertext)
	ct2 := kem.SerializeCiphertext(&result2.Ciphertext)

	t.Logf("Ciphertext 1 hash: %x", utils.SHA3256(ct1)[:16])
	t.Logf("Ciphertext 2 hash: %x", utils.SHA3256(ct2)[:16])
	t.Logf("Ciphertext sizes: %d, %d", len(ct1), len(ct2))

	if !bytes.Equal(ct1, ct2) {
		t.Errorf("Ciphertexts are not deterministic!")

		// Find where they differ
		for i := 0; i < len(ct1) && i < len(ct2); i++ {
			if ct1[i] != ct2[i] {
				t.Logf("First difference at byte %d: %02x vs %02x", i, ct1[i], ct2[i])
				break
			}
		}
	}

	if !bytes.Equal(result1.SharedSecret, result2.SharedSecret) {
		t.Errorf("Shared secrets are not deterministic!")
	} else {
		t.Logf("Shared secrets match: %x", result1.SharedSecret[:16])
	}
}

func TestSecretShareDeterminism(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 1)
	}

	randomness := make([]byte, 32)
	for i := range randomness {
		randomness[i] = byte(i + 100)
	}

	shares1, _ := entanglement.SecretShareDeterministic(secret, 3, randomness)
	shares2, _ := entanglement.SecretShareDeterministic(secret, 3, randomness)

	for i := 0; i < 3; i++ {
		if !bytes.Equal(shares1[i], shares2[i]) {
			t.Errorf("Share %d not deterministic", i)
		} else {
			t.Logf("Share %d: %x", i, shares1[i][:16])
		}
	}
}
