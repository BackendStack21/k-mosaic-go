package test

import (
	"bytes"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/entanglement"
	"github.com/BackendStack21/k-mosaic-go/kem"
	"github.com/BackendStack21/k-mosaic-go/problems/qcsd"
	"github.com/BackendStack21/k-mosaic-go/problems/slss"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

func TestSLSSEncryptDecrypt(t *testing.T) {
	params, _ := core.GetParams("MOS-128")
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}

	kp, err := slss.KeyGen(params.SLSS, seed)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	msg := make([]byte, 32)
	for i := range msg {
		msg[i] = byte(i)
	}

	randomness := utils.SHA3256(seed)
	ct, err := slss.Encrypt(kp.PublicKey, msg, params.SLSS, randomness)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted := slss.Decrypt(ct, kp.SecretKey, params.SLSS)

	t.Logf("Original:  %x", msg)
	t.Logf("Decrypted: %x", decrypted)

	if !bytes.Equal(msg, decrypted) {
		t.Errorf("SLSS: Decrypted message does not match original")
	}
}

func TestSecretShareReconstruct(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}

	shares, err := entanglement.SecretShare(secret, 3)
	if err != nil {
		t.Fatalf("SecretShare failed: %v", err)
	}

	reconstructed, err := entanglement.SecretReconstruct(shares)
	if err != nil {
		t.Fatalf("SecretReconstruct failed: %v", err)
	}

	t.Logf("Original:      %x", secret)
	t.Logf("Reconstructed: %x", reconstructed)

	if !bytes.Equal(secret, reconstructed) {
		t.Errorf("Reconstructed secret does not match original")
	}
}

func TestKEMEncapsulateDecapsulate(t *testing.T) {
	kp, err := kem.GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Test with deterministic ephemeral secret
	ephemeralSecret := make([]byte, 32)
	for i := range ephemeralSecret {
		ephemeralSecret[i] = byte(i + 1)
	}

	result, err := kem.EncapsulateDeterministic(&kp.PublicKey, ephemeralSecret)
	if err != nil {
		t.Fatalf("EncapsulateDeterministic failed: %v", err)
	}

	t.Logf("Encapsulated shared secret: %x", result.SharedSecret[:16])

	// Decrypt and reconstruct
	params := kp.PublicKey.Params

	// Decrypt shares manually with each component's secret key
	m1 := slss.Decrypt(&result.Ciphertext.C1, kp.SecretKey.SLSS, params.SLSS)
	m2, ok2 := qcsd.Decrypt(&result.Ciphertext.C2, kp.SecretKey.Code, params.Code)
	if ok2 != 1 {
		t.Fatalf("code component failed to decode")
	}

	randomness := utils.HashConcat(ephemeralSecret, kem.PublicKeyHash(&kp.PublicKey))
	expectedShares, _ := entanglement.SecretShareDeterministic(ephemeralSecret, 2, randomness)
	if !bytes.Equal(m1, expectedShares[0]) || !bytes.Equal(m2, expectedShares[1]) {
		t.Fatalf("component decryptions do not match the shares")
	}

	reconstructed, err := entanglement.SecretReconstruct([][]byte{m1, m2})
	if err != nil {
		t.Fatalf("SecretReconstruct failed: %v", err)
	}
	if !bytes.Equal(reconstructed, ephemeralSecret) {
		t.Fatalf("reconstructed ephemeral secret mismatch")
	}

	// Now test decapsulate
	sharedSecret, err := kem.Decapsulate(&kp.SecretKey, &kp.PublicKey, &result.Ciphertext)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}

	t.Logf("Decapsulated shared secret: %x", sharedSecret[:16])

	if !bytes.Equal(result.SharedSecret, sharedSecret) {
		t.Errorf("Shared secrets don't match")
	}
}
