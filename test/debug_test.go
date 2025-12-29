package test

import (
	"bytes"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/entanglement"
	"github.com/BackendStack21/k-mosaic-go/kem"
	"github.com/BackendStack21/k-mosaic-go/problems/egrw"
	"github.com/BackendStack21/k-mosaic-go/problems/slss"
	"github.com/BackendStack21/k-mosaic-go/problems/tdd"
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

	// Decrypt shares manually
	m1 := slss.Decrypt(&result.Ciphertext.C1, kp.SecretKey.SLSS, params.SLSS)
	m2 := tdd.Decrypt(&result.Ciphertext.C2, kp.SecretKey.TDD, kp.PublicKey.TDD, params.TDD)
	m3 := egrw.Decrypt(&result.Ciphertext.C3, kp.SecretKey.EGRW, kp.PublicKey.EGRW, params.EGRW)

	t.Logf("Decrypted m1: %x", m1)
	t.Logf("Decrypted m2: %x", m2)
	t.Logf("Decrypted m3: %x", m3)

	// Check that we got the expected shares
	randomness := utils.HashConcat(ephemeralSecret, kp.PublicKey.Binding)
	expectedShares, _ := entanglement.SecretShareDeterministic(ephemeralSecret, 3, randomness)

	t.Logf("Expected share0: %x", expectedShares[0])
	t.Logf("Expected share1: %x", expectedShares[1])
	t.Logf("Expected share2: %x", expectedShares[2])

	// Reconstruct
	shares := [][]byte{m1, m2, m3}
	reconstructed, err := entanglement.SecretReconstruct(shares)
	if err != nil {
		t.Fatalf("SecretReconstruct failed: %v", err)
	}

	t.Logf("Original ephemeral:     %x", ephemeralSecret)
	t.Logf("Reconstructed ephemeral: %x", reconstructed)

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
