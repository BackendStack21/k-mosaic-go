package test

import (
	"bytes"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/entanglement"
	"github.com/BackendStack21/k-mosaic-go/kem"
	"github.com/BackendStack21/k-mosaic-go/sign"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

// =============================================================================
// Utils Tests
// =============================================================================

func TestUtils_RandomInt(t *testing.T) {
	// Test edge cases
	_, err := utils.RandomInt(0)
	if err == nil {
		t.Error("RandomInt(0) should fail")
	}

	val, err := utils.RandomInt(1)
	if err != nil {
		t.Errorf("RandomInt(1) failed: %v", err)
	}
	if val != 0 {
		t.Errorf("RandomInt(1) should return 0, got %d", val)
	}

	// Test range
	max := 100
	for i := 0; i < 1000; i++ {
		val, err := utils.RandomInt(max)
		if err != nil {
			t.Fatalf("RandomInt failed: %v", err)
		}
		if val < 0 || val >= max {
			t.Errorf("RandomInt returned value out of range: %d", val)
		}
	}
}

func TestUtils_ValidateSeedEntropy(t *testing.T) {
	// Test all zeros
	zeros := make([]byte, 32)
	if err := utils.ValidateSeedEntropy(zeros); err == nil {
		t.Error("ValidateSeedEntropy should reject all zeros")
	}

	// Test sequential
	seq := make([]byte, 32)
	for i := range seq {
		seq[i] = byte(i)
	}
	if err := utils.ValidateSeedEntropy(seq); err == nil {
		t.Error("ValidateSeedEntropy should reject sequential bytes")
	}

	// Test good seed
	good, _ := utils.SecureRandomBytes(32)
	if err := utils.ValidateSeedEntropy(good); err != nil {
		t.Errorf("ValidateSeedEntropy rejected good seed: %v", err)
	}
}

func TestUtils_ConstantTime(t *testing.T) {
	a := []byte{1, 2, 3}
	b := []byte{1, 2, 3}
	c := []byte{1, 2, 4}

	if !utils.ConstantTimeEqual(a, b) {
		t.Error("ConstantTimeEqual failed for equal slices")
	}
	if utils.ConstantTimeEqual(a, c) {
		t.Error("ConstantTimeEqual passed for unequal slices")
	}

	res := utils.ConstantTimeSelect(1, a, c)
	if !bytes.Equal(res, a) {
		t.Error("ConstantTimeSelect(1) failed")
	}
	res = utils.ConstantTimeSelect(0, a, c)
	if !bytes.Equal(res, c) {
		t.Error("ConstantTimeSelect(0) failed")
	}
}

// =============================================================================
// Core Tests
// =============================================================================

func TestCore_ValidateParams(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS_128)

	// Test valid params
	if err := core.ValidateParams(params); err != nil {
		t.Errorf("ValidateParams failed for valid params: %v", err)
	}

	// Test invalid SLSS params
	invalid := params
	invalid.SLSS.N = 0
	if err := core.ValidateParams(invalid); err == nil {
		t.Error("ValidateParams should reject N=0")
	}

	invalid = params
	invalid.SLSS.W = invalid.SLSS.N + 1
	if err := core.ValidateParams(invalid); err == nil {
		t.Error("ValidateParams should reject W > N")
	}
}

// =============================================================================
// Entanglement Tests
// =============================================================================

func TestEntanglement_SecretShare(t *testing.T) {
	secret := []byte("secret")

	// Test invalid n
	_, err := entanglement.SecretShare(secret, 1)
	if err == nil {
		t.Error("SecretShare should reject n=1")
	}

	// Test reconstruction
	shares, err := entanglement.SecretShare(secret, 5)
	if err != nil {
		t.Fatalf("SecretShare failed: %v", err)
	}
	if len(shares) != 5 {
		t.Errorf("Expected 5 shares, got %d", len(shares))
	}

	rec, err := entanglement.SecretReconstruct(shares)
	if err != nil {
		t.Fatalf("SecretReconstruct failed: %v", err)
	}
	if !bytes.Equal(secret, rec) {
		t.Error("Reconstructed secret does not match")
	}
}

func TestEntanglement_Commitment(t *testing.T) {
	data := []byte("data")
	comm, err := entanglement.CreateCommitment(data)
	if err != nil {
		t.Fatalf("CreateCommitment failed: %v", err)
	}

	if !entanglement.VerifyCommitment(data, comm.Commitment, comm.Opening) {
		t.Error("VerifyCommitment failed")
	}

	// Test wrong data
	if entanglement.VerifyCommitment([]byte("wrong"), comm.Commitment, comm.Opening) {
		t.Error("VerifyCommitment passed with wrong data")
	}

	// Test wrong opening
	wrongOpening := make([]byte, len(comm.Opening))
	copy(wrongOpening, comm.Opening)
	wrongOpening[0] ^= 1
	if entanglement.VerifyCommitment(data, comm.Commitment, wrongOpening) {
		t.Error("VerifyCommitment passed with wrong opening")
	}
}

// =============================================================================
// KEM Tests
// =============================================================================

func TestKEM_Failures(t *testing.T) {
	kp, _ := kem.GenerateKeyPair(kmosaic.MOS_128)
	res, _ := kem.Encapsulate(&kp.PublicKey)

	// Test modified ciphertext (should implicitly reject)
	badCT := res.Ciphertext
	badCT.C1.U[0] ^= 1 // Modify SLSS ciphertext

	ss, err := kem.Decapsulate(&kp.SecretKey, &kp.PublicKey, &badCT)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}
	if bytes.Equal(ss, res.SharedSecret) {
		t.Error("Decapsulate should return different shared secret for modified ciphertext")
	}

	// Test modified proof
	badCT = res.Ciphertext
	badCT.Proof[0] ^= 1
	ss, err = kem.Decapsulate(&kp.SecretKey, &kp.PublicKey, &badCT)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}
	if bytes.Equal(ss, res.SharedSecret) {
		t.Error("Decapsulate should return different shared secret for modified proof")
	}
}

func TestKEM_Encryption(t *testing.T) {
	kp, _ := kem.GenerateKeyPair(kmosaic.MOS_128)
	msg := []byte("test message")

	// Encrypt
	enc, err := kem.Encrypt(&kp.PublicKey, msg)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt
	dec, err := kem.Decrypt(&kp.SecretKey, &kp.PublicKey, enc)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(msg, dec) {
		t.Error("Decrypted message does not match")
	}

	// Test tampering
	enc.Encrypted[0] ^= 1
	_, err = kem.Decrypt(&kp.SecretKey, &kp.PublicKey, enc)
	if err == nil {
		t.Error("Decrypt should fail with tampered ciphertext")
	}
}

// =============================================================================
// Sign Tests
// =============================================================================

func TestSign_Failures(t *testing.T) {
	kp, _ := sign.GenerateKeyPair(kmosaic.MOS_128)
	msg := []byte("message")
	sig, _ := sign.Sign(&kp.SecretKey, &kp.PublicKey, msg)

	// Test modified message
	if sign.Verify(&kp.PublicKey, []byte("wrong"), sig) {
		t.Error("Verify passed with wrong message")
	}

	// Test modified signature
	badSig := *sig
	badSig.Challenge[0] ^= 1
	if sign.Verify(&kp.PublicKey, msg, &badSig) {
		t.Error("Verify passed with modified challenge")
	}

	badSig = *sig
	badSig.Response[0] ^= 1
	if sign.Verify(&kp.PublicKey, msg, &badSig) {
		t.Error("Verify passed with modified response")
	}
}
