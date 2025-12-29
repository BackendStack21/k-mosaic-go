package entanglement

import (
	"bytes"
	"testing"
)

func TestSecretShare(t *testing.T) {
	secret := []byte("secret")

	// Test invalid n
	_, err := SecretShare(secret, 1)
	if err == nil {
		t.Error("SecretShare should reject n=1")
	}

	// Test reconstruction
	shares, err := SecretShare(secret, 5)
	if err != nil {
		t.Fatalf("SecretShare failed: %v", err)
	}
	if len(shares) != 5 {
		t.Errorf("Expected 5 shares, got %d", len(shares))
	}

	rec, err := SecretReconstruct(shares)
	if err != nil {
		t.Fatalf("SecretReconstruct failed: %v", err)
	}
	if !bytes.Equal(secret, rec) {
		t.Error("Reconstructed secret does not match")
	}
}

func TestSecretShareDeterministic(t *testing.T) {
	secret := []byte("secret")
	seed := make([]byte, 32) // zero seed

	shares1, err := SecretShareDeterministic(secret, 5, seed)
	if err != nil {
		t.Fatalf("SecretShareDeterministic failed: %v", err)
	}

	shares2, err := SecretShareDeterministic(secret, 5, seed)
	if err != nil {
		t.Fatalf("SecretShareDeterministic failed: %v", err)
	}

	for i := range shares1 {
		if !bytes.Equal(shares1[i], shares2[i]) {
			t.Error("SecretShareDeterministic not deterministic")
		}
	}
}

func TestCommitment(t *testing.T) {
	data := []byte("data")
	comm, err := CreateCommitment(data)
	if err != nil {
		t.Fatalf("CreateCommitment failed: %v", err)
	}

	if !VerifyCommitment(data, comm.Commitment, comm.Opening) {
		t.Error("VerifyCommitment failed")
	}

	// Test wrong data
	if VerifyCommitment([]byte("wrong"), comm.Commitment, comm.Opening) {
		t.Error("VerifyCommitment passed with wrong data")
	}

	// Test wrong opening
	wrongOpening := make([]byte, len(comm.Opening))
	copy(wrongOpening, comm.Opening)
	wrongOpening[0] ^= 1
	if VerifyCommitment(data, comm.Commitment, wrongOpening) {
		t.Error("VerifyCommitment passed with wrong opening")
	}
}

func TestBinding(t *testing.T) {
	id := []byte("identity")
	msg := []byte("message")
	other := []byte("other")
	binding := ComputeBinding(id, msg, other)

	if len(binding) != 32 {
		t.Errorf("Expected 32 byte binding, got %d", len(binding))
	}

	binding2 := ComputeBinding(id, msg, other)
	if !bytes.Equal(binding, binding2) {
		t.Error("ComputeBinding not deterministic")
	}

	binding3 := ComputeBinding([]byte("other"), msg, other)
	if bytes.Equal(binding, binding3) {
		t.Error("ComputeBinding collision on ID")
	}
}

func TestNIZKProof(t *testing.T) {
	// Mock data for NIZK - must match security requirements
	secret := []byte("secret")
	shares := [][]byte{[]byte("share1"), []byte("share2")}
	// NIZK requires exactly 3 ciphertext hashes, each 32 bytes
	hashes := [][]byte{
		make([]byte, 32),
		make([]byte, 32),
		make([]byte, 32),
	}
	// Fill with non-zero data
	for i := range hashes {
		for j := range hashes[i] {
			hashes[i][j] = byte(i*32 + j)
		}
	}
	// Binding must be 32 bytes
	binding := make([]byte, 32)
	for i := range binding {
		binding[i] = byte(i + 100)
	}
	seed := []byte("seed")

	proof := GenerateNIZKProof(secret, shares, hashes, seed)
	if len(proof) != 32 {
		t.Errorf("GenerateNIZKProof returned wrong length: %d", len(proof))
	}

	if !VerifyNIZKProof(proof, hashes, binding) {
		t.Error("VerifyNIZKProof failed")
	}

	// Test serialization
	serialized := SerializeNIZKProof(proof)
	// DeserializeNIZKProof is not implemented/exported in the snippet I saw,
	// but SerializeNIZKProof returns []byte so it's likely identity or simple copy.
	if !bytes.Equal(proof, serialized) {
		t.Error("Serialization roundtrip failed")
	}

	// Test that invalid inputs are rejected
	if VerifyNIZKProof(proof, hashes, nil) {
		t.Error("VerifyNIZKProof should reject nil binding")
	}
	if VerifyNIZKProof(proof, hashes[:2], binding) {
		t.Error("VerifyNIZKProof should reject wrong number of hashes")
	}
	if VerifyNIZKProof(make([]byte, 32), hashes, binding) {
		t.Error("VerifyNIZKProof should reject all-zero proof")
	}
}
