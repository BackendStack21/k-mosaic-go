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
