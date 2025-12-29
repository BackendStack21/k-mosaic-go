package entanglement

import (
	"bytes"
	"errors"
	"testing"

	"github.com/BackendStack21/k-mosaic-go/utils"
)

func TestSecretShare_EdgeCases(t *testing.T) {
	secret := []byte("test secret")

	// Test n < 2
	_, err := SecretShare(secret, 1)
	if err == nil {
		t.Error("expected error for n < 2")
	}

	// Test n > 255
	_, err = SecretShare(secret, 256)
	if err == nil {
		t.Error("expected error for n > 255")
	}

	// Test empty secret
	_, err = SecretShare([]byte{}, 3)
	if err == nil {
		t.Error("expected error for empty secret")
	}
}

func TestSecretShareDeterministic_EdgeCases(t *testing.T) {
	secret := []byte("test secret")
	seed, _ := utils.SecureRandomBytes(32)

	// Test n < 2
	_, err := SecretShareDeterministic(secret, 1, seed)
	if err == nil {
		t.Error("expected error for n < 2")
	}

	// Test n > 255
	_, err = SecretShareDeterministic(secret, 256, seed)
	if err == nil {
		t.Error("expected error for n > 255")
	}

	// Test empty secret
	_, err = SecretShareDeterministic([]byte{}, 3, seed)
	if err == nil {
		t.Error("expected error for empty secret")
	}

	// Test short seed
	_, err = SecretShareDeterministic(secret, 3, make([]byte, 10))
	if err == nil {
		t.Error("expected error for short seed")
	}
}

func TestSecretReconstruct_EdgeCases(t *testing.T) {
	// Test with mismatched share lengths
	share1 := []byte{1, 0, 1, 2, 3}
	share2 := []byte{2, 0, 1, 2, 3, 4} // Different length
	_, err := SecretReconstruct([][]byte{share1, share2})
	if err == nil {
		t.Error("expected error for mismatched share lengths")
	}

	// Test empty shares
	_, err = SecretReconstruct([][]byte{})
	if err == nil {
		t.Error("expected error for empty shares")
	}

	// Test single share
	_, err = SecretReconstruct([][]byte{share1})
	if err == nil {
		t.Error("expected error for single share")
	}
}

func TestSecretShare_RandError(t *testing.T) {
	old := utils.RandReader
	utils.RandReader = &errorReader{}
	defer func() { utils.RandReader = old }()

	_, err := SecretShare([]byte("test"), 3)
	if err == nil {
		t.Error("expected error from rand failure")
	}
}

func TestSecretShareReconstruct_Coverage(t *testing.T) {
	secret := []byte("this is a test secret for coverage")
	n := 5

	shares, err := SecretShare(secret, n)
	if err != nil {
		t.Fatal(err)
	}

	if len(shares) != n {
		t.Errorf("expected %d shares, got %d", n, len(shares))
	}

	// Reconstruct with all n shares (n-of-n scheme)
	reconstructed, err := SecretReconstruct(shares)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(reconstructed, secret) {
		t.Errorf("expected %s, got %s", secret, reconstructed)
	}
}

func TestSecretShareDeterministic_Coverage(t *testing.T) {
	secret := []byte("deterministic test secret")
	seed, _ := utils.SecureRandomBytes(32)
	n := 5

	shares1, err := SecretShareDeterministic(secret, n, seed)
	if err != nil {
		t.Fatal(err)
	}

	shares2, err := SecretShareDeterministic(secret, n, seed)
	if err != nil {
		t.Fatal(err)
	}

	// Same seed should produce same shares
	for i := range shares1 {
		if !bytes.Equal(shares1[i], shares2[i]) {
			t.Errorf("share %d differs", i)
		}
	}
}

type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("simulated rand error")
}
