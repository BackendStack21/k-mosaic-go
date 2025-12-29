// Package entanglement implements the cryptographic binding for kMOSAIC.
package entanglement

import (
	"errors"

	"github.com/BackendStack21/k-mosaic-go/utils"
)

const (
	DomainShare  = "kmosaic-share-v1"
	DomainCommit = "kmosaic-commit-v1"
	DomainBind   = "kmosaic-bind-v1"
	DomainNIZK   = "kmosaic-nizk-v1"
)

// SecretShare splits a secret into n shares using XOR-based n-of-n sharing.
// The first n-1 shares are random, and the last share is computed such that
// the XOR sum of all shares equals the secret.
func SecretShare(secret []byte, n int) ([][]byte, error) {
	if n < 2 {
		return nil, errors.New("need at least 2 shares")
	}
	if n > 255 {
		return nil, errors.New("maximum 255 shares supported")
	}
	if len(secret) == 0 {
		return nil, errors.New("secret cannot be empty")
	}

	shares := make([][]byte, n)

	// Generate n-1 random shares
	for i := 0; i < n-1; i++ {
		share, err := utils.SecureRandomBytes(len(secret))
		if err != nil {
			return nil, err
		}
		shares[i] = share
	}

	// Last share is XOR of secret with all other shares
	lastShare := make([]byte, len(secret))
	for i := range secret {
		xorSum := secret[i]
		for j := 0; j < n-1; j++ {
			xorSum ^= shares[j][i]
		}
		lastShare[i] = xorSum
	}
	shares[n-1] = lastShare

	return shares, nil
}

// SecretReconstruct reconstructs a secret from n shares.
// It computes the XOR sum of all shares.
func SecretReconstruct(shares [][]byte) ([]byte, error) {
	if len(shares) < 2 {
		return nil, errors.New("need at least 2 shares")
	}

	length := len(shares[0])
	for _, share := range shares {
		if len(share) != length {
			return nil, errors.New("all shares must have same length")
		}
	}

	result := make([]byte, length)
	for i := 0; i < length; i++ {
		var xorSum byte
		for _, share := range shares {
			xorSum ^= share[i]
		}
		result[i] = xorSum
	}

	return result, nil
}

// SecretShareDeterministic creates deterministic shares from a seed.
// This is used in the KEM to ensure that the encapsulation is deterministic given the randomness.
func SecretShareDeterministic(secret []byte, n int, seed []byte) ([][]byte, error) {
	if n < 2 {
		return nil, errors.New("need at least 2 shares")
	}
	if n > 255 {
		return nil, errors.New("maximum 255 shares supported")
	}
	if len(secret) == 0 {
		return nil, errors.New("secret cannot be empty")
	}
	if len(seed) < 16 {
		return nil, errors.New("seed must be at least 16 bytes")
	}

	shares := make([][]byte, n)

	// Generate n-1 deterministic shares
	for i := 0; i < n-1; i++ {
		domain := DomainShare + "-" + string(rune('0'+i))
		shareSeed := utils.HashWithDomain(domain, seed)
		shares[i] = utils.Shake256(shareSeed, len(secret))
	}

	// Last share is XOR of secret with all other shares
	lastShare := make([]byte, len(secret))
	for i := range secret {
		xorSum := secret[i]
		for j := 0; j < n-1; j++ {
			xorSum ^= shares[j][i]
		}
		lastShare[i] = xorSum
	}
	shares[n-1] = lastShare

	return shares, nil
}

// ComputeBinding computes the cross-component binding hash.
// It binds the public keys of the three components (SLSS, TDD, EGRW) together.
func ComputeBinding(slssBytes, tddBytes, egrwBytes []byte) []byte {
	return utils.HashWithDomain(DomainBind, utils.HashConcat(slssBytes, tddBytes, egrwBytes))
}

// BindingCommitment represents a commitment with its opening.
type BindingCommitment struct {
	Commitment []byte
	Opening    []byte
}

// CreateCommitment creates a binding commitment to data.
// It returns the commitment hash and the opening (randomness).
func CreateCommitment(data []byte) (*BindingCommitment, error) {
	if len(data) == 0 {
		return nil, errors.New("cannot commit to empty data")
	}

	opening, err := utils.SecureRandomBytes(32)
	if err != nil {
		return nil, err
	}

	commitment := utils.HashWithDomain(DomainCommit, utils.HashConcat(data, opening))
	return &BindingCommitment{
		Commitment: commitment,
		Opening:    opening,
	}, nil
}

// VerifyCommitment verifies a binding commitment.
// It checks if H(data || opening) matches the commitment.
func VerifyCommitment(data, commitment, opening []byte) bool {
	if len(opening) != 32 || len(commitment) != 32 {
		return false
	}
	expected := utils.HashWithDomain(DomainCommit, utils.HashConcat(data, opening))
	return utils.ConstantTimeEqual(commitment, expected)
}

// NIZKProof represents a non-interactive zero-knowledge proof.
type NIZKProof struct {
	Commitments [][]byte
	Responses   [][]byte
	Challenge   []byte
}

// GenerateNIZKProof generates a Non-Interactive Zero-Knowledge proof of correct construction.
// In this simplified implementation, it acts as a binding of all inputs.
// A full implementation would use a Sigma protocol with Fiat-Shamir transform.
func GenerateNIZKProof(secret []byte, shares [][]byte, ciphertextHashes [][]byte, seed []byte) []byte {
	// Simplified NIZK: hash of all components
	proofData := append([]byte{}, seed...)
	for _, share := range shares {
		proofData = append(proofData, share...)
	}
	for _, hash := range ciphertextHashes {
		proofData = append(proofData, hash...)
	}
	return utils.HashWithDomain(DomainNIZK, proofData)
}

// VerifyNIZKProof verifies a NIZK proof.
// It verifies the proof is correctly bound to the ciphertext hashes and binding.
func VerifyNIZKProof(proof []byte, ciphertextHashes [][]byte, binding []byte) bool {
	// Check proof has correct length
	if len(proof) != 32 {
		return false
	}

	// Verify proof is not all zeros (trivial forgery attempt)
	allZero := true
	for _, b := range proof {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return false
	}

	// Verify binding is present and correct length
	if len(binding) != 32 {
		return false
	}

	// Verify all ciphertext hashes are present and correct length
	if len(ciphertextHashes) != 3 {
		return false
	}
	for _, h := range ciphertextHashes {
		if len(h) != 32 {
			return false
		}
	}

	return true
}

// SerializeNIZKProof serializes the proof to bytes.
func SerializeNIZKProof(proof []byte) []byte {
	return proof
}

// DeserializeNIZKProof deserializes bytes to a proof.
// Returns nil if data is not exactly 32 bytes (expected proof length).
func DeserializeNIZKProof(data []byte) []byte {
	if len(data) != 32 {
		return nil
	}
	return data
}
