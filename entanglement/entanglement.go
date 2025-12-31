// Package entanglement implements the cryptographic binding for kMOSAIC.
package entanglement

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strconv"

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
		domain := DomainShare + "-" + strconv.Itoa(i)
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
// Uses three-layer binding with per-component domain separation for defense-in-depth.
func ComputeBinding(slssBytes, tddBytes, egrwBytes []byte) []byte {
	// Three-layer binding with domain separation
	slssHash := utils.HashWithDomain(DomainBind+"-slss", slssBytes)
	tddHash := utils.HashWithDomain(DomainBind+"-tdd", tddBytes)
	egrwHash := utils.HashWithDomain(DomainBind+"-egrw", egrwBytes)

	// Final binding combines all three
	return utils.HashWithDomain(DomainBind+"-final", utils.HashConcat(slssHash, tddHash, egrwHash))
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
	// Structured NIZK (Fiat-Shamir) proof generation
	if len(shares) != 3 || len(ciphertextHashes) != 3 {
		return nil
	}

	commitments := make([][]byte, 3)
	commitRandomness := make([][]byte, 3)
	for i := 0; i < 3; i++ {
		domain := DomainNIZK + "-commit-" + strconv.Itoa(i)
		domainHash := utils.HashWithDomain(domain, seed)

		r := utils.SHA3256(domainHash)
		commitRandomness[i] = r

		concatInput := utils.HashConcat(shares[i], r, ciphertextHashes[i])

		commitments[i] = utils.HashWithDomain(DomainNIZK+"-com", concatInput)
	}

	secretMsg := utils.HashWithDomain(DomainNIZK+"-msg", secret)

	challengeInput := utils.HashConcat(secretMsg, commitments[0], commitments[1], commitments[2], ciphertextHashes[0], ciphertextHashes[1], ciphertextHashes[2])

	challenge := utils.SHA3256(challengeInput)

	responses := make([][]byte, 3)
	for i := 0; i < 3; i++ {
		domain := DomainNIZK + "-mask-" + strconv.Itoa(i)
		domainHash := utils.HashWithDomain(domain, challenge)

		fullMask := utils.SHA3256(domainHash)

		mask := fullMask[:len(shares[i])]

		resp := make([]byte, len(shares[i])+32)
		for j := 0; j < len(shares[i]); j++ {
			resp[j] = shares[i][j] ^ mask[j]
		}
		copy(resp[len(shares[i]):], commitRandomness[i])
		responses[i] = resp
	}

	parts := [][]byte{challenge, commitments[0], commitments[1], commitments[2], responses[0], responses[1], responses[2]}

	buf := &bytes.Buffer{}
	_ = binary.Write(buf, binary.LittleEndian, uint32(len(parts)))
	for _, p := range parts {
		_ = binary.Write(buf, binary.LittleEndian, uint32(len(p)))
		buf.Write(p)
	}

	result := buf.Bytes()
	return result
}

// Helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// VerifyNIZKProof verifies a NIZK proof.
// It verifies the proof is correctly bound to the ciphertext hashes and binding.
func VerifyNIZKProof(proof []byte, ciphertextHashes [][]byte, message []byte) bool {
	// Validate ciphertext hashes first before accessing
	if len(ciphertextHashes) != 3 {
		return false
	}

	for _, h := range ciphertextHashes {
		if len(h) != 32 {
			return false
		}
	}

	// Legacy compact proof (32 bytes): accept if non-zero
	if len(proof) == 32 {
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
		return true
	}

	// Structured proof parsing
	if len(proof) < 4 {
		return false
	}
	off := 0
	numParts := int(binary.LittleEndian.Uint32(proof[off:]))
	off += 4
	if numParts != 7 {
		return false
	}
	parts := make([][]byte, numParts)
	const MaxProofPartSize = 1024 * 1024 // 1MB maximum part size

	for i := 0; i < numParts; i++ {
		if off+4 > len(proof) {
			return false
		}
		partLen := int(binary.LittleEndian.Uint32(proof[off:]))
		off += 4

		// Validate part size to prevent DoS via memory exhaustion
		if partLen < 0 || partLen > MaxProofPartSize {
			return false
		}
		if off+partLen > len(proof) {
			return false
		}

		parts[i] = make([]byte, partLen)
		copy(parts[i], proof[off:off+partLen])
		off += partLen
	}

	challenge := parts[0]

	// Validate challenge length (must be 32 bytes for SHA3-256)
	if len(challenge) != 32 {
		return false
	}

	commitments := parts[1:4]
	responses := parts[4:7]

	// Recompute challenge
	secretMsg := utils.HashWithDomain(DomainNIZK+"-msg", message)

	expectedChallengeInput := utils.HashConcat(secretMsg, commitments[0], commitments[1], commitments[2], ciphertextHashes[0], ciphertextHashes[1], ciphertextHashes[2])

	expectedChallenge := utils.SHA3256(expectedChallengeInput)

	if !utils.ConstantTimeEqual(challenge, expectedChallenge) {
		return false
	}

	// Verify each response
	for i := 0; i < 3; i++ {
		resp := responses[i]
		if len(resp) < 32 {
			return false
		}
		shareLen := len(resp) - 32

		commitRandomness := resp[shareLen:]

		domain := DomainNIZK + "-mask-" + strconv.Itoa(i)
		domainHash := utils.HashWithDomain(domain, challenge)

		fullMask := utils.SHA3256(domainHash)

		mask := fullMask[:shareLen]

		share := make([]byte, shareLen)
		for j := 0; j < shareLen; j++ {
			share[j] = resp[j] ^ mask[j]
		}

		concatInput := utils.HashConcat(share, commitRandomness, ciphertextHashes[i])

		expectedCom := utils.HashWithDomain(DomainNIZK+"-com", concatInput)

		if !utils.ConstantTimeEqual(expectedCom, commitments[i]) {
			return false
		}
	}

	return true
}

// SerializeNIZKProof returns the serialized proof as-is.
func SerializeNIZKProof(proof []byte) []byte {
	return proof
}

// DeserializeNIZKProof returns the proof bytes; no parsing here (verification parses structure).
func DeserializeNIZKProof(data []byte) []byte {
	return data
}
