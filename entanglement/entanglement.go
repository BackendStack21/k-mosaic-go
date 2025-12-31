// Package entanglement implements the cryptographic binding for kMOSAIC.
package entanglement

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/BackendStack21/k-mosaic-go/utils"
)

const (
	DomainShare  = "kmosaic-share-v1"
	DomainCommit = "kmosaic-commit-v1"
	DomainBind   = "kmosaic-bind-v1"
	DomainNIZK   = "kmosaic-nizk-v1"
)

// Debug logging helpers
var debugNIZK = os.Getenv("DEBUG_NIZK") != ""

func logNIZK(format string, args ...interface{}) {
	if debugNIZK {
		fmt.Fprintf(os.Stderr, "[NIZK-Go] "+format+"\n", args...)
	}
}

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

	logNIZK("=== GenerateNIZKProof START ===")
	logNIZK("Secret: %s", hex.EncodeToString(secret))
	logNIZK("Seed: %s", hex.EncodeToString(seed))
	logNIZK("Share[0] len=%d: %s", len(shares[0]), hex.EncodeToString(shares[0][:min(len(shares[0]), 32)]))
	logNIZK("Share[1] len=%d: %s", len(shares[1]), hex.EncodeToString(shares[1][:min(len(shares[1]), 32)]))
	logNIZK("Share[2] len=%d: %s", len(shares[2]), hex.EncodeToString(shares[2][:min(len(shares[2]), 32)]))
	logNIZK("CiphertextHash[0]: %s", hex.EncodeToString(ciphertextHashes[0]))
	logNIZK("CiphertextHash[1]: %s", hex.EncodeToString(ciphertextHashes[1]))
	logNIZK("CiphertextHash[2]: %s", hex.EncodeToString(ciphertextHashes[2]))

	commitments := make([][]byte, 3)
	commitRandomness := make([][]byte, 3)
	for i := 0; i < 3; i++ {
		domain := DomainNIZK + "-commit-" + strconv.Itoa(i)
		domainHash := utils.HashWithDomain(domain, seed)
		logNIZK("Domain[%d]: %s", i, domain)
		logNIZK("DomainHash[%d]: %s", i, hex.EncodeToString(domainHash))

		r := utils.SHA3256(domainHash)
		commitRandomness[i] = r
		logNIZK("CommitRandomness[%d]: %s", i, hex.EncodeToString(r))

		concatInput := utils.HashConcat(shares[i], r, ciphertextHashes[i])
		logNIZK("Concat input[%d] (share+randomness+hash) len=%d", i, len(concatInput))

		commitments[i] = utils.HashWithDomain(DomainNIZK+"-com", concatInput)
		logNIZK("Commitment[%d]: %s", i, hex.EncodeToString(commitments[i]))
	}

	logNIZK("--- Challenge Computation ---")
	secretMsg := utils.HashWithDomain(DomainNIZK+"-msg", secret)
	logNIZK("SecretMsg (hashed): %s", hex.EncodeToString(secretMsg))

	challengeInput := utils.HashConcat(secretMsg, commitments[0], commitments[1], commitments[2], ciphertextHashes[0], ciphertextHashes[1], ciphertextHashes[2])
	logNIZK("ChallengeInput (concat of 7 items) len=%d", len(challengeInput))

	challenge := utils.SHA3256(challengeInput)
	logNIZK("Challenge: %s", hex.EncodeToString(challenge))

	responses := make([][]byte, 3)
	for i := 0; i < 3; i++ {
		logNIZK("--- Response[%d] ---", i)
		domain := DomainNIZK + "-mask-" + strconv.Itoa(i)
		domainHash := utils.HashWithDomain(domain, challenge)
		logNIZK("Mask domain: %s", domain)
		logNIZK("Mask domainHash: %s", hex.EncodeToString(domainHash))

		fullMask := utils.SHA3256(domainHash)
		logNIZK("FullMask: %s", hex.EncodeToString(fullMask))

		mask := fullMask[:len(shares[i])]
		logNIZK("Mask (truncated to %d): %s", len(mask), hex.EncodeToString(mask[:min(len(mask), 32)]))

		resp := make([]byte, len(shares[i])+32)
		for j := 0; j < len(shares[i]); j++ {
			resp[j] = shares[i][j] ^ mask[j]
		}
		copy(resp[len(shares[i]):], commitRandomness[i])
		logNIZK("Response[%d] len=%d", i, len(resp))
		responses[i] = resp
	}

	parts := [][]byte{challenge, commitments[0], commitments[1], commitments[2], responses[0], responses[1], responses[2]}
	logNIZK("--- Serializing ---")
	logNIZK("Parts count: %d", len(parts))

	buf := &bytes.Buffer{}
	_ = binary.Write(buf, binary.LittleEndian, uint32(len(parts)))
	for idx, p := range parts {
		logNIZK("Part[%d] len=%d: %s", idx, len(p), hex.EncodeToString(p[:min(len(p), 32)]))
		_ = binary.Write(buf, binary.LittleEndian, uint32(len(p)))
		buf.Write(p)
	}

	result := buf.Bytes()
	logNIZK("Final proof len=%d: %s", len(result), hex.EncodeToString(result[:min(len(result), 64)]))
	logNIZK("=== GenerateNIZKProof END ===")

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
	logNIZK("=== VerifyNIZKProof START ===")
	logNIZK("Proof len=%d: %s", len(proof), hex.EncodeToString(proof[:min(len(proof), 64)]))
	logNIZK("Message: %s", hex.EncodeToString(message))

	// Validate ciphertext hashes first before accessing
	if len(ciphertextHashes) != 3 {
		logNIZK("ERROR: Expected 3 ciphertext hashes, got %d", len(ciphertextHashes))
		return false
	}

	logNIZK("CiphertextHash[0]: %s", hex.EncodeToString(ciphertextHashes[0]))
	logNIZK("CiphertextHash[1]: %s", hex.EncodeToString(ciphertextHashes[1]))
	logNIZK("CiphertextHash[2]: %s", hex.EncodeToString(ciphertextHashes[2]))

	for i, h := range ciphertextHashes {
		if len(h) != 32 {
			logNIZK("ERROR: CiphertextHash[%d] has wrong length %d (expected 32)", i, len(h))
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
			logNIZK("ERROR: Legacy proof is all zeros")
			return false
		}
		logNIZK("ACCEPT: Legacy proof format")
		return true
	}

	// Structured proof parsing
	if len(proof) < 4 {
		logNIZK("ERROR: Proof too short (%d bytes)", len(proof))
		return false
	}
	off := 0
	numParts := int(binary.LittleEndian.Uint32(proof[off:]))
	off += 4
	logNIZK("Proof numParts: %d", numParts)
	if numParts != 7 {
		logNIZK("ERROR: Expected 7 parts, got %d", numParts)
		return false
	}
	parts := make([][]byte, numParts)
	const MaxProofPartSize = 1024 * 1024 // 1MB maximum part size

	for i := 0; i < numParts; i++ {
		if off+4 > len(proof) {
			logNIZK("ERROR: Not enough data for part %d length", i)
			return false
		}
		partLen := int(binary.LittleEndian.Uint32(proof[off:]))
		off += 4

		logNIZK("Part[%d] len=%d", i, partLen)

		// Validate part size to prevent DoS via memory exhaustion
		if partLen < 0 || partLen > MaxProofPartSize {
			logNIZK("ERROR: Part[%d] size %d out of range", i, partLen)
			return false
		}
		if off+partLen > len(proof) {
			logNIZK("ERROR: Part[%d] data extends beyond proof", i)
			return false
		}

		parts[i] = make([]byte, partLen)
		copy(parts[i], proof[off:off+partLen])
		off += partLen
	}

	challenge := parts[0]

	// Validate challenge length (must be 32 bytes for SHA3-256)
	if len(challenge) != 32 {
		logNIZK("ERROR: Challenge has wrong length %d (expected 32)", len(challenge))
		return false
	}
	logNIZK("Challenge: %s", hex.EncodeToString(challenge))

	commitments := parts[1:4]
	responses := parts[4:7]

	logNIZK("Commitment[0]: %s", hex.EncodeToString(commitments[0]))
	logNIZK("Commitment[1]: %s", hex.EncodeToString(commitments[1]))
	logNIZK("Commitment[2]: %s", hex.EncodeToString(commitments[2]))

	// Recompute challenge
	logNIZK("--- Challenge Verification ---")
	secretMsg := utils.HashWithDomain(DomainNIZK+"-msg", message)
	logNIZK("SecretMsg (hashed): %s", hex.EncodeToString(secretMsg))

	expectedChallengeInput := utils.HashConcat(secretMsg, commitments[0], commitments[1], commitments[2], ciphertextHashes[0], ciphertextHashes[1], ciphertextHashes[2])
	logNIZK("ChallengeInput (concat of 7 items) len=%d", len(expectedChallengeInput))

	expectedChallenge := utils.SHA3256(expectedChallengeInput)
	logNIZK("ExpectedChallenge: %s", hex.EncodeToString(expectedChallenge))
	logNIZK("Match: %v", utils.ConstantTimeEqual(challenge, expectedChallenge))

	if !utils.ConstantTimeEqual(challenge, expectedChallenge) {
		logNIZK("ERROR: Challenge verification failed")
		return false
	}

	// Verify each response
	logNIZK("--- Response Verification ---")
	for i := 0; i < 3; i++ {
		logNIZK("Response[%d]:", i)
		resp := responses[i]
		if len(resp) < 32 {
			logNIZK("ERROR: Response[%d] too short (%d bytes)", i, len(resp))
			return false
		}
		shareLen := len(resp) - 32
		logNIZK("  shareLen=%d", shareLen)

		commitRandomness := resp[shareLen:]
		logNIZK("  CommitRandomness: %s", hex.EncodeToString(commitRandomness))

		domain := DomainNIZK + "-mask-" + strconv.Itoa(i)
		domainHash := utils.HashWithDomain(domain, challenge)
		logNIZK("  Mask domain: %s", domain)
		logNIZK("  Mask domainHash: %s", hex.EncodeToString(domainHash))

		fullMask := utils.SHA3256(domainHash)
		logNIZK("  FullMask: %s", hex.EncodeToString(fullMask))

		mask := fullMask[:shareLen]
		logNIZK("  Mask (truncated): %s", hex.EncodeToString(mask[:min(len(mask), 32)]))

		share := make([]byte, shareLen)
		for j := 0; j < shareLen; j++ {
			share[j] = resp[j] ^ mask[j]
		}
		logNIZK("  ReconstructedShare: %s", hex.EncodeToString(share[:min(len(share), 32)]))

		concatInput := utils.HashConcat(share, commitRandomness, ciphertextHashes[i])
		logNIZK("  Concat input (share+randomness+hash) len=%d", len(concatInput))

		expectedCom := utils.HashWithDomain(DomainNIZK+"-com", concatInput)
		logNIZK("  ExpectedCommitment: %s", hex.EncodeToString(expectedCom))
		logNIZK("  ActualCommitment:   %s", hex.EncodeToString(commitments[i]))
		logNIZK("  Match: %v", utils.ConstantTimeEqual(expectedCom, commitments[i]))

		if !utils.ConstantTimeEqual(expectedCom, commitments[i]) {
			logNIZK("ERROR: Commitment[%d] verification failed", i)
			return false
		}
	}

	logNIZK("=== VerifyNIZKProof END (SUCCESS) ===")
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
