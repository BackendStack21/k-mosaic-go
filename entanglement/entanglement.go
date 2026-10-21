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

// ComputeBinding computes the cross-component binding hash of the serialized
// component public keys, with per-position domain separation.
func ComputeBinding(components ...[]byte) []byte {
	hashes := make([][]byte, len(components))
	for i, c := range components {
		hashes[i] = utils.HashWithDomain(DomainBind+"-"+strconv.Itoa(i), c)
	}
	return utils.HashWithDomain(DomainBind+"-final", utils.HashConcat(hashes...))
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

// MaxNIZKShareSize is the maximum share length a NIZK proof can carry.
// Shares are masked with a single SHA3-256 output (32 bytes).
const MaxNIZKShareSize = 32

// NIZKProof represents a non-interactive zero-knowledge proof.
type NIZKProof struct {
	Commitments [][]byte
	Responses   [][]byte
	Challenge   []byte
}

// GenerateNIZKProof generates the share-binding proof carried in a ciphertext.
//
// It is a hash commitment to every share, keyed to the hash of the component
// ciphertext that carries it and to the ephemeral secret. It is deterministic
// in the ephemeral secret, so the Fujisaki-Okamoto re-encryption check covers
// it; it is not a zero-knowledge proof and adds no security on its own.
func GenerateNIZKProof(secret []byte, shares [][]byte, ciphertextHashes [][]byte, seed []byte) []byte {
	n := len(shares)
	if n < 2 || len(ciphertextHashes) != n {
		return nil
	}

	// Each share is masked with a single 32-byte SHA3-256 output, so shares
	// longer than that cannot be encoded in a proof.
	for _, share := range shares {
		if len(share) > MaxNIZKShareSize {
			return nil
		}
	}

	commitments := make([][]byte, n)
	commitRandomness := make([][]byte, n)
	for i := 0; i < n; i++ {
		domain := DomainNIZK + "-commit-" + strconv.Itoa(i)
		domainHash := utils.HashWithDomain(domain, seed)

		r := utils.SHA3256(domainHash)
		commitRandomness[i] = r

		concatInput := utils.HashConcat(shares[i], r, ciphertextHashes[i])

		commitments[i] = utils.HashWithDomain(DomainNIZK+"-com", concatInput)
	}

	secretMsg := utils.HashWithDomain(DomainNIZK+"-msg", secret)

	challengeInput := utils.HashConcat(append(append([][]byte{secretMsg}, commitments...), ciphertextHashes...)...)

	challenge := utils.SHA3256(challengeInput)

	responses := make([][]byte, n)
	for i := 0; i < n; i++ {
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

	parts := append(append([][]byte{challenge}, commitments...), responses...)

	buf := &bytes.Buffer{}
	_ = binary.Write(buf, binary.LittleEndian, uint32(len(parts)))
	for _, p := range parts {
		_ = binary.Write(buf, binary.LittleEndian, uint32(len(p)))
		buf.Write(p)
	}

	result := buf.Bytes()
	return result
}

// VerifyNIZKProof verifies a share-binding proof against the component
// ciphertext hashes and the recovered ephemeral secret.
func VerifyNIZKProof(proof []byte, ciphertextHashes [][]byte, message []byte) bool {
	n := len(ciphertextHashes)
	if n < 2 {
		return false
	}

	for _, h := range ciphertextHashes {
		if len(h) != 32 {
			return false
		}
	}

	// Structured proof parsing
	if len(proof) < 4 {
		return false
	}
	off := 0
	numParts := int(binary.LittleEndian.Uint32(proof[off:]))
	off += 4
	if numParts != 1+2*n {
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

	commitments := parts[1 : 1+n]
	responses := parts[1+n : 1+2*n]

	// Recompute challenge
	secretMsg := utils.HashWithDomain(DomainNIZK+"-msg", message)

	expectedChallengeInput := utils.HashConcat(append(append([][]byte{secretMsg}, commitments...), ciphertextHashes...)...)

	expectedChallenge := utils.SHA3256(expectedChallengeInput)

	if !utils.ConstantTimeEqual(challenge, expectedChallenge) {
		return false
	}

	// Verify each response
	for i := 0; i < n; i++ {
		resp := responses[i]
		if len(resp) < 32 {
			return false
		}
		shareLen := len(resp) - 32
		// The mask is a single 32-byte hash output; a longer share cannot have
		// been produced by GenerateNIZKProof and would overrun the mask.
		if shareLen > MaxNIZKShareSize {
			return false
		}

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
