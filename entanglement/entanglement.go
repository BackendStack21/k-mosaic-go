// Package entanglement implements the XOR secret sharing that splits the
// KEM's ephemeral secret between its components, and the binding checksum
// stored in composite public keys.
//
// The binding is a domain-separated hash of the serialized component public
// keys. Anyone can recompute it from the public key, so it is an integrity
// check against accidental or careless mixing of components, not an
// authentication: what prevents a secret key from being used with the wrong
// public key is the public-key hash stored in the secret key and checked by
// kem.Decapsulate and sign.Sign.
package entanglement

import (
	"errors"
	"strconv"

	"github.com/BackendStack21/k-mosaic-go/v2/utils"
)

const (
	DomainShare = "kmosaic-share-v4"
	DomainBind  = "kmosaic-bind-v4"
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

// SecretShareDeterministic, SecretReconstruct and ComputeBinding are the only
// primitives this package provides. Earlier versions carried a "NIZK proof"
// inside every ciphertext; it masked each share with a hash of a value that
// was itself part of the proof, so anyone could unmask the shares and recover
// the ephemeral secret from the ciphertext alone. It has been removed; the
// Fujisaki-Okamoto re-encryption check in the KEM binds the shares to the
// ciphertext without any extra field.
