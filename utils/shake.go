package utils

import (
	"sync"

	"golang.org/x/crypto/sha3"
)

const (
	// MaxHashConcatInputSize prevents integer overflow and collision attacks in HashConcat.
	// Each input must be <= 100MB. This provides safe encoding while remaining reasonable.
	MaxHashConcatInputSize = 100 * 1024 * 1024
)

var shake256Pool = sync.Pool{
	New: func() interface{} {
		return sha3.NewShake256()
	},
}

// Shake256 computes the SHAKE256 extendable output function (XOF).
// It takes an input byte slice and generates an output of the specified length.
// This is used for generating pseudo-random bytes from a seed.
func Shake256(input []byte, outputLen int) []byte {
	h := shake256Pool.Get().(sha3.ShakeHash)
	defer func() {
		h.Reset()
		shake256Pool.Put(h)
	}()

	h.Write(input)
	output := make([]byte, outputLen)
	_, _ = h.Read(output)
	return output
}

// Shake256Into computes SHAKE256 and writes the output into the provided buffer.
func Shake256Into(input []byte, output []byte) {
	h := shake256Pool.Get().(sha3.ShakeHash)
	defer func() {
		h.Reset()
		shake256Pool.Put(h)
	}()

	h.Write(input)
	_, _ = h.Read(output)
}

// SHA3256 computes the SHA3-256 cryptographic hash of the input.
// It returns a 32-byte hash.
func SHA3256(input []byte) []byte {
	h := sha3.New256()
	h.Write(input)
	return h.Sum(nil)
}

// HashWithDomain computes a domain-separated SHA3-256 hash.
// It prefixes the data with the length of the domain string and the domain string itself.
// This prevents collisions between different uses of the hash function.
// Panics if domain is longer than 255 bytes.
func HashWithDomain(domain string, data []byte) []byte {
	domainBytes := []byte(domain)
	if len(domainBytes) > 255 {
		panic("domain string must be at most 255 bytes")
	}
	h := sha3.New256()
	h.Write([]byte{byte(len(domainBytes))})
	h.Write(domainBytes)
	h.Write(data)
	return h.Sum(nil)
}

// HashConcat computes the SHA3-256 hash of the concatenation of multiple byte slices.
// Each slice is prefixed with its length (4 bytes, little-endian) to ensure unique encoding.
// SECURITY: Validates input sizes to prevent integer overflow and hash collisions.
func HashConcat(inputs ...[]byte) []byte {
	h := sha3.New256()
	lenBytes := make([]byte, 4)
	for _, input := range inputs {
		// Validate input size to prevent DoS and overflow
		if len(input) > MaxHashConcatInputSize {
			panic("HashConcat: input size exceeds maximum")
		}

		l := len(input)
		lenBytes[0] = byte(l)
		lenBytes[1] = byte(l >> 8)
		lenBytes[2] = byte(l >> 16)
		lenBytes[3] = byte(l >> 24)
		h.Write(lenBytes)
		h.Write(input)
	}
	return h.Sum(nil)
}

// Shake256WithDomain computes SHAKE256 with domain separation.
// It works like HashWithDomain but produces an output of arbitrary length.
// Panics if domain is longer than 255 bytes.
func Shake256WithDomain(domain string, data []byte, outputLen int) []byte {
	domainBytes := []byte(domain)
	if len(domainBytes) > 255 {
		panic("domain string must be at most 255 bytes")
	}

	h := shake256Pool.Get().(sha3.ShakeHash)
	defer func() {
		h.Reset()
		shake256Pool.Put(h)
	}()

	h.Write([]byte{byte(len(domainBytes))})
	h.Write(domainBytes)
	h.Write(data)
	output := make([]byte, outputLen)
	_, _ = h.Read(output)
	return output
}
