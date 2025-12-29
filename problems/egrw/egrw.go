// Package egrw implements the Expander Graph Random Walk problem for kMOSAIC.
package egrw

import (
	"encoding/binary"
	"errors"
	"sync"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

const (
	DomainStart   = "kmosaic-egrw-start-v1"
	DomainWalk    = "kmosaic-egrw-walk-v1"
	DomainEncrypt = "kmosaic-egrw-encrypt-v1"
	DomainMask    = "kmosaic-egrw-mask-v1"
)

// Generator cache with LRU eviction
var (
	generatorCacheMu sync.RWMutex
	generatorCache   = make(map[int][]kmosaic.SL2Element)
	cacheMaxSize     = 16
)

// mod returns x mod p, ensuring the result is always non-negative in [0, p).
func mod(x int64, p int) int {
	r := x % int64(p)
	if r < 0 {
		r += int64(p)
	}
	return int(r)
}

// ModInverse computes the modular multiplicative inverse a^(-1) mod p.
// It uses the extended Euclidean algorithm.
// Panics if a is 0.
func ModInverse(a, p int) int {
	if a == 0 {
		panic("cannot compute inverse of zero")
	}
	oldR, r := mod(int64(a), p), p
	oldS, s := 1, 0

	for r != 0 {
		q := oldR / r
		oldR, r = r, oldR-q*r
		oldS, s = s, oldS-q*s
	}
	return mod(int64(oldS), p)
}

// SL2Multiply multiplies two SL(2, Z_p) elements.
// The result is (m1 * m2) mod p.
func SL2Multiply(m1, m2 kmosaic.SL2Element, p int) kmosaic.SL2Element {
	return kmosaic.SL2Element{
		A: mod(int64(m1.A)*int64(m2.A)+int64(m1.B)*int64(m2.C), p),
		B: mod(int64(m1.A)*int64(m2.B)+int64(m1.B)*int64(m2.D), p),
		C: mod(int64(m1.C)*int64(m2.A)+int64(m1.D)*int64(m2.C), p),
		D: mod(int64(m1.C)*int64(m2.B)+int64(m1.D)*int64(m2.D), p),
	}
}

// SL2Inverse computes the inverse of an SL(2, Z_p) element.
// For a matrix [[A, B], [C, D]] with determinant 1, the inverse is [[D, -B], [-C, A]].
func SL2Inverse(m kmosaic.SL2Element, p int) kmosaic.SL2Element {
	return kmosaic.SL2Element{
		A: mod(int64(m.D), p),
		B: mod(int64(-m.B), p),
		C: mod(int64(-m.C), p),
		D: mod(int64(m.A), p),
	}
}

// GetGenerators returns the standard generating set for SL(2, Z_p).
// The generators are S = [[0, -1], [1, 0]] and T = [[1, 1], [0, 1]], along with their inverses.
// The results are cached to avoid recomputation.
func GetGenerators(p int) []kmosaic.SL2Element {
	generatorCacheMu.RLock()
	if gens, ok := generatorCache[p]; ok {
		generatorCacheMu.RUnlock()
		return gens
	}
	generatorCacheMu.RUnlock()

	generatorCacheMu.Lock()
	defer generatorCacheMu.Unlock()

	// Double-check after acquiring write lock
	if gens, ok := generatorCache[p]; ok {
		return gens
	}

	S := kmosaic.SL2Element{A: 0, B: mod(-1, p), C: 1, D: 0}
	T := kmosaic.SL2Element{A: 1, B: 1, C: 0, D: 1}
	SInv := SL2Inverse(S, p)
	TInv := SL2Inverse(T, p)

	gens := []kmosaic.SL2Element{S, SInv, T, TInv}

	// Evict if cache is full
	if len(generatorCache) >= cacheMaxSize {
		for k := range generatorCache {
			delete(generatorCache, k)
			break
		}
	}
	generatorCache[p] = gens
	return gens
}

// ApplyGenerator multiplies an element by one of the generators.
// genIdx is an index into the generator list returned by GetGenerators.
func ApplyGenerator(element kmosaic.SL2Element, genIdx, p int) kmosaic.SL2Element {
	gens := GetGenerators(p)
	return SL2Multiply(element, gens[genIdx], p)
}

// ApplyWalk applies a sequence of generator multiplications starting from 'start'.
// The walk is defined by a sequence of generator indices.
func ApplyWalk(start kmosaic.SL2Element, walk []int, p int) kmosaic.SL2Element {
	current := start
	gens := GetGenerators(p)
	for _, genIdx := range walk {
		current = SL2Multiply(current, gens[genIdx], p)
	}
	return current
}

// SL2ToBytes serializes an SL(2, Z_p) element to a 16-byte slice.
// Each component (A, B, C, D) is stored as a 4-byte little-endian integer.
func SL2ToBytes(m kmosaic.SL2Element) []byte {
	result := make([]byte, 16)
	binary.LittleEndian.PutUint32(result[0:], uint32(m.A))
	binary.LittleEndian.PutUint32(result[4:], uint32(m.B))
	binary.LittleEndian.PutUint32(result[8:], uint32(m.C))
	binary.LittleEndian.PutUint32(result[12:], uint32(m.D))
	return result
}

// BytesToSL2 deserializes a 16-byte slice to an SL(2, Z_p) element.
func BytesToSL2(data []byte) kmosaic.SL2Element {
	return kmosaic.SL2Element{
		A: int(int32(binary.LittleEndian.Uint32(data[0:]))),
		B: int(int32(binary.LittleEndian.Uint32(data[4:]))),
		C: int(int32(binary.LittleEndian.Uint32(data[8:]))),
		D: int(int32(binary.LittleEndian.Uint32(data[12:]))),
	}
}

// sampleSL2Element samples a uniform random element from SL(2, Z_p).
// It uses rejection sampling to find a matrix with determinant 1.
func sampleSL2Element(seed []byte, p int) kmosaic.SL2Element {
	bytes := utils.Shake256(seed, 128)

	maxAttempts := 32
	for attempt := 0; attempt < maxAttempts; attempt++ {
		offset := attempt * 12
		if offset+12 > len(bytes) {
			break
		}

		a := mod(int64(binary.LittleEndian.Uint32(bytes[offset:])), p)
		b := mod(int64(binary.LittleEndian.Uint32(bytes[offset+4:])), p)
		c := mod(int64(binary.LittleEndian.Uint32(bytes[offset+8:])), p)

		if a != 0 {
			aInv := ModInverse(a, p)
			d := mod(int64(1+b*c)*int64(aInv), p)
			// Verify determinant
			if mod(int64(a*d-b*c), p) == 1 {
				return kmosaic.SL2Element{A: a, B: b, C: c, D: d}
			}
		}
	}

	// Fallback: T^k (guaranteed to be in SL(2, Z_p))
	k := mod(int64(binary.LittleEndian.Uint32(bytes[0:])), p)
	return kmosaic.SL2Element{A: 1, B: k, C: 0, D: 1}
}

// sampleWalk samples a random walk of a given length.
// Each step is an index in [0, 3] corresponding to one of the 4 generators.
func sampleWalk(seed []byte, length int) []int {
	bytes := utils.Shake256(seed, length)
	walk := make([]int, length)
	for i := 0; i < length; i++ {
		walk[i] = int(bytes[i]) % 4
	}
	return walk
}

// KeyGen generates EGRW key pair
func KeyGen(params kmosaic.EGRWParams, seed []byte) (*kmosaic.EGRWKeyPair, error) {
	if len(seed) < 32 {
		return nil, errors.New("seed must be at least 32 bytes")
	}

	p, k := params.P, params.K

	vStart := sampleSL2Element(utils.HashWithDomain(DomainStart, seed), p)
	walk := sampleWalk(utils.HashWithDomain(DomainWalk, seed), k)
	vEnd := ApplyWalk(vStart, walk, p)

	return &kmosaic.EGRWKeyPair{
		PublicKey: kmosaic.EGRWPublicKey{VStart: vStart, VEnd: vEnd},
		SecretKey: kmosaic.EGRWSecretKey{Walk: walk},
	}, nil
}

// Encrypt encrypts a message fragment using EGRW
func Encrypt(pk kmosaic.EGRWPublicKey, message []byte, params kmosaic.EGRWParams, randomness []byte) (*kmosaic.EGRWCiphertext, error) {
	if len(randomness) < 32 {
		return nil, errors.New("randomness must be at least 32 bytes")
	}

	p, k := params.P, params.K

	ephemeralWalk := sampleWalk(utils.HashWithDomain(DomainEncrypt, randomness), k)
	ephemeralVertex := ApplyWalk(pk.VStart, ephemeralWalk, p)

	// Derive keystream
	keyInput := utils.HashConcat(
		utils.HashWithDomain(DomainMask, SL2ToBytes(ephemeralVertex)),
		utils.HashWithDomain(DomainMask, SL2ToBytes(pk.VStart)),
		utils.HashWithDomain(DomainMask, SL2ToBytes(pk.VEnd)),
	)
	keyStream := utils.Shake256(keyInput, 32)

	// XOR message
	masked := make([]byte, 32)
	for i := 0; i < 32; i++ {
		if i < len(message) {
			masked[i] = message[i] ^ keyStream[i]
		} else {
			masked[i] = keyStream[i]
		}
	}

	return &kmosaic.EGRWCiphertext{
		Vertex:     ephemeralVertex,
		Commitment: masked,
	}, nil
}

// Decrypt decrypts an EGRW ciphertext
func Decrypt(ct *kmosaic.EGRWCiphertext, sk kmosaic.EGRWSecretKey, pk kmosaic.EGRWPublicKey, params kmosaic.EGRWParams) []byte {
	// Derive same keystream
	keyInput := utils.HashConcat(
		utils.HashWithDomain(DomainMask, SL2ToBytes(ct.Vertex)),
		utils.HashWithDomain(DomainMask, SL2ToBytes(pk.VStart)),
		utils.HashWithDomain(DomainMask, SL2ToBytes(pk.VEnd)),
	)
	keyStream := utils.Shake256(keyInput, 32)

	// XOR decrypt
	result := make([]byte, 32)
	for i := 0; i < 32 && i < len(ct.Commitment); i++ {
		result[i] = ct.Commitment[i] ^ keyStream[i]
	}

	return result
}

// SerializePublicKey serializes EGRW public key
func SerializePublicKey(pk kmosaic.EGRWPublicKey) []byte {
	startBytes := SL2ToBytes(pk.VStart)
	endBytes := SL2ToBytes(pk.VEnd)
	result := make([]byte, len(startBytes)+len(endBytes))
	copy(result, startBytes)
	copy(result[len(startBytes):], endBytes)
	return result
}

// DeserializePublicKey deserializes EGRW public key
func DeserializePublicKey(data []byte) (*kmosaic.EGRWPublicKey, error) {
	if len(data) < 32 {
		return nil, errors.New("invalid EGRW public key: too short")
	}

	pk := &kmosaic.EGRWPublicKey{}
	pk.VStart = BytesToSL2(data[0:16])
	pk.VEnd = BytesToSL2(data[16:32])
	return pk, nil
}
