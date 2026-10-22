package utils

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"math/bits"
	"runtime"
)

var RandReader io.Reader = rand.Reader

// SecureRandomBytes generates n cryptographically secure random bytes.
// It uses crypto/rand, which relies on the operating system's CSPRNG.
func SecureRandomBytes(n int) ([]byte, error) {
	if n < 0 {
		return nil, errors.New("negative length")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(RandReader, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// RandomInt generates a cryptographically secure random integer in [0, max).
// It uses rejection sampling to ensure a uniform distribution.
func RandomInt(max int) (int, error) {
	if max <= 0 {
		return 0, errors.New("max must be positive")
	}
	if max == 1 {
		return 0, nil
	}

	// Calculate number of bytes needed
	bitsNeeded := 0
	for m := max - 1; m > 0; m >>= 1 {
		bitsNeeded++
	}
	bytesNeeded := (bitsNeeded + 7) / 8
	mask := (1 << bitsNeeded) - 1

	for {
		bytes, err := SecureRandomBytes(bytesNeeded)
		if err != nil {
			return 0, err
		}

		var value int
		for i := 0; i < bytesNeeded; i++ {
			value = (value << 8) | int(bytes[i])
		}
		value &= mask

		if value < max {
			return value, nil
		}
	}
}

// SampleGaussianVector samples a vector of integers from a discrete Gaussian distribution.
// It uses the Box-Muller transform on uniform random bytes generated from a seed via SHAKE256.
// The result is rounded to the nearest integer.
func SampleGaussianVector(seed []byte, n int, sigma float64) []int32 {
	bytes := Shake256(seed, n*8)
	result := make([]int32, n)

	for i := 0; i < n; i++ {
		// Box-Muller transform
		u1Raw := binary.LittleEndian.Uint32(bytes[i*8:])
		u2Raw := binary.LittleEndian.Uint32(bytes[i*8+4:])

		// Map to (0, 1] and [0, 1)
		u1 := (float64(u1Raw) + 1) / 4294967296.0
		u2 := float64(u2Raw) / 4294967296.0

		z := math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)
		result[i] = int32(math.Round(z * sigma))
	}

	return result
}

// SampleCenteredBinomial samples n integers from the centered binomial
// distribution with parameter eta (mean 0, variance eta/2, support
// [-eta, eta]). It is the deterministic, integer-only replacement for
// SampleGaussianVector: the output depends only on the bits of SHAKE256(seed),
// so it is reproducible across platforms and compilers, which
// Fujisaki-Okamoto re-encryption requires.
//
// The XOF output is read as a little-endian bit stream (bit k is
// (byte[k/8] >> (k%8)) & 1). Coefficient i consumes bits [2·eta·i, 2·eta·(i+1)):
// it is the number of set bits among the first eta minus the number of set
// bits among the next eta. The running time depends only on n and eta.
//
// Returns nil if n < 0, n > MaxVectorLength, or eta is outside [1, 64].
func SampleCenteredBinomial(seed []byte, n, eta int) []int32 {
	if n < 0 || n > MaxVectorLength || eta < 1 || eta > 64 {
		return nil
	}
	result := make([]int32, n)
	if n == 0 {
		return result
	}
	// Eight bytes of slack let every field be read with one 64-bit load;
	// those bytes never contribute to the output.
	buf := Shake256(seed, (n*2*eta+7)/8+8)

	// field returns the k ≤ 32 bits of the stream starting at bit offset off.
	field := func(off, k int) uint64 {
		return binary.LittleEndian.Uint64(buf[off>>3:]) >> (off & 7) & (uint64(1)<<k - 1)
	}
	for i := range result {
		off := 2 * eta * i
		var a, b int
		for k := 0; k < eta; k += 32 {
			width := min(32, eta-k)
			a += bits.OnesCount64(field(off+k, width))
			b += bits.OnesCount64(field(off+eta+k, width))
		}
		result[i] = int32(a - b)
	}
	Zeroize(buf)
	return result
}

// SampleVectorZq samples a uniform random vector in Z_q^n.
// It uses rejection sampling on bytes generated from a seed via SHAKE256.
// This ensures the distribution is uniform modulo q.
func SampleVectorZq(seed []byte, n, q int) []int32 {
	result := make([]int32, n)

	// Rejection threshold for unbiased sampling
	threshold := uint32(0xFFFFFFFF - (0xFFFFFFFF % uint32(q)))

	extraFactor := 2
	bytes := Shake256(seed, n*4*extraFactor)

	bytesUsed := 0
	generated := 0
	extensionCounter := 0

	for generated < n {
		if bytesUsed+4 > len(bytes) {
			extensionCounter++
			extSeed := make([]byte, len(seed)+4)
			copy(extSeed, seed)
			binary.LittleEndian.PutUint32(extSeed[len(seed):], uint32(extensionCounter))
			bytes = Shake256(extSeed, n*4*extraFactor)
			bytesUsed = 0
		}

		value := binary.LittleEndian.Uint32(bytes[bytesUsed:])
		bytesUsed += 4

		if value < threshold {
			result[generated] = int32(value % uint32(q))
			generated++
		}
	}

	return result
}

// ValidateSeedEntropy checks if a seed has sufficient entropy.
// It performs basic statistical tests to reject obviously weak seeds (e.g., all zeros, sequential).
// This is a sanity check, not a rigorous randomness test.
func ValidateSeedEntropy(seed []byte) error {
	if len(seed) < 32 {
		return errors.New("seed must be at least 32 bytes")
	}

	// Check for all bytes identical
	first := seed[0]
	allSame := true
	for i := 1; i < len(seed); i++ {
		if seed[i] != first {
			allSame = false
			break
		}
	}
	if allSame {
		return errors.New("seed has low entropy: all bytes are identical")
	}

	// Check for sequential patterns
	isAscending := true
	isDescending := true
	for i := 1; i < len(seed); i++ {
		if seed[i] != byte((int(seed[i-1])+1)%256) {
			isAscending = false
		}
		if seed[i] != byte((int(seed[i-1])-1+256)%256) {
			isDescending = false
		}
		if !isAscending && !isDescending {
			break
		}
	}
	if isAscending || isDescending {
		return errors.New("seed has low entropy: sequential pattern detected")
	}

	// Check for low byte diversity
	unique := make(map[byte]struct{})
	for _, b := range seed {
		unique[b] = struct{}{}
		if len(unique) >= 8 {
			break
		}
	}
	if len(unique) < 8 {
		return errors.New("seed has low entropy: insufficient byte diversity")
	}

	return nil
}

// ConstantTimeEqual compares two byte slices in constant time.
// It returns true if the slices are equal, false otherwise.
// This function leaks only the length of the slices.
func ConstantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// ConstantTimeSelect returns a if condition is 1, b if condition is 0.
// condition must be 0 or 1.
// a and b must have the same length.
func ConstantTimeSelect(condition int, a, b []byte) []byte {
	if len(a) != len(b) {
		panic("arrays must have same length")
	}
	result := make([]byte, len(a))
	for i := range a {
		result[i] = byte(subtle.ConstantTimeSelect(condition, int(a[i]), int(b[i])))
	}
	return result
}

// Zeroize overwrites a byte slice with zeros.
// This is used to clear sensitive data from memory.
// Uses runtime.KeepAlive to prevent compiler optimization from eliminating the stores.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
	// Prevent the compiler from optimizing away the zeroing.
	// runtime.KeepAlive ensures the slice is considered "live" until this point.
	runtime.KeepAlive(b)
}

// ZeroizeInt32 overwrites an int32 slice with zeros.
// Uses runtime.KeepAlive to prevent compiler optimization from eliminating the stores.
func ZeroizeInt32(s []int32) {
	for i := range s {
		s[i] = 0
	}
	runtime.KeepAlive(s)
}

// ZeroizeInt8 overwrites an int8 slice with zeros.
func ZeroizeInt8(s []int8) {
	for i := range s {
		s[i] = 0
	}
	runtime.KeepAlive(s)
}
