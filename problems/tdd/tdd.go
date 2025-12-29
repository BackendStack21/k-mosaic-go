// Package tdd implements the Tensor Decomposition Distinguishing problem for kMOSAIC.
package tdd

import (
	"encoding/binary"
	"errors"
	"runtime"
	"sync"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

const (
	DomainFactors = "kmosaic-tdd-factors-v1"
	DomainNoise   = "kmosaic-tdd-noise-v1"
	DomainMask    = "kmosaic-tdd-mask-v1"
	DomainHint    = "kmosaic-tdd-hint-v1"
	DomainFactorA = "kmosaic-tdd-factor-a-v1"
	DomainFactorB = "kmosaic-tdd-factor-b-v1"
	DomainFactorC = "kmosaic-tdd-factor-c-v1"
)

// mod returns x mod q, ensuring the result is always non-negative in [0, q).
func mod(x int64, q int) int32 {
	r := x % int64(q)
	if r < 0 {
		r += int64(q)
	}
	return int32(r)
}

// fastMod returns x mod q, assuming x >= 0.
func fastMod(x int64, q int) int32 {
	return int32(x % int64(q))
}

// tensorAddOuterProduct adds the outer product a ⊗ b ⊗ c to the tensor T.
// T is an n x n x n tensor flattened into a 1D array.
// a, b, c are vectors of length n.
// The operation is performed modulo q.
func tensorAddOuterProduct(T []int32, n int, a, b, c []int32, q int) {
	n2 := n * n
	numWorkers := runtime.GOMAXPROCS(0)

	if n < 16 || numWorkers <= 1 {
		for i := 0; i < n; i++ {
			ai := int64(a[i])
			iOffset := i * n2
			for j := 0; j < n; j++ {
				aibj := ai * int64(b[j])
				ijOffset := iOffset + j*n
				for k := 0; k < n; k++ {
					idx := ijOffset + k
					T[idx] = fastMod(int64(T[idx])+aibj*int64(c[k]), q)
				}
			}
		}
		return
	}

	var wg sync.WaitGroup
	rowsPerWorker := (n + numWorkers - 1) / numWorkers

	for w := 0; w < numWorkers; w++ {
		start := w * rowsPerWorker
		end := start + rowsPerWorker
		if end > n {
			end = n
		}
		if start >= n {
			break
		}

		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			for i := start; i < end; i++ {
				ai := int64(a[i])
				iOffset := i * n2
				for j := 0; j < n; j++ {
					aibj := ai * int64(b[j])
					ijOffset := iOffset + j*n
					for k := 0; k < n; k++ {
						idx := ijOffset + k
						T[idx] = fastMod(int64(T[idx])+aibj*int64(c[k]), q)
					}
				}
			}
		}(start, end)
	}
	wg.Wait()
}

// tensorAdd adds two tensors element-wise modulo q.
func tensorAdd(A, B []int32, q int) []int32 {
	result := make([]int32, len(A))
	for i := range A {
		result[i] = fastMod(int64(A[i])+int64(B[i]), q)
	}
	return result
}

// tensorContractedProduct computes the contracted product T ×₁ λ.
// T is an n x n x n tensor.
// λ is a vector of length r (or less).
// The result is an n x n matrix flattened into a 1D array.
// This operation corresponds to summing weighted slices of the tensor.
func tensorContractedProduct(T, lambda []int32, n, r, q int) []int32 {
	result := make([]int32, n*n)
	n2 := n * n
	lambdaLen := n
	if len(lambda) < lambdaLen {
		lambdaLen = len(lambda)
	}

	numWorkers := runtime.GOMAXPROCS(0)
	if n < 32 || numWorkers <= 1 {
		for j := 0; j < n; j++ {
			for k := 0; k < n; k++ {
				var sum int64
				for i := 0; i < lambdaLen; i++ {
					sum += int64(T[i*n2+j*n+k]) * int64(lambda[i])
				}
				result[j*n+k] = fastMod(sum, q)
			}
		}
		return result
	}

	var wg sync.WaitGroup
	rowsPerWorker := (n + numWorkers - 1) / numWorkers

	for w := 0; w < numWorkers; w++ {
		start := w * rowsPerWorker
		end := start + rowsPerWorker
		if end > n {
			end = n
		}
		if start >= n {
			break
		}

		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			for j := start; j < end; j++ {
				for k := 0; k < n; k++ {
					var sum int64
					for i := 0; i < lambdaLen; i++ {
						sum += int64(T[i*n2+j*n+k]) * int64(lambda[i])
					}
					result[j*n+k] = fastMod(sum, q)
				}
			}
		}(start, end)
	}
	wg.Wait()
	return result
}

// sampleVector samples a uniform random vector in Z_q^n using a seed.
func sampleVector(seed []byte, n, q int) []int32 {
	return utils.SampleVectorZq(seed, n, q)
}

// sampleTensorFactors samples r factor triples (a, b, c) for tensor decomposition.
// Each factor vector is sampled uniformly from Z_q^n.
// The sampling is parallelized for performance.
func sampleTensorFactors(seed []byte, n, r, q int) kmosaic.TDDFactors {
	factors := kmosaic.TDDFactors{
		A: make([][]int32, r),
		B: make([][]int32, r),
		C: make([][]int32, r),
	}

	numWorkers := runtime.GOMAXPROCS(0)
	if r < numWorkers {
		numWorkers = r
	}

	var wg sync.WaitGroup
	factorsPerWorker := (r + numWorkers - 1) / numWorkers

	for w := 0; w < numWorkers; w++ {
		start := w * factorsPerWorker
		end := start + factorsPerWorker
		if end > r {
			end = r
		}
		if start >= r {
			break
		}

		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			for i := start; i < end; i++ {
				indexSeed := make([]byte, len(seed)+4)
				copy(indexSeed, seed)
				binary.LittleEndian.PutUint32(indexSeed[len(seed):], uint32(i))

				factors.A[i] = sampleVector(utils.HashWithDomain(DomainFactorA, indexSeed), n, q)
				factors.B[i] = sampleVector(utils.HashWithDomain(DomainFactorB, indexSeed), n, q)
				factors.C[i] = sampleVector(utils.HashWithDomain(DomainFactorC, indexSeed), n, q)
			}
		}(start, end)
	}
	wg.Wait()
	return factors
}

// sampleNoiseTensor samples a tensor with entries from a discrete Gaussian distribution.
func sampleNoiseTensor(seed []byte, n int, sigma float64, q int) []int32 {
	size := n * n * n
	return utils.SampleGaussianVector(seed, size, sigma)
}

// sampleRandomTensor samples a uniform random tensor in Z_q^{n^3}.
func sampleRandomTensor(seed []byte, size, q int) []int32 {
	return utils.SampleVectorZq(seed, size, q)
}

// KeyGen generates TDD key pair
func KeyGen(params kmosaic.TDDParams, seed []byte) (*kmosaic.TDDKeyPair, error) {
	if len(seed) < 32 {
		return nil, errors.New("seed must be at least 32 bytes")
	}

	n, r, q, sigma := params.N, params.R, params.Q, params.Sigma

	factors := sampleTensorFactors(utils.HashWithDomain(DomainFactors, seed), n, r, q)

	// Construct secret tensor
	T := make([]int32, n*n*n)
	for i := 0; i < r; i++ {
		tensorAddOuterProduct(T, n, factors.A[i], factors.B[i], factors.C[i], q)
	}

	// Add noise
	E := sampleNoiseTensor(utils.HashWithDomain(DomainNoise, seed), n, sigma, q)
	TPub := tensorAdd(T, E, q)

	utils.ZeroizeInt32(T)
	utils.ZeroizeInt32(E)

	return &kmosaic.TDDKeyPair{
		PublicKey: kmosaic.TDDPublicKey{T: TPub},
		SecretKey: kmosaic.TDDSecretKey{Factors: factors},
	}, nil
}

// Encrypt encrypts a message fragment using TDD
func Encrypt(pk kmosaic.TDDPublicKey, message []byte, params kmosaic.TDDParams, randomness []byte) (*kmosaic.TDDCiphertext, error) {
	if len(randomness) < 32 {
		return nil, errors.New("randomness must be at least 32 bytes")
	}

	n, r, q := params.N, params.R, params.Q

	// Encode message as coefficients
	lambda := make([]int32, r)
	scale := int32(q / 256)
	for i := 0; i < r && i < len(message); i++ {
		lambda[i] = mod(int64(message[i])*int64(scale), q)
	}

	// Compute contracted product
	contracted := tensorContractedProduct(pk.T, lambda, n, r, q)

	// Add random masking
	R := sampleRandomTensor(utils.HashWithDomain(DomainMask, randomness), n*n, q)
	masked := tensorAdd(contracted, R, q)

	// Derive keystream from masked matrix
	maskedBytes := make([]byte, len(masked)*4)
	for i, v := range masked {
		binary.LittleEndian.PutUint32(maskedBytes[i*4:], uint32(v))
	}
	keystream := utils.Shake256(utils.HashWithDomain(DomainHint, maskedBytes), 32)

	// XOR encrypt message
	encryptedMsg := make([]byte, 32)
	for i := 0; i < 32; i++ {
		if i < len(message) {
			encryptedMsg[i] = message[i] ^ keystream[i]
		} else {
			encryptedMsg[i] = keystream[i]
		}
	}

	// Build ciphertext
	encMsgLen := 8
	data := make([]int32, len(masked)+encMsgLen)
	copy(data, masked)

	for i := 0; i < encMsgLen; i++ {
		data[len(masked)+i] = int32(encryptedMsg[i*4]) |
			int32(encryptedMsg[i*4+1])<<8 |
			int32(encryptedMsg[i*4+2])<<16 |
			int32(encryptedMsg[i*4+3])<<24
	}

	utils.ZeroizeInt32(lambda)
	utils.ZeroizeInt32(contracted)
	utils.ZeroizeInt32(R)
	utils.Zeroize(keystream)
	utils.Zeroize(encryptedMsg)

	return &kmosaic.TDDCiphertext{Data: data}, nil
}

// Decrypt decrypts a TDD ciphertext
func Decrypt(ct *kmosaic.TDDCiphertext, sk kmosaic.TDDSecretKey, pk kmosaic.TDDPublicKey, params kmosaic.TDDParams) []byte {
	n := params.N
	encMsgLen := 8

	masked := ct.Data[:len(ct.Data)-encMsgLen]

	// Extract encrypted message
	encryptedMsg := make([]byte, 32)
	for i := 0; i < encMsgLen; i++ {
		v := ct.Data[len(ct.Data)-encMsgLen+i]
		encryptedMsg[i*4] = byte(v)
		encryptedMsg[i*4+1] = byte(v >> 8)
		encryptedMsg[i*4+2] = byte(v >> 16)
		encryptedMsg[i*4+3] = byte(v >> 24)
	}

	// Derive same keystream
	maskedBytes := make([]byte, len(masked)*4)
	for i, v := range masked {
		binary.LittleEndian.PutUint32(maskedBytes[i*4:], uint32(v))
	}
	keystream := utils.Shake256(utils.HashWithDomain(DomainHint, maskedBytes), 32)

	// XOR decrypt
	result := make([]byte, 32)
	for i := 0; i < 32; i++ {
		result[i] = encryptedMsg[i] ^ keystream[i]
	}

	_ = n // Used for validation

	return result
}

// SerializePublicKey serializes TDD public key
func SerializePublicKey(pk kmosaic.TDDPublicKey) []byte {
	result := make([]byte, 4+len(pk.T)*4)
	binary.LittleEndian.PutUint32(result[0:], uint32(len(pk.T)))
	for i, v := range pk.T {
		binary.LittleEndian.PutUint32(result[4+i*4:], uint32(v))
	}
	return result
}

// DeserializePublicKey deserializes TDD public key
func DeserializePublicKey(data []byte) (*kmosaic.TDDPublicKey, error) {
	if len(data) < 4 {
		return nil, errors.New("invalid TDD public key: too short")
	}

	pk := &kmosaic.TDDPublicKey{}
	tLen := int(binary.LittleEndian.Uint32(data[0:]))
	if 4+tLen*4 > len(data) {
		return nil, errors.New("invalid TDD public key: T data truncated")
	}
	pk.T = make([]int32, tLen)
	for i := 0; i < tLen; i++ {
		pk.T[i] = int32(binary.LittleEndian.Uint32(data[4+i*4:]))
	}
	return pk, nil
}
