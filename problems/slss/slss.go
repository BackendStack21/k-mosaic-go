// Package slss implements the Sparse Lattice Subset Sum problem for kMOSAIC.
package slss

import (
	"encoding/binary"
	"errors"
	"runtime"
	"sync"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

const (
	DomainMatrix    = "kmosaic-slss-matrix-v1"
	DomainSecret    = "kmosaic-slss-secret-v1"
	DomainError     = "kmosaic-slss-error-v1"
	DomainEphemeral = "kmosaic-slss-ephemeral-v1"
	DomainError1    = "kmosaic-slss-error1-v1"
	DomainError2    = "kmosaic-slss-error2-v1"
)

// mod returns x mod q, ensuring the result is always non-negative in [0, q).
func mod(x int64, q int) int32 {
	r := x % int64(q)
	if r < 0 {
		r += int64(q)
	}
	return int32(r)
}

// centerMod returns x mod q centered in [-q/2, q/2).
// This is used for decoding LWE samples where the error is small and centered around 0.
func centerMod(x int32, q int) int32 {
	r := mod(int64(x), q)
	if int(r) > q/2 {
		return r - int32(q)
	}
	return r
}

// fastMod returns x mod q, assuming x >= 0.
func fastMod(x int64, q int) int32 {
	return int32(x % int64(q))
}

// matVecMul computes the matrix-vector product A * v mod q.
// A is an m x n matrix stored in row-major order.
// v is an n-element vector with entries in {-1, 0, 1}.
// The operation is parallelized for large matrices.
func matVecMul(A []int32, v []int8, m, n, q int) []int32 {
	result := make([]int32, m)
	numWorkers := runtime.GOMAXPROCS(0)

	if m < 64 || numWorkers <= 1 {
		// Sequential execution for small matrices or single core
		for i := 0; i < m; i++ {
			var sum int64
			rowOffset := i * n
			for j := 0; j < n; j++ {
				sum += int64(A[rowOffset+j]) * int64(v[j])
			}
			result[i] = mod(sum, q)
		}
		return result
	}

	// Parallel execution for large matrices
	var wg sync.WaitGroup
	rowsPerWorker := (m + numWorkers - 1) / numWorkers

	for w := 0; w < numWorkers; w++ {
		start := w * rowsPerWorker
		end := start + rowsPerWorker
		if end > m {
			end = m
		}
		if start >= m {
			break
		}

		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			for i := start; i < end; i++ {
				var sum int64
				rowOffset := i * n
				for j := 0; j < n; j++ {
					sum += int64(A[rowOffset+j]) * int64(v[j])
				}
				result[i] = mod(sum, q)
			}
		}(start, end)
	}
	wg.Wait()
	return result
}

// matVecMulInt32 computes the matrix-vector product A * v mod q.
// A is an m x n matrix stored in row-major order.
// v is an n-element vector with entries in Z_q.
func matVecMulInt32(A []int32, v []int32, m, n, q int) []int32 {
	result := make([]int32, m)
	for i := 0; i < m; i++ {
		var sum int64
		rowOffset := i * n
		for j := 0; j < n; j++ {
			sum += int64(A[rowOffset+j]) * int64(v[j])
		}
		result[i] = fastMod(sum, q)
	}
	return result
}

// matTVecMul computes the transpose matrix-vector product A^T * v mod q.
// A is an m x n matrix stored in row-major order.
// v is an m-element vector.
// The result is an n-element vector.
func matTVecMul(A []int32, v []int32, m, n, q int) []int32 {
	result := make([]int32, n)
	for i := 0; i < m; i++ {
		vi := int64(v[i])
		rowOffset := i * n
		for j := 0; j < n; j++ {
			result[j] = fastMod(int64(result[j])+int64(A[rowOffset+j])*vi, q)
		}
	}
	return result
}

// vecAdd adds two vectors element-wise modulo q.
func vecAdd(a, b []int32, q int) []int32 {
	result := make([]int32, len(a))
	for i := range a {
		result[i] = mod(int64(a[i])+int64(b[i]), q)
	}
	return result
}

// innerProduct computes the dot product of two vectors modulo q.
// a is a vector in Z_q, b is a vector with small entries (e.g., {-1, 0, 1}).
func innerProduct(a []int32, b []int8, q int) int32 {
	var sum int64
	for i := range a {
		sum += int64(a[i]) * int64(b[i])
	}
	return mod(sum, q)
}

// sampleMatrix generates a deterministic uniform random matrix using SHAKE256.
// The matrix is generated row by row in parallel.
func sampleMatrix(seed []byte, m, n, q int) []int32 {
	// Check for overflow in matrix size
	matrixSize, err := utils.SafeMultiply(m, n)
	if err != nil {
		return nil // parameters cause overflow
	}
	A := make([]int32, matrixSize)
	numWorkers := runtime.GOMAXPROCS(0)

	// Helper to generate a row using provided buffers
	generateRow := func(rowIdx int, rowSeed, bytes []byte) {
		copy(rowSeed, seed)
		binary.LittleEndian.PutUint32(rowSeed[len(seed):], uint32(rowIdx))

		threshold := uint32(0xFFFFFFFF - (0xFFFFFFFF % uint32(q)))

		// Initial generation
		utils.Shake256Into(rowSeed, bytes)

		bytesUsed := 0
		generated := 0
		extensionCounter := 0
		rowOffset := rowIdx * n

		for generated < n {
			if bytesUsed+4 > len(bytes) {
				extensionCounter++
				extSeed := make([]byte, len(rowSeed)+4)
				copy(extSeed, rowSeed)
				binary.LittleEndian.PutUint32(extSeed[len(rowSeed):], uint32(extensionCounter))
				utils.Shake256Into(extSeed, bytes)
				bytesUsed = 0
			}

			value := binary.LittleEndian.Uint32(bytes[bytesUsed:])
			bytesUsed += 4

			if value < threshold {
				A[rowOffset+generated] = int32(value % uint32(q))
				generated++
			}
		}
	}

	if m < 4 || numWorkers <= 1 {
		rowSeed := make([]byte, len(seed)+4)
		bytes := make([]byte, n*4*2)
		for i := 0; i < m; i++ {
			generateRow(i, rowSeed, bytes)
		}
		return A
	}

	var wg sync.WaitGroup
	rowsPerWorker := (m + numWorkers - 1) / numWorkers

	for w := 0; w < numWorkers; w++ {
		start := w * rowsPerWorker
		end := start + rowsPerWorker
		if end > m {
			end = m
		}
		if start >= m {
			break
		}

		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			rowSeed := make([]byte, len(seed)+4)
			bytes := make([]byte, n*4*2)
			for i := start; i < end; i++ {
				generateRow(i, rowSeed, bytes)
			}
		}(start, end)
	}
	wg.Wait()
	return A
}

// sampleSparseVector generates a deterministic sparse vector with exactly w non-zero entries.
// The non-zero entries are uniformly distributed in {-1, 1}.
// The positions are chosen uniformly at random without replacement.
// Returns nil if parameters are invalid (n <= 0 or w > n).
func sampleSparseVector(seed []byte, n, w int) []int8 {
	if n <= 0 {
		return nil // invalid dimension
	}
	if w > n || w < 0 {
		return nil // invalid sparsity
	}

	v := make([]int8, n)
	positionSet := make(map[int]struct{})
	positionList := make([]int, 0, w) // Keep ordered list of positions

	extraFactor := 8
	bytesNeeded := w*extraFactor*4 + w
	bytes := utils.Shake256(seed, bytesNeeded)

	byteOffset := 0
	extensionCounter := 0

	for len(positionList) < w {
		if byteOffset+4 > len(bytes)-w {
			extensionCounter++
			extSeed := make([]byte, len(seed)+4)
			copy(extSeed, seed)
			binary.LittleEndian.PutUint32(extSeed[len(seed):], uint32(extensionCounter))
			bytes = utils.Shake256(extSeed, bytesNeeded)
			byteOffset = 0
		}

		pos := int(binary.LittleEndian.Uint32(bytes[byteOffset:])) % n
		if pos < 0 {
			pos += n
		}
		byteOffset += 4
		if _, exists := positionSet[pos]; !exists {
			positionSet[pos] = struct{}{}
			positionList = append(positionList, pos)
		}
	}

	signBytes := bytes[len(bytes)-w:]
	for signIdx, pos := range positionList {
		if signBytes[signIdx]&1 == 1 {
			v[pos] = 1
		} else {
			v[pos] = -1
		}
	}
	return v
}

// sampleError generates a vector with entries sampled from a discrete Gaussian distribution.
func sampleError(seed []byte, n int, sigma float64) []int32 {
	return utils.SampleGaussianVector(seed, n, sigma)
}

// encodeMessage encodes a byte slice into a vector of LWE samples.
// Each bit of the message is mapped to a coefficient, scaled by q/2.
func encodeMessage(msg []byte, q int) []int32 {
	result := make([]int32, len(msg)*8)
	scale := int32(q / 2)
	for i := 0; i < len(msg); i++ {
		b := msg[i]
		baseIdx := i * 8
		for j := 0; j < 8; j++ {
			bit := (b >> j) & 1
			result[baseIdx+j] = int32(bit) * scale
		}
	}
	return result
}

// decodeMessage decodes a vector of LWE samples into a byte slice.
// It maps coefficients close to 0 to bit 0, and coefficients close to q/2 to bit 1.
// Uses constant-time operations to prevent timing side channels.
func decodeMessage(values []int32, q int) []byte {
	numBytes := len(values) / 8
	result := make([]byte, numBytes)
	threshold := int32(q / 4)

	for i := 0; i < numBytes; i++ {
		var b byte
		baseIdx := i * 8
		for j := 0; j < 8; j++ {
			v := centerMod(values[baseIdx+j], q)
			// Constant-time absolute value
			// mask is all 1s if v < 0, all 0s otherwise
			mask := v >> 31
			absV := (v ^ mask) - mask
			// Constant-time comparison: bit is 1 if absV > threshold
			// diff > 0 when absV > threshold
			diff := absV - threshold - 1
			// bit is 0 if diff < 0 (absV <= threshold), 1 if diff >= 0 (absV > threshold)
			bit := byte(1 - ((diff >> 31) & 1))
			b |= bit << j
		}
		result[i] = b
	}
	return result
}

// KeyGen generates SLSS key pair
func KeyGen(params kmosaic.SLSSParams, seed []byte) (*kmosaic.SLSSKeyPair, error) {
	if len(seed) < 32 {
		return nil, errors.New("seed must be at least 32 bytes")
	}

	n, m, q, w, sigma := params.N, params.M, params.Q, params.W, params.Sigma

	matrixSeed := utils.HashWithDomain(DomainMatrix, seed)
	secretSeed := utils.HashWithDomain(DomainSecret, seed)
	errorSeed := utils.HashWithDomain(DomainError, seed)
	defer func() {
		utils.Zeroize(matrixSeed)
		utils.Zeroize(secretSeed)
		utils.Zeroize(errorSeed)
	}()

	A := sampleMatrix(matrixSeed, m, n, q)
	s := sampleSparseVector(secretSeed, n, w)
	e := sampleError(errorSeed, m, sigma)

	// t = A*s + e mod q
	As := matVecMul(A, s, m, n, q)
	t := vecAdd(As, e, q)

	// Zeroize intermediate values
	utils.ZeroizeInt32(As)
	utils.ZeroizeInt32(e)

	return &kmosaic.SLSSKeyPair{
		PublicKey: kmosaic.SLSSPublicKey{A: A, T: t},
		SecretKey: kmosaic.SLSSSecretKey{S: s},
	}, nil
}

// DebugInfo for SLSS encryption internals
type SlssDebugInfo struct {
	RIndices []int   `json:"r_indices"`
	RValues  []int8  `json:"r_values"`
	E1Head   []int32 `json:"e1_head"`
	E2Head   []int32 `json:"e2_head"`
	UHead    []int32 `json:"u_head"`
	VHead    []int32 `json:"v_head"`
}

// DebugEncrypt performs SLSS encryption but also returns internal debug information
func DebugEncrypt(pk kmosaic.SLSSPublicKey, message []byte, params kmosaic.SLSSParams, randomness []byte) (*kmosaic.SLSSCiphertext, *SlssDebugInfo, error) {
	if len(randomness) < 32 {
		return nil, nil, errors.New("randomness must be at least 32 bytes")
	}
	if len(message) > utils.MaxMessageSize {
		return nil, nil, errors.New("message exceeds maximum allowed size")
	}

	n, m, q, sigma := params.N, params.M, params.Q, params.Sigma

	// Sample ephemeral values (with domain separation as in Encrypt)
	rSeed := utils.HashWithDomain(DomainEphemeral, randomness)
	e1Seed := utils.HashWithDomain(DomainError1, randomness)
	e2Seed := utils.HashWithDomain(DomainError2, randomness)

	r := sampleSparseVector(rSeed, m, params.W)
	e1 := sampleError(e1Seed, n, sigma)
	e2 := sampleError(e2Seed, len(message)*8, sigma)

	// Convert r to int32 for matTVecMul
	rInt32 := make([]int32, len(r))
	for i, v := range r {
		rInt32[i] = int32(v)
	}

	ATr := matTVecMul(pk.A, rInt32, m, n, q)
	u := vecAdd(ATr, e1, q)

	tTr := innerProduct(pk.T, r, q)
	encoded := encodeMessage(message, q)

	v := make([]int32, len(encoded))
	for i := range encoded {
		val := int64(tTr) + int64(e2[i%len(e2)]) + int64(encoded[i])
		v[i] = mod(val, q)
	}

	// Collect debug info (small heads)
	debug := &SlssDebugInfo{}
	// Record non-zero indices and values for r (first up to 16)
	for i := 0; i < len(r) && len(debug.RIndices) < 16; i++ {
		if r[i] != 0 {
			debug.RIndices = append(debug.RIndices, i)
			debug.RValues = append(debug.RValues, r[i])
		}
	}
	// Heads of error and ciphertext components
	k := func(arr []int32, n int) []int32 {
		if len(arr) < n {
			n = len(arr)
		}
		out := make([]int32, n)
		copy(out, arr[:n])
		return out
	}
	debug.E1Head = k(e1, 8)
	debug.E2Head = k(e2, 8)
	debug.UHead = k(u, 8)
	debug.VHead = k(v, 8)

	// Zeroize ephemeral values
	utils.ZeroizeInt32(ATr)
	utils.ZeroizeInt32(e1)
	utils.ZeroizeInt32(e2)
	utils.ZeroizeInt32(encoded)

	return &kmosaic.SLSSCiphertext{U: u, V: v}, debug, nil
}

// Encrypt encrypts a message fragment using SLSS
func Encrypt(pk kmosaic.SLSSPublicKey, message []byte, params kmosaic.SLSSParams, randomness []byte) (*kmosaic.SLSSCiphertext, error) {
	if len(randomness) < 32 {
		return nil, errors.New("randomness must be at least 32 bytes")
	}
	if len(message) > utils.MaxMessageSize {
		return nil, errors.New("message exceeds maximum allowed size")
	}

	n, m, q, sigma := params.N, params.M, params.Q, params.Sigma

	// Sample ephemeral values
	rSeed := utils.HashWithDomain(DomainEphemeral, randomness)
	e1Seed := utils.HashWithDomain(DomainError1, randomness)
	e2Seed := utils.HashWithDomain(DomainError2, randomness)

	r := sampleSparseVector(rSeed, m, params.W)
	e1 := sampleError(e1Seed, n, sigma)
	e2 := sampleError(e2Seed, len(message)*8, sigma)

	// u = A^T * r + e1
	rInt32 := make([]int32, len(r))
	for i, v := range r {
		rInt32[i] = int32(v)
	}
	ATr := matTVecMul(pk.A, rInt32, m, n, q)
	u := vecAdd(ATr, e1, q)

	// v = t^T * r + e2 + encode(msg)
	tTr := innerProduct(pk.T, r, q)
	encoded := encodeMessage(message, q)

	v := make([]int32, len(encoded))
	for i := range encoded {
		val := int64(tTr) + int64(e2[i%len(e2)]) + int64(encoded[i])
		v[i] = mod(val, q)
	}

	// Zeroize ephemeral values
	utils.ZeroizeInt8(r)
	utils.ZeroizeInt32(rInt32)
	utils.ZeroizeInt32(e1)
	utils.ZeroizeInt32(e2)
	utils.ZeroizeInt32(ATr)
	utils.ZeroizeInt32(encoded)

	return &kmosaic.SLSSCiphertext{U: u, V: v}, nil
}

// Decrypt decrypts an SLSS ciphertext
func Decrypt(ct *kmosaic.SLSSCiphertext, sk kmosaic.SLSSSecretKey, params kmosaic.SLSSParams) []byte {
	q := params.Q

	// m = v - s^T * u
	sTu := innerProduct(ct.U, sk.S, q)

	decrypted := make([]int32, len(ct.V))
	for i := range ct.V {
		decrypted[i] = mod(int64(ct.V[i])-int64(sTu), q)
	}

	result := decodeMessage(decrypted, q)

	// Zeroize intermediate values
	utils.ZeroizeInt32(decrypted)

	return result
}

// SerializePublicKey serializes SLSS public key
func SerializePublicKey(pk kmosaic.SLSSPublicKey) []byte {
	// 4 bytes for A length + A data + 4 bytes for T length + T data
	aBytes := len(pk.A) * 4
	tBytes := len(pk.T) * 4
	result := make([]byte, 8+aBytes+tBytes)

	// Write byte length (not element count)
	binary.LittleEndian.PutUint32(result[0:], uint32(aBytes))
	offset := 4
	for i, v := range pk.A {
		binary.LittleEndian.PutUint32(result[offset+i*4:], uint32(v))
	}
	offset += aBytes

	// Write byte length (not element count)
	binary.LittleEndian.PutUint32(result[offset:], uint32(tBytes))
	offset += 4
	for i, v := range pk.T {
		binary.LittleEndian.PutUint32(result[offset+i*4:], uint32(v))
	}

	return result
}

// DeserializePublicKey deserializes SLSS public key
func DeserializePublicKey(data []byte) (*kmosaic.SLSSPublicKey, error) {
	if len(data) < 8 {
		return nil, errors.New("invalid SLSS public key: too short")
	}

	pk := &kmosaic.SLSSPublicKey{}
	offset := 0

	// Read byte length (not element count)
	aBytes := int(binary.LittleEndian.Uint32(data[offset:]))
	if aBytes%4 != 0 {
		return nil, errors.New("invalid SLSS public key: A length not multiple of 4")
	}
	aLen := aBytes / 4
	if aLen > utils.MaxMatrixElements {
		return nil, errors.New("invalid SLSS public key: A length exceeds limit")
	}
	offset += 4
	if offset+aBytes > len(data) {
		return nil, errors.New("invalid SLSS public key: A data truncated")
	}
	pk.A = make([]int32, aLen)
	for i := 0; i < aLen; i++ {
		pk.A[i] = int32(binary.LittleEndian.Uint32(data[offset:]))
		offset += 4
	}

	if offset+4 > len(data) {
		return nil, errors.New("invalid SLSS public key: missing T length")
	}
	// Read byte length (not element count)
	tBytes := int(binary.LittleEndian.Uint32(data[offset:]))
	if tBytes%4 != 0 {
		return nil, errors.New("invalid SLSS public key: T length not multiple of 4")
	}
	tLen := tBytes / 4
	if tLen > utils.MaxVectorLength {
		return nil, errors.New("invalid SLSS public key: T length exceeds limit")
	}
	offset += 4
	if offset+tBytes > len(data) {
		return nil, errors.New("invalid SLSS public key: T data truncated")
	}
	pk.T = make([]int32, tLen)
	for i := 0; i < tLen; i++ {
		pk.T[i] = int32(binary.LittleEndian.Uint32(data[offset:]))
		offset += 4
	}

	return pk, nil
}
