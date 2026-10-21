// Package slss implements the "Sparse Lattice Subset Sum" component of
// kMOSAIC: a plain (unstructured) LWE public-key encryption scheme with sparse
// ternary secrets.
//
//	KeyGen:  A ∈ Z_q^{M×N} from a public seed,
//	         s_j ∈ {-1,0,1}^N with W non-zero entries, e_j ← D_σ^M  (j = 0..L-1)
//	         t_j = A·s_j + e_j (mod q)
//	Encrypt: r ∈ {-1,0,1}^M with W non-zero entries, e1 ← D_σ^N, e2 ← D_σ^L
//	         u = Aᵀ·r + e1,   v_j = ⟨t_j, r⟩ + e2_j + bit_j·⌊q/2⌋
//	Decrypt: bit_j = [ |v_j − ⟨s_j, u⟩ mod± q| > q/4 ]
//
// Each message bit uses its own secret column, so the ciphertext carries L
// independent LWE samples. (The previous design reused a single inner
// product ⟨t, r⟩ for every bit, which exposed the message up to one global
// bit directly from the ciphertext.)
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
	DomainMatrix    = "kmosaic-slss-matrix-v2"
	DomainSecret    = "kmosaic-slss-secret-v2"
	DomainError     = "kmosaic-slss-error-v2"
	DomainEphemeral = "kmosaic-slss-ephemeral-v2"
	DomainError1    = "kmosaic-slss-error1-v2"
	DomainError2    = "kmosaic-slss-error2-v2"

	// SeedSize is the size of the public matrix seed stored in a public key.
	SeedSize = 32
)

// mod returns x mod q, ensuring the result is always non-negative in [0, q).
func mod(x int64, q int) int32 {
	r := x % int64(q)
	if r < 0 {
		r += int64(q)
	}
	return int32(r)
}

// centerMod returns x mod q centered in [-q/2, q/2].
func centerMod(x int32, q int) int32 {
	r := mod(int64(x), q)
	if int(r) > q/2 {
		return r - int32(q)
	}
	return r
}

// matVecMul computes A·v mod q for an M×N row-major matrix A and a ternary
// vector v of length N. It is used by tests and kept for API stability.
func matVecMul(A []int32, v []int8, m, n, q int) []int32 {
	result := make([]int32, m)
	for i := 0; i < m; i++ {
		var sum int64
		row := A[i*n : (i+1)*n]
		for j, a := range row {
			sum += int64(a) * int64(v[j])
		}
		result[i] = mod(sum, q)
	}
	return result
}

// nonzeros returns the positions and signs of the non-zero entries of a
// ternary vector.
func nonzeros(v []int8) (pos []int, sgn []int8) {
	for i, x := range v {
		if x != 0 {
			pos = append(pos, i)
			sgn = append(sgn, x)
		}
	}
	return pos, sgn
}

// sampleMatrix generates a deterministic uniform random M×N matrix over Z_q
// from seed using SHAKE256 with rejection sampling. Rows are generated in
// parallel from SHAKE256(seed || row index).
func sampleMatrix(seed []byte, m, n, q int) []int32 {
	matrixSize, err := utils.SafeMultiply(m, n)
	if err != nil {
		return nil
	}
	A := make([]int32, matrixSize)
	if matrixSize == 0 {
		return A
	}
	numWorkers := runtime.GOMAXPROCS(0)

	generateRow := func(rowIdx int, rowSeed, bytes []byte) {
		copy(rowSeed, seed)
		binary.LittleEndian.PutUint32(rowSeed[len(seed):], uint32(rowIdx))

		threshold := uint32(0xFFFFFFFF - (0xFFFFFFFF % uint32(q)))

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

// sampleSparseVector generates a deterministic ternary vector of length n with
// exactly w non-zero entries at uniformly random positions (chosen without
// replacement by rejection sampling, so there is no modulo bias) and uniform
// signs. Returns nil if parameters are invalid (n <= 0, w < 0 or w > n).
func sampleSparseVector(seed []byte, n, w int) []int8 {
	if n <= 0 {
		return nil
	}
	if w > n || w < 0 {
		return nil
	}

	v := make([]int8, n)
	positionSet := make(map[int]struct{}, w)
	positionList := make([]int, 0, w)

	// Largest multiple of n that fits in 32 bits: values at or above it are
	// rejected so that value % n is exactly uniform.
	limit := (uint64(1) << 32) / uint64(n) * uint64(n)

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

		value := binary.LittleEndian.Uint32(bytes[byteOffset:])
		byteOffset += 4
		if uint64(value) >= limit {
			continue
		}
		pos := int(value % uint32(n))
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

// columnSeed returns seed || j (little-endian uint32).
func columnSeed(seed []byte, j int) []byte {
	out := make([]byte, len(seed)+4)
	copy(out, seed)
	binary.LittleEndian.PutUint32(out[len(seed):], uint32(j))
	return out
}

// checkParams validates the dimensions used by this package.
func checkParams(params kmosaic.SLSSParams) error {
	if params.N <= 0 || params.M <= 0 || params.L <= 0 || params.Q <= 1 {
		return errors.New("SLSS parameters must be positive")
	}
	if params.L%8 != 0 {
		return errors.New("SLSS L must be a multiple of 8")
	}
	if params.W < 0 || params.W > params.N || params.W > params.M {
		return errors.New("SLSS sparsity must not exceed the dimensions")
	}
	if _, err := utils.SafeMultiply(params.M, params.N); err != nil {
		return err
	}
	if _, err := utils.SafeMultiply(params.L, params.N); err != nil {
		return err
	}
	if _, err := utils.SafeMultiply(params.L, params.M); err != nil {
		return err
	}
	return nil
}

// ExpandMatrix derives the public matrix A (M×N, row-major) from a public key seed.
func ExpandMatrix(seed []byte, params kmosaic.SLSSParams) []int32 {
	return sampleMatrix(seed, params.M, params.N, params.Q)
}

// KeyGen generates an SLSS key pair from a secret seed of at least 32 bytes.
func KeyGen(params kmosaic.SLSSParams, seed []byte) (*kmosaic.SLSSKeyPair, error) {
	if len(seed) < 32 {
		return nil, errors.New("seed must be at least 32 bytes")
	}
	if err := checkParams(params); err != nil {
		return nil, err
	}

	n, m, q, w, sigma, l := params.N, params.M, params.Q, params.W, params.Sigma, params.L

	// The matrix seed is public: it is a domain-separated hash of the secret
	// seed and reveals nothing about it beyond preimage resistance.
	matrixSeed := utils.HashWithDomain(DomainMatrix, seed)
	A := sampleMatrix(matrixSeed, m, n, q)

	S := make([]int8, l*n)
	T := make([]int32, l*m)

	numWorkers := runtime.GOMAXPROCS(0)
	if numWorkers > l {
		numWorkers = l
	}
	colsPerWorker := (l + numWorkers - 1) / numWorkers

	var wg sync.WaitGroup
	for wk := 0; wk < numWorkers; wk++ {
		start := wk * colsPerWorker
		end := start + colsPerWorker
		if end > l {
			end = l
		}
		if start >= l {
			break
		}
		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			for j := start; j < end; j++ {
				cs := columnSeed(seed, j)
				secretSeed := utils.HashWithDomain(DomainSecret, cs)
				errorSeed := utils.HashWithDomain(DomainError, cs)

				sj := sampleSparseVector(secretSeed, n, w)
				ej := sampleError(errorSeed, m, sigma)
				copy(S[j*n:(j+1)*n], sj)

				// t_j = A·s_j + e_j, using the sparsity of s_j.
				pos, sgn := nonzeros(sj)
				for i := 0; i < m; i++ {
					row := A[i*n : (i+1)*n]
					var sum int64
					for k, p := range pos {
						sum += int64(row[p]) * int64(sgn[k])
					}
					T[j*m+i] = mod(sum+int64(ej[i]), q)
				}

				utils.Zeroize(cs)
				utils.Zeroize(secretSeed)
				utils.Zeroize(errorSeed)
				utils.ZeroizeInt8(sj)
				utils.ZeroizeInt32(ej)
			}
		}(start, end)
	}
	wg.Wait()

	return &kmosaic.SLSSKeyPair{
		PublicKey: kmosaic.SLSSPublicKey{Seed: matrixSeed, A: A, T: T},
		SecretKey: kmosaic.SLSSSecretKey{S: S},
	}, nil
}

// MessageSize returns the exact message length in bytes that Encrypt accepts.
func MessageSize(params kmosaic.SLSSParams) int {
	return params.L / 8
}

// Encrypt encrypts a message of exactly L/8 bytes under pk. randomness (at
// least 32 bytes) deterministically selects the ephemeral values.
func Encrypt(pk kmosaic.SLSSPublicKey, message []byte, params kmosaic.SLSSParams, randomness []byte) (*kmosaic.SLSSCiphertext, error) {
	if len(randomness) < 32 {
		return nil, errors.New("randomness must be at least 32 bytes")
	}
	if err := checkParams(params); err != nil {
		return nil, err
	}
	n, m, q, w, sigma, l := params.N, params.M, params.Q, params.W, params.Sigma, params.L
	if len(message) != l/8 {
		return nil, errors.New("message must be exactly L/8 bytes")
	}
	if len(pk.A) != m*n {
		return nil, errors.New("public key matrix has wrong dimensions")
	}
	if len(pk.T) != l*m {
		return nil, errors.New("public key T has wrong dimensions")
	}

	rSeed := utils.HashWithDomain(DomainEphemeral, randomness)
	e1Seed := utils.HashWithDomain(DomainError1, randomness)
	e2Seed := utils.HashWithDomain(DomainError2, randomness)
	defer func() {
		utils.Zeroize(rSeed)
		utils.Zeroize(e1Seed)
		utils.Zeroize(e2Seed)
	}()

	r := sampleSparseVector(rSeed, m, w)
	e1 := sampleError(e1Seed, n, sigma)
	e2 := sampleError(e2Seed, l, sigma)
	pos, sgn := nonzeros(r)

	// u = Aᵀ·r + e1
	acc := make([]int64, n)
	for k, p := range pos {
		row := pk.A[p*n : (p+1)*n]
		if sgn[k] > 0 {
			for i, a := range row {
				acc[i] += int64(a)
			}
		} else {
			for i, a := range row {
				acc[i] -= int64(a)
			}
		}
	}
	u := make([]int32, n)
	for i := range u {
		u[i] = mod(acc[i]+int64(e1[i]), q)
	}

	// v_j = ⟨t_j, r⟩ + e2_j + bit_j·⌊q/2⌋
	scale := int64(q / 2)
	v := make([]int32, l)
	for j := 0; j < l; j++ {
		tj := pk.T[j*m : (j+1)*m]
		var sum int64
		for k, p := range pos {
			sum += int64(tj[p]) * int64(sgn[k])
		}
		bit := int64((message[j/8] >> (j % 8)) & 1)
		v[j] = mod(sum+int64(e2[j])+bit*scale, q)
	}

	utils.ZeroizeInt8(r)
	utils.ZeroizeInt32(e1)
	utils.ZeroizeInt32(e2)
	for i := range acc {
		acc[i] = 0
	}

	return &kmosaic.SLSSCiphertext{U: u, V: v}, nil
}

// Decrypt decrypts an SLSS ciphertext. Returns nil if the ciphertext or key
// dimensions do not match params.
func Decrypt(ct *kmosaic.SLSSCiphertext, sk kmosaic.SLSSSecretKey, params kmosaic.SLSSParams) []byte {
	if err := checkParams(params); err != nil {
		return nil
	}
	n, q, l := params.N, params.Q, params.L
	if len(ct.U) != n || len(ct.V) != l || len(sk.S) != l*n {
		return nil
	}

	threshold := int32(q / 4)
	result := make([]byte, l/8)
	for j := 0; j < l; j++ {
		sj := sk.S[j*n : (j+1)*n]
		var sum int64
		for i, s := range sj {
			sum += int64(ct.U[i]) * int64(s)
		}
		d := centerMod(mod(int64(ct.V[j])-sum, q), q)

		// Constant-time |d| > threshold.
		mask := d >> 31
		absD := (d ^ mask) - mask
		diff := absD - threshold - 1
		bit := byte(1 - ((diff >> 31) & 1))
		result[j/8] |= bit << (j % 8)
	}
	return result
}

// SerializePublicKey serializes an SLSS public key as
// [seed:32][t_count:4][T entries as uint16 little-endian].
// The matrix A is not stored; it is re-expanded from the seed.
func SerializePublicKey(pk kmosaic.SLSSPublicKey) []byte {
	result := make([]byte, SeedSize+4+2*len(pk.T))
	copy(result, pk.Seed)
	binary.LittleEndian.PutUint32(result[SeedSize:], uint32(len(pk.T)))
	off := SeedSize + 4
	for i, v := range pk.T {
		binary.LittleEndian.PutUint16(result[off+2*i:], uint16(v))
	}
	return result
}

// DeserializePublicKey parses an SLSS public key produced by SerializePublicKey
// for the given parameters and expands the matrix A from the seed.
func DeserializePublicKey(data []byte, params kmosaic.SLSSParams) (*kmosaic.SLSSPublicKey, error) {
	if err := checkParams(params); err != nil {
		return nil, err
	}
	if params.Q > 1<<16 {
		return nil, errors.New("SLSS modulus does not fit the 16-bit encoding")
	}
	if len(data) < SeedSize+4 {
		return nil, errors.New("invalid SLSS public key: too short")
	}
	tCount := int(binary.LittleEndian.Uint32(data[SeedSize:]))
	if tCount != params.L*params.M {
		return nil, errors.New("invalid SLSS public key: T length mismatch with params")
	}
	if len(data) != SeedSize+4+2*tCount {
		return nil, errors.New("invalid SLSS public key: wrong length")
	}

	pk := &kmosaic.SLSSPublicKey{Seed: make([]byte, SeedSize), T: make([]int32, tCount)}
	copy(pk.Seed, data[:SeedSize])
	off := SeedSize + 4
	for i := 0; i < tCount; i++ {
		v := int32(binary.LittleEndian.Uint16(data[off+2*i:]))
		if int(v) >= params.Q {
			return nil, errors.New("invalid SLSS public key: entry out of range")
		}
		pk.T[i] = v
	}
	pk.A = ExpandMatrix(pk.Seed, params)
	return pk, nil
}
