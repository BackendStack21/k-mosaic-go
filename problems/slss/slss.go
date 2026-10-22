// Package slss implements the "Sparse Lattice Subset Sum" component of
// kMOSAIC: a plain (unstructured) LWE public-key encryption scheme with sparse
// ternary secrets and FIPS 203-style ciphertext compression.
//
//	KeyGen:  A ∈ Z_q^{M×N} expanded from a public seed,
//	         s_j ∈ {-1,0,1}^N with W non-zero entries, e_j ← B_η^M  (j = 0..L-1)
//	         t_j = A·s_j + e_j (mod q)
//	Encrypt: r ∈ {-1,0,1}^M with W non-zero entries, e1 ← B_η^N, e2 ← B_η^L
//	         u = Compress_DU(Aᵀ·r + e1),   v_j = Compress_DV(⟨t_j, r⟩ + e2_j + bit_j·⌊q/2⌋)
//	Decrypt: bit_j = [ |Decompress(v_j) − ⟨s_j, Decompress(u)⟩ mod± q| > q/4 ]
//
// B_η is the centered binomial distribution (variance η/2), sampled with
// integer arithmetic only so that encryption is bit-reproducible, as
// Fujisaki-Okamoto re-encryption requires. Each message bit uses its own
// secret column, so the ciphertext carries L independent LWE samples.
//
// The modulus is fixed at q = 12289 and every reduction of secret-dependent
// data is a reduction by that compile-time constant, which the compiler turns
// into a multiply-and-shift (no hardware division, whose latency depends on
// its operands). Decryption touches every secret coefficient in the same
// order regardless of its value.
//
// # Decryption failure analysis
//
// For bit j, Decompress(v_j) − ⟨s_j, Decompress(u)⟩ = bit_j·⌊q/2⌋ + noise with
//
//	noise = ⟨e_j, r⟩ − ⟨s_j, e1⟩ − ⟨s_j, εu⟩ + e2_j + εv
//
// where εu, εv are the compression rounding errors. With η = 20 (variance 10),
// W non-zero entries in s_j and r, and a rounding error that is close to
// uniform over a step of q/2^d (variance (q/2^d)²/12):
//
//	Var⟨e_j, r⟩  = Var⟨s_j, e1⟩ = 10·W
//	Var⟨s_j, εu⟩ = W·(12289/2^11)²/12 ≈ 3.0·W
//	Var e2_j     = 10
//	Var εv       = (12289/2^5)²/12 ≈ 12290        (|εv| ≤ 192)
//
// MOS-128 (W = 192): 1920 + 1920 + 576 + 10 + 12290 = 16716, σ ≈ 129.
// MOS-256 (W = 288): 2880 + 2880 + 864 + 10 + 12290 = 18924, σ ≈ 138.
// The decoding threshold is q/4 = 3072, i.e. ≥ 22σ. Since εv is bounded by
// 192, the remaining sub-Gaussian part (σ ≈ 67 at MOS-128) would have to
// exceed 2880 ≈ 43σ: the per-bit failure probability is far below 2^-400.
//
// # Encodings
//
//	public key:  seed (32 bytes) || T packed at 14 bits per entry (L·M entries)
//	secret key:  S packed at 2 bits per entry (00 = 0, 01 = +1, 10 = −1)
//	ciphertext:  U packed at DU bits || V packed at DV bits
//
// Values are packed in little-endian bit order; each packed field is padded
// to a whole byte with zero bits, and the deserializers reject anything that
// is not the canonical encoding.
package slss

import (
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"runtime"
	"sync"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

const (
	DomainMatrix    = "kmosaic-slss-matrix-v4"
	DomainSecret    = "kmosaic-slss-secret-v4"
	DomainError     = "kmosaic-slss-error-v4"
	DomainEphemeral = "kmosaic-slss-ephemeral-v4"
	DomainError1    = "kmosaic-slss-error1-v4"
	DomainError2    = "kmosaic-slss-error2-v4"

	// SeedSize is the size of the public matrix seed stored in a public key.
	SeedSize = 32

	// q is the SLSS modulus. It is a compile-time constant so that every
	// reduction compiles to a multiply-and-shift rather than a division.
	q = 12289

	// pkBits is the width of a packed public-key coefficient (q < 2^14).
	pkBits = 14

	// rejBound is the largest multiple of q below 2^16: 16-bit candidates
	// below it reduce mod q without bias (acceptance 61445/65536 ≈ 93.8%).
	rejBound = 5 * q

	// shakeRate is the SHAKE256 block size; extra XOF output is read in
	// blocks of this size.
	shakeRate = 136

	// maxDim bounds N and M so that int32 accumulators cannot overflow:
	// 2^16 · 12289 < 2^30.
	maxDim = 1 << 16
)

// mod returns x mod q in [0, q).
func mod(x int64) int32 {
	r := x % q
	r += q & (r >> 63)
	return int32(r)
}

// mod32 returns x mod q in [0, q).
func mod32(x int32) int32 {
	r := x % q
	r += q & (r >> 31)
	return r
}

// centerMod returns x mod q in [-(q-1)/2, (q-1)/2].
func centerMod(x int32) int32 {
	r := mod32(x)
	r -= q & ((q/2 - r) >> 31)
	return r
}

// compress returns ⌊(x·2^d + ⌊q/2⌋) / q⌉ mod 2^d for x ∈ [0, q) and d ≤ 14.
func compress(x int32, d uint) int32 {
	t := (uint32(x)<<d + q/2) / q
	return int32(t & (1<<d - 1))
}

// decompress returns ⌊(c·q + 2^(d-1)) / 2^d⌋ for c ∈ [0, 2^d); c is
// masked to d bits first so that the result is always in [0, q).
func decompress(c int32, d uint) int32 {
	return int32((uint32(c)&(1<<d-1)*q + 1<<(d-1)) >> d)
}

// matVecMul computes A·v mod q for an M×N row-major matrix A and a ternary
// vector v of length N. It is a straightforward reference used by tests.
func matVecMul(A []int32, v []int8, m, n int) []int32 {
	result := make([]int32, m)
	for i := 0; i < m; i++ {
		var sum int64
		row := A[i*n : (i+1)*n]
		for j, a := range row {
			sum += int64(a) * int64(v[j])
		}
		result[i] = mod(sum)
	}
	return result
}

// fillRow appends uniform values mod q from 16-bit little-endian candidates
// in b to row, starting at index k, and returns the new count.
func fillRow(row []int32, k int, b []byte) int {
	for i := 0; i+1 < len(b) && k < len(row); i += 2 {
		v := uint32(b[i]) | uint32(b[i+1])<<8
		if v < rejBound {
			row[k] = int32(v % q)
			k++
		}
	}
	return k
}

// sampleMatrix expands a uniform M×N matrix over Z_q (row-major) from seed.
// Row i is drawn from SHAKE256(seed || uint32le(i)): 2·N bytes are read first
// as 16-bit candidates and further blocks are streamed only on shortfall.
// Rows are generated in parallel.
func sampleMatrix(seed []byte, m, n int) []int32 {
	if m < 0 || n < 0 {
		return nil
	}
	size, err := utils.SafeMultiply(m, n)
	if err != nil {
		return nil
	}
	A := make([]int32, size)
	if size == 0 {
		return A
	}

	genRows := func(start, end int) {
		h := sha3.NewSHAKE256()
		in := make([]byte, len(seed)+4)
		copy(in, seed)
		buf := make([]byte, 2*n)
		ext := buf[:min(shakeRate, len(buf))]
		for i := start; i < end; i++ {
			binary.LittleEndian.PutUint32(in[len(seed):], uint32(i))
			h.Reset()
			_, _ = h.Write(in)
			_, _ = h.Read(buf)
			row := A[i*n : (i+1)*n]
			k := fillRow(row, 0, buf)
			for k < n {
				_, _ = h.Read(ext)
				k = fillRow(row, k, ext)
			}
		}
	}

	workers := runtime.GOMAXPROCS(0)
	if workers > m {
		workers = m
	}
	if workers <= 1 || size < 1<<14 {
		genRows(0, m)
		return A
	}
	per := (m + workers - 1) / workers
	var wg sync.WaitGroup
	for start := 0; start < m; start += per {
		end := min(start+per, m)
		wg.Add(1)
		go func() {
			defer wg.Done()
			genRows(start, end)
		}()
	}
	wg.Wait()
	return A
}

// sampleSparse draws a ternary vector of length len(v) with exactly w
// non-zero entries from SHAKE256(seed) and writes it into v, which must be
// all zero on entry. The first ⌈w/8⌉ output bytes are sign bits (bit k gives
// the sign of the k-th selected position: 1 → +1, 0 → −1); the rest is a
// stream of 32-bit little-endian candidates mapped to [0, n) with Lemire's
// multiply-and-reject method (unbiased, no division by n), skipping
// positions already chosen. signs is scratch space of capacity ⌈w/8⌉.
func sampleSparse(h *sha3.SHAKE, seed []byte, w int, v []int8, signs []byte) {
	n := len(v)
	h.Reset()
	_, _ = h.Write(seed)
	signs = signs[:(w+7)/8]
	_, _ = h.Read(signs)

	var buf [shakeRate]byte
	off := len(buf)
	thresh := -uint32(n) % uint32(n) // 2^32 mod n; n is public
	for k := 0; k < w; {
		if off+4 > len(buf) {
			_, _ = h.Read(buf[:])
			off = 0
		}
		x := binary.LittleEndian.Uint32(buf[off:])
		off += 4
		prod := uint64(x) * uint64(n)
		if uint32(prod) < thresh {
			continue
		}
		p := int(prod >> 32)
		if v[p] != 0 {
			continue
		}
		v[p] = int8(2*((signs[k>>3]>>(k&7))&1)) - 1
		k++
	}
	clear(buf[:])
	clear(signs)
}

// splitTernary scans the ternary vector v (with w non-zero entries) and
// writes the positions of its +1 entries in ascending order to out[:np] and
// those of its −1 entries in descending order to out[np:w]; it returns np.
// out must have length w+1 (out[w] is scratch). The scan is branch-free and
// touches every entry of v, so its timing does not depend on v.
func splitTernary(v []int8, w int, out []int32) int {
	out = out[:w+1]
	np, nm := 0, w
	for i, x := range v {
		b := uint8(x)
		isM := int(b >> 7)
		isP := int(b&1) &^ isM
		idx := w ^ ((w ^ np) & -isP) ^ ((w ^ (nm - 1)) & -isM)
		out[idx] = int32(i)
		np += isP
		nm -= isM
	}
	out[w] = 0
	return np
}

// sampleSparseVector returns the dense ternary vector drawn by sampleSparse,
// or nil if the parameters are invalid (n <= 0, w < 0 or w > n).
func sampleSparseVector(seed []byte, n, w int) []int8 {
	if n <= 0 || w < 0 || w > n {
		return nil
	}
	v := make([]int8, n)
	sampleSparse(sha3.NewSHAKE256(), seed, w, v, make([]byte, (w+7)/8))
	return v
}

// columnSeed writes seed || uint32le(j) into dst (length len(seed)+4).
func columnSeed(dst, seed []byte, j int) []byte {
	copy(dst, seed)
	binary.LittleEndian.PutUint32(dst[len(seed):], uint32(j))
	return dst
}

// checkParams validates the parameters used by this package.
func checkParams(params kmosaic.SLSSParams) error {
	if params.Q != q {
		return errors.New("SLSS modulus must be 12289")
	}
	if params.N <= 0 || params.M <= 0 || params.L <= 0 {
		return errors.New("SLSS dimensions must be positive")
	}
	if params.N > maxDim || params.M > maxDim {
		return errors.New("SLSS dimensions too large")
	}
	if params.L%8 != 0 {
		return errors.New("SLSS L must be a multiple of 8")
	}
	if params.W <= 0 || params.W > params.N || params.W > params.M {
		return errors.New("SLSS sparsity must be in (0, min(N, M)]")
	}
	if params.Eta < 16 || params.Eta > 64 {
		return errors.New("SLSS eta must be in [16, 64]")
	}
	if params.DU < 10 || params.DU > 14 {
		return errors.New("SLSS DU must be in [10, 14]")
	}
	if params.DV < 4 || params.DV > 14 {
		return errors.New("SLSS DV must be in [4, 14]")
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

// ExpandMatrix derives the public matrix A (M×N, row-major) from a public key
// seed. It returns nil if the dimensions are invalid.
func ExpandMatrix(seed []byte, params kmosaic.SLSSParams) []int32 {
	return sampleMatrix(seed, params.M, params.N)
}

// KeyGen generates an SLSS key pair from a secret seed of at least 32 bytes.
// The output is a deterministic function of params and seed.
func KeyGen(params kmosaic.SLSSParams, seed []byte) (*kmosaic.SLSSKeyPair, error) {
	if len(seed) < 32 {
		return nil, errors.New("seed must be at least 32 bytes")
	}
	if err := checkParams(params); err != nil {
		return nil, err
	}
	n, m, w, eta, l := params.N, params.M, params.W, params.Eta, params.L

	// The matrix seed is public: it is a domain-separated hash of the secret
	// seed and reveals nothing about it beyond preimage resistance.
	matrixSeed := utils.HashWithDomain(DomainMatrix, seed)
	A := sampleMatrix(matrixSeed, m, n)

	S := make([]int8, l*n)
	T := make([]int32, l*m)

	workers := runtime.GOMAXPROCS(0)
	if workers > l {
		workers = l
	}
	per := (l + workers - 1) / workers

	// Each worker owns a block of columns. It first samples the sparse
	// secrets of its columns as ±1 position lists, then streams A once, row
	// by row, computing ⟨A_i, s_j⟩ for all its columns while the row is in
	// cache, and finally adds the errors and reduces.
	//
	// The loads A_i[p] are at secret positions p. This is a cache-timing
	// channel at cache-line granularity during key generation (a one-time
	// operation per key); Decrypt does not index memory by secret data.
	var wg sync.WaitGroup
	for start := 0; start < l; start += per {
		end := min(start+per, l)
		wg.Add(1)
		go func() {
			defer wg.Done()
			cols := end - start
			pos := make([]int32, cols*w+1)
			nplus := make([]int, cols)
			signs := make([]byte, (w+7)/8)
			cs := make([]byte, len(seed)+4)
			h := sha3.NewSHAKE256()
			defer func() {
				utils.ZeroizeInt32(pos)
				clear(nplus)
				utils.Zeroize(cs)
			}()

			for c := 0; c < cols; c++ {
				j := start + c
				secretSeed := utils.HashWithDomain(DomainSecret, columnSeed(cs, seed, j))
				sj := S[j*n : (j+1)*n]
				sampleSparse(h, secretSeed, w, sj, signs)
				// Column c's list is pos[c*w:(c+1)*w]; the scratch slot
				// pos[(c+1)*w] is overwritten by the next column.
				nplus[c] = splitTernary(sj, w, pos[c*w:(c+1)*w+1])
				utils.Zeroize(secretSeed)
			}

			// Four rows at a time: each position is loaded once and used
			// for four independent sums.
			i := 0
			for ; i+4 <= m; i += 4 {
				r0 := A[i*n : (i+1)*n]
				r1 := A[(i+1)*n:][:len(r0)]
				r2 := A[(i+2)*n:][:len(r0)]
				r3 := A[(i+3)*n:][:len(r0)]
				for c := 0; c < cols; c++ {
					lst := pos[c*w : (c+1)*w]
					np := nplus[c]
					var x0, x1, x2, x3 int32
					for _, p := range lst[:np] {
						x0 += r0[p]
						x1 += r1[p]
						x2 += r2[p]
						x3 += r3[p]
					}
					for _, p := range lst[np:] {
						x0 -= r0[p]
						x1 -= r1[p]
						x2 -= r2[p]
						x3 -= r3[p]
					}
					tj := T[(start+c)*m+i:][:4]
					tj[0], tj[1], tj[2], tj[3] = x0, x1, x2, x3
				}
			}
			for ; i < m; i++ {
				row := A[i*n : (i+1)*n]
				for c := 0; c < cols; c++ {
					lst := pos[c*w : (c+1)*w]
					np := nplus[c]
					var sum int32
					for _, p := range lst[:np] {
						sum += row[p]
					}
					for _, p := range lst[np:] {
						sum -= row[p]
					}
					T[(start+c)*m+i] = sum
				}
			}

			for c := 0; c < cols; c++ {
				j := start + c
				errorSeed := utils.HashWithDomain(DomainError, columnSeed(cs, seed, j))
				e := utils.SampleCenteredBinomial(errorSeed, m, eta)
				tj := T[j*m : (j+1)*m]
				e = e[:len(tj)]
				for i := range tj {
					tj[i] = mod32(tj[i] + e[i])
				}
				utils.ZeroizeInt32(e)
				utils.Zeroize(errorSeed)
			}
		}()
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

// addRows adds sign·A_p to acc for every row index p in rows, where A is
// row-major with len(acc) columns. Rows are combined four at a time so that
// acc is loaded and stored once per four rows.
func addRows(acc, A []int32, rows []int32, sign int32) {
	n := len(acc)
	k := 0
	for ; k+4 <= len(rows); k += 4 {
		r0 := A[int(rows[k])*n : int(rows[k])*n+n]
		r1 := A[int(rows[k+1])*n : int(rows[k+1])*n+n]
		r2 := A[int(rows[k+2])*n : int(rows[k+2])*n+n]
		r3 := A[int(rows[k+3])*n : int(rows[k+3])*n+n]
		r1, r2, r3 = r1[:len(r0)], r2[:len(r0)], r3[:len(r0)]
		a := acc[:len(r0)]
		if sign > 0 {
			for i, x := range r0 {
				a[i] += x + r1[i] + r2[i] + r3[i]
			}
		} else {
			for i, x := range r0 {
				a[i] -= x + r1[i] + r2[i] + r3[i]
			}
		}
	}
	for ; k < len(rows); k++ {
		r0 := A[int(rows[k])*n : int(rows[k])*n+n]
		a := acc[:len(r0)]
		for i, x := range r0 {
			a[i] += sign * x
		}
	}
}

// Encrypt encrypts a message of exactly L/8 bytes under pk. randomness (at
// least 32 bytes) deterministically selects the ephemeral values, so the
// ciphertext is a deterministic function of (pk, message, randomness).
//
// The rows of A and entries of each t_j that are read are selected by the
// ephemeral secret r; as in KeyGen this is a cache-line-granular memory
// access pattern that depends on r.
func Encrypt(pk kmosaic.SLSSPublicKey, message []byte, params kmosaic.SLSSParams, randomness []byte) (*kmosaic.SLSSCiphertext, error) {
	if len(randomness) < 32 {
		return nil, errors.New("randomness must be at least 32 bytes")
	}
	if err := checkParams(params); err != nil {
		return nil, err
	}
	n, m, w, eta, l := params.N, params.M, params.W, params.Eta, params.L
	du, dv := uint(params.DU), uint(params.DV)
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
	r := make([]int8, m)
	pos := make([]int32, w+1)
	sampleSparse(sha3.NewSHAKE256(), rSeed, w, r, make([]byte, (w+7)/8))
	np := splitTernary(r, w, pos)
	e1 := utils.SampleCenteredBinomial(e1Seed, n, eta)
	e2 := utils.SampleCenteredBinomial(e2Seed, l, eta)
	defer func() {
		utils.Zeroize(rSeed)
		utils.Zeroize(e1Seed)
		utils.Zeroize(e2Seed)
		utils.ZeroizeInt8(r)
		utils.ZeroizeInt32(pos)
		utils.ZeroizeInt32(e1)
		utils.ZeroizeInt32(e2)
	}()

	// u = Compress_DU(Aᵀ·r + e1). |accumulator| ≤ W·q < 2^30.
	u := make([]int32, n)
	addRows(u, pk.A, pos[:np], 1)
	addRows(u, pk.A, pos[np:w], -1)
	e1 = e1[:len(u)]
	for i := range u {
		u[i] = compress(mod32(u[i]+e1[i]), du)
	}

	// v_j = Compress_DV(⟨t_j, r⟩ + e2_j + bit_j·⌊q/2⌋)
	v := make([]int32, l)
	plus, minus := pos[:np], pos[np:w]
	for j := range v {
		tj := pk.T[j*m : (j+1)*m]
		var sum int32
		for _, p := range plus {
			sum += tj[p]
		}
		for _, p := range minus {
			sum -= tj[p]
		}
		bit := int32((message[j/8] >> (j % 8)) & 1)
		v[j] = compress(mod32(sum+e2[j]+bit*(q/2)), dv)
	}

	return &kmosaic.SLSSCiphertext{U: u, V: v}, nil
}

// Decrypt decrypts an SLSS ciphertext. It returns nil only if the ciphertext
// or key shapes do not match params (shapes are public); every well-shaped
// input decrypts to some L/8-byte message. Coefficients outside [0, 2^d) are
// reduced to their low d bits.
//
// The inner products ⟨s_j, u⟩ run over every coefficient of s_j with a
// multiply, so neither the control flow nor the memory accesses depend on the
// secret key.
func Decrypt(ct *kmosaic.SLSSCiphertext, sk kmosaic.SLSSSecretKey, params kmosaic.SLSSParams) []byte {
	if ct == nil || checkParams(params) != nil {
		return nil
	}
	n, l := params.N, params.L
	du, dv := uint(params.DU), uint(params.DV)
	if len(ct.U) != n || len(ct.V) != l || len(sk.S) != l*n {
		return nil
	}

	u := make([]int32, n)
	for i, c := range ct.U {
		u[i] = decompress(c, du)
	}

	result := make([]byte, l/8)
	var acc [4]int32
	for j := 0; j < l; j += 4 {
		// L is a multiple of 8: four columns at a time share each load of u.
		innerProducts4(&acc, u, sk.S[j*n:(j+4)*n])
		for c := 0; c < 4; c++ {
			d := centerMod(decompress(ct.V[j+c], dv) - acc[c])

			// Constant-time |d| > q/4.
			mask := d >> 31
			absD := (d ^ mask) - mask
			bit := byte(((q/4 - absD) >> 31) & 1)
			result[(j+c)/8] |= bit << ((j + c) % 8)
		}
	}
	clear(acc[:])
	return result
}

// innerProducts4 sets acc[c] = ⟨s_c, u⟩ for the four consecutive secret
// columns s_0..s_3 stored in S (length 4·len(u)). Every coefficient is
// multiplied, so timing and memory accesses are independent of S.
func innerProducts4(acc *[4]int32, u []int32, S []int8) {
	n := len(u)
	s0 := S[:n]
	s1 := S[n:][:n]
	s2 := S[2*n:][:n]
	s3 := S[3*n:][:n]
	var a0, a1, a2, a3 int32
	for i, x := range u {
		a0 += x * int32(s0[i])
		a1 += x * int32(s1[i])
		a2 += x * int32(s2[i])
		a3 += x * int32(s3[i])
	}
	acc[0], acc[1], acc[2], acc[3] = a0, a1, a2, a3
}

// packBits writes vals at the given width (≤ 32) into dst in little-endian
// bit order; each value is masked to its width and the final partial byte
// is zero-padded. dst must hold ⌈len(vals)·bits/8⌉ bytes.
func packBits(dst []byte, vals []int32, bits uint) {
	var acc uint64
	var nb uint
	o := 0
	mask := uint64(1)<<bits - 1
	for _, v := range vals {
		acc |= (uint64(uint32(v)) & mask) << nb
		nb += bits
		for nb >= 8 {
			dst[o] = byte(acc)
			o++
			acc >>= 8
			nb -= 8
		}
	}
	if nb > 0 {
		dst[o] = byte(acc)
	}
}

// unpackBits reads len(out) values of the given width (≤ 32) from src, which
// must hold exactly ⌈len(out)·bits/8⌉ bytes. It returns the padding bits of
// the final byte, which are zero in a canonical encoding.
func unpackBits(src []byte, out []int32, bits uint) uint64 {
	var acc uint64
	var nb uint
	o := 0
	mask := uint64(1)<<bits - 1
	for i := range out {
		for nb < bits {
			acc |= uint64(src[o]) << nb
			o++
			nb += 8
		}
		out[i] = int32(acc & mask)
		acc >>= bits
		nb -= bits
	}
	return acc
}

func packedLen(count int, bits int) int {
	return (count*bits + 7) / 8
}

// PublicKeySize returns the length of a serialized public key.
func PublicKeySize(params kmosaic.SLSSParams) int {
	return SeedSize + packedLen(params.L*params.M, pkBits)
}

// SecretKeySize returns the length of a serialized secret key.
func SecretKeySize(params kmosaic.SLSSParams) int {
	return packedLen(params.L*params.N, 2)
}

// CiphertextSize returns the length of a serialized ciphertext.
func CiphertextSize(params kmosaic.SLSSParams) int {
	return packedLen(params.N, params.DU) + packedLen(params.L, params.DV)
}

// SerializePublicKey encodes pk as seed (32 bytes) || T packed at 14 bits per
// entry. A is not stored; it is re-expanded from the seed. Entries of T are
// expected in [0, q).
func SerializePublicKey(pk kmosaic.SLSSPublicKey) []byte {
	out := make([]byte, SeedSize+packedLen(len(pk.T), pkBits))
	copy(out[:SeedSize], pk.Seed)
	packBits(out[SeedSize:], pk.T, pkBits)
	return out
}

// DeserializePublicKey parses a public key produced by SerializePublicKey.
// The encoding must have exactly PublicKeySize(params) bytes, every entry of
// T must be below q and the padding must be zero. The matrix A is expanded
// from the seed.
func DeserializePublicKey(data []byte, params kmosaic.SLSSParams) (*kmosaic.SLSSPublicKey, error) {
	if err := checkParams(params); err != nil {
		return nil, err
	}
	if len(data) != PublicKeySize(params) {
		return nil, errors.New("invalid SLSS public key: wrong length")
	}
	T := make([]int32, params.L*params.M)
	if unpackBits(data[SeedSize:], T, pkBits) != 0 {
		return nil, errors.New("invalid SLSS public key: non-canonical padding")
	}
	for _, t := range T {
		if t >= q {
			return nil, errors.New("invalid SLSS public key: entry out of range")
		}
	}
	seed := make([]byte, SeedSize)
	copy(seed, data[:SeedSize])
	return &kmosaic.SLSSPublicKey{Seed: seed, A: ExpandMatrix(seed, params), T: T}, nil
}

// SerializeCiphertext encodes ct as U packed at DU bits || V packed at DV
// bits, each part padded to a whole byte. It returns nil if ct does not have
// the shape given by params.
func SerializeCiphertext(ct *kmosaic.SLSSCiphertext, params kmosaic.SLSSParams) []byte {
	if ct == nil || checkParams(params) != nil || len(ct.U) != params.N || len(ct.V) != params.L {
		return nil
	}
	uLen := packedLen(params.N, params.DU)
	out := make([]byte, uLen+packedLen(params.L, params.DV))
	packBits(out[:uLen], ct.U, uint(params.DU))
	packBits(out[uLen:], ct.V, uint(params.DV))
	return out
}

// DeserializeCiphertext parses a ciphertext produced by SerializeCiphertext.
// The encoding must have exactly CiphertextSize(params) bytes and zero
// padding bits, so every ciphertext has exactly one encoding.
func DeserializeCiphertext(data []byte, params kmosaic.SLSSParams) (*kmosaic.SLSSCiphertext, error) {
	if err := checkParams(params); err != nil {
		return nil, err
	}
	if len(data) != CiphertextSize(params) {
		return nil, errors.New("invalid SLSS ciphertext: wrong length")
	}
	uLen := packedLen(params.N, params.DU)
	ct := &kmosaic.SLSSCiphertext{U: make([]int32, params.N), V: make([]int32, params.L)}
	padU := unpackBits(data[:uLen], ct.U, uint(params.DU))
	padV := unpackBits(data[uLen:], ct.V, uint(params.DV))
	if padU|padV != 0 {
		return nil, errors.New("invalid SLSS ciphertext: non-canonical padding")
	}
	return ct, nil
}

// SerializeSecretKey encodes S at 2 bits per entry (00 = 0, 01 = +1,
// 10 = −1) in little-endian bit order. The encoding is branch-free. It returns
// nil if S does not have L·N entries.
func SerializeSecretKey(sk kmosaic.SLSSSecretKey, params kmosaic.SLSSParams) []byte {
	if checkParams(params) != nil || len(sk.S) != params.L*params.N {
		return nil
	}
	out := make([]byte, SecretKeySize(params))
	for i, s := range sk.S {
		b := uint8(s)
		neg := b >> 7                   // 1 for −1
		code := neg<<1 | (b & 1 &^ neg) // 0 → 00, +1 → 01, −1 → 10
		out[i>>2] |= code << (2 * (i & 3))
	}
	return out
}

// DeserializeSecretKey parses a secret key produced by SerializeSecretKey.
// It rejects encodings of the wrong length and the invalid code 11. The
// decoding is branch-free in the key material.
func DeserializeSecretKey(data []byte, params kmosaic.SLSSParams) (*kmosaic.SLSSSecretKey, error) {
	if err := checkParams(params); err != nil {
		return nil, err
	}
	if len(data) != SecretKeySize(params) {
		return nil, errors.New("invalid SLSS secret key: wrong length")
	}
	S := make([]int8, params.L*params.N)
	var bad uint8
	for i := range S {
		c := (data[i>>2] >> (2 * (i & 3))) & 3
		bad |= c & (c >> 1) & 1
		S[i] = int8(c&1) - int8(c>>1)
	}
	if bad != 0 {
		utils.ZeroizeInt8(S)
		return nil, errors.New("invalid SLSS secret key: invalid coefficient code")
	}
	return &kmosaic.SLSSSecretKey{S: S}, nil
}
