package latsig

import (
	"crypto/sha3"
	"encoding/binary"
	"runtime"
	"sync"

	"github.com/BackendStack21/k-mosaic-go/v2/core"
)

// Low-level lattice helpers for the signature scheme. Everything here follows
// CRYSTALS-Dilithium / FIPS 204 with matrices over Z_q in place of polynomial
// rings.
//
// Constant-time policy: no value that depends on secret data is ever divided
// or reduced with a hardware division. All reductions use the compile-time
// modulus q = 2^23 - 2^13 + 1 through shifts, masks and multiplications
// (reduce32, reduce64, freeze), and the FIPS 204 Decompose and Power2Round
// use the reference implementation's multiply-shift formulas.

const (
	qMod     = 8380417         // q = 2^23 - 2^13 + 1
	gamma1   = 1 << 19         // mask range
	gamma2   = (qMod - 1) / 32 // 261888
	alpha    = 2 * gamma2      // 523776; HighBits take values in [0, 16)
	dropBits = 13              // d: bits dropped from T by Power2Round
	chalLen  = 256             // L: length of the challenge vector
	t0Half   = 1 << (dropBits - 1)
	maxTau   = 64            // core.ValidateLatticeSignParams bound
	t1Bits   = 23 - dropBits // 10 bits per T1 entry
	t0Bits   = dropBits      // 13 bits per T0 entry
	zBits    = 20            // bits per packed response entry
	w1Bits   = 4             // bits per HighBits entry in the challenge hash
	t1Limit  = 1 << t1Bits   // T1 entries are in [0, 1024)
	zLimit   = 1 << zBits    // packed response values are in [0, 2^20)
	signLane = 4             // masks processed per pass over A
)

// The constants above must agree with the frozen parameter definitions.
var _ = [1]struct{}{}[qMod-core.LatticeSignQ]

// shake computes SHAKE256 over the concatenation of parts. The sponge state
// is cleared afterwards since some inputs (K, ρ') are secret.
func shake(outLen int, parts ...[]byte) []byte {
	h := sha3.NewSHAKE256()
	defer h.Reset()
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	out := make([]byte, outLen)
	_, _ = h.Read(out)
	return out
}

// uint32LE returns v as 4 little-endian bytes.
func uint32LE(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// reduce32 returns r ≡ a (mod q) with -6283008 <= r <= 6283008 for
// |a| <= 2^31 - 2^22 - 1 (FIPS 204 reference reduce32).
func reduce32(a int32) int32 {
	t := (a + (1 << 22)) >> 23
	return a - t*qMod
}

// caddq adds q to a if a is negative, without branching.
func caddq(a int32) int32 {
	return a + ((a >> 31) & qMod)
}

// freeze returns a mod q in [0, q) for |a| <= 2^31 - 2^22 - 1.
func freeze(a int32) int32 {
	return caddq(reduce32(a))
}

// reduce64 returns x mod q in [0, q) for |x| < 2^62, using 2^23 ≡ 2^13 - 1
// (mod q) to fold the high part four times and then freeze.
func reduce64(x int64) int32 {
	const lo23 = 1<<23 - 1
	const fold = 1<<13 - 1
	x = (x>>23)*fold + (x & lo23) // |x| < 2^52 + 2^23
	x = (x>>23)*fold + (x & lo23) // |x| < 2^42 + 2^23
	x = (x>>23)*fold + (x & lo23) // |x| < 2^32 + 2^23
	x = (x>>23)*fold + (x & lo23) // -2^23 < x < 2^24
	return freeze(int32(x))
}

// absU returns |x| as an unsigned value, without branching (correct for MinInt32).
func absU(x int32) uint32 {
	m := x >> 31
	return uint32((x ^ m) - m)
}

// normU returns max |v_i| without data-dependent branches.
func normU(v []int32) uint32 {
	var max uint32
	for _, x := range v {
		a := absU(x)
		// mask is all ones when a > max (the 64-bit difference borrows).
		mask := -uint32((uint64(max) - uint64(a)) >> 63)
		max = (max &^ mask) | (a & mask)
	}
	return max
}

// decompose splits r ∈ [0, q) as r ≡ r1·2γ2 + r0 with r0 ∈ (-γ2, γ2] and the
// FIPS 204 adjustment at r - r0 = q - 1 (r1 = 0, r0 = r0 - 1). It is the
// reference implementation's constant-time formula for γ2 = (q-1)/32.
func decompose(r int32) (r1, r0 int32) {
	r1 = (r + 127) >> 7
	r1 = (r1*1025 + (1 << 21)) >> 22
	r1 &= 15
	r0 = r - r1*alpha
	r0 -= (((qMod-1)/2 - r0) >> 31) & qMod
	return r1, r0
}

// highBits returns HighBits(r) for r ∈ [0, q).
func highBits(r int32) int32 {
	r1, _ := decompose(r)
	return r1
}

// makeHint returns 1 when HighBits(r) != HighBits(r + z mod q), the FIPS 204
// MakeHint(z, r) for r ∈ [0, q) and |z| < 2^30, without branching.
func makeHint(z, r int32) int32 {
	d := highBits(r) ^ highBits(freeze(r+z))
	return int32(uint32(d|-d) >> 31)
}

// useHint is FIPS 204 UseHint for γ2 = (q-1)/32 (m = 16): it recovers the
// high bits of r + z from r and the hint produced by makeHint(-z, r + z).
// It only runs on public data in Verify.
func useHint(h, r int32) int32 {
	r1, r0 := decompose(r)
	if h == 0 {
		return r1
	}
	if r0 > 0 {
		return (r1 + 1) & 15
	}
	return (r1 - 1) & 15
}

// power2Round splits r ∈ [0, q) as r = r1·2^d + r0 with r0 ∈ (-2^(d-1), 2^(d-1)].
func power2Round(r int32) (r1, r0 int32) {
	r1 = (r + t0Half - 1) >> dropBits
	r0 = r - r1<<dropBits
	return r1, r0
}

// parallelRows runs fn(start, end) over [0, rows) split across GOMAXPROCS workers.
func parallelRows(rows int, fn func(start, end int)) {
	workers := runtime.GOMAXPROCS(0)
	if workers > rows/16 {
		workers = rows / 16
	}
	if workers <= 1 {
		fn(0, rows)
		return
	}
	per := (rows + workers - 1) / workers
	var wg sync.WaitGroup
	for start := 0; start < rows; start += per {
		end := min(start+per, rows)
		wg.Add(1)
		go func(s, e int) {
			defer wg.Done()
			fn(s, e)
		}(start, end)
	}
	wg.Wait()
}

// expandA derives the public M×N matrix A over Z_q from rho. Row i is read
// from SHAKE128(rho || i) by rejection sampling of 23-bit values below q, as
// in FIPS 204 RejNTTPoly.
func expandA(rho []byte, m, n int) []int32 {
	A := make([]int32, m*n)
	parallelRows(m, func(start, end int) {
		h := sha3.NewSHAKE128()
		var buf [3 * 168]byte // a multiple of the SHAKE128 rate
		var idx [4]byte
		for i := start; i < end; i++ {
			h.Reset()
			_, _ = h.Write(rho)
			binary.LittleEndian.PutUint32(idx[:], uint32(i))
			_, _ = h.Write(idx[:])
			row := A[i*n : (i+1)*n]
			k := 0
			for k < n {
				_, _ = h.Read(buf[:])
				for off := 0; off+3 <= len(buf) && k < n; off += 3 {
					v := (uint32(buf[off]) | uint32(buf[off+1])<<8 | uint32(buf[off+2])<<16) & 0x7FFFFF
					if v < qMod {
						row[k] = int32(v)
						k++
					}
				}
			}
		}
	})
	return A
}

// sampleEta samples count values uniform in [-eta, eta] (eta ∈ {2, 4}) from
// SHAKE256(seed || nonce) by rejection on nibbles (FIPS 204 RejBoundedPoly).
func sampleEta(seed []byte, nonce uint16, count, eta int) []int8 {
	out := make([]int8, count)
	h := sha3.NewSHAKE256()
	defer h.Reset()
	_, _ = h.Write(seed)
	var nb [2]byte
	binary.LittleEndian.PutUint16(nb[:], nonce)
	_, _ = h.Write(nb[:])
	var buf [136]byte
	defer clear(buf[:])
	k := 0
	for k < count {
		_, _ = h.Read(buf[:])
		for _, b := range buf {
			for _, t := range [2]uint32{uint32(b & 0x0F), uint32(b >> 4)} {
				if k >= count {
					break
				}
				if eta == 2 {
					if t < 15 {
						// t mod 5 without division (FIPS 204 CoeffFromHalfByte).
						out[k] = int8(2 - int32(t-((205*t)>>10)*5))
						k++
					}
				} else if t < 9 {
					out[k] = int8(4 - int32(t))
					k++
				}
			}
		}
	}
	return out
}

// expandMaskLane samples a mask y with n entries uniform in (-γ1, γ1] from
// SHAKE256(rhoPrime || kappa) and writes it into lane j of the interleaved
// buffer ys (ys[signLane*k + j] = y_k).
func expandMaskLane(rhoPrime []byte, kappa uint16, n int, ys []int32, j int) {
	h := sha3.NewSHAKE256()
	defer h.Reset()
	_, _ = h.Write(rhoPrime)
	var kb [2]byte
	binary.LittleEndian.PutUint16(kb[:], kappa)
	_, _ = h.Write(kb[:])
	var buf [5 * 136]byte // 5 bytes encode two 20-bit values
	defer clear(buf[:])
	k := 0
	for k < n {
		_, _ = h.Read(buf[:])
		for off := 0; off+5 <= len(buf) && k < n; off += 5 {
			t0 := uint32(buf[off]) | uint32(buf[off+1])<<8 | uint32(buf[off+2]&0x0F)<<16
			t1 := uint32(buf[off+2]>>4) | uint32(buf[off+3])<<4 | uint32(buf[off+4])<<12
			ys[signLane*k+j] = gamma1 - int32(t0)
			k++
			if k < n {
				ys[signLane*k+j] = gamma1 - int32(t1)
				k++
			}
		}
	}
}

// challenge is the sparse form of c ∈ {-1,0,1}^256 with tau non-zero entries.
type challenge struct {
	pos [maxTau]uint8
	sgn [maxTau]int32
	n   int
}

// sampleInBall derives the challenge c with exactly tau non-zero ±1 entries
// from c̃ (FIPS 204 SampleInBall) and returns it in dense and sparse form.
func sampleInBall(ctilde []byte, tau int) (dense [chalLen]int8, sparse challenge) {
	h := sha3.NewSHAKE256()
	_, _ = h.Write(ctilde)
	var buf [136]byte
	_, _ = h.Read(buf[:])
	signs := binary.LittleEndian.Uint64(buf[:8])
	off := 8
	for i := chalLen - tau; i < chalLen; i++ {
		var j int
		for {
			if off == len(buf) {
				_, _ = h.Read(buf[:])
				off = 0
			}
			j = int(buf[off])
			off++
			if j <= i {
				break
			}
		}
		dense[i] = dense[j]
		dense[j] = int8(1 - 2*int(signs&1))
		signs >>= 1
	}
	for i, v := range dense {
		if v != 0 {
			sparse.pos[sparse.n] = uint8(i)
			sparse.sgn[sparse.n] = int32(v)
			sparse.n++
		}
	}
	return dense, sparse
}

// mulSparse8 computes out = S·c for the rows×256 row-major matrix S by adding
// the tau signed entries selected by c in each row.
func mulSparse8(S []int8, c *challenge, rows int, out []int32) {
	pos := c.pos[:c.n]
	sgn := c.sgn[:c.n]
	for i := 0; i < rows; i++ {
		row := (*[chalLen]int8)(S[i*chalLen:])
		var sum int32
		for t, p := range pos {
			sum += sgn[t] * int32(row[p])
		}
		out[i] = sum
	}
}

// mulSparse32 computes out = T·c for the rows×256 row-major matrix T.
func mulSparse32(T []int32, c *challenge, rows int, out []int32) {
	pos := c.pos[:c.n]
	sgn := c.sgn[:c.n]
	for i := 0; i < rows; i++ {
		row := (*[chalLen]int32)(T[i*chalLen:])
		var sum int32
		for t, p := range pos {
			sum += sgn[t] * row[p]
		}
		out[i] = sum
	}
}

// matVec computes out = A·x - sub·2^d mod q for the M×N row-major matrix A
// (entries in [0, q)) and x with |x_i| <= 2^19; sub may be nil. Sums stay
// below 2^53 in absolute value.
func matVec(A []int32, x []int32, sub []int32, m, n int, out []int32) {
	parallelRows(m, func(start, end int) {
		for i := start; i < end; i++ {
			row := A[i*n : (i+1)*n]
			xs := x[:len(row)]
			var s0, s1, s2, s3 int64
			k := 0
			for ; k+4 <= len(row); k += 4 {
				s0 += int64(row[k]) * int64(xs[k])
				s1 += int64(row[k+1]) * int64(xs[k+1])
				s2 += int64(row[k+2]) * int64(xs[k+2])
				s3 += int64(row[k+3]) * int64(xs[k+3])
			}
			for ; k < len(row); k++ {
				s0 += int64(row[k]) * int64(xs[k])
			}
			sum := s0 + s1 + s2 + s3
			if sub != nil {
				sum -= int64(sub[i]) << dropBits
			}
			out[i] = reduce64(sum)
		}
	})
}

// matVec4 computes the four products out[j] = A·y_j mod q in one pass over A,
// where ys holds the masks interleaved (ys[signLane*k + j] = y_j[k]). Signing
// spends most of its time streaming A, so four products cost far less than
// four passes. n must be a multiple of 4.
func matVec4(A []int32, ys []int32, m, n int, out *[signLane][]int32) {
	parallelRows(m, func(start, end int) {
		for i := start; i < end; i++ {
			row := A[i*n : (i+1)*n]
			ys := ys[:signLane*len(row)]
			var s0, s1, s2, s3 int64
			for k := 0; k+4 <= len(row); k += 4 {
				a := (*[4]int32)(row[k:])
				y := (*[4 * signLane]int32)(ys[signLane*k:])
				a0, a1, a2, a3 := int64(a[0]), int64(a[1]), int64(a[2]), int64(a[3])
				s0 += (a0*int64(y[0]) + a1*int64(y[4])) + (a2*int64(y[8]) + a3*int64(y[12]))
				s1 += (a0*int64(y[1]) + a1*int64(y[5])) + (a2*int64(y[9]) + a3*int64(y[13]))
				s2 += (a0*int64(y[2]) + a1*int64(y[6])) + (a2*int64(y[10]) + a3*int64(y[14]))
				s3 += (a0*int64(y[3]) + a1*int64(y[7])) + (a2*int64(y[11]) + a3*int64(y[15]))
			}
			out[0][i] = reduce64(s0)
			out[1][i] = reduce64(s1)
			out[2][i] = reduce64(s2)
			out[3][i] = reduce64(s3)
		}
	})
}

// computeT computes T = A·S1 + S2 mod q, with A M×N, S1 N×L and S2 M×L
// (row-major). S1 is transposed first so that every entry of T is a
// sequential dot product; four columns share each load of A.
func computeT(A []int32, S1, S2 []int8, m, n int) []int32 {
	const l = chalLen
	s1t := make([]int8, n*l)
	defer clear(s1t)
	for k := 0; k < n; k++ {
		for j := 0; j < l; j++ {
			s1t[j*n+k] = S1[k*l+j]
		}
	}
	T := make([]int32, m*l)
	parallelRows(m, func(start, end int) {
		for i := start; i < end; i++ {
			row := A[i*n : (i+1)*n]
			for j := 0; j < l; j += 4 {
				c0 := s1t[j*n : j*n+len(row)]
				c1 := s1t[(j+1)*n : (j+1)*n+len(row)]
				c2 := s1t[(j+2)*n : (j+2)*n+len(row)]
				c3 := s1t[(j+3)*n : (j+3)*n+len(row)]
				var a0, a1, a2, a3 int64
				for k, a := range row {
					av := int64(a)
					a0 += av * int64(c0[k])
					a1 += av * int64(c1[k])
					a2 += av * int64(c2[k])
					a3 += av * int64(c3[k])
				}
				t := T[i*l+j : i*l+j+4]
				s2 := S2[i*l+j : i*l+j+4]
				t[0] = reduce64(a0 + int64(s2[0]))
				t[1] = reduce64(a1 + int64(s2[1]))
				t[2] = reduce64(a2 + int64(s2[2]))
				t[3] = reduce64(a3 + int64(s2[3]))
			}
		}
	})
	return T
}

// packW1 encodes HighBits values (in [0, 16)) with 4 bits each, low nibble
// first, as FIPS 204 w1Encode does for γ2 = (q-1)/32. len(w1) must be even.
func packW1(w1 []int32, out []byte) {
	for i := range out {
		out[i] = byte(w1[2*i]&15) | byte(w1[2*i+1]&15)<<4
	}
}
