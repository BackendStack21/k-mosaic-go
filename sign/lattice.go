package sign

import (
	"encoding/binary"
	"runtime"
	"sync"

	"golang.org/x/crypto/sha3"
)

// Low-level lattice helpers for the signature scheme. Everything here follows
// CRYSTALS-Dilithium / FIPS 204 with matrices over Z_q in place of polynomial
// rings.

// shake computes SHAKE256 over the concatenation of parts.
func shake(outLen int, parts ...[]byte) []byte {
	h := sha3.NewShake256()
	for _, p := range parts {
		h.Write(p)
	}
	out := make([]byte, outLen)
	_, _ = h.Read(out)
	return out
}

// uint16LE returns v as 2 little-endian bytes.
func uint16LE(v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return b
}

// uint32LE returns v as 4 little-endian bytes.
func uint32LE(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// modQ reduces x into [0, q).
func modQ(x int64, q int) int32 {
	r := x % int64(q)
	if r < 0 {
		r += int64(q)
	}
	return int32(r)
}

// parallelRows runs fn(start, end) over [0, rows) split across GOMAXPROCS workers.
func parallelRows(rows int, fn func(start, end int)) {
	workers := runtime.GOMAXPROCS(0)
	if workers > rows {
		workers = rows
	}
	if workers <= 1 {
		fn(0, rows)
		return
	}
	per := (rows + workers - 1) / workers
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		start := w * per
		end := start + per
		if end > rows {
			end = rows
		}
		if start >= end {
			break
		}
		wg.Add(1)
		go func(s, e int) {
			defer wg.Done()
			fn(s, e)
		}(start, end)
	}
	wg.Wait()
}

// expandA derives the public M×N matrix A over Z_q from rho. Row i is read
// from SHAKE256(rho || i) by rejection sampling of 23-bit values below q.
func expandA(rho []byte, m, n, q int) []int32 {
	A := make([]int32, m*n)
	parallelRows(m, func(start, end int) {
		h := sha3.NewShake256()
		buf := make([]byte, 3*256)
		for i := start; i < end; i++ {
			h.Reset()
			h.Write(rho)
			h.Write(uint32LE(uint32(i)))
			row := A[i*n : (i+1)*n]
			k := 0
			for k < n {
				_, _ = h.Read(buf)
				for off := 0; off+3 <= len(buf) && k < n; off += 3 {
					v := (uint32(buf[off]) | uint32(buf[off+1])<<8 | uint32(buf[off+2])<<16) & 0x7FFFFF
					if int(v) < q {
						row[k] = int32(v)
						k++
					}
				}
			}
		}
	})
	return A
}

// sampleEta samples count values uniform in [-eta, eta] from
// SHAKE256(seed || nonce) by rejection on nibbles (FIPS 204 RejBoundedPoly).
func sampleEta(seed []byte, nonce uint16, count, eta int) []int8 {
	out := make([]int8, count)
	h := sha3.NewShake256()
	h.Write(seed)
	h.Write(uint16LE(nonce))
	buf := make([]byte, 512)
	k := 0
	for k < count {
		_, _ = h.Read(buf)
		for _, b := range buf {
			for _, t := range [2]byte{b & 0x0F, b >> 4} {
				if k >= count {
					break
				}
				switch eta {
				case 2:
					if t < 15 {
						out[k] = int8(2 - int(t%5))
						k++
					}
				case 4:
					if t < 9 {
						out[k] = int8(4 - int(t))
						k++
					}
				default:
					// Generic rejection: uniform in [0, 2eta].
					if int(t) < 2*eta+1 {
						out[k] = int8(eta - int(t))
						k++
					}
				}
			}
			if k >= count {
				break
			}
		}
	}
	return out
}

// expandMask samples the mask y with n entries uniform in [-(gamma1-1), gamma1]
// from SHAKE256(rhoPrime || kappa). gamma1 must be 2^19 (20 bits per entry).
func expandMask(rhoPrime []byte, kappa uint16, n, gamma1 int) []int32 {
	y := make([]int32, n)
	h := sha3.NewShake256()
	h.Write(rhoPrime)
	h.Write(uint16LE(kappa))
	buf := make([]byte, 5*128) // 5 bytes encode two 20-bit values
	k := 0
	for k < n {
		_, _ = h.Read(buf)
		for off := 0; off+5 <= len(buf) && k < n; off += 5 {
			t0 := uint32(buf[off]) | uint32(buf[off+1])<<8 | uint32(buf[off+2]&0x0F)<<16
			t1 := uint32(buf[off+2]>>4) | uint32(buf[off+3])<<4 | uint32(buf[off+4])<<12
			y[k] = int32(gamma1) - int32(t0)
			k++
			if k < n {
				y[k] = int32(gamma1) - int32(t1)
				k++
			}
		}
	}
	return y
}

// sampleInBall derives the challenge c ∈ {-1,0,1}^l with exactly tau non-zero
// entries from c̃ (FIPS 204 SampleInBall).
func sampleInBall(ctilde []byte, tau, l int) []int8 {
	c := make([]int8, l)
	h := sha3.NewShake256()
	h.Write(ctilde)
	signBytes := make([]byte, 8)
	_, _ = h.Read(signBytes)
	signs := binary.LittleEndian.Uint64(signBytes)
	one := make([]byte, 1)
	for i := l - tau; i < l; i++ {
		var j int
		for {
			_, _ = h.Read(one)
			j = int(one[0])
			if j <= i {
				break
			}
		}
		c[i] = c[j]
		c[j] = int8(1 - 2*int(signs&1))
		signs >>= 1
	}
	return c
}

// decompose splits r ∈ [0, q) as r = r1·(2·gamma2) + r0 with r0 ∈ (-gamma2, gamma2],
// with the FIPS 204 adjustment at r - r0 = q - 1.
func decompose(r int32, q, gamma2 int) (r1, r0 int32) {
	alpha := int32(2 * gamma2)
	r0 = r % alpha
	if r0 > int32(gamma2) {
		r0 -= alpha
	}
	if r-r0 == int32(q-1) {
		return 0, r0 - 1
	}
	return (r - r0) / alpha, r0
}

// highBits returns HighBits of every entry of w (entries in [0, q)).
func highBits(w []int32, q, gamma2 int) []int32 {
	out := make([]int32, len(w))
	for i, r := range w {
		out[i], _ = decompose(r, q, gamma2)
	}
	return out
}

// lowBits returns LowBits of every entry of w (entries in [0, q)).
func lowBits(w []int32, q, gamma2 int) []int32 {
	out := make([]int32, len(w))
	for i, r := range w {
		_, out[i] = decompose(r, q, gamma2)
	}
	return out
}

// matVec computes A·x mod q for the M×N row-major matrix A (entries in [0, q))
// and x with |x_i| < 2^20. Products stay below 2^43 and sums below 2^55.
func matVec(A []int32, x []int32, m, n, q int) []int32 {
	out := make([]int32, m)
	parallelRows(m, func(start, end int) {
		for i := start; i < end; i++ {
			row := A[i*n : (i+1)*n]
			var sum int64
			for k, a := range row {
				sum += int64(a) * int64(x[k])
			}
			out[i] = modQ(sum, q)
		}
	})
	return out
}

// mulSmall computes S·c for the rows×l row-major small matrix S and challenge c.
// Entries are bounded by tau·eta in absolute value.
func mulSmall(S []int8, c []int8, rows, l int) []int32 {
	out := make([]int32, rows)
	for i := 0; i < rows; i++ {
		row := S[i*l : (i+1)*l]
		var sum int32
		for j, s := range row {
			sum += int32(s) * int32(c[j])
		}
		out[i] = sum
	}
	return out
}

// mulT computes T·c mod q for the M×L row-major matrix T (entries in [0, q)).
func mulT(T []int32, c []int8, m, l, q int) []int32 {
	out := make([]int32, m)
	for i := 0; i < m; i++ {
		row := T[i*l : (i+1)*l]
		var sum int64
		for j, t := range row {
			sum += int64(t) * int64(c[j])
		}
		out[i] = modQ(sum, q)
	}
	return out
}

// computeT computes T = A·S1 + S2 mod q, with A M×N, S1 N×L, S2 M×L (row-major).
func computeT(A []int32, S1, S2 []int8, m, n, l, q int) []int32 {
	T := make([]int32, m*l)
	parallelRows(m, func(start, end int) {
		acc := make([]int64, l)
		for i := start; i < end; i++ {
			for j := range acc {
				acc[j] = 0
			}
			row := A[i*n : (i+1)*n]
			for k, a := range row {
				s1row := S1[k*l : (k+1)*l]
				av := int64(a)
				for j, s := range s1row {
					acc[j] += av * int64(s)
				}
			}
			for j := 0; j < l; j++ {
				T[i*l+j] = modQ(acc[j]+int64(S2[i*l+j]), q)
			}
		}
	})
	return T
}

// packW1 encodes HighBits values (all below 2^8 for the supported gamma2) as
// one byte each for hashing.
func packW1(w1 []int32) []byte {
	out := make([]byte, len(w1))
	for i, v := range w1 {
		out[i] = byte(v)
	}
	return out
}

// infNorm returns max |v_i|.
func infNorm(v []int32) int32 {
	var max int32
	for _, x := range v {
		if x < 0 {
			x = -x
		}
		if x > max {
			max = x
		}
	}
	return max
}
