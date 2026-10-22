package qcsd

import (
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"math/bits"
)

// Bit vectors over F_2 stored little-endian in uint64 words. A vector of n
// bits is an element of F_2[X]/(X^n - 1) with bit i the coefficient of X^i.
// Vectors are canonical when every bit at index >= n is zero.

func words(nbits int) int { return (nbits + 63) / 64 }

func setBit(v []uint64, i int)      { v[i>>6] |= 1 << (uint(i) & 63) }
func getBit(v []uint64, i int) bool { return v[i>>6]>>(uint(i)&63)&1 == 1 }

// maskTop clears every bit at index >= nbits.
func maskTop(v []uint64, nbits int) {
	if nbits%64 != 0 {
		v[len(v)-1] &= (1 << (uint(nbits) % 64)) - 1
	}
}

// isCanonical reports whether every bit of v at index >= nbits is zero.
func isCanonical(v []uint64, nbits int) bool {
	if nbits%64 == 0 || len(v) == 0 {
		return true
	}
	return v[len(v)-1]>>(uint(nbits)%64) == 0
}

// xorInto computes dst ^= src.
func xorInto(dst, src []uint64) {
	src = src[:len(dst)]
	for i := range dst {
		dst[i] ^= src[i]
	}
}

// zeroWords overwrites v with zeros.
func zeroWords(v []uint64) { clear(v) }

// zeroInts overwrites v with zeros.
func zeroInts(v []int) { clear(v) }

// positions lists, in increasing order, the set bits of v below nbits.
func positions(v []uint64, nbits int) []int {
	out := make([]int, 0, weight(v))
	for w, word := range v {
		for word != 0 {
			i := w*64 + bits.TrailingZeros64(word)
			if i < nbits {
				out = append(out, i)
			}
			word &= word - 1
		}
	}
	return out
}

// window returns D, the 2n-bit vector dense||dense followed by one zero
// guard word, so that the n bits of dense·X^p are D[n-p .. 2n-p).
func window(dense []uint64, n int) []uint64 {
	nw := words(n)
	d := make([]uint64, words(2*n)+1)
	copy(d, dense[:nw])
	maskTop(d[:nw], n)
	ws, bs := n/64, uint(n%64)
	// Descending order: the second copy overlaps the first copy's top word.
	for i := nw - 1; i >= 0; i-- {
		x := d[i]
		d[ws+i] |= x << bs
		if bs != 0 {
			d[ws+i+1] |= x >> (64 - bs)
		}
	}
	return d
}

// mulWindowAcc computes acc ^= dense·sparse (before reduction of the
// padding bits) where d = window(dense, n) and pos lists the set bits of
// sparse, all in [0, n). The work per position is independent of its value.
func mulWindowAcc(acc, d []uint64, pos []int, n int) {
	nw := len(acc)
	for _, p := range pos {
		o := n - p // 1..n
		lo := uint(o) & 63
		s := d[o>>6 : o>>6+nw+1]
		xorShifted(acc, s, lo)
	}
}

// xorShifted computes a[i] ^= (s[i] >> lo) | (s[i+1] << (64-lo)) for every
// i < len(a), where len(s) = len(a)+1 and lo < 64; lo = 0 contributes s[i]
// only. Written as a leaf loop over equal-length slices so that the
// compiler keeps everything in registers and drops the bounds checks.
func xorShifted(a, s []uint64, lo uint) {
	lo &= 63
	hi := (63 - lo) & 63
	s0 := s[:len(a)]
	s1 := s[1 : len(a)+1]
	i := 0
	for ; i+4 <= len(a); i += 4 {
		a[i] ^= s0[i]>>lo | (s1[i]<<1)<<hi
		a[i+1] ^= s0[i+1]>>lo | (s1[i+1]<<1)<<hi
		a[i+2] ^= s0[i+2]>>lo | (s1[i+2]<<1)<<hi
		a[i+3] ^= s0[i+3]>>lo | (s1[i+3]<<1)<<hi
	}
	for ; i < len(a); i++ {
		a[i] ^= s0[i]>>lo | (s1[i]<<1)<<hi
	}
}

// mulSparse computes dense · sparse in F_2[X]/(X^n - 1), where sparse is
// given by its set bit positions (each in [0, n)). The result is canonical.
func mulSparse(dense []uint64, sparsePos []int, n int) []uint64 {
	d := window(dense, n)
	acc := make([]uint64, words(n))
	mulWindowAcc(acc, d, sparsePos, n)
	maskTop(acc, n)
	return acc
}

// mulSparse2 computes (a·sparse, b·sparse) in one fused pass over the
// sparse positions (both windows stay hot in cache).
func mulSparse2(a, b []uint64, sparsePos []int, n int) ([]uint64, []uint64) {
	da, db := window(a, n), window(b, n)
	ra, rb := make([]uint64, words(n)), make([]uint64, words(n))
	nw := len(ra)
	for _, p := range sparsePos {
		o := n - p // 1..n
		lo := uint(o) & 63
		xorShifted(ra, da[o>>6:o>>6+nw+1], lo)
		xorShifted(rb, db[o>>6:o>>6+nw+1], lo)
	}
	maskTop(ra, n)
	maskTop(rb, n)
	return ra, rb
}

// sampleUniform derives an nbits-bit uniform canonical vector from seed.
func sampleUniform(seed []byte, nbits int) []uint64 {
	nw := words(nbits)
	buf := make([]byte, nw*8)
	h := sha3.NewSHAKE256()
	_, _ = h.Write(seed)
	_, _ = h.Read(buf)
	v := make([]uint64, nw)
	for i := range v {
		v[i] = binary.LittleEndian.Uint64(buf[i*8:])
	}
	maskTop(v, nbits)
	return v
}

// ctEqInt returns -1 if a == b and 0 otherwise, without branching (a and b
// must be non-negative).
func ctEqInt(a, b int) int { return -int((uint64(a^b) - 1) >> 63) }

// ctGtInt returns -1 if a > b and 0 otherwise, without branching (a and b
// must be non-negative and below 2^30).
func ctGtInt(a, b int) int { return -int(uint64(int64(b-a)) >> 63) }

// sampleFixedWeight derives an nbits-bit canonical vector of Hamming weight
// w from seed. See sampleFixedWeightPos.
func sampleFixedWeight(seed []byte, nbits, w int) []uint64 {
	v, pos := sampleFixedWeightPos(seed, nbits, w)
	zeroInts(pos)
	return v
}

// sampleFixedWeightPos derives an nbits-bit canonical vector of Hamming
// weight w from seed and also returns its w positions (unsorted).
//
// The sampler is constant-time with respect to the seed: it reads exactly
// 8·w bytes from SHAKE256(seed), maps the i-th 64-bit word x_i to
// i + ⌊x_i·(nbits−i)/2^64⌋ with a multiply (bias below 2^-48, no division),
// removes collisions with Sendrier's constant-time Fisher-Yates variant
// (for i = w−1 down to 0, position i is replaced by i when it equals a
// later position, which yields a uniformly random w-subset), and scatters
// the positions into the bit vector by touching every word for every
// position. Neither the control flow nor the memory addresses depend on
// the seed.
func sampleFixedWeightPos(seed []byte, nbits, w int) ([]uint64, []int) {
	v := make([]uint64, words(nbits))
	pos := make([]int, w)
	h := sha3.NewSHAKE256()
	_, _ = h.Write(seed)
	buf := make([]byte, 8*w)
	_, _ = h.Read(buf)
	h.Reset()
	for i := range pos {
		x := binary.LittleEndian.Uint64(buf[8*i:])
		hi, _ := bits.Mul64(x, uint64(nbits-i))
		pos[i] = i + int(hi)
	}
	clear(buf)
	for i := w - 1; i >= 0; i-- {
		found := 0
		pi := pos[i]
		for _, pj := range pos[i+1:] {
			found |= ctEqInt(pj, pi)
		}
		pos[i] = (found & i) | (^found & pi)
	}
	for _, p := range pos {
		wi := p >> 6
		bit := uint64(1) << (uint(p) & 63)
		for k := range v {
			v[k] |= uint64(int64(ctEqInt(k, wi))) & bit
		}
	}
	return v, pos
}

// ctSortInts sorts a (non-negative entries below 2^30) in place with a
// bitonic sorting network: the sequence of compare-exchange operations and
// the memory accesses depend only on len(a), not on the values.
func ctSortInts(a []int) {
	n := len(a)
	m := 1
	for m < n {
		m <<= 1
	}
	b := make([]int, m)
	copy(b, a)
	for i := n; i < m; i++ {
		b[i] = 1 << 30 // sentinel above every valid position (N < 2^30)
	}
	for k := 2; k <= m; k <<= 1 {
		for j := k >> 1; j > 0; j >>= 1 {
			for i := 0; i < m; i++ {
				l := i ^ j
				if l <= i {
					continue // depends only on the indices
				}
				x, y := b[i], b[l]
				var swap int
				if i&k == 0 {
					swap = ctGtInt(x, y) // ascending run
				} else {
					swap = ctGtInt(y, x) // descending run
				}
				d := swap & (x ^ y)
				b[i], b[l] = x^d, y^d
			}
		}
	}
	copy(a, b[:n])
	zeroInts(b)
}

// weight returns the Hamming weight of v.
func weight(v []uint64) int {
	n := 0
	for _, w := range v {
		n += bits.OnesCount64(w)
	}
	return n
}

// bitsToBytes serializes the low nbits bits of v (little-endian), clearing
// any padding bits. A vector shorter than nbits is zero-padded so that
// malformed inputs serialize without panicking.
func bitsToBytes(v []uint64, nbits int) []byte {
	nb := (nbits + 7) / 8
	size := len(v) * 8
	if size < nb {
		size = nb
	}
	out := make([]byte, size)
	for i, w := range v {
		binary.LittleEndian.PutUint64(out[i*8:], w)
	}
	// Clear the padding bits of the last byte so that the output is always
	// canonical (bytesToBits rejects non-zero padding).
	if nbits%8 != 0 && nb > 0 {
		out[nb-1] &= byte(1<<(uint(nbits)%8)) - 1
	}
	return out[:nb]
}

// bytesToBits parses an nbits-bit vector; padding bits must be zero.
func bytesToBits(data []byte, nbits int) ([]uint64, error) {
	nb := (nbits + 7) / 8
	if len(data) != nb {
		return nil, errors.New("bit vector has wrong length")
	}
	buf := make([]byte, words(nbits)*8)
	copy(buf, data)
	v := make([]uint64, words(nbits))
	for i := range v {
		v[i] = binary.LittleEndian.Uint64(buf[i*8:])
	}
	if !isCanonical(v, nbits) {
		return nil, errors.New("bit vector has non-zero padding")
	}
	return v, nil
}
