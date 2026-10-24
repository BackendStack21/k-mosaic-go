package qcsd

// First-order Reed-Muller code RM(1,7): 128-bit codewords encoding one byte,
// duplicated `mult` times. The codeword bit at position x (0 <= x < 128) is
// a0 ⊕ ⊕_{i=1..7} a_i·x_{i-1}, where a_i are the bits of the encoded byte.
//
// Encoding and decoding are branch-free and do no secret-indexed memory
// accesses: a codeword is the masked XOR of the 8 basis codewords, and the
// decoder counts ones with SWAR bit spreading, runs a fast Hadamard
// transform and selects the peak with compare-and-select arithmetic.

// rmBasis[i] is the codeword of the byte 1<<i as two little-endian words.
var rmBasis [8][2]uint64

func init() {
	for x := 0; x < 128; x++ {
		rmBasis[0][x>>6] |= 1 << uint(x&63)
		for i := 1; i < 8; i++ {
			if x>>uint(i-1)&1 == 1 {
				rmBasis[i][x>>6] |= 1 << uint(x&63)
			}
		}
	}
}

// rmCodeword returns the 128-bit codeword of b as two words.
func rmCodeword(b byte) (uint64, uint64) {
	var c0, c1 uint64
	for i := 0; i < 8; i++ {
		m := bitMask(b, i)
		c0 ^= rmBasis[i][0] & m
		c1 ^= rmBasis[i][1] & m
	}
	return c0, c1
}

// rmEncodeByte writes the 128*mult codeword bits of b into dst starting at
// word index w (codewords are word aligned).
func rmEncodeByte(dst []uint64, w int, b byte, mult int) {
	c0, c1 := rmCodeword(b)
	d := dst[w : w+2*mult]
	for rep := 0; rep < mult; rep++ {
		d[2*rep] = c0
		d[2*rep+1] = c1
	}
}

// spreadBits returns the 8 bits of b in the 8 byte lanes of a word (lane j
// holds bit j as 0 or 1).
func spreadBits(b uint64) uint64 {
	x := (b & 0xFF) * lanes01 & 0x8040201008040201
	return ((x + lanes7f) & lanes80) >> 7
}

// rmDecodeByte decodes the 128*mult bits of src starting at word index w
// into the most likely byte.
func rmDecodeByte(src []uint64, w int, mult int) byte {
	// cnt[g] lane j counts the ones at position 8g+j over the repetitions
	// (mult <= 170 by checkParams, so a byte lane cannot overflow).
	var cnt [16]uint64
	s := src[w : w+2*mult]
	for rep := 0; rep < mult; rep++ {
		w0, w1 := s[2*rep], s[2*rep+1]
		for g := 0; g < 8; g++ {
			cnt[g] += spreadBits(w0 >> uint(8*g))
			cnt[8+g] += spreadBits(w1 >> uint(8*g))
		}
	}
	var soft [128]int32
	m := int32(mult)
	for g := 0; g < 16; g++ {
		c := cnt[g]
		o := soft[8*g : 8*g+8]
		for j := range o {
			o[j] = m - 2*int32(c>>uint(8*j)&0xFF) // positive when mostly 0
		}
	}
	// Fast Walsh-Hadamard transform: T[y] = Σ_x soft[x]·(-1)^{<x,y>}.
	for step := 1; step < 128; step <<= 1 {
		for i := 0; i < 128; i += 2 * step {
			lo := soft[i : i+step]
			hi := soft[i+step : i+2*step]
			hi = hi[:len(lo)]
			for j := range lo {
				a, b := lo[j], hi[j]
				lo[j], hi[j] = a+b, a-b
			}
		}
	}
	// Branch-free argmax of |T[y]| (first maximum wins).
	best, bestAbs, bestVal := int32(0), int32(-1), int32(0)
	for y := int32(0); y < 128; y++ {
		v := soft[y]
		sg := v >> 31
		a := (v ^ sg) - sg
		gt := (bestAbs - a) >> 31 // -1 iff a > bestAbs
		best ^= gt & (y ^ best)
		bestAbs ^= gt & (a ^ bestAbs)
		bestVal ^= gt & (v ^ bestVal)
	}
	a0 := byte(uint32(bestVal) >> 31)
	clear(cnt[:])
	clear(soft[:])
	return a0 | byte(best)<<1
}
