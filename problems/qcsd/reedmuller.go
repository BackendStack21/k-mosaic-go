package qcsd

// First-order Reed-Muller code RM(1,7): 128-bit codewords encoding one byte,
// duplicated `mult` times. The codeword bit at position x (0 <= x < 128) is
// a0 ⊕ ⊕_{i=1..7} a_i·x_{i-1}, where a_i are the bits of the encoded byte.

// rmEncodeByte writes the 128*mult codeword bits of b starting at bit offset
// `off` of the bit vector dst.
func rmEncodeByte(dst []uint64, off int, b byte, mult int) {
	a0 := b & 1
	lin := b >> 1
	for rep := 0; rep < mult; rep++ {
		base := off + rep*128
		for x := 0; x < 128; x++ {
			bit := a0 ^ parity8(lin&byte(x))
			if bit == 1 {
				setBit(dst, base+x)
			}
		}
	}
}

// rmDecodeByte decodes the 128*mult bits of src starting at bit `off` into
// the most likely byte, using a fast Hadamard transform over the summed
// repetitions.
func rmDecodeByte(src []uint64, off int, mult int) byte {
	var soft [128]int32
	for x := 0; x < 128; x++ {
		ones := 0
		for rep := 0; rep < mult; rep++ {
			if getBit(src, off+rep*128+x) {
				ones++
			}
		}
		soft[x] = int32(mult - 2*ones) // positive when the bit is mostly 0
	}
	// Fast Walsh-Hadamard transform: T[y] = Σ_x soft[x]·(-1)^{<x,y>}.
	for step := 1; step < 128; step <<= 1 {
		for i := 0; i < 128; i += 2 * step {
			for j := i; j < i+step; j++ {
				a, b := soft[j], soft[j+step]
				soft[j], soft[j+step] = a+b, a-b
			}
		}
	}
	best := 0
	bestAbs := int32(-1)
	for y := 0; y < 128; y++ {
		v := soft[y]
		if v < 0 {
			v = -v
		}
		if v > bestAbs {
			bestAbs = v
			best = y
		}
	}
	a0 := byte(0)
	if soft[best] < 0 {
		a0 = 1
	}
	return a0 | byte(best)<<1
}

func parity8(b byte) byte {
	b ^= b >> 4
	b ^= b >> 2
	b ^= b >> 1
	return b & 1
}
