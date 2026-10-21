package qcsd

import (
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/sha3"
)

// Bit vectors over F_2 stored little-endian in uint64 words. A vector of n
// bits is an element of F_2[X]/(X^n - 1) with bit i the coefficient of X^i.

func words(nbits int) int { return (nbits + 63) / 64 }

func setBit(v []uint64, i int)      { v[i>>6] |= 1 << (uint(i) & 63) }
func getBit(v []uint64, i int) bool { return v[i>>6]>>(uint(i)&63)&1 == 1 }

// maskTop clears every bit at index >= nbits.
func maskTop(v []uint64, nbits int) {
	if nbits%64 != 0 {
		v[len(v)-1] &= (1 << (uint(nbits) % 64)) - 1
	}
}

// xorInto computes dst ^= src.
func xorInto(dst, src []uint64) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

// shiftLeft returns src << s truncated to nbits (bits that would pass nbits are dropped).
func shiftLeft(src []uint64, s, nbits int) []uint64 {
	nw := len(src)
	dst := make([]uint64, nw)
	ws, bs := s/64, uint(s%64)
	for i := nw - 1; i >= ws; i-- {
		dst[i] = src[i-ws] << bs
		if bs != 0 && i-ws-1 >= 0 {
			dst[i] |= src[i-ws-1] >> (64 - bs)
		}
	}
	maskTop(dst, nbits)
	return dst
}

// shiftRight returns src >> s.
func shiftRight(src []uint64, s int) []uint64 {
	nw := len(src)
	dst := make([]uint64, nw)
	ws, bs := s/64, uint(s%64)
	for i := 0; i+ws < nw; i++ {
		dst[i] = src[i+ws] >> bs
		if bs != 0 && i+ws+1 < nw {
			dst[i] |= src[i+ws+1] << (64 - bs)
		}
	}
	return dst
}

// rotate returns src · X^s in F_2[X]/(X^nbits - 1): bit i moves to (i+s) mod nbits.
func rotate(src []uint64, s, nbits int) []uint64 {
	s %= nbits
	if s == 0 {
		return append([]uint64{}, src...)
	}
	lo := shiftLeft(src, s, nbits)
	hi := shiftRight(src, nbits-s)
	xorInto(lo, hi)
	return lo
}

// positions lists the set bits of v below nbits.
func positions(v []uint64, nbits int) []int {
	var out []int
	for w, word := range v {
		for word != 0 {
			b := word & -word
			i := w*64 + bitIndex(b)
			if i < nbits {
				out = append(out, i)
			}
			word ^= b
		}
	}
	return out
}

func bitIndex(b uint64) int {
	n := 0
	for b > 1 {
		b >>= 1
		n++
	}
	return n
}

// mulSparse computes dense · sparse where sparse is given by its set bit positions.
func mulSparse(dense []uint64, sparsePos []int, nbits int) []uint64 {
	acc := make([]uint64, len(dense))
	for _, p := range sparsePos {
		xorInto(acc, rotate(dense, p, nbits))
	}
	return acc
}

// sampleUniform derives an nbits-bit uniform vector from seed.
func sampleUniform(seed []byte, nbits int) []uint64 {
	nw := words(nbits)
	buf := make([]byte, nw*8)
	h := sha3.NewShake256()
	h.Write(seed)
	_, _ = h.Read(buf)
	v := make([]uint64, nw)
	for i := range v {
		v[i] = binary.LittleEndian.Uint64(buf[i*8:])
	}
	maskTop(v, nbits)
	return v
}

// sampleFixedWeight derives an nbits-bit vector of Hamming weight w from
// seed, choosing distinct positions by rejection sampling (no modulo bias).
func sampleFixedWeight(seed []byte, nbits, w int) []uint64 {
	v := make([]uint64, words(nbits))
	limit := (uint64(1) << 32) / uint64(nbits) * uint64(nbits)
	h := sha3.NewShake256()
	h.Write(seed)
	buf := make([]byte, 4*64)
	count := 0
	for count < w {
		_, _ = h.Read(buf)
		for off := 0; off+4 <= len(buf) && count < w; off += 4 {
			x := uint64(binary.LittleEndian.Uint32(buf[off:]))
			if x >= limit {
				continue
			}
			p := int(x % uint64(nbits))
			if !getBit(v, p) {
				setBit(v, p)
				count++
			}
		}
	}
	return v
}

// weight returns the Hamming weight of v.
func weight(v []uint64) int {
	n := 0
	for _, w := range v {
		for w != 0 {
			w &= w - 1
			n++
		}
	}
	return n
}

// bitsToBytes serializes the low nbits bits of v (little-endian). A vector
// shorter than nbits is zero-padded so that malformed inputs serialize
// without panicking.
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
	check := append([]uint64{}, v...)
	maskTop(check, nbits)
	for i := range v {
		if v[i] != check[i] {
			return nil, errors.New("bit vector has non-zero padding")
		}
	}
	return v, nil
}
