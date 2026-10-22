package qcsd

// Arithmetic in GF(2^8) with the primitive polynomial x^8 + x^4 + x^3 + x^2 + 1
// (0x11D), as used by HQC's Reed-Solomon code.
//
// Every operation that can touch secret data is branch-free and table-free:
// products are computed bit-serially with masks, eight independent field
// elements at a time packed in the byte lanes of a uint64 ("lanes"). The only
// table, gfExp, is indexed by public exponents when building the public
// Reed-Solomon tables.

const (
	gfPoly  = 0x11D
	lanes01 = 0x0101010101010101
	lanes7f = 0x7F7F7F7F7F7F7F7F
	lanes80 = 0x8080808080808080
)

// gfExp[i] = α^i for 0 <= i < 255 with α = x. Public data only.
var gfExp [255]byte

func init() {
	x := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(x)
		x <<= 1
		if x&0x100 != 0 {
			x ^= gfPoly
		}
	}
}

// gfPow returns α^e for any integer e (public exponents only).
func gfPow(e int) byte {
	e %= 255
	if e < 0 {
		e += 255
	}
	return gfExp[e]
}

// xtime8 multiplies each byte lane of a by α.
func xtime8(a uint64) uint64 {
	return (a&lanes7f)<<1 ^ ((a>>7)&lanes01)*(gfPoly&0xFF)
}

// gfMul8 multiplies the byte lanes of a and b pairwise.
func gfMul8(a, b uint64) uint64 {
	var r uint64
	for k := 0; k < 8; k++ {
		r ^= a & (((b >> uint(k)) & lanes01) * 0xFF)
		a = xtime8(a)
	}
	return r
}

// gfSqr8 squares each byte lane of a.
func gfSqr8(a uint64) uint64 { return gfMul8(a, a) }

// gfInv8 inverts each byte lane of a as a^254 (0 maps to 0).
func gfInv8(a uint64) uint64 {
	a2 := gfSqr8(a)
	r := gfMul8(a2, a)       // a^3
	r = gfMul8(gfSqr8(r), a) // a^7
	r = gfMul8(gfSqr8(r), a) // a^15
	r = gfMul8(gfSqr8(r), a) // a^31
	r = gfMul8(gfSqr8(r), a) // a^63
	r = gfMul8(gfSqr8(r), a) // a^127
	return gfSqr8(r)         // a^254
}

// gfMul multiplies two field elements (branch-free).
func gfMul(a, b byte) byte { return byte(gfMul8(uint64(a), uint64(b))) }

// gfInv returns the inverse of a (0 maps to 0), branch-free.
func gfInv(a byte) byte { return byte(gfInv8(uint64(a))) }

// zeroLanes returns 0xFF in every byte lane of x that is zero and 0x00 in
// every other lane.
func zeroLanes(x uint64) uint64 {
	t := ^(((x & lanes7f) + lanes7f) | x) & lanes80
	return (t >> 7) * 0xFF
}

// foldLanes returns the XOR of the eight byte lanes of x.
func foldLanes(x uint64) byte {
	x ^= x >> 32
	x ^= x >> 16
	x ^= x >> 8
	return byte(x)
}

// laneWords returns the number of uint64 words holding n byte lanes.
func laneWords(n int) int { return (n + 7) / 8 }

// getLane returns byte lane j of the packed vector v.
func getLane(v []uint64, j int) byte { return byte(v[j>>3] >> (uint(j&7) * 8)) }

// xorLane XORs b into byte lane j of v.
func xorLane(v []uint64, j int, b byte) { v[j>>3] ^= uint64(b) << (uint(j&7) * 8) }

// packLanes packs src into the byte lanes of dst (dst must be zero beyond).
func packLanes(dst []uint64, src []byte) {
	for i := range dst {
		dst[i] = 0
	}
	for j, b := range src {
		xorLane(dst, j, b)
	}
}

// lanesUpOne multiplies the packed polynomial v by x (moves lane j to j+1);
// the top lane is dropped.
func lanesUpOne(v []uint64) {
	for i := len(v) - 1; i > 0; i-- {
		v[i] = v[i]<<8 | v[i-1]>>56
	}
	if len(v) > 0 {
		v[0] <<= 8
	}
}

// lanesDown writes src shifted down by s lanes (lane j+s moves to lane j) into dst.
func lanesDown(dst, src []uint64, s int) {
	ws, bs := s>>3, uint(s&7)*8
	for i := range dst {
		var w uint64
		if i+ws < len(src) {
			w = src[i+ws] >> bs
			if bs != 0 && i+ws+1 < len(src) {
				w |= src[i+ws+1] << (64 - bs)
			}
		}
		dst[i] = w
	}
}

// keepLanes clears every lane at index >= n.
func keepLanes(v []uint64, n int) {
	for i := range v {
		switch {
		case 8*i >= n:
			v[i] = 0
		case 8*i+8 > n:
			v[i] &= (uint64(1) << (uint(n-8*i) * 8)) - 1
		}
	}
}

// mulScalarAcc computes dst ^= c·src lane-wise for a (secret) scalar c.
func mulScalarAcc(dst, src []uint64, c byte) {
	cc := uint64(c) * lanes01
	for i := range dst {
		dst[i] ^= gfMul8(src[i], cc)
	}
}
