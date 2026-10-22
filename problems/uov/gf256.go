package uov

import "encoding/binary"

// Arithmetic in GF(2^8) with the polynomial x^8 + x^4 + x^3 + x + 1 (0x11B),
// log/exp tables built from the primitive element 3.
//
// Three families of routines are used:
//
//   - table arithmetic: gfMul through the 64 KB table gfMulTab and gfInv
//     through the log/exp tables. A lookup's address depends on the operands,
//     so these are used ONLY where every operand is public (verification
//     and tests);
//   - constant-time scalar arithmetic: gfMulCT (bit-serial with masks) and
//     gfInvCT (a fixed addition chain for a^254 built from gfMulCT);
//   - constant-time packed arithmetic on uint64 words holding 8 field
//     elements each (little-endian byte order, rows zero-padded to whole
//     words), in the style of gf256v_mul_u64 of the UOV reference
//     implementation: xtime64 doubles 8 elements with shifts, xors and
//     constant masks; gfMulU64, mulAddVec, mulAddVec64, accumPlanes and the
//     doubling tables (buildPowTable/mulAddPow/outerAddPow) multiply by a
//     scalar through masks derived from its bits, so neither control flow
//     nor any address depends on the scalar or the vector.
//
// Nibble tables (buildNibbleTable/mulRowInto) are indexed by the scalar; they
// are used only with public scalars (the P1 coefficients in key generation),
// where their contents may be secret but the addresses are public.

const gfPoly = 0x11B

var (
	gfExp    [512]byte
	gfLog    [256]byte
	gfMulTab [256][256]byte
)

func init() {
	// 3 = x + 1 is a primitive element modulo 0x11B (2 is not: its order is 51).
	x := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(x)
		gfLog[x] = byte(i)
		x = x ^ (x << 1) // multiply by 3
		if x&0x100 != 0 {
			x ^= gfPoly
		}
	}
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			if a == 0 || b == 0 {
				gfMulTab[a][b] = 0
			} else {
				gfMulTab[a][b] = gfExp[int(gfLog[a])+int(gfLog[b])]
			}
		}
	}
}

func gfMul(a, b byte) byte { return gfMulTab[a][b] }

func gfInv(a byte) byte {
	if a == 0 {
		return 0
	}
	return gfExp[255-int(gfLog[a])]
}

// words returns the number of uint64 words holding n packed field elements.
func words(n int) int { return (n + 7) / 8 }

// xtime64 multiplies each of the 8 packed field elements of x by x (i.e. 2):
// shift every byte left and reduce the bytes whose top bit was set by 0x1B.
// The reduction h·0x1B (h a byte-wise 0/1 vector) is spelled with shifts
// (0x1B = 1+2+8+16; no carry crosses a byte) so that no multiply instruction,
// whose latency is operand-dependent on some old CPUs, touches secret data.
func xtime64(x uint64) uint64 {
	hi := x & 0x8080808080808080
	h := hi >> 7
	return ((x ^ hi) << 1) ^ h ^ (h << 1) ^ (h << 3) ^ (h << 4)
}

// isZeroMask returns all ones if b == 0 and zero otherwise, without branches:
// uint64(b)-1 has its top bit set exactly when it wraps around.
func isZeroMask(b byte) uint64 { return -((uint64(b) - 1) >> 63) }

// gfMulCT multiplies a and b bit by bit with masks. Its control flow and
// memory accesses do not depend on a or b.
func gfMulCT(a, b byte) byte {
	x, y := uint32(a), uint32(b)
	var r uint32
	for i := 0; i < 8; i++ {
		r ^= x & -(y >> i & 1)
		x = (x << 1) ^ (0x11B & -(x >> 7 & 1))
	}
	return byte(r)
}

// gfInvCT returns a^254, the inverse of a (0 for a = 0), through a fixed
// addition chain of 7 squarings and 4 multiplications with gfMulCT.
func gfInvCT(a byte) byte {
	a2 := gfMulCT(a, a)
	a3 := gfMulCT(a2, a)
	a6 := gfMulCT(a3, a3)
	a12 := gfMulCT(a6, a6)
	a15 := gfMulCT(a12, a3)
	a30 := gfMulCT(a15, a15)
	a60 := gfMulCT(a30, a30)
	a120 := gfMulCT(a60, a60)
	a240 := gfMulCT(a120, a120)
	a252 := gfMulCT(a240, a12)
	return gfMulCT(a252, a2)
}

// scalarMasks returns, for j = 0..7, all ones if bit j of c is set and zero
// otherwise.
func scalarMasks(c byte) (m0, m1, m2, m3, m4, m5, m6, m7 uint64) {
	x := uint64(c)
	return -(x & 1), -(x >> 1 & 1), -(x >> 2 & 1), -(x >> 3 & 1),
		-(x >> 4 & 1), -(x >> 5 & 1), -(x >> 6 & 1), -(x >> 7 & 1)
}

// gfMulU64 multiplies the 8 field elements packed in x by the scalar c
// (gf256v_mul_u64 of the UOV reference implementation).
func gfMulU64(x uint64, c byte) uint64 {
	m0, m1, m2, m3, m4, m5, m6, m7 := scalarMasks(c)
	r := x & m0
	x = xtime64(x)
	r ^= x & m1
	x = xtime64(x)
	r ^= x & m2
	x = xtime64(x)
	r ^= x & m3
	x = xtime64(x)
	r ^= x & m4
	x = xtime64(x)
	r ^= x & m5
	x = xtime64(x)
	r ^= x & m6
	x = xtime64(x)
	return r ^ (x & m7)
}

// mulAddVec computes dst ^= c·src on the first len(src) bytes of dst, eight
// bytes at a time with a packed tail. len(dst) must be at least len(src).
func mulAddVec(dst, src []byte, c byte) {
	dst = dst[:len(src)]
	full := len(src) &^ 7
	for k := 0; k < full; k += 8 {
		d := binary.LittleEndian.Uint64(dst[k:])
		binary.LittleEndian.PutUint64(dst[k:], d^gfMulU64(binary.LittleEndian.Uint64(src[k:]), c))
	}
	if full < len(src) {
		var x uint64
		for j, b := range src[full:] {
			x |= uint64(b) << (8 * j)
		}
		x = gfMulU64(x, c)
		for j := range dst[full:] {
			dst[full+j] ^= byte(x >> (8 * j))
		}
	}
}

// mulAddVec64 computes dst ^= c·src on packed words.
func mulAddVec64(dst, src []uint64, c byte) {
	src = src[:len(dst)]
	for k := range dst {
		dst[k] ^= gfMulU64(src[k], c)
	}
}

// buildPowTable fills t (8 rows of len(row) words) with t[j] = x^j·row, the
// successive doublings of row, so that c·row = Σ_j bit_j(c)·t[j]. Building
// the table involves no data-dependent branch or address.
func buildPowTable(t []uint64, row []uint64) {
	w := len(row)
	t = t[:8*w]
	copy(t, row)
	for j := 1; j < 8; j++ {
		prev, cur := t[(j-1)*w:j*w], t[j*w:(j+1)*w]
		for k := range cur {
			cur[k] = xtime64(prev[k])
		}
	}
}

// mulAddPow computes dst ^= c·row from the doubling table t of row. Every row
// of the table is read for every scalar; the scalar only selects through
// masks.
func mulAddPow(dst, t []uint64, c byte) {
	w := len(dst)
	m0, m1, m2, m3, m4, m5, m6, m7 := scalarMasks(c)
	t0, t1, t2, t3 := t[0:w], t[w:2*w], t[2*w:3*w], t[3*w:4*w]
	t4, t5, t6, t7 := t[4*w:5*w], t[5*w:6*w], t[6*w:7*w], t[7*w:8*w]
	for k := range dst {
		dst[k] ^= (t0[k] & m0) ^ (t1[k] & m1) ^ (t2[k] & m2) ^ (t3[k] & m3) ^
			(t4[k] & m4) ^ (t5[k] & m5) ^ (t6[k] & m6) ^ (t7[k] & m7)
	}
}

// outerAddPow computes, for b < len(dst)/w with w = len(t)/8, dst[b] ^=
// q_b·row, where t is the doubling table of row and q_b is packed element b
// of q: the rank-one update dst += q ⊗ row with masked products only (the
// same operation as calling mulAddPow per b, with the table slicing hoisted).
func outerAddPow(dst, t, q []uint64) {
	w := len(t) / 8
	t0, t1, t2, t3 := t[0:w], t[w:2*w], t[2*w:3*w], t[3*w:4*w]
	t4, t5, t6, t7 := t[4*w:5*w], t[5*w:6*w], t[6*w:7*w], t[7*w:8*w]
	for b := 0; b < len(dst)/w; b++ {
		m0, m1, m2, m3, m4, m5, m6, m7 := scalarMasks(byte(q[b>>3] >> (8 * (b & 7))))
		d := dst[b*w : (b+1)*w]
		for k := range d {
			d[k] ^= (t0[k] & m0) ^ (t1[k] & m1) ^ (t2[k] & m2) ^ (t3[k] & m3) ^
				(t4[k] & m4) ^ (t5[k] & m5) ^ (t6[k] & m6) ^ (t7[k] & m7)
		}
	}
}

// accumPlanes adds c·vec lazily into 8 bit planes: plane j (len(planes)/8
// words) gains vec masked by bit j of c. hornerPlanes later returns
// Σ_j x^j·plane_j, i.e. the sum of all c·vec accumulated. vec holds
// 8·len(planes)/8 bytes.
func accumPlanes(planes []uint64, vec []byte, c byte) {
	w := len(planes) / 8
	m0, m1, m2, m3, m4, m5, m6, m7 := scalarMasks(c)
	p0, p1, p2, p3 := planes[0:w], planes[w:2*w], planes[2*w:3*w], planes[3*w:4*w]
	p4, p5, p6, p7 := planes[4*w:5*w], planes[5*w:6*w], planes[6*w:7*w], planes[7*w:8*w]
	vec = vec[:8*w]
	for k := range p0 {
		s := binary.LittleEndian.Uint64(vec[8*k:])
		p0[k] ^= s & m0
		p1[k] ^= s & m1
		p2[k] ^= s & m2
		p3[k] ^= s & m3
		p4[k] ^= s & m4
		p5[k] ^= s & m5
		p6[k] ^= s & m6
		p7[k] ^= s & m7
	}
}

// packBytes packs src into dst (len(dst) == words(len(src))), zero-padding the
// last word.
func packBytes(dst []uint64, src []byte) {
	full := len(src) / 8
	for k := 0; k < full; k++ {
		dst[k] = binary.LittleEndian.Uint64(src[8*k:])
	}
	if full < len(dst) {
		var x uint64
		for j, b := range src[8*full:] {
			x |= uint64(b) << (8 * j)
		}
		dst[full] = x
	}
}

// unpackBytes writes the first len(dst) packed elements of src to dst.
func unpackBytes(dst []byte, src []uint64) {
	full := len(dst) / 8
	for k := 0; k < full; k++ {
		binary.LittleEndian.PutUint64(dst[8*k:], src[k])
	}
	for j := 8 * full; j < len(dst); j++ {
		dst[j] = byte(src[j>>3] >> (8 * (j & 7)))
	}
}

// buildNibbleTable fills t (32 rows of len(row) words) with the multiples of
// the packed row: t[k] = k·row and t[16+k] = (k<<4)·row for k < 16, so that
// a·row = t[a&15] ^ t[16+(a>>4)]. Building the table is branch- and
// table-free; looking it up depends on the scalar a, so mulRowInto must only
// be called with public scalars.
func buildNibbleTable(t []uint64, row []uint64) {
	w := len(row)
	t = t[:32*w]
	clear(t[:w])
	clear(t[16*w : 17*w])
	copy(t[w:2*w], row)
	// Powers x^j·row for j = 1..7 into slots 2, 4, 8, 16+1, 16+2, 16+4, 16+8.
	slots := [8]int{1, 2, 4, 8, 17, 18, 20, 24}
	for j := 1; j < 8; j++ {
		prev := t[slots[j-1]*w : slots[j-1]*w+w]
		cur := t[slots[j]*w : slots[j]*w+w]
		for k := range cur {
			cur[k] = xtime64(prev[k])
		}
	}
	for _, base := range [2]int{0, 16} {
		for k := 3; k < 16; k++ {
			if k&(k-1) == 0 {
				continue
			}
			low := k & -k
			dst := t[(base+k)*w : (base+k)*w+w]
			a := t[(base+k-low)*w : (base+k-low)*w+w]
			b := t[(base+low)*w : (base+low)*w+w]
			for i := range dst {
				dst[i] = a[i] ^ b[i]
			}
		}
	}
}

// mulRowInto computes dst ^= a·row from a nibble table of row.
func mulRowInto(dst []uint64, t []uint64, a byte) {
	w := len(dst)
	lo := int(a&15) * w
	hi := (16 + int(a>>4)) * w
	tl := t[lo : lo+w]
	th := t[hi : hi+w]
	for k := range dst {
		dst[k] ^= tl[k] ^ th[k]
	}
}

// hornerPlanes sets dst = Σ_j x^j·planes[j], where planes holds 8 packed
// vectors of len(dst) words.
func hornerPlanes(dst []uint64, planes []uint64) {
	w := len(dst)
	copy(dst, planes[7*w:8*w])
	for j := 6; j >= 0; j-- {
		p := planes[j*w : (j+1)*w]
		for k := range dst {
			dst[k] = xtime64(dst[k]) ^ p[k]
		}
	}
}

// combineBuckets sets dst = Σ_b b·acc[b] for 256 packed buckets acc[b] of
// len(dst) words. Its memory access pattern does not depend on the data (the
// bucket indices themselves, in evalBuckets, do; see there).
func combineBuckets(dst []uint64, acc []uint64) {
	w := len(dst)
	clear(dst)
	for j := 7; j >= 0; j-- {
		for k := range dst {
			dst[k] = xtime64(dst[k])
		}
		for b := 1; b < 256; b++ {
			if (b>>j)&1 == 0 {
				continue
			}
			a := acc[b*w : b*w+w]
			for k := range dst {
				dst[k] ^= a[k]
			}
		}
	}
}
