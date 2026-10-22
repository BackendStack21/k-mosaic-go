package uov

import "encoding/binary"

// Arithmetic in GF(2^8) with the polynomial x^8 + x^4 + x^3 + x + 1 (0x11B),
// log/exp tables built from the primitive element 3.
//
// Two representations are used:
//
//   - scalar arithmetic through the 64 KB table gfMulTab (and gfInv through the
//     log/exp tables); a lookup's address depends on both operands, so these
//     are used only where at least one operand is secret by necessity (signing)
//     or where both are public (verification);
//   - packed arithmetic on uint64 words holding 8 field elements each
//     (little-endian byte order, rows zero-padded to whole words). xtime64 is
//     branch- and table-free; nibble tables (see buildNibbleTable) multiply a
//     packed row by a scalar with two lookups whose address depends only on
//     the scalar.

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

// xtime64 multiplies each of the 8 packed field elements of x by x (i.e. 2).
func xtime64(x uint64) uint64 {
	hi := x & 0x8080808080808080
	return ((x ^ hi) << 1) ^ ((hi >> 7) * 0x1B)
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
// table-free; looking it up depends only on the scalar a.
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
// len(dst) words. Its memory access pattern does not depend on the data.
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
