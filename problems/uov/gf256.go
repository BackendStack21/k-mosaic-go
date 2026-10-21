package uov

// Arithmetic in GF(2^8) with the polynomial x^8 + x^4 + x^3 + x + 1 (0x11B),
// log/exp tables built from the primitive element 3.

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
