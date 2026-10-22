package qcsd

import (
	"math/bits"
	"sync"
)

// Reed-Solomon [n1, k] code over GF(2^8) with 2δ = n1 - k parity symbols.
// Codewords are polynomials c(x) = Σ c_i x^i of degree < n1; the message
// occupies the coefficients of degree >= 2δ and the parity the low degrees.
//
// The decoder follows the structure of HQC's constant-time reference
// decoder: all 2δ syndromes are always computed, Berlekamp-Massey runs a
// fixed 2δ iterations on fixed-size arrays updated through masks, the error
// locator, its derivative and the error evaluator are evaluated at all n1
// positions, Forney's formula is applied at every position and corrections
// are applied under masks. Every loop bound and memory address depends only
// on (n1, δ); field elements are kept eight to a word ("lanes", see gf256.go).

const (
	maxN1 = 255
	maxLW = (maxN1 + 1 + 7) / 8 // lane words for up to 256 symbols
)

// rsTables holds public precomputed data for one (n1, δ).
type rsTables struct {
	n1, delta int
	sw, ew    int         // lane words of a syndrome vector (2δ) and an evaluation vector (n1)
	gen       [8][]uint64 // gen[k] lane j = α^k·g_j, j < 2δ
	syn       []uint64    // row (i*8+k): lane j = α^k·α^{i(j+1)}, i < n1, j < 2δ
	eval      []uint64    // row (d*8+k): lane i = α^k·α^{-id}, d <= δ, i < n1
	posMask   []uint64    // 0xFF in lanes i < n1
}

var (
	rsCacheMu sync.Mutex
	rsCache   = map[[2]int]*rsTables{}
)

// rsGenerator returns the generator polynomial g(x) = Π_{i=1}^{2δ} (x - α^i),
// coefficients in increasing degree, g[2δ] = 1. Public data.
func rsGenerator(delta int) []byte {
	g := []byte{1}
	for i := 1; i <= 2*delta; i++ {
		root := gfPow(i)
		next := make([]byte, len(g)+1)
		for j, c := range g {
			next[j+1] ^= c
			next[j] ^= gfMul(c, root)
		}
		g = next
	}
	return g
}

// getRSTables returns the (cached) public tables for (n1, δ).
func getRSTables(n1, delta int) *rsTables {
	rsCacheMu.Lock()
	defer rsCacheMu.Unlock()
	key := [2]int{n1, delta}
	if t, ok := rsCache[key]; ok {
		return t
	}
	t2 := 2 * delta
	t := &rsTables{n1: n1, delta: delta, sw: laneWords(t2), ew: laneWords(n1)}
	g := rsGenerator(delta)
	for k := 0; k < 8; k++ {
		t.gen[k] = make([]uint64, t.sw)
		for j := 0; j < t2; j++ {
			xorLane(t.gen[k], j, gfMul(g[j], gfPow(k)))
		}
	}
	t.syn = make([]uint64, n1*8*t.sw)
	for i := 0; i < n1; i++ {
		for k := 0; k < 8; k++ {
			row := t.syn[(i*8+k)*t.sw:][:t.sw]
			for j := 0; j < t2; j++ {
				xorLane(row, j, gfPow(k+i*(j+1)))
			}
		}
	}
	t.eval = make([]uint64, (delta+1)*8*t.ew)
	for d := 0; d <= delta; d++ {
		for k := 0; k < 8; k++ {
			row := t.eval[(d*8+k)*t.ew:][:t.ew]
			for i := 0; i < n1; i++ {
				xorLane(row, i, gfPow(k-i*d))
			}
		}
	}
	t.posMask = make([]uint64, t.ew)
	for i := 0; i < n1; i++ {
		xorLane(t.posMask, i, 0xFF)
	}
	rsCache[key] = t
	return t
}

// bitMask returns all-ones if bit k of c is set and zero otherwise.
func bitMask(c byte, k int) uint64 { return -(uint64(c>>uint(k)) & 1) }

// rsEncodeInto writes the n1-symbol systematic codeword of the k-symbol
// message msg into cw (branch-free in the message).
func rsEncodeInto(cw, msg []byte, n1, delta int) {
	t := getRSTables(n1, delta)
	t2 := 2 * delta
	k := n1 - t2
	var remBuf [maxLW]uint64
	rem := remBuf[:t.sw]
	// Remainder of m(x)·x^{2δ} modulo g(x) by synthetic division.
	for i := k - 1; i >= 0; i-- {
		coef := msg[i] ^ getLane(rem, t2-1)
		lanesUpOne(rem)
		keepLanes(rem, t2)
		for b := 0; b < 8; b++ {
			m := bitMask(coef, b)
			g := t.gen[b][:len(rem)]
			for w := range rem {
				rem[w] ^= g[w] & m
			}
		}
	}
	for j := 0; j < t2; j++ {
		cw[j] = getLane(rem, j)
	}
	copy(cw[t2:], msg[:k])
	clear(remBuf[:])
}

// rsEncode returns the n1-symbol systematic codeword of a k-symbol message.
func rsEncode(msg []byte, n1, delta int) []byte {
	cw := make([]byte, n1)
	rsEncodeInto(cw, msg, n1, delta)
	return cw
}

// rsSyndromes sets out (t.sw words) to the 2δ syndromes S_j = c(α^j),
// j = 1..2δ (lane j-1), of the packed word cw.
func rsSyndromes(out, cw []uint64, t *rsTables) {
	clear(out)
	for i := 0; i < t.n1; i++ {
		c := getLane(cw, i)
		for k := 0; k < 8; k++ {
			m := bitMask(c, k)
			row := t.syn[(i*8+k)*t.sw:][:len(out)]
			for w := range out {
				out[w] ^= row[w] & m
			}
		}
	}
}

// rsEvalAll sets out (t.ew words) to p(α^{-i}) in lane i for every
// position i < n1, where p has ncoef <= δ+1 coefficients packed in lanes.
func rsEvalAll(out, p []uint64, ncoef int, t *rsTables) {
	clear(out)
	for d := 0; d < ncoef; d++ {
		c := getLane(p, d)
		for k := 0; k < 8; k++ {
			m := bitMask(c, k)
			row := t.eval[(d*8+k)*t.ew:][:len(out)]
			for w := range out {
				out[w] ^= row[w] & m
			}
		}
	}
}

// convolveCoef returns Σ_{i=0..n} λ_i·S_{n-i} where srev holds the
// syndromes in reverse order (lane j = S_{2δ-1-j}); scratch has len(lambda) words.
func convolveCoef(lambda, srev, scratch []uint64, n, t2 int) byte {
	lanesDown(scratch, srev, t2-1-n)
	keepLanes(scratch, n+1)
	var acc uint64
	for w := 0; w < laneWords(n+1); w++ {
		acc ^= gfMul8(lambda[w], scratch[w])
	}
	return foldLanes(acc)
}

// ctMaskNonZero returns -1 if x != 0 and 0 otherwise.
func ctMaskNonZero(x int) int { return (x | -x) >> 63 }

// rsWork holds the decoder's scratch vectors so that they live on the stack
// and can be wiped with one clear.
type rsWork struct{ buf [15][maxLW]uint64 }

// rsDecodeInto decodes the n1-symbol word cw and writes its k message
// symbols to msg. It returns 1 if the word was within distance δ of a
// codeword (which is then the decoded word) and 0 otherwise; in the latter
// case msg receives the systematic symbols of cw uncorrected. The running
// time depends only on (n1, δ). cw is not modified.
func rsDecodeInto(msg, cw []byte, n1, delta int) int {
	t := getRSTables(n1, delta)
	t2 := 2 * delta
	lw := laneWords(t2 + 2) // Λ and B have degree <= 2δ

	var ws rsWork
	word, synd, srev := ws.buf[0][:], ws.buf[1][:], ws.buf[2][:]
	lambda, prev, tmp := ws.buf[3][:], ws.buf[4][:], ws.buf[5][:]
	scratch, omega, der := ws.buf[6][:], ws.buf[7][:], ws.buf[8][:]
	evL, evD, evO, corr := ws.buf[9][:], ws.buf[10][:], ws.buf[11][:], ws.buf[12][:]
	fixed, synd2 := ws.buf[13][:], ws.buf[14][:]

	packLanes(word[:t.ew], cw[:n1])

	// 1. Syndromes.
	rsSyndromes(synd[:t.sw], word[:t.ew], t)
	for j := 0; j < t2; j++ {
		xorLane(srev[:t.sw], t2-1-j, getLane(synd, j))
	}

	// 2. Berlekamp-Massey, 2δ iterations, no branch on the discrepancy.
	// prev holds x^m·B(x) (shifted at the start of each iteration).
	lambda[0], prev[0] = 1, 1
	L := 0
	b := byte(1)
	for n := 0; n < t2; n++ {
		d := convolveCoef(lambda[:lw], srev[:lw], scratch[:lw], n, t2)
		lanesUpOne(prev[:lw])
		copy(tmp[:lw], lambda[:lw])
		mulScalarAcc(lambda[:lw], prev[:lw], gfMul(d, gfInv(b)))
		// cond = -1 iff d != 0 and 2L <= n.
		cond := ctMaskNonZero(int(d)) & ((2*L - n - 1) >> 63)
		L ^= cond & ((n + 1 - L) ^ L)
		um := uint64(int64(cond))
		for w := 0; w < lw; w++ {
			prev[w] ^= um & (tmp[w] ^ prev[w])
		}
		b ^= byte(um) & (d ^ b)
	}

	// 3. Error evaluator Ω = S·Λ mod x^δ (true degree < L <= δ on success).
	for i := 0; i < delta; i++ {
		xorLane(omega, i, convolveCoef(lambda[:lw], srev[:lw], scratch[:lw], i, t2))
	}
	// Formal derivative: Λ'(x) = Σ_{d odd} λ_d x^{d-1}.
	lanesDown(der[:lw], lambda[:lw], 1)
	for w := 0; w < lw; w++ {
		der[w] &= 0x00FF00FF00FF00FF
	}

	// 4. Evaluate Λ, Λ', Ω at α^{-i} for every position (Chien search).
	ew := t.ew
	rsEvalAll(evL[:ew], lambda, delta+1, t)
	rsEvalAll(evD[:ew], der, delta, t)
	rsEvalAll(evO[:ew], omega, delta, t)

	// 5. Forney at every position, corrections under the root mask.
	roots := 0
	for w := 0; w < ew; w++ {
		r := zeroLanes(evL[w]) & t.posMask[w]
		roots += bits.OnesCount64(r) / 8
		corr[w] = gfMul8(evO[w], gfInv8(evD[w])) & r
		fixed[w] = word[w] ^ corr[w]
	}

	// 6. Accept iff L <= δ, Λ has L distinct roots among the positions and
	// the corrected word is a codeword.
	rsSyndromes(synd2[:t.sw], fixed[:ew], t)
	var nz uint64
	for w := 0; w < t.sw; w++ {
		nz |= synd2[w]
	}
	bad := ctMaskNonZero(int(nz)) | ((delta - L) >> 63) | ctMaskNonZero(roots^L)
	okMask := ^uint64(int64(bad))
	for w := 0; w < ew; w++ {
		fixed[w] = word[w] ^ (corr[w] & okMask)
	}
	for i := t2; i < n1; i++ {
		msg[i-t2] = getLane(fixed, i)
	}
	ws = rsWork{}
	return int(okMask & 1)
}

// rsDecode is a convenience wrapper around rsDecodeInto.
func rsDecode(cw []byte, n1, delta int) ([]byte, int) {
	msg := make([]byte, n1-2*delta)
	ok := rsDecodeInto(msg, cw, n1, delta)
	return msg, ok
}
