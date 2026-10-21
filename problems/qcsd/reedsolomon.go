package qcsd

import (
	"errors"
	"sync"
)

// Reed-Solomon [n1, k] code over GF(2^8) with 2δ = n1 - k parity symbols.
// Codewords are polynomials c(x) = Σ c_i x^i of degree < n1; the message
// occupies the coefficients of degree >= 2δ and the parity the low degrees.
// Decoding uses syndromes, Berlekamp-Massey, a Chien search and Forney's
// formula.

var (
	genCacheMu sync.Mutex
	genCache   = map[int][]byte{}
)

// rsGenerator returns the generator polynomial g(x) = Π_{i=1}^{2δ} (x - α^i),
// coefficients in increasing degree, g[2δ] = 1.
func rsGenerator(delta int) []byte {
	genCacheMu.Lock()
	defer genCacheMu.Unlock()
	if g, ok := genCache[delta]; ok {
		return g
	}
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
	genCache[delta] = g
	return g
}

// rsEncode returns the n1-symbol systematic codeword of a k-symbol message.
func rsEncode(msg []byte, n1, delta int) []byte {
	k := n1 - 2*delta
	g := rsGenerator(delta)
	cw := make([]byte, n1)
	copy(cw[2*delta:], msg[:k])
	// Remainder of m(x)·x^{2δ} modulo g(x) by synthetic division.
	rem := make([]byte, 2*delta)
	for i := n1 - 1; i >= 2*delta; i-- {
		coef := cw[i] ^ rem[2*delta-1]
		// shift remainder up by one degree
		copy(rem[1:], rem[:2*delta-1])
		rem[0] = 0
		if coef != 0 {
			for j := 0; j < 2*delta; j++ {
				rem[j] ^= gfMul(coef, g[j])
			}
		}
	}
	copy(cw[:2*delta], rem)
	return cw
}

// polyEval evaluates p(x) = Σ p_i x^i at x.
func polyEval(p []byte, x byte) byte {
	var acc byte
	for i := len(p) - 1; i >= 0; i-- {
		acc = gfMul(acc, x) ^ p[i]
	}
	return acc
}

// rsDecode corrects up to delta symbol errors in cw (in place) and returns
// the k-symbol message. It returns an error when the word is undecodable.
func rsDecode(cw []byte, n1, delta int) ([]byte, error) {
	if len(cw) != n1 {
		return nil, errors.New("reed-solomon: wrong length")
	}
	t2 := 2 * delta
	k := n1 - t2

	// Syndromes S_j = c(α^j), j = 1..2δ (stored at index j-1).
	synd := make([]byte, t2)
	allZero := true
	for j := 0; j < t2; j++ {
		synd[j] = polyEval(cw, gfPow(j+1))
		if synd[j] != 0 {
			allZero = false
		}
	}
	msg := make([]byte, k)
	if allZero {
		copy(msg, cw[t2:])
		return msg, nil
	}

	// Berlekamp-Massey: error locator Λ(x) with Λ(0) = 1.
	lambda := []byte{1}
	prev := []byte{1}
	L := 0
	m := 1
	var b byte = 1
	for n := 0; n < t2; n++ {
		d := synd[n]
		for i := 1; i <= L && i < len(lambda); i++ {
			d ^= gfMul(lambda[i], synd[n-i])
		}
		if d == 0 {
			m++
			continue
		}
		// lambda = lambda - (d/b) x^m prev
		scale := gfDiv(d, b)
		next := make([]byte, maxInt(len(lambda), len(prev)+m))
		copy(next, lambda)
		for i, c := range prev {
			next[i+m] ^= gfMul(scale, c)
		}
		if 2*L <= n {
			L = n + 1 - L
			prev = lambda
			b = d
			m = 1
		} else {
			m++
		}
		lambda = next
	}
	// Trim leading zeros
	for len(lambda) > 1 && lambda[len(lambda)-1] == 0 {
		lambda = lambda[:len(lambda)-1]
	}
	if len(lambda)-1 != L || L > delta {
		return nil, errors.New("reed-solomon: too many errors")
	}

	// Chien search: error at position i iff Λ(α^{-i}) = 0.
	var positions []int
	for i := 0; i < n1; i++ {
		if polyEval(lambda, gfPow(-i)) == 0 {
			positions = append(positions, i)
		}
	}
	if len(positions) != L {
		return nil, errors.New("reed-solomon: locator roots do not match degree")
	}

	// Forney: Ω(x) = S(x)Λ(x) mod x^{2δ}; e_i = Ω(X_i^{-1}) / Λ'(X_i^{-1}).
	omega := make([]byte, t2)
	for i := 0; i < t2; i++ {
		for j := 0; j < len(lambda) && i+j < t2; j++ {
			omega[i+j] ^= gfMul(synd[i], lambda[j])
		}
	}
	// Formal derivative in characteristic 2 keeps the odd-degree terms.
	deriv := make([]byte, maxInt(len(lambda)-1, 1))
	for j := 1; j < len(lambda); j += 2 {
		deriv[j-1] = lambda[j]
	}
	for _, pos := range positions {
		xinv := gfPow(-pos)
		den := polyEval(deriv, xinv)
		if den == 0 {
			return nil, errors.New("reed-solomon: zero derivative")
		}
		cw[pos] ^= gfDiv(polyEval(omega, xinv), den)
	}

	// Confirm the corrected word is a codeword.
	for j := 0; j < t2; j++ {
		if polyEval(cw, gfPow(j+1)) != 0 {
			return nil, errors.New("reed-solomon: correction failed")
		}
	}
	copy(msg, cw[t2:])
	return msg, nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
