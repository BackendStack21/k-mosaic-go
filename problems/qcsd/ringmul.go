package qcsd

import (
	"math/bits"
	"runtime"
	"sync"
)

// Sparse-dense multiplication in F_2[X]/(X^n - 1) whose memory accesses and
// control flow do not depend on the sparse operand.
//
// For a position p of the sparse operand, dense·X^p is the n-bit window of
// D = dense||dense that starts at bit o = n - p ∈ [1, n]. Writing
// o - 1 = 64·s + (lo - 1) with s ∈ [0, (n-1)>>6] and lo ∈ [1, 64], the
// window is word j of
//
//	(D[s+j] >> lo) | (D[s+j+1] << (64-lo)),   j < nw = ⌈n/64⌉.
//
// Reading D[s .. s+nw] directly (as the previous implementation did) makes
// the addresses reveal s, i.e. the position up to 64 bits: a cache-line
// granular leak of the secret support.
//
// Word offset. s is selected obliviously with a logarithmic barrel shifter:
// with K = bits.Len((n-1)>>6) stages, stage k (from k = K-1 down to 0)
// computes
//
//	out[i] = in[i] ^ (m_k & (in[i] ^ in[i + 2^k])),   m_k = -((s >> k) & 1),
//
// over every i < nw + 2^k, so that after stage 0 out[i] = D[s+i] for every
// i ≤ nw. Each stage reads and writes every word of buffers whose lengths
// depend only on n, whatever the mask. For n = 57637 that is 10 stages over
// 1413, 1157, 1029, …, 902 words.
//
// Bit offset. The shift by lo is done without shift instructions on secret
// amounts: with m = 2^(64-lo) ∈ [1, 2^63], the 128-bit product w·m has high
// half w >> lo and low half w << (64-lo), so one 64×64→128 multiply per word
// (bits.Mul64) does it; m itself is built with six multiplies by public
// constants. Stage 0 and the shift are fused into the pass that XORs the
// window into the accumulator.
//
// Parallelism. Positions are split into contiguous chunks, one per
// goroutine; the number of goroutines and the chunk boundaries depend only
// on runtime.GOMAXPROCS, n, the number of operands and the number of
// positions, never on their values. Each goroutine has its own accumulators
// and scratch buffers, XOR-reduced at the end.
//
// The secret values thus only flow into data: masks (AND/XOR) and
// multiplier operands. This assumes AND/XOR/64-bit multiplication run in
// constant time (true on amd64 and arm64; on 386 the compiler expands
// bits.Mul64 into branch-free 32-bit multiplies). Not covered: the Go
// runtime (scheduling, garbage collection) and the compiler's instruction
// selection, which the Go language does not specify.

// mulPlan holds the public dimensions of a multiplication.
type mulPlan struct {
	n, nw   int // ring length in bits and words
	stages  int // K = bits.Len((n-1)>>6): barrel shifter stages (≤ 10)
	dlen    int // length of the padded doubled vector D
	buflen  int // length of each ping-pong scratch buffer
	workers int // number of goroutines (≥ 1)
	chunk   int // positions per goroutine (the last one may get fewer)
}

// minWorkPerWorker is the number of word operations below which an extra
// goroutine costs more than it saves.
const minWorkPerWorker = 1 << 16

// newMulPlan derives the plan from public values only: n, the number of
// sparse positions, the number of dense operands and GOMAXPROCS.
func newMulPlan(n, npos, nvec int) mulPlan {
	nw := words(n)
	k := bits.Len(uint((n - 1) >> 6))
	// The first stage reads D[i + 2^(K-1)] for i < nw + 2^(K-1); the final
	// pass reads D[0 .. nw+1] when K = 0.
	pl := mulPlan{n: n, nw: nw, stages: k, dlen: nw + (1 << uint(k)) + 1}
	if k > 0 {
		pl.buflen = nw + (1 << uint(k-1))
	}
	perPos := nvec * (k + 1) * (nw + (1 << uint(k)))
	w := runtime.GOMAXPROCS(0)
	if limit := npos * perPos / minWorkPerWorker; w > limit {
		w = limit
	}
	if w > npos {
		w = npos
	}
	if w < 1 {
		w = 1
	}
	pl.chunk = (npos + w - 1) / w
	if pl.chunk > 0 {
		pl.workers = (npos + pl.chunk - 1) / pl.chunk // drop empty trailing workers
	}
	if pl.workers < 1 {
		pl.workers = 1
	}
	return pl
}

// fillWindow writes D = dense||dense (each copy n bits, the padding bits of
// dense ignored) into d, which must be zero and at least n/64 + nw + 1 words
// long, so that the n bits of dense·X^p are D[n-p .. 2n-p).
func fillWindow(d, dense []uint64, n int) {
	nw := words(n)
	copy(d, dense[:nw])
	maskTop(d[:nw], n)
	ws, bs := n/64, uint(n%64)
	// Descending order: the second copy overlaps the first copy's top word.
	for i := nw - 1; i >= 0; i-- {
		x := d[i]
		d[ws+i] |= x << bs
		if bs != 0 { // public
			d[ws+i+1] |= x >> (64 - bs)
		}
	}
}

// ctSelectShift computes dst[i] = src[i+sh] if mask is all ones and src[i]
// if mask is zero, for every i < len(dst), touching every word either way.
// The loop trip counts depend only on len(dst); the three-index reslices
// let the compiler drop the per-element bounds checks.
func ctSelectShift(dst, src []uint64, sh int, mask uint64) {
	a := src[:len(dst)]
	b := src[sh : sh+len(dst)]
	n4 := len(dst) &^ 3
	for i := 0; i < n4; i += 4 {
		d := dst[i : i+4 : i+4]
		x := a[i : i+4 : i+4]
		y := b[i : i+4 : i+4]
		d[0] = x[0] ^ mask&(x[0]^y[0])
		d[1] = x[1] ^ mask&(x[1]^y[1])
		d[2] = x[2] ^ mask&(x[2]^y[2])
		d[3] = x[3] ^ mask&(x[3]^y[3])
	}
	for i := n4; i < len(dst); i++ {
		dst[i] = a[i] ^ mask&(a[i]^b[i])
	}
}

// pow2 returns 2^e for e ∈ [0, 63] with multiplications by 1 or a public
// power of two, instead of a shift by the secret amount e.
func pow2(e uint) uint64 {
	m := uint64(1)
	for j := uint(0); j < 6; j++ {
		b := uint64(e>>j) & 1
		m *= 1 + (-b & (uint64(1)<<(1<<j) - 1))
	}
	return m
}

// xorSelShifted fuses the last barrel-shifter stage with the bit shift and
// the accumulation: with w[j] = mask ? s[j+1] : s[j] for j ≤ len(a) and
// m = 2^(64-lo), lo ∈ [1, 64], it computes
//
//	a[i] ^= (w[i] >> lo) | (w[i+1] << (64-lo))
//
// as the high half of w[i]·m OR the low half of w[i+1]·m. len(s) ≥ len(a)+2.
func xorSelShifted(a, s []uint64, mask, m uint64) {
	s1 := s[1 : len(a)+1]
	s2 := s[2 : len(a)+2]
	x, y := s[0], s[1]
	prev, _ := bits.Mul64(x^mask&(x^y), m) // w[0] >> lo
	for i := range a {
		y, z := s1[i], s2[i]
		h, l := bits.Mul64(y^mask&(y^z), m)
		a[i] ^= prev | l
		prev = h
	}
}

// mulChunk accumulates accs[v] ^= dense_v · Σ_{p ∈ pos} X^p (before
// reduction of the padding bits) for every v, where ds[v] is the padded
// doubled vector of dense_v and bufA, bufB hold one pair of scratch buffers
// per operand. The stage masks and the multiplier of each position are
// computed once and shared by all operands. The sequence of memory
// addresses and the control flow depend only on the plan and len(pos).
func (pl *mulPlan) mulChunk(accs, ds, bufA, bufB [][]uint64, pos []int) {
	var masks [16]uint64 // K ≤ 10 since n ≤ 2^16
	k := pl.stages
	for _, p := range pos {
		o := uint(pl.n-p) - 1 // o - 1 ∈ [0, n-1]
		s := o >> 6
		m := pow2(63 - o&63) // 2^(64-lo)
		for st := 0; st < k; st++ {
			masks[st] = -uint64((s >> uint(st)) & 1)
		}
		for v := range accs {
			src := ds[v]
			a, b := bufA[v], bufB[v]
			for st := k - 1; st >= 1; st-- {
				sh := 1 << uint(st)
				dst := a[:pl.nw+sh]
				ctSelectShift(dst, src, sh, masks[st])
				src, a, b = dst, b, a
			}
			xorSelShifted(accs[v], src, masks[0], m) // masks[0] = 0 when K = 0
		}
	}
}

// mulSparseN computes dense_v · sparse for every dense operand, where the
// sparse operand is given by its set bit positions (each in [0, n), not
// necessarily distinct: a repeated position contributes once per
// occurrence). The results are canonical. The dense operands may have
// non-zero padding bits; they are ignored.
//
// Memory addresses and control flow depend only on n, len(pos),
// len(dense) and runtime.GOMAXPROCS, not on the values in pos (see the
// comment at the top of this file).
func mulSparseN(dense [][]uint64, pos []int, n int) [][]uint64 {
	nv := len(dense)
	pl := newMulPlan(n, len(pos), nv)
	nw := pl.nw
	perWorker := nv * (nw + 2*pl.buflen)
	slab := make([]uint64, nv*pl.dlen+pl.workers*perWorker)
	ds := make([][]uint64, nv)
	for v := range dense {
		ds[v] = slab[v*pl.dlen : (v+1)*pl.dlen]
		fillWindow(ds[v], dense[v], n)
	}
	scratch := slab[nv*pl.dlen:]
	out := make([][]uint64, nv)
	for v := range out {
		out[v] = make([]uint64, nw)
	}

	run := func(w int) {
		buf := scratch[w*perWorker : (w+1)*perWorker]
		accs := make([][]uint64, nv)
		bufA := make([][]uint64, nv)
		bufB := make([][]uint64, nv)
		for v := 0; v < nv; v++ {
			b := buf[v*(nw+2*pl.buflen):]
			if w == 0 {
				accs[v] = out[v]
			} else {
				accs[v] = b[:nw]
			}
			bufA[v] = b[nw : nw+pl.buflen]
			bufB[v] = b[nw+pl.buflen : nw+2*pl.buflen]
		}
		lo := min(w*pl.chunk, len(pos))
		hi := min(lo+pl.chunk, len(pos))
		pl.mulChunk(accs, ds, bufA, bufB, pos[lo:hi])
	}

	var wg sync.WaitGroup
	wg.Add(pl.workers - 1)
	for w := 1; w < pl.workers; w++ {
		go func(w int) {
			defer wg.Done()
			run(w)
		}(w)
	}
	run(0)
	wg.Wait()

	for v := range out {
		for w := 1; w < pl.workers; w++ {
			b := scratch[w*perWorker+v*(nw+2*pl.buflen):]
			xorInto(out[v], b[:nw])
		}
		maskTop(out[v], n)
	}
	clear(slab) // the scratch buffers hold secret-dependent rotations
	return out
}

// mulSparse computes dense · sparse in F_2[X]/(X^n - 1), where sparse is
// given by its set bit positions (each in [0, n)). The result is canonical.
// The memory addresses and control flow do not depend on the positions;
// see mulSparseN.
func mulSparse(dense []uint64, sparsePos []int, n int) []uint64 {
	return mulSparseN([][]uint64{dense}, sparsePos, n)[0]
}

// mulSparse2 computes (a·sparse, b·sparse) in one fused pass over the
// sparse positions, sharing the per-position stage masks. The memory
// addresses and control flow do not depend on the positions; see
// mulSparseN.
func mulSparse2(a, b []uint64, sparsePos []int, n int) ([]uint64, []uint64) {
	r := mulSparseN([][]uint64{a, b}, sparsePos, n)
	return r[0], r[1]
}
