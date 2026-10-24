package qcsd

import (
	"bytes"
	"github.com/BackendStack21/k-mosaic-go/v4/internal/timingtest"
	"math/rand"
	"runtime"
	"sort"
	"testing"
	"time"

	kmosaic "github.com/BackendStack21/k-mosaic-go/v4"
	"github.com/BackendStack21/k-mosaic-go/v4/core"
	"github.com/BackendStack21/k-mosaic-go/v4/utils"
)

// ---------------------------------------------------------------------------
// Reference implementations (straightforward, not constant-time).

var refExp, refLog [512]int

func init() {
	x := 1
	for i := 0; i < 255; i++ {
		refExp[i], refExp[i+255] = x, x
		refLog[x] = i
		x <<= 1
		if x&0x100 != 0 {
			x ^= gfPoly
		}
	}
}

func refMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return byte(refExp[refLog[a]+refLog[b]])
}

func refRMEncode(b byte) []uint64 {
	v := make([]uint64, 2)
	for x := 0; x < 128; x++ {
		bit := b & 1
		for i := 1; i < 8; i++ {
			bit ^= (b >> uint(i) & 1) & byte(x>>uint(i-1)&1)
		}
		if bit == 1 {
			setBit(v, x)
		}
	}
	return v
}

func shiftLeftRef(src []uint64, s, nbits int) []uint64 {
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

func shiftRightRef(src []uint64, s int) []uint64 {
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

// rotateRef returns src · X^s in F_2[X]/(X^nbits - 1).
func rotateRef(src []uint64, s, nbits int) []uint64 {
	s %= nbits
	if s == 0 {
		return append([]uint64{}, src...)
	}
	lo := shiftLeftRef(src, s, nbits)
	xorInto(lo, shiftRightRef(src, nbits-s))
	return lo
}

// mulSparseRef is the previous rotate-per-position implementation.
func mulSparseRef(dense []uint64, pos []int, nbits int) []uint64 {
	acc := make([]uint64, len(dense))
	for _, p := range pos {
		xorInto(acc, rotateRef(dense, p, nbits))
	}
	return acc
}

// mulSparseNaive multiplies bit by bit: dense · Σ X^p, with repeated
// positions contributing once per occurrence.
func mulSparseNaive(dense []uint64, pos []int, n int) []uint64 {
	acc := make([]uint64, words(n))
	for _, p := range pos {
		xorInto(acc, naiveRotate(dense, p, n))
	}
	return acc
}

func naiveRotate(src []uint64, s, n int) []uint64 {
	dst := make([]uint64, len(src))
	for i := 0; i < n; i++ {
		if getBit(src, i) {
			setBit(dst, (i+s)%n)
		}
	}
	return dst
}

func equal(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func randVec(rng *rand.Rand, n int) []uint64 {
	v := make([]uint64, words(n))
	for i := range v {
		v[i] = rng.Uint64()
	}
	maskTop(v, n)
	return v
}

// ---------------------------------------------------------------------------
// Field arithmetic

func TestGF256(t *testing.T) {
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			if got, want := gfMul(byte(a), byte(b)), refMul(byte(a), byte(b)); got != want {
				t.Fatalf("gfMul(%d,%d) = %d, want %d", a, b, got, want)
			}
		}
		if a != 0 && gfMul(byte(a), gfInv(byte(a))) != 1 {
			t.Fatalf("inverse of %d wrong", a)
		}
	}
	if gfInv(0) != 0 {
		t.Fatal("gfInv(0) != 0")
	}
	rng := rand.New(rand.NewSource(3))
	for i := 0; i < 1000; i++ {
		a, b := rng.Uint64(), rng.Uint64()
		p, z := gfMul8(a, b), zeroLanes(a)
		for j := 0; j < 8; j++ {
			x, y := byte(a>>(8*j)), byte(b>>(8*j))
			if byte(p>>(8*j)) != refMul(x, y) {
				t.Fatal("gfMul8 lane mismatch")
			}
			if (byte(z>>(8*j)) == 0xFF) != (x == 0) || (byte(z>>(8*j)) != 0 && x != 0) {
				t.Fatal("zeroLanes mismatch")
			}
		}
	}
	if zeroLanes(0) != ^uint64(0) || zeroLanes(0x8001) != 0xFFFFFFFFFFFF0000 {
		t.Fatal("zeroLanes edge cases")
	}
}

// ---------------------------------------------------------------------------
// Reed-Solomon

func TestReedSolomonEncode(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for _, tc := range []struct{ n1, delta int }{{46, 15}, {56, 16}, {90, 29}, {255, 16}} {
		k := tc.n1 - 2*tc.delta
		for trial := 0; trial < 50; trial++ {
			msg := make([]byte, k)
			rng.Read(msg)
			cw := rsEncode(msg, tc.n1, tc.delta)
			if !bytes.Equal(cw[2*tc.delta:], msg) {
				t.Fatal("encoding is not systematic")
			}
			for j := 1; j <= 2*tc.delta; j++ {
				var s byte
				for i := len(cw) - 1; i >= 0; i-- {
					s = refMul(s, gfPow(j)) ^ cw[i]
				}
				if s != 0 {
					t.Fatalf("syndrome %d non-zero on a fresh codeword", j)
				}
			}
		}
	}
}

// injectErrors flips nerr distinct random symbols of cw by non-zero values.
func injectErrors(rng *rand.Rand, cw []byte, nerr int) []byte {
	noisy := append([]byte{}, cw...)
	for _, pos := range rng.Perm(len(cw))[:nerr] {
		noisy[pos] ^= byte(1 + rng.Intn(255))
	}
	return noisy
}

func TestReedSolomonDecode(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	trials := 150 // per error count
	if testing.Short() {
		trials = 20
	}
	for _, tc := range []struct{ n1, delta int }{{90, 29}, {46, 15}, {56, 16}} {
		k := tc.n1 - 2*tc.delta
		for nerr := 0; nerr <= tc.delta+1; nerr++ {
			for trial := 0; trial < trials; trial++ {
				msg := make([]byte, k)
				rng.Read(msg)
				cw := rsEncode(msg, tc.n1, tc.delta)
				noisy := injectErrors(rng, cw, nerr)
				saved := append([]byte{}, noisy...)
				dec, ok := rsDecode(noisy, tc.n1, tc.delta)
				if !bytes.Equal(noisy, saved) {
					t.Fatal("rsDecode modified its input")
				}
				if nerr <= tc.delta {
					if ok != 1 || !bytes.Equal(dec, msg) {
						t.Fatalf("[%d,%d] %d errors: ok=%d, correct=%v", tc.n1, k, nerr, ok, bytes.Equal(dec, msg))
					}
					continue
				}
				// δ+1 errors: must be flagged, and the output is the
				// uncorrected systematic part.
				if ok != 0 {
					t.Fatalf("[%d,%d] %d errors not flagged", tc.n1, k, nerr)
				}
				if !bytes.Equal(dec, noisy[2*tc.delta:]) {
					t.Fatal("failure output is not the uncorrected systematic part")
				}
			}
		}
	}
	// Far beyond the capability: random words.
	for trial := 0; trial < 200; trial++ {
		w := make([]byte, 90)
		rng.Read(w)
		if _, ok := rsDecode(w, 90, 29); ok != 0 {
			t.Fatal("random word decoded")
		}
	}
}

// TestReedSolomonFlag30 runs thousands of trials at exactly 29 and 30
// errors for the hqc-256 code.
func TestReedSolomonFlag30(t *testing.T) {
	trials := 2000
	if testing.Short() {
		trials = 200
	}
	rng := rand.New(rand.NewSource(30))
	msg := make([]byte, 32)
	for trial := 0; trial < trials; trial++ {
		rng.Read(msg)
		cw := rsEncode(msg, 90, 29)
		dec, ok := rsDecode(injectErrors(rng, cw, 29), 90, 29)
		if ok != 1 || !bytes.Equal(dec, msg) {
			t.Fatalf("trial %d: 29 errors not corrected", trial)
		}
		if _, ok := rsDecode(injectErrors(rng, cw, 30), 90, 29); ok != 0 {
			t.Fatalf("trial %d: 30 errors not flagged", trial)
		}
	}
}

// measureDecode returns, for each word, the fastest per-decode time over
// many rounds. Rounds visit the words round-robin so that machine noise
// affects all of them alike.
func measureDecode(ws [][]byte, rounds, perBatch int) []time.Duration {
	msg := make([]byte, 32)
	best := make([]time.Duration, len(ws))
	for r := 0; r < rounds; r++ {
		for j, w := range ws {
			start := time.Now()
			for i := 0; i < perBatch; i++ {
				rsDecodeInto(msg, w, 90, 29)
			}
			if d := time.Since(start) / time.Duration(perBatch); best[j] == 0 || d < best[j] {
				best[j] = d
			}
		}
	}
	return best
}

// TestReedSolomonTimingFlat measures that the decoding time does not depend
// on the number of errors. The check is loose (minimum over interleaved
// rounds, 1.5x tolerance, re-measured before failing) so that it does not
// flake on a busy machine; the numbers are logged.
func TestReedSolomonTimingFlat(t *testing.T) {
	timingtest.Gate(t, raceEnabled)
	rng := rand.New(rand.NewSource(5))
	cw := rsEncode(make([]byte, 32), 90, 29)
	counts := []int{0, 1, 5, 10, 15, 20, 25, 29, 30, 45, 90}
	ws := make([][]byte, len(counts))
	for i, nerr := range counts {
		ws[i] = injectErrors(rng, cw, nerr)
	}
	measureDecode(ws, 2, 10) // warm-up
	var ratio float64
	for attempt := 0; attempt < 3; attempt++ {
		times := measureDecode(ws, 40, 10)
		lo, hi := times[0], times[0]
		for i, d := range times {
			t.Logf("rsDecode with %2d errors: %v", counts[i], d)
			lo, hi = min(lo, d), max(hi, d)
		}
		ratio = float64(hi) / float64(lo)
		t.Logf("max/min = %.3f", ratio)
		if ratio <= 1.5 {
			return
		}
	}
	t.Errorf("decode time varies with the number of errors: max/min = %.3f", ratio)
}

// ---------------------------------------------------------------------------
// Reed-Muller

func TestReedMuller(t *testing.T) {
	for _, mult := range []int{1, 3, 5} {
		for b := 0; b < 256; b++ {
			v := make([]uint64, 2*mult)
			rmEncodeByte(v, 0, byte(b), mult)
			ref := refRMEncode(byte(b))
			for rep := 0; rep < mult; rep++ {
				if v[2*rep] != ref[0] || v[2*rep+1] != ref[1] {
					t.Fatalf("mult %d: codeword of %d differs from reference", mult, b)
				}
			}
			if got := rmDecodeByte(v, 0, mult); got != byte(b) {
				t.Fatalf("mult %d: byte %d decoded as %d", mult, b, got)
			}
			// RM(1,7) repeated mult times corrects any pattern of fewer than
			// 32*mult errors. Flip 32*mult-1 random bits.
			rng := rand.New(rand.NewSource(int64(b)))
			for _, p := range rng.Perm(128 * mult)[:32*mult-1] {
				v[p>>6] ^= 1 << (uint(p) & 63)
			}
			if got := rmDecodeByte(v, 0, mult); got != byte(b) {
				t.Fatalf("mult %d: byte %d with errors decoded as %d", mult, b, got)
			}
		}
	}
	// Word offset handling.
	v := make([]uint64, 30)
	rmEncodeByte(v, 20, 0xA5, 5)
	if rmDecodeByte(v, 20, 5) != 0xA5 || v[19] != 0 {
		t.Fatal("offset encoding wrong")
	}
}

// ---------------------------------------------------------------------------
// Ring arithmetic

func TestMulSparseMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for _, n := range []int{1, 7, 63, 64, 65, 127, 128, 129, 191, 1000, 4096, 4097, 17669, 57637} {
		src := randVec(rng, n)
		edges := []int{0, 1, 63, 64, 65, n - 64, n - 63, n - 2, n - 1, n / 2, 3000}
		for _, s := range edges {
			s = ((s % n) + n) % n
			want := naiveRotate(src, s, n)
			if !equal(rotateRef(src, s, n), want) {
				t.Fatalf("reference rotate mismatch n=%d s=%d", n, s)
			}
			if !equal(mulSparse(src, []int{s}, n), want) {
				t.Fatalf("mulSparse single position mismatch n=%d s=%d", n, s)
			}
		}
		// All boundary positions at once, against the bit-level reference.
		var pos []int
		for _, s := range edges {
			pos = append(pos, ((s%n)+n)%n)
		}
		other := randVec(rng, n)
		x1, x2 := mulSparse2(src, other, pos, n)
		if !equal(x1, mulSparseNaive(src, pos, n)) || !equal(x2, mulSparseNaive(other, pos, n)) {
			t.Fatalf("mulSparse2 at boundaries differs from naive reference n=%d", n)
		}
		for trial := 0; trial < 5; trial++ {
			dense := randVec(rng, n)
			w := 1 + rng.Intn(150)
			if w > n {
				w = n
			}
			pos := rng.Perm(n)[:w]
			pos = append(pos, 0, n-1)
			if !equal(mulSparse(dense, pos, n), mulSparseRef(dense, pos, n)) {
				t.Fatalf("mulSparse differs from reference n=%d", n)
			}
		}
	}
	// Commutativity: a·b via sparse b equals b·a via sparse a.
	n := 17669
	a := sampleFixedWeight([]byte("a"), n, 50)
	b := sampleFixedWeight([]byte("b"), n, 60)
	if !equal(mulSparse(a, positions(b, n), n), mulSparse(b, positions(a, n), n)) {
		t.Fatal("ring multiplication not commutative")
	}
	if weight(a) != 50 || weight(b) != 60 {
		t.Fatal("fixed-weight sampling returned the wrong weight")
	}
	// Parallel pair.
	h, s := randVec(rng, 57637), randVec(rng, 57637)
	pos := positions(sampleFixedWeight([]byte("r"), 57637, 149), 57637)
	x1, x2 := mulSparse2(h, s, pos, 57637)
	if !equal(x1, mulSparseRef(h, pos, 57637)) || !equal(x2, mulSparseRef(s, pos, 57637)) {
		t.Fatal("mulSparse2 mismatch")
	}
	// Non-canonical dense input is reduced, not propagated.
	h[len(h)-1] |= 1 << 63
	if !equal(mulSparse(h, pos, 57637), x1) {
		t.Fatal("padding bits of the dense operand leaked into the product")
	}
	// Empty support.
	if !equal(mulSparse(h, nil, 57637), make([]uint64, words(57637))) {
		t.Fatal("product with zero is not zero")
	}
}

func TestPow2(t *testing.T) {
	for e := uint(0); e < 64; e++ {
		if pow2(e) != 1<<e {
			t.Fatalf("pow2(%d) = %#x", e, pow2(e))
		}
	}
}

// TestMulSparseWorkerCounts checks that the result does not depend on how
// the positions are split between goroutines.
func TestMulSparseWorkerCounts(t *testing.T) {
	rng := rand.New(rand.NewSource(17))
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(0))
	for _, n := range []int{129, 4097, 57637} {
		a, b := randVec(rng, n), randVec(rng, n)
		pos := rng.Perm(n)[:min(n, 149)]
		wantA, wantB := mulSparseRef(a, pos, n), mulSparseRef(b, pos, n)
		for _, procs := range []int{1, 2, 3, 4, 7, 16} {
			runtime.GOMAXPROCS(procs)
			pl := newMulPlan(n, len(pos), 2)
			if pl.workers < 1 || pl.workers > procs || (pl.workers-1)*pl.chunk >= len(pos) || pl.workers*pl.chunk < len(pos) {
				t.Fatalf("bad split n=%d procs=%d: %+v", n, procs, pl)
			}
			ra, rb := mulSparse2(a, b, pos, n)
			if !equal(ra, wantA) || !equal(rb, wantB) {
				t.Fatalf("result depends on GOMAXPROCS=%d (n=%d)", procs, n)
			}
		}
	}
}

// timingSupports returns WR-position supports of the four shapes used by
// the obliviousness tests. The first two repeat positions (only 64 distinct
// values exist); the multiply does not assume distinct positions.
func timingSupports(n, w int) (names []string, sups [][]int) {
	first, last, spread := make([]int, w), make([]int, w), make([]int, w)
	for i := 0; i < w; i++ {
		first[i] = i % 64
		last[i] = n - 64 + i%64
		spread[i] = i * n / w
	}
	random := rand.New(rand.NewSource(23)).Perm(n)[:w]
	return []string{"first 64 bits", "last 64 bits", "evenly spread", "random"},
		[][]int{first, last, spread, random}
}

// TestMulSparseOblivious checks that the work done does not depend on the
// support: the same number of allocations (so the same number of
// goroutines and buffers) for every support, and correct results.
func TestMulSparseOblivious(t *testing.T) {
	rng := rand.New(rand.NewSource(19))
	n := core.CodeHQC256.N
	h, s := randVec(rng, n), randVec(rng, n)
	names, sups := timingSupports(n, core.CodeHQC256.WR)
	var allocs []float64
	for i, pos := range sups {
		ra, rb := mulSparse2(h, s, pos, n)
		if !equal(ra, mulSparseRef(h, pos, n)) || !equal(rb, mulSparseRef(s, pos, n)) {
			t.Fatalf("%s: wrong product", names[i])
		}
		allocs = append(allocs, testing.AllocsPerRun(20, func() { mulSparse2(h, s, pos, n) }))
		t.Logf("%-14s allocs/op = %v", names[i], allocs[i])
	}
	for i := range allocs {
		if allocs[i] != allocs[0] {
			t.Fatalf("allocation count depends on the support: %v", allocs)
		}
	}
}

// measureMul returns, for each support, the fastest time of the fused
// multiply over interleaved rounds.
func measureMul(h, s []uint64, sups [][]int, n, rounds, perBatch int) []time.Duration {
	best := make([]time.Duration, len(sups))
	for r := 0; r < rounds; r++ {
		for j, pos := range sups {
			start := time.Now()
			for i := 0; i < perBatch; i++ {
				mulSparse2(h, s, pos, n)
			}
			if d := time.Since(start) / time.Duration(perBatch); best[j] == 0 || d < best[j] {
				best[j] = d
			}
		}
	}
	return best
}

// TestMulSparseTimingFlat measures that the fused multiply of Encrypt takes
// the same time for supports concentrated in the first or last 64 bits,
// evenly spread or random (max/min ≤ 1.15, minimum over interleaved
// rounds, re-measured up to five times before failing). The old windowed
// multiply read the same cache lines for every position of (a) and (b).
func TestMulSparseTimingFlat(t *testing.T) {
	timingtest.Gate(t, raceEnabled)
	rng := rand.New(rand.NewSource(29))
	n := core.CodeHQC256.N
	h, s := randVec(rng, n), randVec(rng, n)
	names, sups := timingSupports(n, core.CodeHQC256.WR)
	measureMul(h, s, sups, n, 2, 2) // warm-up
	var ratio float64
	for attempt := 0; attempt < 5; attempt++ {
		// Single calls, minimum over many interleaved rounds: the goroutine
		// scheduling noise of a call only ever adds time.
		times := measureMul(h, s, sups, n, 60, 1)
		lo, hi := times[0], times[0]
		for i, d := range times {
			t.Logf("mulSparse2, support %-14s: %v", names[i], d)
			lo, hi = min(lo, d), max(hi, d)
		}
		ratio = float64(hi) / float64(lo)
		t.Logf("max/min = %.3f", ratio)
		if ratio <= 1.15 {
			return
		}
	}
	t.Errorf("multiply time varies with the support: max/min = %.3f", ratio)
}

func TestPositions(t *testing.T) {
	rng := rand.New(rand.NewSource(9))
	n := 57637
	v := sampleFixedWeight([]byte("p"), n, 131)
	pos := positions(v, n)
	if len(pos) != 131 || !sort.IntsAreSorted(pos) {
		t.Fatal("positions not sorted / wrong count")
	}
	for _, p := range pos {
		if !getBit(v, p) {
			t.Fatal("position not set")
		}
	}
	_ = rng
}

// ---------------------------------------------------------------------------
// Scheme

func newKey(t testing.TB) (*kmosaic.CodeKeyPair, kmosaic.CodeParams) {
	p := core.CodeHQC256
	seed, _ := utils.SecureRandomBytes(32)
	kp, err := KeyGen(p, seed)
	if err != nil {
		t.Fatal(err)
	}
	return kp, p
}

func TestKeyGen(t *testing.T) {
	kp, p := newKey(t)
	sk, pk := kp.SecretKey, kp.PublicKey
	if weight(sk.X) != p.W || weight(sk.Y) != p.W {
		t.Fatal("secret weights wrong")
	}
	if !isCanonical(pk.S, p.N) || !isCanonical(pk.H, p.N) || !isCanonical(sk.Y, p.N) {
		t.Fatal("non-canonical key vectors")
	}
	want := positions(sk.Y, p.N)
	if len(sk.YPos) != p.W {
		t.Fatal("YPos not populated")
	}
	for i := range want {
		if want[i] != sk.YPos[i] {
			t.Fatal("YPos does not match Y")
		}
	}
	// s = x + h·y
	s := mulSparseRef(pk.H, want, p.N)
	xorInto(s, sk.X)
	if !equal(s, pk.S) {
		t.Fatal("s != x + h·y")
	}
	// Deterministic in the seed.
	seed := bytes.Repeat([]byte{7}, 32)
	k1, _ := KeyGen(p, seed)
	k2, _ := KeyGen(p, seed)
	if !bytes.Equal(SerializePublicKey(k1.PublicKey, p), SerializePublicKey(k2.PublicKey, p)) ||
		!bytes.Equal(SerializeSecretKey(k1.SecretKey, p), SerializeSecretKey(k2.SecretKey, p)) {
		t.Fatal("KeyGen not deterministic")
	}
	if _, err := KeyGen(p, seed[:31]); err == nil {
		t.Fatal("accepted short seed")
	}
}

func TestRoundTrip(t *testing.T) {
	kp, p := newKey(t)
	trials := 200
	if testing.Short() {
		trials = 20
	}
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < trials; i++ {
		msg := make([]byte, p.K)
		rng.Read(msg)
		rnd, _ := utils.SecureRandomBytes(32)
		ct, err := Encrypt(kp.PublicKey, msg, p, rnd)
		if err != nil {
			t.Fatal(err)
		}
		if !isCanonical(ct.U, p.N) || !isCanonical(ct.V, CodeLength(p)) {
			t.Fatal("non-canonical ciphertext")
		}
		dec, ok := Decrypt(ct, kp.SecretKey, p)
		if ok != 1 || !bytes.Equal(dec, msg) {
			t.Fatalf("trial %d: decryption failed (ok=%d)", i, ok)
		}
	}

	// Deterministic in the randomness.
	msg := make([]byte, p.K)
	rnd, _ := utils.SecureRandomBytes(32)
	c1, _ := Encrypt(kp.PublicKey, msg, p, rnd)
	c2, _ := Encrypt(kp.PublicKey, msg, p, rnd)
	if !equal(c1.U, c2.U) || !equal(c1.V, c2.V) {
		t.Fatal("encryption not deterministic in randomness")
	}
	// u = r1 + h·r2 must match the reference product.
	r1 := sampleFixedWeight(utils.HashWithDomain(DomainR1, rnd), p.N, p.WR)
	r2 := sampleFixedWeight(utils.HashWithDomain(DomainR2, rnd), p.N, p.WR)
	u := mulSparseRef(kp.PublicKey.H, positions(r2, p.N), p.N)
	xorInto(u, r1)
	if !equal(u, c1.U) {
		t.Fatal("u differs from the reference computation")
	}

	if _, err := Encrypt(kp.PublicKey, make([]byte, p.K-1), p, rnd); err == nil {
		t.Fatal("accepted wrong message size")
	}
	if _, err := Encrypt(kp.PublicKey, msg, p, rnd[:31]); err == nil {
		t.Fatal("accepted short randomness")
	}
	badPK := kp.PublicKey
	badPK.S = append([]uint64{}, badPK.S...)
	badPK.S[len(badPK.S)-1] |= 1 << 63
	if _, err := Encrypt(badPK, msg, p, rnd); err == nil {
		t.Fatal("accepted public key with padding bits")
	}
}

func TestDecryptShape(t *testing.T) {
	kp, p := newKey(t)
	rnd := make([]byte, 32)
	ct, _ := Encrypt(kp.PublicKey, make([]byte, p.K), p, rnd)
	check := func(name string, ct *kmosaic.CodeCiphertext, sk kmosaic.CodeSecretKey) {
		t.Helper()
		if m, ok := Decrypt(ct, sk, p); m != nil || ok != 0 {
			t.Fatalf("%s: expected (nil, 0)", name)
		}
	}
	check("nil ciphertext", nil, kp.SecretKey)
	check("short U", &kmosaic.CodeCiphertext{U: ct.U[:3], V: ct.V}, kp.SecretKey)
	check("short V", &kmosaic.CodeCiphertext{U: ct.U, V: ct.V[:3]}, kp.SecretKey)
	badU := append([]uint64{}, ct.U...)
	badU[len(badU)-1] |= 1 << 63 // bit >= N
	check("U padding", &kmosaic.CodeCiphertext{U: badU, V: ct.V}, kp.SecretKey)
	check("empty key", ct, kmosaic.CodeSecretKey{})
	badSK := kp.SecretKey
	badSK.YPos = append([]int{}, badSK.YPos...)
	badSK.YPos[0], badSK.YPos[1] = badSK.YPos[1], badSK.YPos[0]
	check("unsorted YPos", ct, badSK)
	badSK.YPos = append([]int{}, kp.SecretKey.YPos...)
	badSK.YPos[p.W-1] = p.N
	check("YPos out of range", ct, badSK)
	badSK.YPos = kp.SecretKey.YPos[:p.W-1]
	check("short YPos", ct, badSK)
	pp := p
	pp.Delta++
	if m, ok := Decrypt(ct, kp.SecretKey, pp); m != nil || ok != 0 {
		t.Fatal("bad params accepted")
	}

	// A key without YPos is rejected: deriving the positions from Y would
	// not be constant-time.
	check("Y without YPos", ct, kmosaic.CodeSecretKey{Y: kp.SecretKey.Y})
}

// TestDecryptFailure checks that undecodable ciphertexts are processed in
// full: K bytes, ok = 0, deterministic.
func TestDecryptFailure(t *testing.T) {
	kp, p := newKey(t)
	rng := rand.New(rand.NewSource(11))
	msg := make([]byte, p.K)
	rng.Read(msg)
	ct, _ := Encrypt(kp.PublicKey, msg, p, make([]byte, 32))

	for trial := 0; trial < 5; trial++ {
		bad := &kmosaic.CodeCiphertext{U: append([]uint64{}, ct.U...), V: randVec(rng, CodeLength(p))}
		m1, ok1 := Decrypt(bad, kp.SecretKey, p)
		m2, ok2 := Decrypt(bad, kp.SecretKey, p)
		if len(m1) != p.K || ok1 != 0 || ok2 != 0 || !bytes.Equal(m1, m2) {
			t.Fatalf("random v: len=%d ok=%d/%d deterministic=%v", len(m1), ok1, ok2, bytes.Equal(m1, m2))
		}
	}
	// Corrupt 30 RM blocks completely (each block decodes to a wrong RS
	// symbol with overwhelming probability): exactly beyond δ.
	bad := &kmosaic.CodeCiphertext{U: ct.U, V: append([]uint64{}, ct.V...)}
	n2w := rmLength * p.Mult / 64
	for blk := 0; blk < p.Delta+1; blk++ {
		for w := 0; w < n2w; w++ {
			bad.V[blk*n2w+w] ^= ^uint64(0)
		}
	}
	m, ok := Decrypt(bad, kp.SecretKey, p)
	if ok != 0 || len(m) != p.K {
		t.Fatalf("δ+1 corrupted blocks: ok=%d len=%d", ok, len(m))
	}
	// Corrupting δ blocks is still corrected.
	bad.V = append([]uint64{}, ct.V...)
	for blk := 0; blk < p.Delta; blk++ {
		for w := 0; w < n2w; w++ {
			bad.V[(p.N1-1-blk)*n2w+w] ^= ^uint64(0)
		}
	}
	if m, ok := Decrypt(bad, kp.SecretKey, p); ok != 1 || !bytes.Equal(m, msg) {
		t.Fatal("δ corrupted blocks not corrected")
	}
	// Wrong key: full-length output, failure flagged.
	kp2, _ := newKey(t)
	if m, ok := Decrypt(ct, kp2.SecretKey, p); ok != 0 || len(m) != p.K {
		t.Fatal("wrong key not flagged")
	}
}

func TestSerialization(t *testing.T) {
	kp, p := newKey(t)
	msg := make([]byte, p.K)
	rand.New(rand.NewSource(43)).Read(msg)
	rnd, _ := utils.SecureRandomBytes(32)
	ct, _ := Encrypt(kp.PublicKey, msg, p, rnd)

	pkb := SerializePublicKey(kp.PublicKey, p)
	if len(pkb) != SeedSize+(p.N+7)/8 {
		t.Fatal("pk size")
	}
	pk2, err := DeserializePublicKey(pkb, p)
	if err != nil {
		t.Fatal(err)
	}
	if !equal(pk2.H, kp.PublicKey.H) || !bytes.Equal(SerializePublicKey(*pk2, p), pkb) {
		t.Fatal("public key round trip failed")
	}
	skb := SerializeSecretKey(kp.SecretKey, p)
	if len(skb) != 2*p.W || len(skb) != SecretKeySize(p) {
		t.Fatalf("sk size %d", len(skb))
	}
	sk2, err := DeserializeSecretKey(skb, p)
	if err != nil {
		t.Fatal(err)
	}
	if !equal(sk2.Y, kp.SecretKey.Y) || len(sk2.YPos) != p.W || sk2.X != nil {
		t.Fatal("secret key round trip failed")
	}
	if !bytes.Equal(SerializeSecretKey(*sk2, p), skb) {
		t.Fatal("secret key re-serialization differs")
	}
	if SerializeSecretKey(kmosaic.CodeSecretKey{Y: kp.SecretKey.Y}, p) != nil {
		t.Fatal("serialized a key without YPos")
	}
	ctb := SerializeCiphertext(ct, p)
	if len(ctb) != (p.N+7)/8+(CodeLength(p)+7)/8 {
		t.Fatal("ct size")
	}
	ct2, err := DeserializeCiphertext(ctb, p)
	if err != nil {
		t.Fatal(err)
	}
	if dec, ok := Decrypt(ct2, *sk2, p); ok != 1 || !bytes.Equal(dec, msg) {
		t.Fatal("round-tripped objects do not decrypt")
	}
	t.Logf("pk=%d sk=%d ct=%d bytes", len(pkb), len(skb), len(ctb))

	// Malformed public keys / ciphertexts.
	if _, err := DeserializePublicKey(pkb[:len(pkb)-1], p); err == nil {
		t.Fatal("accepted truncated pk")
	}
	bad := append([]byte{}, pkb...)
	bad[len(bad)-1] |= 0x80 // padding bit of a 57637-bit vector
	if _, err := DeserializePublicKey(bad, p); err == nil {
		t.Fatal("accepted non-zero padding")
	}
	if _, err := DeserializeCiphertext(ctb[:10], p); err == nil {
		t.Fatal("accepted truncated ciphertext")
	}
	badCT := append([]byte{}, ctb...)
	badCT[(p.N+7)/8-1] |= 0x80
	if _, err := DeserializeCiphertext(badCT, p); err == nil {
		t.Fatal("accepted ciphertext with padding bit set in u")
	}

	// Malformed secret keys.
	put := func(b []byte, i, v int) { b[2*i], b[2*i+1] = byte(v), byte(v>>8) }
	mutations := map[string]func([]byte) []byte{
		"truncated": func(b []byte) []byte { return b[:len(b)-2] },
		"extended":  func(b []byte) []byte { return append(b, 0, 0) },
		"duplicate": func(b []byte) []byte { copy(b[2:4], b[0:2]); return b },
		"unsorted": func(b []byte) []byte {
			b[0], b[1], b[2], b[3] = b[2], b[3], b[0], b[1]
			return b
		},
		"out of range": func(b []byte) []byte { put(b, p.W-1, p.N); return b },
		"max uint16":   func(b []byte) []byte { put(b, p.W-1, 0xFFFF); return b },
	}
	for name, mut := range mutations {
		if _, err := DeserializeSecretKey(mut(append([]byte{}, skb...)), p); err == nil {
			t.Fatalf("accepted secret key: %s", name)
		}
	}
	if SerializeSecretKey(kmosaic.CodeSecretKey{}, p) != nil {
		t.Fatal("serialized an empty secret key")
	}
}

// ---------------------------------------------------------------------------
// Benchmarks

func BenchmarkKeyGen(b *testing.B) {
	p := core.CodeHQC256
	seed := make([]byte, 32)
	for i := 0; i < b.N; i++ {
		seed[0] = byte(i)
		if _, err := KeyGen(p, seed); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncrypt(b *testing.B) {
	kp, p := newKey(b)
	msg := make([]byte, p.K)
	rnd := make([]byte, 32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rnd[0] = byte(i)
		if _, err := Encrypt(kp.PublicKey, msg, p, rnd); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	kp, p := newKey(b)
	ct, _ := Encrypt(kp.PublicKey, make([]byte, p.K), p, make([]byte, 32))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := Decrypt(ct, kp.SecretKey, p); ok != 1 {
			b.Fatal("decryption failed")
		}
	}
}

func BenchmarkMulSparse(b *testing.B) {
	rng := rand.New(rand.NewSource(1))
	n := 57637
	dense := randVec(rng, n)
	pos := positions(sampleFixedWeight([]byte("y"), n, 131), n)
	b.Run("fused", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			mulSparse(dense, pos, n)
		}
	})
	b.Run("reference", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			mulSparseRef(dense, pos, n)
		}
	})
}

func BenchmarkRSDecode(b *testing.B) {
	rng := rand.New(rand.NewSource(1))
	cw := rsEncode(make([]byte, 32), 90, 29)
	msg := make([]byte, 32)
	for _, nerr := range []int{0, 15, 29, 30} {
		w := injectErrors(rng, cw, nerr)
		b.Run(map[int]string{0: "0err", 15: "15err", 29: "29err", 30: "30err"}[nerr], func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				rsDecodeInto(msg, w, 90, 29)
			}
		})
	}
}

func BenchmarkRMDecode(b *testing.B) {
	v := make([]uint64, 10)
	rmEncodeByte(v, 0, 0x5A, 5)
	for i := 0; i < b.N; i++ {
		rmDecodeByte(v, 0, 5)
	}
}
