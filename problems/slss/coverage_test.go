package slss

import (
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go/v2"
	"github.com/BackendStack21/k-mosaic-go/v2/core"
	"github.com/BackendStack21/k-mosaic-go/v2/utils"
)

func TestKeyGen_ShortSeed(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS128)
	if _, err := KeyGen(params.SLSS, make([]byte, 31)); err == nil {
		t.Error("expected error from KeyGen for short seed")
	}
}

func TestKeyGen_BadParams(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS128)
	seed, _ := utils.SecureRandomBytes(32)
	mutations := map[string]func(p *kmosaic.SLSSParams){
		"W > N":       func(p *kmosaic.SLSSParams) { p.W = p.N + 1 },
		"W = 0":       func(p *kmosaic.SLSSParams) { p.W = 0 },
		"L % 8 != 0":  func(p *kmosaic.SLSSParams) { p.L = 12 },
		"L = 0":       func(p *kmosaic.SLSSParams) { p.L = 0 },
		"Q != 12289":  func(p *kmosaic.SLSSParams) { p.Q = 3329 },
		"Eta < 16":    func(p *kmosaic.SLSSParams) { p.Eta = 15 },
		"Eta > 64":    func(p *kmosaic.SLSSParams) { p.Eta = 65 },
		"DU < 10":     func(p *kmosaic.SLSSParams) { p.DU = 9 },
		"DU > 14":     func(p *kmosaic.SLSSParams) { p.DU = 15 },
		"DV < 4":      func(p *kmosaic.SLSSParams) { p.DV = 3 },
		"DV > 14":     func(p *kmosaic.SLSSParams) { p.DV = 15 },
		"N = 0":       func(p *kmosaic.SLSSParams) { p.N = 0 },
		"M too large": func(p *kmosaic.SLSSParams) { p.M = maxDim + 1 },
	}
	for name, mutate := range mutations {
		bad := params.SLSS
		mutate(&bad)
		if _, err := KeyGen(bad, seed); err == nil {
			t.Errorf("%s: expected error", name)
		}
		if _, err := Encrypt(kmosaic.SLSSPublicKey{}, nil, bad, seed); err == nil {
			t.Errorf("%s: Encrypt accepted invalid params", name)
		}
		if Decrypt(&kmosaic.SLSSCiphertext{}, kmosaic.SLSSSecretKey{}, bad) != nil {
			t.Errorf("%s: Decrypt accepted invalid params", name)
		}
	}
}

func TestMatVecMul_Basic(t *testing.T) {
	A := []int32{1, 2, 3, 4} // 2x2
	v := []int8{1, -1}
	res := matVecMul(A, v, 2, 2)
	if res[0] != q-1 || res[1] != q-1 {
		t.Errorf("expected [q-1, q-1], got %v", res)
	}
	if len(matVecMul([]int32{}, []int8{}, 0, 0)) != 0 {
		t.Error("expected empty result")
	}
}

// TestKeyGen_Structure checks t_j = A·s_j + e_j with s_j of weight W and
// ||e_j||∞ ≤ η.
func TestKeyGen_Structure(t *testing.T) {
	p := core.MOS128Params.SLSS
	seed, _ := utils.SecureRandomBytes(32)
	kp, err := KeyGen(p, seed)
	if err != nil {
		t.Fatal(err)
	}
	if len(kp.PublicKey.Seed) != SeedSize {
		t.Fatalf("seed length %d", len(kp.PublicKey.Seed))
	}
	for _, j := range []int{0, 1, 63, 64, 200, p.L - 1} {
		sj := kp.SecretKey.S[j*p.N : (j+1)*p.N]
		weight := 0
		for _, s := range sj {
			if s < -1 || s > 1 {
				t.Fatalf("column %d: entry %d not ternary", j, s)
			}
			if s != 0 {
				weight++
			}
		}
		if weight != p.W {
			t.Fatalf("column %d: weight %d, want %d", j, weight, p.W)
		}
		as := matVecMul(kp.PublicKey.A, sj, p.M, p.N)
		for i := 0; i < p.M; i++ {
			tij := kp.PublicKey.T[j*p.M+i]
			if tij < 0 || tij >= q {
				t.Fatalf("T entry %d out of range", tij)
			}
			e := centerMod(tij - as[i])
			if e < -int32(p.Eta) || e > int32(p.Eta) {
				t.Fatalf("column %d row %d: error %d exceeds eta", j, i, e)
			}
		}
	}
}

func TestSampleMatrix_Coverage(t *testing.T) {
	seed := make([]byte, 32)
	if len(sampleMatrix(seed, 0, 0)) != 0 {
		t.Error("expected empty result")
	}
	if sampleMatrix(seed, -1, 2) != nil {
		t.Error("expected nil for negative dimension")
	}
	A := sampleMatrix(seed, 2, 2)
	if len(A) != 4 {
		t.Errorf("expected length 4, got %d", len(A))
	}
	// Small rows force the streaming path on shortfall; the large matrix
	// exercises the parallel path.
	for _, dims := range [][2]int{{64, 1}, {64, 3}, {500, 500}} {
		A = sampleMatrix(seed, dims[0], dims[1])
		if len(A) != dims[0]*dims[1] {
			t.Fatalf("expected length %d, got %d", dims[0]*dims[1], len(A))
		}
		for _, a := range A {
			if a < 0 || a >= q {
				t.Fatalf("entry %d out of range", a)
			}
		}
	}
	// Row i depends only on (seed, i), not on the number of rows or workers.
	B := sampleMatrix(seed, 3, 500)
	for i := range B {
		if B[i] != A[i] {
			t.Fatal("row generation depends on matrix height")
		}
	}
}

// TestSampleMatrix_Uniform is a coarse chi-square check of the rejection
// sampler over 16 buckets.
func TestSampleMatrix_Uniform(t *testing.T) {
	A := sampleMatrix([]byte("uniformity"), 256, 768)
	const buckets = 16
	var counts [buckets]float64
	for _, a := range A {
		counts[int(a)*buckets/q]++
	}
	var chi2 float64
	for b := 0; b < buckets; b++ {
		lo := (b*q + buckets - 1) / buckets
		hi := ((b+1)*q + buckets - 1) / buckets
		exp := float64(len(A)) * float64(hi-lo) / q
		chi2 += (counts[b] - exp) * (counts[b] - exp) / exp
	}
	if chi2 > 50 { // 15 degrees of freedom; p ≈ 1e-5
		t.Fatalf("chi-square %.1f too large", chi2)
	}
}

func TestSampleSparseVector_Coverage(t *testing.T) {
	seed := make([]byte, 32)
	v := sampleSparseVector(seed, 10, 2)
	if len(v) != 10 {
		t.Errorf("expected length 10, got %d", len(v))
	}
	w := 0
	for _, x := range v {
		if x != 0 {
			w++
		}
	}
	if w != 2 {
		t.Errorf("expected weight 2, got %d", w)
	}
	if sampleSparseVector(seed, 0, 0) != nil || sampleSparseVector(seed, 5, 6) != nil || sampleSparseVector(seed, 5, -1) != nil {
		t.Error("expected nil for invalid parameters")
	}
}

func TestSampleSparseVector_HighSparsity(t *testing.T) {
	seed, _ := utils.SecureRandomBytes(32)
	for _, n := range []int{1, 7, 100, 768} {
		v := sampleSparseVector(seed, n, n)
		for i, x := range v {
			if x != 1 && x != -1 {
				t.Fatalf("n=%d full weight: entry %d is %d", n, i, x)
			}
		}
	}
	v := sampleSparseVector(seed, 100, 90) // not a power of two: exercises rejection
	count := 0
	for _, x := range v {
		if x != 0 {
			count++
		}
	}
	if count != 90 {
		t.Errorf("expected weight 90, got %d", count)
	}
}

// TestSampleSparseVector_Balance checks that positions and signs are not
// grossly biased.
func TestSampleSparseVector_Balance(t *testing.T) {
	const n, w, trials = 768, 192, 400
	posCount := make([]int, n)
	plus := 0
	seed := make([]byte, 32)
	for trial := 0; trial < trials; trial++ {
		seed[0], seed[1] = byte(trial), byte(trial>>8)
		for i, x := range sampleSparseVector(seed, n, w) {
			if x != 0 {
				posCount[i]++
			}
			if x == 1 {
				plus++
			}
		}
	}
	if d := plus - trials*w/2; d < -1000 || d > 1000 { // σ ≈ 139
		t.Errorf("sign imbalance: %d of %d positive", plus, trials*w)
	}
	for i, c := range posCount { // mean 100, σ ≈ 8.7
		if c < 50 || c > 150 {
			t.Errorf("position %d chosen %d times", i, c)
		}
	}
}

// TestSampleCenteredBinomial checks range, determinism and the first two
// moments of utils.SampleCenteredBinomial.
func TestSampleCenteredBinomial(t *testing.T) {
	const n = 200000
	for _, eta := range []int{1, 16, 20, 33, 64} {
		e := utils.SampleCenteredBinomial([]byte("cbd"), n, eta)
		if len(e) != n {
			t.Fatalf("eta=%d: length %d", eta, len(e))
		}
		var sum, sq float64
		for _, x := range e {
			if x < -int32(eta) || x > int32(eta) {
				t.Fatalf("eta=%d: sample %d out of range", eta, x)
			}
			sum += float64(x)
			sq += float64(x) * float64(x)
		}
		mean, variance := sum/n, sq/n-(sum/n)*(sum/n)
		want := float64(eta) / 2
		if mean > 0.05*want+0.02 || mean < -0.05*want-0.02 || variance < 0.97*want || variance > 1.03*want {
			t.Errorf("eta=%d: mean %.4f variance %.4f, want 0 and %.1f", eta, mean, variance, want)
		}
		again := utils.SampleCenteredBinomial([]byte("cbd"), n, eta)
		for i := range e {
			if e[i] != again[i] {
				t.Fatalf("eta=%d: not deterministic", eta)
			}
		}
	}
	// Known answer: SHAKE256("") starts 46 b9 dd 2b 0b a8 8d 13 ...
	// eta=4: coefficient 0 = popcount(0x6) - popcount(0x4) = 2 - 1 = 1,
	// coefficient 1 = popcount(0x9) - popcount(0xb) = 2 - 3 = -1.
	e := utils.SampleCenteredBinomial(nil, 2, 4)
	if e[0] != 1 || e[1] != -1 {
		t.Errorf("eta=4 known answer: got %v, want [1 -1]", e)
	}
	for _, bad := range [][2]int{{-1, 20}, {10, 0}, {10, 65}, {utils.MaxVectorLength + 1, 20}} {
		if utils.SampleCenteredBinomial(nil, bad[0], bad[1]) != nil {
			t.Errorf("expected nil for n=%d eta=%d", bad[0], bad[1])
		}
	}
	if e := utils.SampleCenteredBinomial(nil, 0, 20); e == nil || len(e) != 0 {
		t.Error("expected empty slice for n=0")
	}
}
