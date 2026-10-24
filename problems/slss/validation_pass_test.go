package slss

import (
	"math/rand"
	"slices"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go/v2"
	"github.com/BackendStack21/k-mosaic-go/v2/core"
)

func TestCtSortU64(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	for _, m := range []int{1, 2, 4, 64, 1024, 2048} {
		a := make([]uint64, m)
		for i := range a {
			a[i] = rng.Uint64() >> 1 // below 2^63
		}
		want := slices.Clone(a)
		slices.Sort(want)
		ctSortU64(a)
		if !slices.Equal(a, want) {
			t.Fatalf("m=%d: sorting network wrong", m)
		}
	}
}

// TestSampleSparse_WeightSignsUniformity checks the sort-based sampler:
// exact weight, balanced signs, and uniform positions (chi-square over 32
// buckets), for both parameter sets.
func TestSampleSparse_WeightSignsUniformity(t *testing.T) {
	for _, level := range []kmosaic.SecurityLevel{kmosaic.MOS_128, kmosaic.MOS_256} {
		params, _ := core.GetParams(level)
		n, w := params.SLSS.N, params.SLSS.W
		const trials = 400
		counts := make([]float64, 32)
		plus := 0
		seed := make([]byte, 32)
		for i := 0; i < trials; i++ {
			seed[0], seed[1] = byte(i), byte(i>>8)
			v := sampleSparseVector(seed, n, w)
			nz := 0
			for k, x := range v {
				if x != 0 {
					nz++
					counts[k*32/n]++
					if x == 1 {
						plus++
					}
				}
			}
			if nz != w {
				t.Fatalf("%s trial %d: weight %d, want %d", level, i, nz, w)
			}
		}
		exp := float64(trials*w) / 32
		chi2 := 0.0
		for _, c := range counts {
			chi2 += (c - exp) * (c - exp) / exp
		}
		if chi2 > 75 { // 31 degrees of freedom; p < 1e-5
			t.Fatalf("%s: positions not uniform: chi-square %.1f", level, chi2)
		}
		total := float64(trials * w)
		if ratio := float64(plus) / total; ratio < 0.48 || ratio > 0.52 {
			t.Fatalf("%s: sign bias: %.3f of entries are +1", level, ratio)
		}
	}
}

func TestCiphertextCanonical(t *testing.T) {
	p := core.MOS128Params.SLSS
	ct := &kmosaic.SLSSCiphertext{U: make([]int32, p.N), V: make([]int32, p.L)}
	if !CiphertextCanonical(ct, p) {
		t.Fatal("zero ciphertext not canonical")
	}
	ct.U[0] = 1 << uint(p.DU)
	if CiphertextCanonical(ct, p) {
		t.Fatal("out-of-range U accepted")
	}
	ct.U[0] = 0
	ct.V[3] = -1
	if CiphertextCanonical(ct, p) {
		t.Fatal("negative V accepted")
	}
	ct.V[3] = 0
	ct.U = ct.U[:p.N-1]
	if CiphertextCanonical(ct, p) || CiphertextCanonical(nil, p) {
		t.Fatal("mis-shaped or nil ciphertext accepted")
	}
}
