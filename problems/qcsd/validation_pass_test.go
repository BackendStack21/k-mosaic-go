package qcsd

import (
	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"math/rand"
	"slices"
	"testing"

	"github.com/BackendStack21/k-mosaic-go/core"
)

// TestSampleFixedWeight_WeightAndUniformity checks that the constant-time
// sampler returns exactly w distinct positions and that positions are
// uniform (chi-square over 64 buckets) with no bias toward low indices.
func TestSampleFixedWeight_WeightAndUniformity(t *testing.T) {
	p := core.CodeHQC256
	const trials = 2000
	counts := make([]float64, 64)
	seed := make([]byte, 32)
	for i := 0; i < trials; i++ {
		seed[0], seed[1] = byte(i), byte(i>>8)
		v, pos := sampleFixedWeightPos(seed, p.N, p.W)
		if weight(v) != p.W || len(pos) != p.W {
			t.Fatalf("trial %d: weight %d, %d positions", i, weight(v), len(pos))
		}
		sorted := slices.Clone(pos)
		slices.Sort(sorted)
		for k := 1; k < len(sorted); k++ {
			if sorted[k] == sorted[k-1] {
				t.Fatalf("trial %d: duplicate position %d", i, sorted[k])
			}
		}
		for _, q := range pos {
			if q < 0 || q >= p.N || !getBit(v, q) {
				t.Fatalf("trial %d: position %d out of range or not set", i, q)
			}
			counts[q*64/p.N]++
		}
	}
	exp := float64(trials*p.W) / 64
	chi2 := 0.0
	for _, c := range counts {
		chi2 += (c - exp) * (c - exp) / exp
	}
	if chi2 > 120 { // 63 degrees of freedom; p < 1e-5
		t.Fatalf("positions not uniform: chi-square %.1f", chi2)
	}
}

// TestSampleFixedWeight_Deterministic checks that the sampler is a pure
// function of its seed (FO re-encryption depends on it).
func TestSampleFixedWeight_Deterministic(t *testing.T) {
	p := core.CodeHQC256
	for i := 0; i < 50; i++ {
		seed := []byte{byte(i), 1, 2, 3}
		v, pos := sampleFixedWeightPos(seed, p.N, p.WR)
		v2, pos2 := sampleFixedWeightPos(seed, p.N, p.WR)
		if !equal(v, v2) || !slices.Equal(pos, pos2) {
			t.Fatal("sampler not deterministic")
		}
	}
}

func TestCtSortInts(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for _, n := range []int{0, 1, 2, 3, 131, 149, 256, 500} {
		a := make([]int, n)
		for i := range a {
			a[i] = rng.Intn(60000)
		}
		want := slices.Clone(a)
		slices.Sort(want)
		ctSortInts(a)
		if !slices.Equal(a, want) {
			t.Fatalf("n=%d: sorting network wrong", n)
		}
	}
}

func TestKeyGenPositionsSortedAndCanonicalPadding(t *testing.T) {
	p := core.CodeHQC256
	kp, err := KeyGen(p, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.IsSorted(kp.SecretKey.YPos) || !slices.Equal(kp.SecretKey.YPos, positions(kp.SecretKey.Y, p.N)) {
		t.Fatal("YPos is not the sorted support of y")
	}
	// bitsToBytes must clear padding bits so that its output always parses.
	v := make([]uint64, words(p.N))
	v[len(v)-1] = ^uint64(0)
	b := bitsToBytes(v, p.N)
	if _, err := bytesToBits(b, p.N); err != nil {
		t.Fatalf("bitsToBytes emitted non-canonical padding: %v", err)
	}
	ct := &kmosaic.CodeCiphertext{U: make([]uint64, words(p.N)), V: make([]uint64, words(CodeLength(p)))}
	if !CiphertextCanonical(ct, p) {
		t.Fatal("zero ciphertext not canonical")
	}
	ct.U[len(ct.U)-1] = 1 << 63
	if CiphertextCanonical(ct, p) {
		t.Fatal("padding bit accepted as canonical")
	}
}
