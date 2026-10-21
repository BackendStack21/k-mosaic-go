package slss

import (
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/utils"
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
	bad := params.SLSS
	bad.W = bad.N + 1
	if _, err := KeyGen(bad, seed); err == nil {
		t.Error("expected error for sparsity above dimension")
	}
	bad = params.SLSS
	bad.L = 12
	if _, err := KeyGen(bad, seed); err == nil {
		t.Error("expected error for L not a multiple of 8")
	}
}

func TestMatVecMul_Basic(t *testing.T) {
	A := []int32{1, 2, 3, 4} // 2x2
	v := []int8{1, -1}
	res := matVecMul(A, v, 2, 2, 100)
	if res[0] != 99 || res[1] != 99 {
		t.Errorf("expected [99, 99], got %v", res)
	}
	if len(matVecMul([]int32{}, []int8{}, 0, 0, 100)) != 0 {
		t.Error("expected empty result")
	}
}

func TestSampleMatrix_Coverage(t *testing.T) {
	seed := make([]byte, 32)
	if len(sampleMatrix(seed, 0, 0, 100)) != 0 {
		t.Error("expected empty result")
	}
	A := sampleMatrix(seed, 2, 2, 100)
	if len(A) != 4 {
		t.Errorf("expected length 4, got %d", len(A))
	}
	// Large matrix to force the SHAKE extension path
	A = sampleMatrix(seed, 500, 500, 3329)
	if len(A) != 250000 {
		t.Errorf("expected length 250000, got %d", len(A))
	}
	for _, a := range A {
		if a < 0 || a >= 3329 {
			t.Fatalf("entry %d out of range", a)
		}
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
	if sampleSparseVector(seed, 0, 0) != nil || sampleSparseVector(seed, 5, 6) != nil {
		t.Error("expected nil for invalid parameters")
	}
}

func TestSampleSparseVector_HighSparsity(t *testing.T) {
	seed, _ := utils.SecureRandomBytes(32)
	n := 100 // not a power of two: exercises the rejection path
	w := 90
	v := sampleSparseVector(seed, n, w)

	count := 0
	for _, x := range v {
		if x != 0 {
			count++
		}
	}
	if count != w {
		t.Errorf("expected weight %d, got %d", w, count)
	}
}
