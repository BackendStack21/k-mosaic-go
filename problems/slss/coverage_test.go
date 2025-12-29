package slss

import (
	"runtime"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

func TestMatVecMulInt32_Coverage(t *testing.T) {
	A := []int32{1, 2, 3, 4} // 2x2
	v := []int32{1, 0}
	m, n, q := 2, 2, 100
	res := matVecMulInt32(A, v, m, n, q)
	if res[0] != 1 || res[1] != 3 {
		t.Errorf("expected [1, 3], got %v", res)
	}
}

func TestKeyGen_ShortSeed(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS128)
	_, err := KeyGen(params.SLSS, make([]byte, 31))
	if err == nil {
		t.Error("expected error from KeyGen for short seed")
	}
}

func TestMatVecMul_Empty(t *testing.T) {
	res := matVecMul([]int32{}, []int8{}, 0, 0, 100)
	if len(res) != 0 {
		t.Error("expected empty result")
	}
}

func TestSampleMatrix_Empty(t *testing.T) {
	seed := make([]byte, 32)
	res := sampleMatrix(seed, 0, 0, 100)
	if len(res) != 0 {
		t.Error("expected empty result")
	}
}

func TestSampleMatrix_Coverage(t *testing.T) {
	seed := make([]byte, 32)
	A := sampleMatrix(seed, 2, 2, 100)
	if len(A) != 4 {
		t.Errorf("expected length 4, got %d", len(A))
	}
}

func TestSampleMatrix_Extension(t *testing.T) {
	seed := make([]byte, 32)
	// Large matrix to force extension
	A := sampleMatrix(seed, 500, 500, 3329)
	if len(A) != 250000 {
		t.Errorf("expected length 250000, got %d", len(A))
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
}

func TestSampleSparseVector_HighSparsity(t *testing.T) {
	seed, _ := utils.SecureRandomBytes(32)
	n := 100
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

func TestMatVecMul_Parallel(t *testing.T) {
	old := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(old)

	m, n := 200, 100
	A := make([]int32, m*n)
	v := make([]int8, n)
	for i := range A {
		A[i] = 1
	}
	for i := range v {
		v[i] = 1
	}

	res := matVecMul(A, v, m, n, 10000)
	if len(res) != m {
		t.Errorf("expected length %d, got %d", m, len(res))
	}
	// Each row should be n (100)
	for i, val := range res {
		if val != 100 {
			t.Errorf("row %d: expected 100, got %d", i, val)
			break
		}
	}
}
