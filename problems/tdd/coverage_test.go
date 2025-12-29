package tdd

import (
	"bytes"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

func TestKeyGen_ShortSeed(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS128)
	_, err := KeyGen(params.TDD, make([]byte, 31))
	if err == nil {
		t.Error("expected error for short seed")
	}
}

func TestKeyGen_Coverage(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS128)
	seed, _ := utils.SecureRandomBytes(32)
	keys, err := KeyGen(params.TDD, seed)
	if err != nil {
		t.Fatal(err)
	}
	if keys == nil {
		t.Error("keys should not be nil")
	}
}

func TestEncryptDecrypt_Coverage(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS128)
	seed, _ := utils.SecureRandomBytes(32)
	keys, err := KeyGen(params.TDD, seed)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("test message for TDD")
	randomness, _ := utils.SecureRandomBytes(32)
	ct, err := Encrypt(keys.PublicKey, msg, params.TDD, randomness)
	if err != nil {
		t.Fatal(err)
	}

	dec := Decrypt(ct, keys.SecretKey, keys.PublicKey, params.TDD)
	if !bytes.HasPrefix(dec, msg) {
		t.Errorf("decrypted message does not match original")
	}
}

func TestEncrypt_ShortRandomness(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS128)
	seed, _ := utils.SecureRandomBytes(32)
	keys, err := KeyGen(params.TDD, seed)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Encrypt(keys.PublicKey, []byte("test"), params.TDD, make([]byte, 10))
	if err == nil {
		t.Error("expected error for short randomness")
	}
}

func TestSampleTensorFactors_Coverage(t *testing.T) {
	seed, _ := utils.SecureRandomBytes(32)
	params, _ := core.GetParams(kmosaic.MOS128)
	factors := sampleTensorFactors(seed, params.TDD.N, params.TDD.R, params.TDD.Q)
	if len(factors.A) != params.TDD.R {
		t.Errorf("expected %d A factors, got %d", params.TDD.R, len(factors.A))
	}
	if len(factors.B) != params.TDD.R {
		t.Errorf("expected %d B factors, got %d", params.TDD.R, len(factors.B))
	}
	if len(factors.C) != params.TDD.R {
		t.Errorf("expected %d C factors, got %d", params.TDD.R, len(factors.C))
	}
}

func TestSampleTensorFactors_SmallParams(t *testing.T) {
	seed, _ := utils.SecureRandomBytes(32)
	n, r, q := 4, 2, 7
	factors := sampleTensorFactors(seed, n, r, q)
	if len(factors.A) != r {
		t.Errorf("expected %d factors, got %d", r, len(factors.A))
	}
	for i := 0; i < r; i++ {
		if len(factors.A[i]) != n {
			t.Errorf("factor A[%d]: expected length %d, got %d", i, n, len(factors.A[i]))
		}
	}
}

func TestEncrypt_EmptyMessage(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS128)
	seed, _ := utils.SecureRandomBytes(32)
	keys, err := KeyGen(params.TDD, seed)
	if err != nil {
		t.Fatal(err)
	}

	randomness, _ := utils.SecureRandomBytes(32)
	ct, err := Encrypt(keys.PublicKey, []byte{}, params.TDD, randomness)
	if err != nil {
		t.Fatal(err)
	}
	if ct == nil {
		t.Error("ciphertext should not be nil")
	}
}

func TestTensorAdd_Coverage(t *testing.T) {
	A := []int32{1, 2, 3, 4}
	B := []int32{5, 6, 7, 8}
	result := tensorAdd(A, B, 10)
	expected := []int32{6, 8, 0, 2}
	for i, v := range result {
		if v != expected[i] {
			t.Errorf("index %d: expected %d, got %d", i, expected[i], v)
		}
	}
}

func TestTensorContractedProduct_Coverage(t *testing.T) {
	n := 2
	T := make([]int32, n*n*n)
	for i := range T {
		T[i] = int32(i + 1)
	}
	lambda := []int32{1, 0}
	result := tensorContractedProduct(T, lambda, n, 2, 100)
	if len(result) != n*n {
		t.Errorf("expected length %d, got %d", n*n, len(result))
	}
}

func TestSerializePublicKey_Coverage(t *testing.T) {
	pk := kmosaic.TDDPublicKey{T: []int32{1, 2, 3, 4}}
	bytes := SerializePublicKey(pk)
	if len(bytes) != 4+4*4 {
		t.Errorf("expected length %d, got %d", 4+4*4, len(bytes))
	}
}
