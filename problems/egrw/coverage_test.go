package egrw

import (
	"bytes"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

func TestModInverse_One(t *testing.T) {
	inv := ModInverse(1, 7)
	if inv != 1 {
		t.Errorf("expected 1, got %d", inv)
	}
}

func TestModInverse_General(t *testing.T) {
	inv := ModInverse(3, 7)
	if (3*inv)%7 != 1 {
		t.Errorf("expected (3*%d) mod 7 = 1", inv)
	}
}

func TestModInverse_Negative(t *testing.T) {
	inv := ModInverse(-3, 7)
	expected := ((-3%7 + 7) * inv) % 7
	if expected != 1 {
		t.Errorf("expected 1, got %d", expected)
	}
}

func TestModInverse_PanicZero(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for a=0")
		}
	}()
	ModInverse(0, 7)
}

func TestGetGenerators_CacheHit(t *testing.T) {
	g1 := GetGenerators(7)
	g2 := GetGenerators(7)
	if len(g1) != len(g2) {
		t.Error("expected same length from cache")
	}
	// Check if slice contents are identical (same cache hit)
	for i := range g1 {
		if g1[i] != g2[i] {
			t.Error("expected same elements from cache")
		}
	}
}

func TestGetGenerators_DifferentPrimes(t *testing.T) {
	g7 := GetGenerators(7)
	g11 := GetGenerators(11)
	// Should have same structure (4 generators each)
	if len(g7) != 4 || len(g11) != 4 {
		t.Error("expected 4 generators each")
	}
}

func TestSampleSL2Element_Coverage(t *testing.T) {
	seed, _ := utils.SecureRandomBytes(32)
	p := 7
	elem := sampleSL2Element(seed, p)

	// Check det = 1
	det := (elem.A*elem.D - elem.B*elem.C) % p
	if det < 0 {
		det += p
	}
	if det != 1 {
		t.Errorf("expected det=1, got %d", det)
	}
}

func TestKeyGen_ShortSeed(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS128)
	_, err := KeyGen(params.EGRW, make([]byte, 31))
	if err == nil {
		t.Error("expected error from KeyGen for short seed")
	}
}

func TestKeyGen_Coverage(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS128)
	seed, _ := utils.SecureRandomBytes(32)
	keys, err := KeyGen(params.EGRW, seed)
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
	keys, err := KeyGen(params.EGRW, seed)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("test message for EGRW coverage")
	randomness, _ := utils.SecureRandomBytes(32)
	ct, err := Encrypt(keys.PublicKey, msg, params.EGRW, randomness)
	if err != nil {
		t.Fatal(err)
	}

	dec := Decrypt(ct, keys.SecretKey, keys.PublicKey, params.EGRW)
	if !bytes.HasPrefix(dec, msg) {
		t.Errorf("decrypted message does not match original")
	}
}

func TestEncrypt_ShortRandomness(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS128)
	seed, _ := utils.SecureRandomBytes(32)
	keys, err := KeyGen(params.EGRW, seed)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Encrypt(keys.PublicKey, []byte("test"), params.EGRW, make([]byte, 10))
	if err == nil {
		t.Error("expected error for short randomness")
	}
}

func TestSL2Multiply_Coverage(t *testing.T) {
	m1 := kmosaic.SL2Element{A: 1, B: 1, C: 0, D: 1}
	m2 := kmosaic.SL2Element{A: 1, B: 0, C: 1, D: 1}
	result := SL2Multiply(m1, m2, 7)
	// Verify result is a valid SL(2) element
	det := (result.A*result.D - result.B*result.C) % 7
	if det < 0 {
		det += 7
	}
	if det != 1 {
		t.Errorf("expected det=1, got %d", det)
	}
}

func TestSL2Inverse_Coverage(t *testing.T) {
	m := kmosaic.SL2Element{A: 1, B: 1, C: 0, D: 1}
	inv := SL2Inverse(m, 7)
	// m * inv should be identity
	prod := SL2Multiply(m, inv, 7)
	if prod.A != 1 || prod.B != 0 || prod.C != 0 || prod.D != 1 {
		t.Errorf("expected identity, got %v", prod)
	}
}

func TestApplyWalk_Coverage(t *testing.T) {
	start := kmosaic.SL2Element{A: 1, B: 0, C: 0, D: 1}
	walk := []int{0, 1, 2, 3}
	result := ApplyWalk(start, walk, 7)
	// Just verify it returns a valid SL(2) element
	det := (result.A*result.D - result.B*result.C) % 7
	if det < 0 {
		det += 7
	}
	if det != 1 {
		t.Errorf("expected det=1, got %d", det)
	}
}
