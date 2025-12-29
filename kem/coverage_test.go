package kem

import (
	"bytes"
	"errors"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

func TestGenerateKeyPair_Coverage(t *testing.T) {
	keys, err := GenerateKeyPair(kmosaic.MOS128)
	if err != nil {
		t.Fatal(err)
	}
	if keys == nil {
		t.Error("keys should not be nil")
	}
}

func TestGenerateKeyPairFromSeed_Coverage(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS128)
	seed, _ := utils.SecureRandomBytes(32)
	keys, err := GenerateKeyPairFromSeed(params, seed)
	if err != nil {
		t.Fatal(err)
	}
	if keys == nil {
		t.Error("keys should not be nil")
	}
}

func TestGenerateKeyPairFromSeed_ShortSeed(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS128)
	_, err := GenerateKeyPairFromSeed(params, make([]byte, 10))
	if err == nil {
		t.Error("expected error for short seed")
	}
}

func TestEncapsulate_Coverage(t *testing.T) {
	keys, _ := GenerateKeyPair(kmosaic.MOS128)

	result, err := Encapsulate(&keys.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Error("encapsulation result should not be nil")
	}
}

func TestEncapsulateDeterministic_Coverage(t *testing.T) {
	keys, _ := GenerateKeyPair(kmosaic.MOS128)
	randomness, _ := utils.SecureRandomBytes(32)

	result, err := EncapsulateDeterministic(&keys.PublicKey, randomness)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Error("encapsulation result should not be nil")
	}
}

func TestEncapsulateDeterministic_ShortRandomness(t *testing.T) {
	keys, _ := GenerateKeyPair(kmosaic.MOS128)

	_, err := EncapsulateDeterministic(&keys.PublicKey, make([]byte, 10))
	if err == nil {
		t.Error("expected error for short randomness")
	}
}

func TestDecapsulate_Coverage(t *testing.T) {
	keys, _ := GenerateKeyPair(kmosaic.MOS128)
	encap, _ := Encapsulate(&keys.PublicKey)

	ss, err := Decapsulate(&keys.SecretKey, &keys.PublicKey, &encap.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ss, encap.SharedSecret) {
		t.Error("shared secrets should match")
	}
}

func TestEncrypt_Coverage(t *testing.T) {
	keys, _ := GenerateKeyPair(kmosaic.MOS128)
	msg := []byte("hello world")

	ct, err := Encrypt(&keys.PublicKey, msg)
	if err != nil {
		t.Fatal(err)
	}
	if ct == nil {
		t.Error("ciphertext should not be nil")
	}
}

func TestDecrypt_Coverage(t *testing.T) {
	keys, _ := GenerateKeyPair(kmosaic.MOS128)
	msg := []byte("hello world")

	ct, _ := Encrypt(&keys.PublicKey, msg)
	dec, err := Decrypt(&keys.SecretKey, &keys.PublicKey, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, msg) {
		t.Errorf("expected %s, got %s", msg, dec)
	}
}

func TestGenerateKeyPair_RandError(t *testing.T) {
	old := utils.RandReader
	utils.RandReader = &errorReader{}
	defer func() { utils.RandReader = old }()

	_, err := GenerateKeyPair(kmosaic.MOS128)
	if err == nil {
		t.Error("expected error from rand failure")
	}
}

func TestEncapsulate_RandError(t *testing.T) {
	keys, _ := GenerateKeyPair(kmosaic.MOS128)

	old := utils.RandReader
	utils.RandReader = &errorReader{}
	defer func() { utils.RandReader = old }()

	_, err := Encapsulate(&keys.PublicKey)
	if err == nil {
		t.Error("expected error from rand failure")
	}
}

func TestEncrypt_RandError(t *testing.T) {
	keys, _ := GenerateKeyPair(kmosaic.MOS128)

	old := utils.RandReader
	utils.RandReader = &errorReader{}
	defer func() { utils.RandReader = old }()

	_, err := Encrypt(&keys.PublicKey, []byte("test"))
	if err == nil {
		t.Error("expected error from rand failure")
	}
}

type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("simulated rand error")
}
