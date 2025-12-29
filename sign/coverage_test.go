package sign

import (
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

func TestSign_Coverage(t *testing.T) {
	keys, _ := GenerateKeyPair(kmosaic.MOS128)
	msg := []byte("hello world")

	sig, err := Sign(&keys.SecretKey, &keys.PublicKey, msg)
	if err != nil {
		t.Fatal(err)
	}
	if sig == nil {
		t.Error("signature should not be nil")
	}
}

func TestVerify_Coverage(t *testing.T) {
	keys, _ := GenerateKeyPair(kmosaic.MOS128)
	msg := []byte("hello world")

	sig, _ := Sign(&keys.SecretKey, &keys.PublicKey, msg)
	valid := Verify(&keys.PublicKey, msg, sig)
	if !valid {
		t.Error("signature should be valid")
	}
}

func TestVerify_Invalid(t *testing.T) {
	keys, _ := GenerateKeyPair(kmosaic.MOS128)
	msg := []byte("hello world")

	sig, _ := Sign(&keys.SecretKey, &keys.PublicKey, msg)
	// Modify signature
	sig.Commitment[0] ^= 0xFF
	valid := Verify(&keys.PublicKey, msg, sig)
	if valid {
		t.Error("modified signature should be invalid")
	}
}

func TestVerify_WrongMessage(t *testing.T) {
	keys, _ := GenerateKeyPair(kmosaic.MOS128)
	msg := []byte("hello world")

	sig, _ := Sign(&keys.SecretKey, &keys.PublicKey, msg)
	valid := Verify(&keys.PublicKey, []byte("wrong message"), sig)
	if valid {
		t.Error("signature for wrong message should be invalid")
	}
}

func TestVerify_ShortSignature(t *testing.T) {
	keys, _ := GenerateKeyPair(kmosaic.MOS128)

	// Create signature with wrong lengths
	sig := &kmosaic.MOSAICSignature{
		Commitment: make([]byte, 10),
		Challenge:  make([]byte, 32),
		Response:   make([]byte, 64),
	}
	valid := Verify(&keys.PublicKey, []byte("test"), sig)
	if valid {
		t.Error("signature with wrong commitment length should be invalid")
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

func TestSign_RandError(t *testing.T) {
	keys, _ := GenerateKeyPair(kmosaic.MOS128)

	old := utils.RandReader
	utils.RandReader = &errorReader{}
	defer func() { utils.RandReader = old }()

	_, err := Sign(&keys.SecretKey, &keys.PublicKey, []byte("test"))
	if err == nil {
		t.Error("expected error from rand failure")
	}
}

func TestSerializePublicKey_Coverage(t *testing.T) {
	keys, _ := GenerateKeyPair(kmosaic.MOS128)
	bytes := SerializePublicKey(&keys.PublicKey)
	if len(bytes) == 0 {
		t.Error("serialized public key should not be empty")
	}
}

func TestSerializeSignature_Coverage(t *testing.T) {
	keys, _ := GenerateKeyPair(kmosaic.MOS128)
	sig, _ := Sign(&keys.SecretKey, &keys.PublicKey, []byte("test"))
	bytes := SerializeSignature(sig)
	if len(bytes) == 0 {
		t.Error("serialized signature should not be empty")
	}
}

type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("simulated rand error")
}
