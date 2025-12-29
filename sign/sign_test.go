package sign

import (
	"bytes"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

func TestSign_Failures(t *testing.T) {
	kp, _ := GenerateKeyPair(kmosaic.MOS_128)
	msg := []byte("message")
	sig, _ := Sign(&kp.SecretKey, &kp.PublicKey, msg)

	// Test modified message
	if Verify(&kp.PublicKey, []byte("wrong"), sig) {
		t.Error("Verify passed with wrong message")
	}

	// Test modified signature
	badSig := *sig
	badSig.Challenge[0] ^= 1
	if Verify(&kp.PublicKey, msg, &badSig) {
		t.Error("Verify passed with modified challenge")
	}

	badSig = *sig
	badSig.Response[0] ^= 1
	if Verify(&kp.PublicKey, msg, &badSig) {
		t.Error("Verify passed with modified response")
	}
}

func TestSign_Deterministic(t *testing.T) {
	seed, _ := utils.SecureRandomBytes(32)
	params, _ := core.GetParams(kmosaic.MOS_128)

	kp1, err := GenerateKeyPairFromSeed(params, seed)
	if err != nil {
		t.Fatalf("GenerateKeyPairFromSeed failed: %v", err)
	}

	kp2, err := GenerateKeyPairFromSeed(params, seed)
	if err != nil {
		t.Fatalf("GenerateKeyPairFromSeed failed: %v", err)
	}

	pk1 := SerializePublicKey(&kp1.PublicKey)
	pk2 := SerializePublicKey(&kp2.PublicKey)
	if !bytes.Equal(pk1, pk2) {
		t.Error("GenerateKeyPairFromSeed not deterministic")
	}
}

func TestSerialization(t *testing.T) {
	kp, _ := GenerateKeyPair(kmosaic.MOS_128)
	msg := []byte("message")
	sig, _ := Sign(&kp.SecretKey, &kp.PublicKey, msg)

	pkBytes := SerializePublicKey(&kp.PublicKey)
	if len(pkBytes) == 0 {
		t.Error("SerializePublicKey returned empty bytes")
	}

	sigBytes := SerializeSignature(sig)
	if len(sigBytes) == 0 {
		t.Error("SerializeSignature returned empty bytes")
	}
}
