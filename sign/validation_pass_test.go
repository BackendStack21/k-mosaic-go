package sign

import (
	"errors"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go/v2"
	"github.com/BackendStack21/k-mosaic-go/v2/core"
)

func TestSerializersRefuseMismatchedParams(t *testing.T) {
	kp, err := GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(&kp.SecretKey, &kp.PublicKey, []byte("m"))
	if err != nil {
		t.Fatal(err)
	}
	if SerializeSignature(sig, core.Sign256Params) != nil {
		t.Fatal("MOS-128 signature serialized under MOS-256 parameters")
	}
	if SerializeSignature(nil, core.Sign128Params) != nil || SerializePublicKey(nil) != nil || SerializeSecretKey(nil) != nil || PublicKeyHash(nil) != nil {
		t.Fatal("nil input serialized to non-nil bytes")
	}
	var zeroSig kmosaic.MOSAICSignature
	var zeroPK kmosaic.MOSAICSignPublicKey
	var zeroSK kmosaic.MOSAICSignSecretKey
	if SerializeSignature(&zeroSig, core.Sign128Params) != nil || SerializePublicKey(&zeroPK) != nil || SerializeSecretKey(&zeroSK) != nil {
		t.Fatal("zero-value struct serialized to bytes that cannot be parsed back")
	}
	pk := kp.PublicKey
	pk.Params = core.Sign256Params
	if SerializePublicKey(&pk) != nil {
		t.Fatal("MOS-128 public key serialized under MOS-256 parameters")
	}
	if _, err := GenerateKeyPair("bogus"); !errors.Is(err, kmosaic.ErrInvalidParams) {
		t.Fatalf("unknown level error does not wrap ErrInvalidParams: %v", err)
	}
	sk := kp.SecretKey
	sk.Params.MQ.N = 100
	if _, err := Sign(&sk, nil, []byte("m")); !errors.Is(err, kmosaic.ErrInvalidParams) {
		t.Fatalf("signing with altered parameters accepted: %v", err)
	}
}

// TestComponentPanicIsAnError checks that a panic inside a component call
// surfaces as an error from the composite instead of crashing the process.
func TestComponentPanicIsAnError(t *testing.T) {
	kp, _ := GenerateKeyPair(kmosaic.MOS_128)
	sk := kp.SecretKey
	sk.Hash.Seed = nil // slhdsa rejects this; a nil Prepared layout below exercises uov's checks
	if _, err := Sign(&sk, nil, []byte("m")); err == nil {
		t.Fatal("signing with a broken component succeeded")
	}
	pk := kp.PublicKey
	pk.MQ.P3 = pk.MQ.P3[:10]
	if Verify(&pk, []byte("m"), &kmosaic.MOSAICSignature{Nonce: make([]byte, NonceSize)}) {
		t.Fatal("verification with a broken component succeeded")
	}
}
