package kem

import (
	"bytes"
	"errors"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
)

// TestKeyGenRejectsWeakenedParameters pins the fix for key generation
// accepting any dimensions under a valid level label.
func TestKeyGenRejectsWeakenedParameters(t *testing.T) {
	p := core.MOS128Params
	p.SLSS.N, p.SLSS.M, p.SLSS.W = 16, 16, 1
	p.Code.W, p.Code.WR, p.Code.WE = 1, 1, 1
	if _, err := GenerateKeyPairFromSeed(p, make([]byte, SeedSize)); !errors.Is(err, kmosaic.ErrInvalidParams) {
		t.Fatalf("weakened parameters accepted: %v", err)
	}
	if _, err := GenerateKeyPair("bogus"); !errors.Is(err, kmosaic.ErrInvalidParams) {
		t.Fatalf("unknown level error does not wrap ErrInvalidParams: %v", err)
	}
	kp, _ := GenerateKeyPair(kmosaic.MOS_128)
	pk := kp.PublicKey
	pk.Params.Level = "bogus"
	if _, err := Encapsulate(&pk); !errors.Is(err, kmosaic.ErrInvalidParams) {
		t.Fatalf("encapsulation under a bogus level accepted: %v", err)
	}
	if _, err := EncapsulateDeterministic(&kp.PublicKey, make([]byte, 31)); !errors.Is(err, kmosaic.ErrInvalidParams) {
		t.Fatalf("31-byte ephemeral secret error does not wrap a sentinel: %v", err)
	}
}

// TestSerializersAreNilSafe checks that no serializer panics on nil or
// produces unparsable bytes for mis-shaped inputs.
func TestSerializersAreNilSafe(t *testing.T) {
	params := core.MOS128Params
	if SerializePublicKey(nil) != nil || SerializeSecretKey(nil, params) != nil ||
		SerializeCiphertext(nil, params) != nil || SerializeEncryptedMessage(nil, params) != nil || PublicKeyHash(nil) != nil {
		t.Fatal("nil input serialized to non-nil bytes")
	}
	var zeroCT kmosaic.MOSAICCiphertext
	var zeroSK kmosaic.MOSAICSecretKey
	var zeroPK kmosaic.MOSAICPublicKey
	if SerializeCiphertext(&zeroCT, params) != nil || SerializeSecretKey(&zeroSK, params) != nil || SerializePublicKey(&zeroPK) != nil {
		t.Fatal("zero-value struct serialized to bytes that cannot be parsed back")
	}
}

// TestDecapsulateRejectsNonCanonicalStructs checks that an in-memory
// ciphertext with out-of-range coefficients or padding bits is handled the
// same way in every component: it is rejected (implicit rejection), rather
// than accepted in one component and rejected in the other.
func TestDecapsulateRejectsNonCanonicalStructs(t *testing.T) {
	kp, _ := GenerateKeyPair(kmosaic.MOS_128)
	res, _ := Encapsulate(&kp.PublicKey)
	good, err := Decapsulate(&kp.SecretKey, &kp.PublicKey, &res.Ciphertext)
	if err != nil || !bytes.Equal(good, res.SharedSecret) {
		t.Fatal("valid ciphertext does not decapsulate")
	}
	mutations := []struct {
		name string
		mut  func(ct *kmosaic.MOSAICCiphertext)
	}{
		{"slss U out of range (serializes identically)", func(ct *kmosaic.MOSAICCiphertext) { ct.C1.U[0] += 2048 }},
		{"slss V negative", func(ct *kmosaic.MOSAICCiphertext) { ct.C1.V[0] = -1 }},
		{"code padding bit", func(ct *kmosaic.MOSAICCiphertext) { ct.C2.U[len(ct.C2.U)-1] |= 1 << 63 }},
	}
	for _, m := range mutations {
		ct := kmosaic.MOSAICCiphertext{
			C1: kmosaic.SLSSCiphertext{U: append([]int32{}, res.Ciphertext.C1.U...), V: append([]int32{}, res.Ciphertext.C1.V...)},
			C2: kmosaic.CodeCiphertext{U: append([]uint64{}, res.Ciphertext.C2.U...), V: append([]uint64{}, res.Ciphertext.C2.V...)},
		}
		m.mut(&ct)
		ss, err := Decapsulate(&kp.SecretKey, &kp.PublicKey, &ct)
		if err != nil {
			t.Fatalf("%s: error %v", m.name, err)
		}
		if bytes.Equal(ss, res.SharedSecret) {
			t.Fatalf("%s: non-canonical ciphertext accepted with the real shared secret", m.name)
		}
	}
}

// TestDecapsulateRejectsMalformedSecretKey checks that a secret key with
// missing components is an error, not a silent implicit rejection.
func TestDecapsulateRejectsMalformedSecretKey(t *testing.T) {
	kp, _ := GenerateKeyPair(kmosaic.MOS_128)
	res, _ := Encapsulate(&kp.PublicKey)
	sk := kmosaic.MOSAICSecretKey{Seed: kp.SecretKey.Seed, PublicKeyHash: kp.SecretKey.PublicKeyHash}
	if _, err := Decapsulate(&sk, &kp.PublicKey, &res.Ciphertext); !errors.Is(err, kmosaic.ErrInvalidKey) {
		t.Fatalf("secret key without components accepted: %v", err)
	}
}
