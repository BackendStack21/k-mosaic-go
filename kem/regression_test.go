package kem

import (
	"bytes"
	"errors"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go/v4"
)

// TestDecapsulateMalformedCiphertextShape verifies that a ciphertext whose
// components have the wrong dimensions is implicitly rejected instead of
// crashing the process.
func TestDecapsulateMalformedCiphertextShape(t *testing.T) {
	kp, err := GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	res, err := Encapsulate(&kp.PublicKey)
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}

	cases := map[string]func(ct *kmosaic.MOSAICCiphertext){
		"C1.U too long":  func(ct *kmosaic.MOSAICCiphertext) { ct.C1.U = make([]int32, len(ct.C1.U)+1) },
		"C1.U too short": func(ct *kmosaic.MOSAICCiphertext) { ct.C1.U = ct.C1.U[:len(ct.C1.U)-1] },
		"C1.V wrong":     func(ct *kmosaic.MOSAICCiphertext) { ct.C1.V = ct.C1.V[:8] },
		"C2.U too short": func(ct *kmosaic.MOSAICCiphertext) { ct.C2.U = ct.C2.U[:3] },
		"C2.V empty":     func(ct *kmosaic.MOSAICCiphertext) { ct.C2.V = nil },
		"C2.V too long":  func(ct *kmosaic.MOSAICCiphertext) { ct.C2.V = make([]uint64, len(ct.C2.V)+1) },
		"everything nil": func(ct *kmosaic.MOSAICCiphertext) { *ct = kmosaic.MOSAICCiphertext{} },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			ct := res.Ciphertext
			ct.C1.U = append([]int32{}, ct.C1.U...)
			ct.C1.V = append([]int32{}, ct.C1.V...)
			ct.C2.U = append([]uint64{}, ct.C2.U...)
			ct.C2.V = append([]uint64{}, ct.C2.V...)
			mutate(&ct)

			ss, err := Decapsulate(&kp.SecretKey, &kp.PublicKey, &ct)
			if err != nil {
				t.Fatalf("Decapsulate returned error: %v", err)
			}
			if len(ss) != 32 {
				t.Fatalf("expected 32-byte rejection secret, got %d bytes", len(ss))
			}
			if bytes.Equal(ss, res.SharedSecret) {
				t.Fatal("malformed ciphertext produced the real shared secret")
			}
		})
	}
}

// TestDeserializeTruncatedAndOversized verifies that every parser rejects
// truncated input, trailing data and huge length prefixes without panicking.
func TestDeserializeTruncatedAndOversized(t *testing.T) {
	kp, _ := GenerateKeyPair(kmosaic.MOS_128)
	params := kp.PublicKey.Params
	res, _ := Encapsulate(&kp.PublicKey)
	ctBytes := SerializeCiphertext(&res.Ciphertext, params)
	pkBytes := SerializePublicKey(&kp.PublicKey)
	skBytes := SerializeSecretKey(&kp.SecretKey, params)

	for _, cut := range []int{0, 3, 8, 12, 100, len(ctBytes) / 2, len(ctBytes) - 1} {
		if _, _, err := DeserializeCiphertext(ctBytes[:cut]); err == nil {
			t.Errorf("ciphertext truncated to %d bytes accepted", cut)
		}
	}
	if _, _, err := DeserializeCiphertext(append(append([]byte{}, ctBytes...), 0)); err == nil {
		t.Error("ciphertext with trailing byte accepted")
	}
	for _, cut := range []int{8, 12, len(pkBytes) / 2, len(pkBytes) - 1} {
		if _, err := DeserializePublicKey(pkBytes[:cut]); err == nil {
			t.Errorf("public key truncated to %d bytes accepted", cut)
		}
	}
	for _, cut := range []int{8, 12, len(skBytes) / 2, len(skBytes) - 1} {
		if _, err := DeserializeSecretKey(skBytes[:cut]); err == nil {
			t.Errorf("secret key truncated to %d bytes accepted", cut)
		}
	}
	// Huge length prefix right after the header.
	huge := append([]byte{}, ctBytes[:8]...)
	huge = append(huge, 0xff, 0xff, 0xff, 0xff, 1, 2, 3)
	if _, _, err := DeserializeCiphertext(huge); err == nil {
		t.Error("huge C1 length accepted")
	}
}

// TestDecapsulateRequiresMatchingPublicKey verifies the key-mismatch oracle is closed.
func TestDecapsulateRequiresMatchingPublicKey(t *testing.T) {
	kp1, _ := GenerateKeyPair(kmosaic.MOS_128)
	kp2, _ := GenerateKeyPair(kmosaic.MOS_128)
	res, _ := Encapsulate(&kp1.PublicKey)
	if _, err := Decapsulate(&kp1.SecretKey, &kp2.PublicKey, &res.Ciphertext); !errors.Is(err, kmosaic.ErrKeyMismatch) {
		t.Fatalf("expected ErrKeyMismatch, got %v", err)
	}
	if _, err := Decapsulate(&kp1.SecretKey, &kp1.PublicKey, nil); err == nil {
		t.Fatal("nil ciphertext accepted")
	}
	if _, err := Decapsulate(nil, &kp1.PublicKey, &res.Ciphertext); err == nil {
		t.Fatal("nil secret key accepted")
	}
}
