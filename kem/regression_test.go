package kem

import (
	"bytes"
	"encoding/binary"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
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

// TestDeserializeCiphertextTruncatedLengthFields verifies that buffers ending
// where a length prefix should start are rejected rather than panicking.
func TestDeserializeCiphertextTruncatedLengthFields(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS_128)
	data := make([]byte, 12)
	binary.LittleEndian.PutUint32(data[0:], 8)
	if _, err := DeserializeCiphertext(data, params); err == nil {
		t.Fatal("expected error for missing C2 length")
	}
	kp, _ := GenerateKeyPair(kmosaic.MOS_128)
	res, _ := Encapsulate(&kp.PublicKey)
	full := SerializeCiphertext(&res.Ciphertext, params)
	for _, cut := range []int{1, 4, 100, len(full) / 2, len(full) - len(res.Ciphertext.Proof) - 1} {
		if _, err := DeserializeCiphertext(full[:cut], params); err == nil {
			t.Errorf("expected error for ciphertext truncated to %d bytes", cut)
		}
	}
}

// TestDeserializePublicKeyTruncatedLengthFields verifies that a public key
// buffer ending where a component length prefix should start is rejected.
func TestDeserializePublicKeyTruncatedLengthFields(t *testing.T) {
	level := []byte(kmosaic.MOS128)
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(level)))
	data := append(append([]byte{}, lenBuf...), level...)
	if _, err := DeserializePublicKey(data); err == nil {
		t.Fatal("expected error for missing SLSS length")
	}
	binary.LittleEndian.PutUint32(lenBuf, 8)
	data = append(data, lenBuf...)
	data = append(data, make([]byte, 8)...)
	if _, err := DeserializePublicKey(data); err == nil {
		t.Fatal("expected error for missing code length")
	}
	binary.LittleEndian.PutUint32(lenBuf, 4)
	data = append(data, lenBuf...)
	data = append(data, make([]byte, 4)...)
	if _, err := DeserializePublicKey(data); err == nil {
		t.Fatal("expected error for missing binding")
	}
}
