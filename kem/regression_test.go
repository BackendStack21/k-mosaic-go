package kem

import (
	"bytes"
	"encoding/binary"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
)

// TestDecapsulateMalformedCiphertextShape verifies that a ciphertext whose
// components have the wrong dimensions is implicitly rejected instead of
// crashing the process (the component decryptors used to index out of bounds
// inside goroutines, which no caller can recover from).
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
		"C1.U too long":           func(ct *kmosaic.MOSAICCiphertext) { ct.C1.U = make([]int32, len(ct.C1.U)+1) },
		"C1.U too short":          func(ct *kmosaic.MOSAICCiphertext) { ct.C1.U = ct.C1.U[:len(ct.C1.U)-1] },
		"C1.V wrong length":       func(ct *kmosaic.MOSAICCiphertext) { ct.C1.V = ct.C1.V[:8] },
		"C2.Data too short":       func(ct *kmosaic.MOSAICCiphertext) { ct.C2.Data = ct.C2.Data[:3] },
		"C2.Data empty":           func(ct *kmosaic.MOSAICCiphertext) { ct.C2.Data = nil },
		"C3.Commitment too short": func(ct *kmosaic.MOSAICCiphertext) { ct.C3.Commitment = ct.C3.Commitment[:5] },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			ct := res.Ciphertext
			ct.C1.U = append([]int32{}, ct.C1.U...)
			ct.C1.V = append([]int32{}, ct.C1.V...)
			ct.C2.Data = append([]int32{}, ct.C2.Data...)
			ct.C3.Commitment = append([]byte{}, ct.C3.Commitment...)
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

// TestDeserializeCiphertextTruncatedLengthFields verifies that a buffer which
// ends exactly where the next length prefix should start is rejected with an
// error rather than a panic.
func TestDeserializeCiphertextTruncatedLengthFields(t *testing.T) {
	// C1 length says 8 bytes, and the buffer ends right after them: no C2 length.
	data := make([]byte, 12)
	binary.LittleEndian.PutUint32(data[0:], 8)
	if _, err := DeserializeCiphertext(data); err == nil {
		t.Fatal("expected error for missing C2 length")
	}

	// Valid C1 and C2, buffer ends before the C3 length.
	data = make([]byte, 4+8+4+4)
	binary.LittleEndian.PutUint32(data[0:], 8)
	binary.LittleEndian.PutUint32(data[12:], 4)
	if _, err := DeserializeCiphertext(data); err == nil {
		t.Fatal("expected error for missing C3 length")
	}
}

// TestDeserializePublicKeyTruncatedLengthFields verifies that a public key
// buffer ending exactly where a component length prefix should start is
// rejected with an error rather than a panic.
func TestDeserializePublicKeyTruncatedLengthFields(t *testing.T) {
	level := []byte(kmosaic.MOS128)
	lenBuf := make([]byte, 4)

	// Level + minimal SLSS component (8 zero bytes), then end of buffer: no TDD length.
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(level)))
	data := append(append([]byte{}, lenBuf...), level...)
	binary.LittleEndian.PutUint32(lenBuf, 8)
	data = append(data, lenBuf...)
	data = append(data, make([]byte, 8)...)
	if _, err := DeserializePublicKey(data); err == nil {
		t.Fatal("expected error for missing TDD length")
	}

	// Same, plus a minimal TDD component (4 zero bytes), then end of buffer: no EGRW length.
	binary.LittleEndian.PutUint32(lenBuf, 4)
	data = append(data, lenBuf...)
	data = append(data, make([]byte, 4)...)
	if _, err := DeserializePublicKey(data); err == nil {
		t.Fatal("expected error for missing EGRW length")
	}
}
