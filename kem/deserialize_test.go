package kem

import (
	"encoding/binary"
	"testing"
)

func TestDeserializeSLSSCiphertext_Truncated(t *testing.T) {
	// uLen=3 but only 1 element provided -> should error
	data := make([]byte, 12)
	binary.LittleEndian.PutUint32(data[0:], uint32(3)) // uLen=3
	binary.LittleEndian.PutUint32(data[4:], uint32(1)) // only one element
	binary.LittleEndian.PutUint32(data[8:], uint32(0)) // vLen=0
	if _, err := deserializeSLSSCiphertext(data); err == nil {
		t.Fatalf("expected error for truncated SLSS ciphertext, got nil")
	}
}

func TestDeserializeTDDCiphertext_Truncated(t *testing.T) {
	// dataLen=5 but no data provided -> should error
	data := make([]byte, 8)
	binary.LittleEndian.PutUint32(data[0:], uint32(5))
	if _, err := deserializeTDDCiphertext(data); err == nil {
		t.Fatalf("expected error for truncated TDD ciphertext, got nil")
	}
}

func TestDeserializeSecretKey_Truncated(t *testing.T) {
	// Construct a minimal secret key where TDD factor A claims vecLen=3 but only 1 element provided
	buf := make([]byte, 0)
	// slssLen = 1
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(1))
	buf = append(buf, b...)
	// one byte of SLSS.S
	buf = append(buf, byte(0))
	// factorCount = 1
	binary.LittleEndian.PutUint32(b, uint32(1))
	buf = append(buf, b...)
	// vecLen = 3 (claims 3 elements)
	binary.LittleEndian.PutUint32(b, uint32(3))
	buf = append(buf, b...)
	// provide only 1 element (4 bytes)
	binary.LittleEndian.PutUint32(b, uint32(0))
	buf = append(buf, b...)

	if _, err := DeserializeSecretKey(buf); err == nil {
		t.Fatalf("expected error for truncated secret key, got nil")
	}
}

func TestDeserializeEncryptedMessage_Truncated(t *testing.T) {
	// ctLen = 8 but provide only 4 bytes for ciphertext
	b := make([]byte, 4)
	data := make([]byte, 0)
	binary.LittleEndian.PutUint32(b, uint32(8))
	data = append(data, b...)
	// provide only 4 bytes
	data = append(data, []byte{0, 0, 0, 0}...)
	// encrypted payload length=0
	binary.LittleEndian.PutUint32(b, uint32(0))
	data = append(data, b...)
	// nonce length=0
	binary.LittleEndian.PutUint32(b, uint32(0))
	data = append(data, b...)

	if _, err := DeserializeEncryptedMessage(data); err == nil {
		t.Fatalf("expected error for truncated encrypted message, got nil")
	}
}
