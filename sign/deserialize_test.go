package sign

import (
	"encoding/binary"
	"testing"
)

func TestDeserializeSecretKey_Truncated(t *testing.T) {
	// Construct minimal signature secret key where TDD factor A claims vecLen=3 but only 1 element provided
	buf := make([]byte, 0)
	b := make([]byte, 4)
	// slssLen = 1
	binary.LittleEndian.PutUint32(b, uint32(1))
	buf = append(buf, b...)
	// one byte of SLSS.S
	buf = append(buf, byte(0))
	// factorCount = 1
	binary.LittleEndian.PutUint32(b, uint32(1))
	buf = append(buf, b...)
	// vecLen = 3
	binary.LittleEndian.PutUint32(b, uint32(3))
	buf = append(buf, b...)
	// provide only 1 element
	binary.LittleEndian.PutUint32(b, uint32(0))
	buf = append(buf, b...)

	if _, err := DeserializeSecretKey(buf); err == nil {
		t.Fatalf("expected error for truncated signature secret key, got nil")
	}
}

func TestDeserializeSignature_Truncated(t *testing.T) {
	// commitLen = 16 but provide only 8 bytes overall -> should error
	b := make([]byte, 4)
	data := make([]byte, 0)
	binary.LittleEndian.PutUint32(b, uint32(16))
	data = append(data, b...)
	// only 8 bytes of commitment data and no further bytes
	data = append(data, make([]byte, 8)...)

	if _, err := DeserializeSignature(data); err == nil {
		t.Fatalf("expected error for truncated signature, got nil")
	}
}
