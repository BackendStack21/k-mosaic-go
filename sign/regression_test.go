package sign

import (
	"encoding/binary"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
)

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

	// Plus a minimal TDD component (4 zero bytes), then end of buffer: no EGRW length.
	binary.LittleEndian.PutUint32(lenBuf, 4)
	data = append(data, lenBuf...)
	data = append(data, make([]byte, 4)...)
	if _, err := DeserializePublicKey(data); err == nil {
		t.Fatal("expected error for missing EGRW length")
	}
}
