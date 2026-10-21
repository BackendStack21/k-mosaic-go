package entanglement

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/BackendStack21/k-mosaic-go/utils"
)

// TestVerifyNIZKProof_OversizedResponse verifies that a structurally valid
// proof whose response part claims a share longer than the 32-byte mask is
// rejected instead of panicking on a slice out of range.
func TestVerifyNIZKProof_OversizedResponse(t *testing.T) {
	message := []byte("m")
	hashes := [][]byte{make([]byte, 32), make([]byte, 32), make([]byte, 32)}

	parts := [][]byte{
		nil,              // challenge, filled in below
		make([]byte, 32), // commitments
		make([]byte, 32),
		make([]byte, 32),
		make([]byte, 100), // response with a 68-byte "share"
		make([]byte, 64),
		make([]byte, 64),
	}
	secretMsg := utils.HashWithDomain(DomainNIZK+"-msg", message)
	parts[0] = utils.SHA3256(utils.HashConcat(secretMsg, parts[1], parts[2], parts[3], hashes[0], hashes[1], hashes[2]))

	buf := &bytes.Buffer{}
	_ = binary.Write(buf, binary.LittleEndian, uint32(len(parts)))
	for _, p := range parts {
		_ = binary.Write(buf, binary.LittleEndian, uint32(len(p)))
		buf.Write(p)
	}

	if VerifyNIZKProof(buf.Bytes(), hashes, message) {
		t.Fatal("proof with oversized response must not verify")
	}
}

// TestGenerateNIZKProof_OversizedShare verifies that shares longer than the
// mask are refused rather than panicking.
func TestGenerateNIZKProof_OversizedShare(t *testing.T) {
	shares := [][]byte{make([]byte, 33), make([]byte, 32), make([]byte, 32)}
	hashes := [][]byte{make([]byte, 32), make([]byte, 32), make([]byte, 32)}
	if p := GenerateNIZKProof(make([]byte, 32), shares, hashes, make([]byte, 32)); p != nil {
		t.Fatal("expected nil proof for oversized share")
	}
}
