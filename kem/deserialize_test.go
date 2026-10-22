package kem

import (
	"encoding/binary"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
)

func TestDeserializeSecretKey_Truncated(t *testing.T) {
	kp, err := GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		t.Fatal(err)
	}
	data := SerializeSecretKey(&kp.SecretKey, kp.PublicKey.Params)
	for _, cut := range []int{3, 11, len(data) / 3, len(data) / 2, len(data) - 1} {
		if _, err := DeserializeSecretKey(data[:cut]); err == nil {
			t.Errorf("expected error for secret key truncated to %d bytes", cut)
		}
	}
	bad := append([]byte{}, data...)
	bad[12] = 0xFF // first byte of the 2-bit packed S: the code 11 is not a ternary value
	if _, err := DeserializeSecretKey(bad); err == nil {
		t.Error("expected error for non-ternary SLSS entry")
	}
}

func TestDeserializeEncryptedMessage_Truncated(t *testing.T) {
	hdr := []byte{'k', 'M', 'O', 'S', 4, 4, 1, 0}
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(8))
	data := append(append(hdr, b...), []byte{0, 0, 0, 0}...)
	if _, _, err := DeserializeEncryptedMessage(data); err == nil {
		t.Fatalf("expected error for truncated encrypted message, got nil")
	}
	if _, _, err := DeserializeEncryptedMessage(hdr[:5]); err == nil {
		t.Fatalf("expected error for short header, got nil")
	}
}
