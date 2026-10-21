package kem

import (
	"encoding/binary"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
)

func TestDeserializeSLSSCiphertext_Truncated(t *testing.T) {
	data := make([]byte, 12)
	binary.LittleEndian.PutUint32(data[0:], uint32(12)) // claims 12 bytes of U, only 8 follow
	if _, err := deserializeSLSSCiphertext(data); err == nil {
		t.Fatalf("expected error for truncated SLSS ciphertext, got nil")
	}
	data = make([]byte, 8)
	binary.LittleEndian.PutUint32(data[0:], 2) // not a multiple of 4
	binary.LittleEndian.PutUint32(data[4:], 0)
	if _, err := deserializeSLSSCiphertext(data); err == nil {
		t.Fatalf("expected error for odd U length, got nil")
	}
}

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
	bad[20] = 5 // SLSS entry outside {-1,0,1}
	if _, err := DeserializeSecretKey(bad); err == nil {
		t.Error("expected error for non-ternary SLSS entry")
	}
}

func TestDeserializeEncryptedMessage_Truncated(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS_128)
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(8))
	data := append(b, []byte{0, 0, 0, 0}...)
	if _, err := DeserializeEncryptedMessage(data, params); err == nil {
		t.Fatalf("expected error for truncated encrypted message, got nil")
	}
}
