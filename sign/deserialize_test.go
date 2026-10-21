package sign

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
	data := SerializeSecretKey(&kp.SecretKey)

	for _, cut := range []int{len(data) - 1, len(data) / 2, 4 + len(kmosaic.MOS128) + SeedSize, 3} {
		if _, err := DeserializeSecretKey(data[:cut]); err == nil {
			t.Errorf("expected error for secret key truncated to %d bytes", cut)
		}
	}
	if _, err := DeserializeSecretKey(append(append([]byte{}, data...), 0)); err == nil {
		t.Error("expected error for trailing data")
	}

	// An out-of-range secret entry must be rejected.
	bad := append([]byte{}, data...)
	bad[len(bad)-1] = byte(kp.SecretKey.Params.Eta + 1)
	if _, err := DeserializeSecretKey(bad); err == nil {
		t.Error("expected error for out-of-range secret entry")
	}
}

func TestDeserializePublicKey_Truncated(t *testing.T) {
	kp, err := GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		t.Fatal(err)
	}
	data := SerializePublicKey(&kp.PublicKey)
	for _, cut := range []int{len(data) - 1, len(data) / 2, 4 + len(kmosaic.MOS128) + SeedSize, 4 + len(kmosaic.MOS128) + SeedSize + 2} {
		if _, err := DeserializePublicKey(data[:cut]); err == nil {
			t.Errorf("expected error for public key truncated to %d bytes", cut)
		}
	}

	// T entry at or above q must be rejected.
	bad := append([]byte{}, data...)
	bad[len(bad)-1] = 0xFF
	if _, err := DeserializePublicKey(bad); err == nil {
		t.Error("expected error for out-of-range T entry")
	}
}

func TestDeserializeSignature_Truncated(t *testing.T) {
	b := make([]byte, 4)
	data := make([]byte, 0)
	binary.LittleEndian.PutUint32(b, uint32(48))
	data = append(data, b...)
	data = append(data, make([]byte, 8)...)
	if _, err := DeserializeSignature(data); err == nil {
		t.Fatalf("expected error for truncated signature, got nil")
	}

	// Unsupported challenge length
	binary.LittleEndian.PutUint32(b, uint32(16))
	if _, err := DeserializeSignature(append(b, make([]byte, 16+4)...)); err == nil {
		t.Fatal("expected error for unsupported challenge length")
	}
}
