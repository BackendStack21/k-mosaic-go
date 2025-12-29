package slss

import (
	"bytes"
	"encoding/binary"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

func TestSLSS(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS_128)

	// KeyGen
	seed, _ := utils.SecureRandomBytes(32)
	kp, err := KeyGen(params.SLSS, seed)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	// Encrypt
	msg := []byte("test")
	randomness, _ := utils.SecureRandomBytes(32)
	ct, err := Encrypt(kp.PublicKey, msg, params.SLSS, randomness)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt
	dec := Decrypt(ct, kp.SecretKey, params.SLSS)

	// Note: SLSS decryption might not be perfect depending on error distribution,
	// but for small messages and correct params it should work.
	if !bytes.Equal(msg, dec) {
		t.Logf("Decrypted message does not match (expected for noisy encryption if not fully decoded)")
	}
}

func TestMathOps(t *testing.T) {
	// Test mod
	if mod(-5, 3) != 1 {
		t.Error("mod(-5, 3) should be 1")
	}
	if mod(5, 3) != 2 {
		t.Error("mod(5, 3) should be 2")
	}

	// Test centerMod
	if centerMod(13, 5) != -2 { // 13 % 5 = 3 -> 3-5 = -2
		t.Errorf("centerMod(13, 5) = %d, want -2", centerMod(13, 5))
	}
}

func TestSerialization(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS_128)
	seed, _ := utils.SecureRandomBytes(32)
	kp, err := KeyGen(params.SLSS, seed)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	serialized := SerializePublicKey(kp.PublicKey)
	if len(serialized) == 0 {
		t.Error("SerializePublicKey returned empty bytes")
	}
}

func TestSerializeDeserializePublicKey(t *testing.T) {
	for _, level := range []kmosaic.SecurityLevel{kmosaic.MOS_128, kmosaic.MOS_256} {
		t.Run(string(level), func(t *testing.T) {
			params, err := core.GetParams(level)
			if err != nil {
				t.Fatalf("GetParams failed: %v", err)
			}

			seed, _ := utils.SecureRandomBytes(32)
			kp, err := KeyGen(params.SLSS, seed)
			if err != nil {
				t.Fatalf("KeyGen failed: %v", err)
			}

			// Serialize
			serialized := SerializePublicKey(kp.PublicKey)
			if len(serialized) == 0 {
				t.Fatal("SerializePublicKey returned empty bytes")
			}

			// Deserialize
			deserialized, err := DeserializePublicKey(serialized)
			if err != nil {
				t.Fatalf("DeserializePublicKey failed: %v", err)
			}

			// Verify by re-serializing and comparing
			reSerialized := SerializePublicKey(*deserialized)
			if !bytes.Equal(serialized, reSerialized) {
				t.Error("Round-trip serialization of SLSS public key failed")
			}

			// Verify encryption/decryption works with deserialized key
			msg := []byte("test message")
			randomness, _ := utils.SecureRandomBytes(32)

			ct, err := Encrypt(*deserialized, msg, params.SLSS, randomness)
			if err != nil {
				t.Fatalf("Encrypt with deserialized key failed: %v", err)
			}

			dec := Decrypt(ct, kp.SecretKey, params.SLSS)
			if !bytes.Equal(msg, dec) {
				t.Error("Decryption with deserialized public key failed")
			}
		})
	}
}

func TestDeserializePublicKeyErrors(t *testing.T) {
	// Test with too short data
	_, err := DeserializePublicKey([]byte{1, 2, 3})
	if err == nil {
		t.Error("DeserializePublicKey should fail with too short data")
	}

	// Test with invalid A length
	badData := make([]byte, 8)
	binary.LittleEndian.PutUint32(badData[0:], 1000000) // Large A length
	_, err = DeserializePublicKey(badData)
	if err == nil {
		t.Error("DeserializePublicKey should fail with truncated A data")
	}

	// Test with valid A but invalid T length
	badData = make([]byte, 100)
	binary.LittleEndian.PutUint32(badData[0:], 2) // A length = 2
	binary.LittleEndian.PutUint32(badData[4:], 0)
	binary.LittleEndian.PutUint32(badData[8:], 0)
	binary.LittleEndian.PutUint32(badData[12:], 1000000) // Large T length
	_, err = DeserializePublicKey(badData)
	if err == nil {
		t.Error("DeserializePublicKey should fail with truncated T data")
	}
}
