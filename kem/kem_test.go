package kem

import (
	"bytes"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

func TestKEM_Failures(t *testing.T) {
	kp, _ := GenerateKeyPair(kmosaic.MOS_128)
	res, _ := Encapsulate(&kp.PublicKey)

	// Test modified ciphertext (should implicitly reject)
	badCT := res.Ciphertext
	badCT.C1.U[0] ^= 1 // Modify SLSS ciphertext

	ss, err := Decapsulate(&kp.SecretKey, &kp.PublicKey, &badCT)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}
	if bytes.Equal(ss, res.SharedSecret) {
		t.Error("Decapsulate should return different shared secret for modified ciphertext")
	}

	// Test modified proof
	badCT = res.Ciphertext
	badCT.Proof[0] ^= 1
	ss, err = Decapsulate(&kp.SecretKey, &kp.PublicKey, &badCT)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}
	if bytes.Equal(ss, res.SharedSecret) {
		t.Error("Decapsulate should return different shared secret for modified proof")
	}
}

func TestKEM_Encryption(t *testing.T) {
	kp, _ := GenerateKeyPair(kmosaic.MOS_128)
	msg := []byte("test message")

	// Encrypt
	enc, err := Encrypt(&kp.PublicKey, msg)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt
	dec, err := Decrypt(&kp.SecretKey, &kp.PublicKey, enc)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(msg, dec) {
		t.Error("Decrypted message does not match")
	}

	// Test tampering
	enc.Encrypted[0] ^= 1
	_, err = Decrypt(&kp.SecretKey, &kp.PublicKey, enc)
	if err == nil {
		t.Error("Decrypt should fail with tampered ciphertext")
	}
}

func TestKEM_Deterministic(t *testing.T) {
	seed, _ := utils.SecureRandomBytes(32)
	params, _ := core.GetParams(kmosaic.MOS_128)

	kp1, err := GenerateKeyPairFromSeed(params, seed)
	if err != nil {
		t.Fatalf("GenerateKeyPairFromSeed failed: %v", err)
	}

	kp2, err := GenerateKeyPairFromSeed(params, seed)
	if err != nil {
		t.Fatalf("GenerateKeyPairFromSeed failed: %v", err)
	}

	// Check public keys match (deep check needed or serialization)
	pk1 := SerializePublicKey(&kp1.PublicKey)
	pk2 := SerializePublicKey(&kp2.PublicKey)
	if !bytes.Equal(pk1, pk2) {
		t.Error("GenerateKeyPairFromSeed not deterministic")
	}
}

func TestSerialization(t *testing.T) {
	kp, _ := GenerateKeyPair(kmosaic.MOS_128)

	pkBytes := SerializePublicKey(&kp.PublicKey)
	if len(pkBytes) == 0 {
		t.Error("SerializePublicKey returned empty bytes")
	}

	res, _ := Encapsulate(&kp.PublicKey)
	ctBytes := SerializeCiphertext(&res.Ciphertext)
	if len(ctBytes) == 0 {
		t.Error("SerializeCiphertext returned empty bytes")
	}
}

func TestSerializeDeserializePublicKey(t *testing.T) {
	for _, level := range []kmosaic.SecurityLevel{kmosaic.MOS_128, kmosaic.MOS_256} {
		t.Run(string(level), func(t *testing.T) {
			kp, err := GenerateKeyPair(level)
			if err != nil {
				t.Fatalf("GenerateKeyPair failed: %v", err)
			}

			// Serialize
			serialized := SerializePublicKey(&kp.PublicKey)
			if len(serialized) == 0 {
				t.Fatal("SerializePublicKey returned empty bytes")
			}

			// Deserialize
			deserialized, err := DeserializePublicKey(serialized)
			if err != nil {
				t.Fatalf("DeserializePublicKey failed: %v", err)
			}

			// Verify by re-serializing and comparing
			reSerialized := SerializePublicKey(deserialized)
			if !bytes.Equal(serialized, reSerialized) {
				t.Error("Round-trip serialization of public key failed")
			}
		})
	}
}

func TestSerializeDeserializeSecretKey(t *testing.T) {
	for _, level := range []kmosaic.SecurityLevel{kmosaic.MOS_128, kmosaic.MOS_256} {
		t.Run(string(level), func(t *testing.T) {
			kp, err := GenerateKeyPair(level)
			if err != nil {
				t.Fatalf("GenerateKeyPair failed: %v", err)
			}

			// Serialize
			serialized := SerializeSecretKey(&kp.SecretKey)
			if len(serialized) == 0 {
				t.Fatal("SerializeSecretKey returned empty bytes")
			}

			// Deserialize
			deserialized, err := DeserializeSecretKey(serialized)
			if err != nil {
				t.Fatalf("DeserializeSecretKey failed: %v", err)
			}

			// Verify by re-serializing and comparing
			reSerialized := SerializeSecretKey(deserialized)
			if !bytes.Equal(serialized, reSerialized) {
				t.Error("Round-trip serialization of secret key failed")
			}

			// Test decapsulation with deserialized key
			res, err := Encapsulate(&kp.PublicKey)
			if err != nil {
				t.Fatalf("Encapsulate failed: %v", err)
			}

			ss1, err := Decapsulate(&kp.SecretKey, &kp.PublicKey, &res.Ciphertext)
			if err != nil {
				t.Fatalf("Decapsulate with original key failed: %v", err)
			}

			ss2, err := Decapsulate(deserialized, &kp.PublicKey, &res.Ciphertext)
			if err != nil {
				t.Fatalf("Decapsulate with deserialized key failed: %v", err)
			}

			if !bytes.Equal(ss1, ss2) {
				t.Error("Shared secrets differ with deserialized secret key")
			}
		})
	}
}

func TestSerializeDeserializeCiphertext(t *testing.T) {
	for _, level := range []kmosaic.SecurityLevel{kmosaic.MOS_128, kmosaic.MOS_256} {
		t.Run(string(level), func(t *testing.T) {
			kp, err := GenerateKeyPair(level)
			if err != nil {
				t.Fatalf("GenerateKeyPair failed: %v", err)
			}

			res, err := Encapsulate(&kp.PublicKey)
			if err != nil {
				t.Fatalf("Encapsulate failed: %v", err)
			}

			// Serialize
			serialized := SerializeCiphertext(&res.Ciphertext)
			if len(serialized) == 0 {
				t.Fatal("SerializeCiphertext returned empty bytes")
			}

			// Deserialize
			deserialized, err := DeserializeCiphertext(serialized)
			if err != nil {
				t.Fatalf("DeserializeCiphertext failed: %v", err)
			}

			// Verify by re-serializing and comparing
			reSerialized := SerializeCiphertext(deserialized)
			if !bytes.Equal(serialized, reSerialized) {
				t.Error("Round-trip serialization of ciphertext failed")
			}

			// Test decapsulation with deserialized ciphertext
			ss1, err := Decapsulate(&kp.SecretKey, &kp.PublicKey, &res.Ciphertext)
			if err != nil {
				t.Fatalf("Decapsulate with original ciphertext failed: %v", err)
			}

			ss2, err := Decapsulate(&kp.SecretKey, &kp.PublicKey, deserialized)
			if err != nil {
				t.Fatalf("Decapsulate with deserialized ciphertext failed: %v", err)
			}

			if !bytes.Equal(ss1, ss2) {
				t.Error("Shared secrets differ with deserialized ciphertext")
			}
		})
	}
}

func TestSerializeDeserializeEncryptedMessage(t *testing.T) {
	for _, level := range []kmosaic.SecurityLevel{kmosaic.MOS_128, kmosaic.MOS_256} {
		t.Run(string(level), func(t *testing.T) {
			kp, err := GenerateKeyPair(level)
			if err != nil {
				t.Fatalf("GenerateKeyPair failed: %v", err)
			}

			msg := []byte("test message for encryption")
			encrypted, err := Encrypt(&kp.PublicKey, msg)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			// Serialize
			serialized := SerializeEncryptedMessage(encrypted)
			if len(serialized) == 0 {
				t.Fatal("SerializeEncryptedMessage returned empty bytes")
			}

			// Deserialize
			deserialized, err := DeserializeEncryptedMessage(serialized)
			if err != nil {
				t.Fatalf("DeserializeEncryptedMessage failed: %v", err)
			}

			// Verify by re-serializing and comparing
			reSerialized := SerializeEncryptedMessage(deserialized)
			if !bytes.Equal(serialized, reSerialized) {
				t.Error("Round-trip serialization of encrypted message failed")
			}

			// Test decryption with deserialized encrypted message
			dec1, err := Decrypt(&kp.SecretKey, &kp.PublicKey, encrypted)
			if err != nil {
				t.Fatalf("Decrypt with original encrypted message failed: %v", err)
			}

			dec2, err := Decrypt(&kp.SecretKey, &kp.PublicKey, deserialized)
			if err != nil {
				t.Fatalf("Decrypt with deserialized encrypted message failed: %v", err)
			}

			if !bytes.Equal(dec1, dec2) || !bytes.Equal(dec1, msg) {
				t.Error("Decrypted messages differ or don't match original")
			}
		})
	}
}

func TestDeserializeErrors(t *testing.T) {
	// Test invalid public key data
	_, err := DeserializePublicKey([]byte{1, 2, 3})
	if err == nil {
		t.Error("DeserializePublicKey should fail with invalid data")
	}

	// Test invalid secret key data
	_, err = DeserializeSecretKey([]byte{1, 2, 3})
	if err == nil {
		t.Error("DeserializeSecretKey should fail with invalid data")
	}

	// Test invalid ciphertext data
	_, err = DeserializeCiphertext([]byte{1, 2, 3})
	if err == nil {
		t.Error("DeserializeCiphertext should fail with invalid data")
	}

	// Test invalid encrypted message data
	_, err = DeserializeEncryptedMessage([]byte{1, 2, 3})
	if err == nil {
		t.Error("DeserializeEncryptedMessage should fail with invalid data")
	}

	// Test invalid security level in public key
	badData := make([]byte, 100)
	badData[0] = 99 // Invalid security level
	_, err = DeserializePublicKey(badData)
	if err == nil {
		t.Error("DeserializePublicKey should fail with invalid security level")
	}
}

func TestDeserializePublicKeyRejectsInvalidBinding(t *testing.T) {
	kp, err := GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	serialized := SerializePublicKey(&kp.PublicKey)
	if len(serialized) < 40 {
		t.Fatal("serialized public key unexpectedly short")
	}

	// Tamper with binding (last byte)
	bad := make([]byte, len(serialized))
	copy(bad, serialized)
	bad[len(bad)-1] ^= 0xFF

	_, err = DeserializePublicKey(bad)
	if err == nil {
		t.Error("DeserializePublicKey should reject invalid binding")
	}
}
