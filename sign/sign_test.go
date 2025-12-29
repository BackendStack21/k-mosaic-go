package sign

import (
	"bytes"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

func TestSign_Failures(t *testing.T) {
	kp, _ := GenerateKeyPair(kmosaic.MOS_128)
	msg := []byte("message")
	sig, _ := Sign(&kp.SecretKey, &kp.PublicKey, msg)

	// Test modified message
	if Verify(&kp.PublicKey, []byte("wrong"), sig) {
		t.Error("Verify passed with wrong message")
	}

	// Test modified signature
	badSig := *sig
	badSig.Challenge[0] ^= 1
	if Verify(&kp.PublicKey, msg, &badSig) {
		t.Error("Verify passed with modified challenge")
	}

	badSig = *sig
	badSig.Response[0] ^= 1
	if Verify(&kp.PublicKey, msg, &badSig) {
		t.Error("Verify passed with modified response")
	}
}

func TestSign_Deterministic(t *testing.T) {
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

	pk1 := SerializePublicKey(&kp1.PublicKey)
	pk2 := SerializePublicKey(&kp2.PublicKey)
	if !bytes.Equal(pk1, pk2) {
		t.Error("GenerateKeyPairFromSeed not deterministic")
	}
}

func TestSerialization(t *testing.T) {
	kp, _ := GenerateKeyPair(kmosaic.MOS_128)
	msg := []byte("message")
	sig, _ := Sign(&kp.SecretKey, &kp.PublicKey, msg)

	pkBytes := SerializePublicKey(&kp.PublicKey)
	if len(pkBytes) == 0 {
		t.Error("SerializePublicKey returned empty bytes")
	}

	sigBytes := SerializeSignature(sig)
	if len(sigBytes) == 0 {
		t.Error("SerializeSignature returned empty bytes")
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

			// Verify signature with deserialized key
			msg := []byte("test message")
			sig, err := Sign(&kp.SecretKey, &kp.PublicKey, msg)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			if !Verify(deserialized, msg, sig) {
				t.Error("Verify failed with deserialized public key")
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

			// Test signing with deserialized key
			msg := []byte("test message")

			sig1, err := Sign(&kp.SecretKey, &kp.PublicKey, msg)
			if err != nil {
				t.Fatalf("Sign with original key failed: %v", err)
			}

			sig2, err := Sign(deserialized, &kp.PublicKey, msg)
			if err != nil {
				t.Fatalf("Sign with deserialized key failed: %v", err)
			}

			// Both signatures should verify
			if !Verify(&kp.PublicKey, msg, sig1) {
				t.Error("Signature from original key failed to verify")
			}

			if !Verify(&kp.PublicKey, msg, sig2) {
				t.Error("Signature from deserialized key failed to verify")
			}
		})
	}
}

func TestSerializeDeserializeSignature(t *testing.T) {
	for _, level := range []kmosaic.SecurityLevel{kmosaic.MOS_128, kmosaic.MOS_256} {
		t.Run(string(level), func(t *testing.T) {
			kp, err := GenerateKeyPair(level)
			if err != nil {
				t.Fatalf("GenerateKeyPair failed: %v", err)
			}

			msg := []byte("test message for signature")
			sig, err := Sign(&kp.SecretKey, &kp.PublicKey, msg)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			// Serialize
			serialized := SerializeSignature(sig)
			if len(serialized) == 0 {
				t.Fatal("SerializeSignature returned empty bytes")
			}

			// Deserialize
			deserialized, err := DeserializeSignature(serialized)
			if err != nil {
				t.Fatalf("DeserializeSignature failed: %v", err)
			}

			// Verify by re-serializing and comparing
			reSerialized := SerializeSignature(deserialized)
			if !bytes.Equal(serialized, reSerialized) {
				t.Error("Round-trip serialization of signature failed")
			}

			// Verify with deserialized signature
			if !Verify(&kp.PublicKey, msg, sig) {
				t.Error("Original signature failed to verify")
			}

			if !Verify(&kp.PublicKey, msg, deserialized) {
				t.Error("Deserialized signature failed to verify")
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

	// Test invalid signature data
	_, err = DeserializeSignature([]byte{1, 2, 3})
	if err == nil {
		t.Error("DeserializeSignature should fail with invalid data")
	}

	// Test invalid security level in public key
	badData := make([]byte, 100)
	badData[0] = 99 // Invalid security level
	_, err = DeserializePublicKey(badData)
	if err == nil {
		t.Error("DeserializePublicKey should fail with invalid security level")
	}
}
