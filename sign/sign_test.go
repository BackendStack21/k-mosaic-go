package sign

import (
	"bytes"
	"slices"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

func TestSign_Failures(t *testing.T) {
	kp, err := GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("message")
	sig, err := Sign(&kp.SecretKey, &kp.PublicKey, msg)
	if err != nil {
		t.Fatal(err)
	}

	if !Verify(&kp.PublicKey, msg, sig) {
		t.Fatal("valid signature rejected")
	}

	// Wrong message
	if Verify(&kp.PublicKey, []byte("wrong"), sig) {
		t.Error("Verify passed with wrong message")
	}

	// Modified challenge (deep copy so the original is untouched)
	bad := &kmosaic.MOSAICSignature{Challenge: append([]byte{}, sig.Challenge...), Z: append([]int32{}, sig.Z...)}
	bad.Challenge[0] ^= 1
	if Verify(&kp.PublicKey, msg, bad) {
		t.Error("Verify passed with modified challenge")
	}

	// Modified response: every coefficient of z is covered by the check.
	for _, idx := range []int{0, len(sig.Z) / 2, len(sig.Z) - 1} {
		bad = &kmosaic.MOSAICSignature{Challenge: append([]byte{}, sig.Challenge...), Z: append([]int32{}, sig.Z...)}
		bad.Z[idx] += 1
		if Verify(&kp.PublicKey, msg, bad) {
			t.Errorf("Verify passed with modified response at %d", idx)
		}
	}

	// Response out of the allowed range
	bad = &kmosaic.MOSAICSignature{Challenge: append([]byte{}, sig.Challenge...), Z: append([]int32{}, sig.Z...)}
	bad.Z[0] = int32(kp.PublicKey.Params.Gamma1)
	if Verify(&kp.PublicKey, msg, bad) {
		t.Error("Verify passed with out-of-range response")
	}

	// Wrong key
	kp2, _ := GenerateKeyPair(kmosaic.MOS_128)
	if Verify(&kp2.PublicKey, msg, sig) {
		t.Error("Verify passed under a different public key")
	}

	// Mismatched key pair must be refused by Sign
	if _, err := Sign(&kp.SecretKey, &kp2.PublicKey, msg); err == nil {
		t.Error("Sign accepted a public key that does not match the secret key")
	}
}

func TestSign_Deterministic(t *testing.T) {
	seed, _ := utils.SecureRandomBytes(32)
	params, _ := core.GetSignParams(kmosaic.MOS_128)

	kp1, err := GenerateKeyPairFromSeed(params, seed)
	if err != nil {
		t.Fatalf("GenerateKeyPairFromSeed failed: %v", err)
	}
	kp2, err := GenerateKeyPairFromSeed(params, seed)
	if err != nil {
		t.Fatalf("GenerateKeyPairFromSeed failed: %v", err)
	}

	if !bytes.Equal(SerializePublicKey(&kp1.PublicKey), SerializePublicKey(&kp2.PublicKey)) {
		t.Error("GenerateKeyPairFromSeed not deterministic")
	}
	if !bytes.Equal(SerializeSecretKey(&kp1.SecretKey), SerializeSecretKey(&kp2.SecretKey)) {
		t.Error("GenerateKeyPairFromSeed secret key not deterministic")
	}

	// Signatures are hedged with fresh randomness, so two signatures on the
	// same message differ but both verify.
	msg := []byte("m")
	s1, _ := Sign(&kp1.SecretKey, &kp1.PublicKey, msg)
	s2, _ := Sign(&kp1.SecretKey, &kp1.PublicKey, msg)
	if !Verify(&kp1.PublicKey, msg, s1) || !Verify(&kp1.PublicKey, msg, s2) {
		t.Error("hedged signatures failed to verify")
	}
	if bytes.Equal(SerializeSignature(s1), SerializeSignature(s2)) {
		t.Error("two hedged signatures were identical")
	}
}

func TestSign_SignatureShape(t *testing.T) {
	for _, level := range []kmosaic.SecurityLevel{kmosaic.MOS_128, kmosaic.MOS_256} {
		t.Run(string(level), func(t *testing.T) {
			kp, err := GenerateKeyPair(level)
			if err != nil {
				t.Fatal(err)
			}
			p := kp.PublicKey.Params
			sig, err := Sign(&kp.SecretKey, &kp.PublicKey, []byte("shape"))
			if err != nil {
				t.Fatal(err)
			}
			if len(sig.Challenge) != p.CTildeSize {
				t.Errorf("challenge length %d, want %d", len(sig.Challenge), p.CTildeSize)
			}
			if len(sig.Z) != p.N {
				t.Errorf("response length %d, want %d", len(sig.Z), p.N)
			}
			if int(infNorm(sig.Z)) >= p.Gamma1-p.Beta {
				t.Errorf("response norm %d not below gamma1-beta=%d", infNorm(sig.Z), p.Gamma1-p.Beta)
			}
		})
	}
}

func TestSerialization(t *testing.T) {
	kp, _ := GenerateKeyPair(kmosaic.MOS_128)
	msg := []byte("message")
	sig, _ := Sign(&kp.SecretKey, &kp.PublicKey, msg)

	if len(SerializePublicKey(&kp.PublicKey)) == 0 {
		t.Error("SerializePublicKey returned empty bytes")
	}
	if len(SerializeSignature(sig)) == 0 {
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

			serialized := SerializePublicKey(&kp.PublicKey)
			deserialized, err := DeserializePublicKey(serialized)
			if err != nil {
				t.Fatalf("DeserializePublicKey failed: %v", err)
			}
			if !bytes.Equal(serialized, SerializePublicKey(deserialized)) {
				t.Error("Round-trip serialization of public key failed")
			}
			if !slices.Equal(deserialized.A, kp.PublicKey.A) {
				t.Error("expanded matrix differs after deserialization")
			}

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

			serialized := SerializeSecretKey(&kp.SecretKey)
			deserialized, err := DeserializeSecretKey(serialized)
			if err != nil {
				t.Fatalf("DeserializeSecretKey failed: %v", err)
			}
			if !bytes.Equal(serialized, SerializeSecretKey(deserialized)) {
				t.Error("Round-trip serialization of secret key failed")
			}

			msg := []byte("test message")
			sig, err := Sign(deserialized, &kp.PublicKey, msg)
			if err != nil {
				t.Fatalf("Sign with deserialized key failed: %v", err)
			}
			if !Verify(&kp.PublicKey, msg, sig) {
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

			serialized := SerializeSignature(sig)
			deserialized, err := DeserializeSignature(serialized)
			if err != nil {
				t.Fatalf("DeserializeSignature failed: %v", err)
			}
			if !bytes.Equal(serialized, SerializeSignature(deserialized)) {
				t.Error("Round-trip serialization of signature failed")
			}
			if !Verify(&kp.PublicKey, msg, deserialized) {
				t.Error("Deserialized signature failed to verify")
			}
		})
	}
}

func TestDeserializeErrors(t *testing.T) {
	if _, err := DeserializePublicKey([]byte{1, 2, 3}); err == nil {
		t.Error("DeserializePublicKey should fail with invalid data")
	}
	if _, err := DeserializeSecretKey([]byte{1, 2, 3}); err == nil {
		t.Error("DeserializeSecretKey should fail with invalid data")
	}
	if _, err := DeserializeSignature([]byte{1, 2, 3}); err == nil {
		t.Error("DeserializeSignature should fail with invalid data")
	}

	badData := make([]byte, 100)
	badData[0] = 99 // bogus level length
	if _, err := DeserializePublicKey(badData); err == nil {
		t.Error("DeserializePublicKey should fail with invalid security level")
	}
}
