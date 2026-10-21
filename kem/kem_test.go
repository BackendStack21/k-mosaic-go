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

	mutate := func(f func(ct *kmosaic.MOSAICCiphertext)) *kmosaic.MOSAICCiphertext {
		ct := res.Ciphertext
		ct.C1.U = append([]int32{}, ct.C1.U...)
		ct.C1.V = append([]int32{}, ct.C1.V...)
		ct.C2.U = append([]uint64{}, ct.C2.U...)
		ct.C2.V = append([]uint64{}, ct.C2.V...)
		ct.Proof = append([]byte{}, ct.Proof...)
		f(&ct)
		return &ct
	}
	cases := map[string]*kmosaic.MOSAICCiphertext{
		"SLSS u":   mutate(func(ct *kmosaic.MOSAICCiphertext) { ct.C1.U[0] ^= 1 }),
		"SLSS v":   mutate(func(ct *kmosaic.MOSAICCiphertext) { ct.C1.V[3] ^= 1 }),
		"code u":   mutate(func(ct *kmosaic.MOSAICCiphertext) { ct.C2.U[5] ^= 1 }),
		"code v":   mutate(func(ct *kmosaic.MOSAICCiphertext) { ct.C2.V[7] ^= 1 << 9 }),
		"proof":    mutate(func(ct *kmosaic.MOSAICCiphertext) { ct.Proof[0] ^= 1 }),
		"no proof": mutate(func(ct *kmosaic.MOSAICCiphertext) { ct.Proof = nil }),
	}
	for name, ct := range cases {
		ss, err := Decapsulate(&kp.SecretKey, &kp.PublicKey, ct)
		if err != nil {
			t.Fatalf("%s: Decapsulate failed: %v", name, err)
		}
		if bytes.Equal(ss, res.SharedSecret) {
			t.Errorf("%s: modified ciphertext yielded the real shared secret", name)
		}
		ss2, _ := Decapsulate(&kp.SecretKey, &kp.PublicKey, ct)
		if !bytes.Equal(ss, ss2) {
			t.Errorf("%s: implicit rejection is not deterministic", name)
		}
	}
}

func TestKEM_Encryption(t *testing.T) {
	kp, _ := GenerateKeyPair(kmosaic.MOS_128)
	msg := []byte("test message")

	enc, err := Encrypt(&kp.PublicKey, msg)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	dec, err := Decrypt(&kp.SecretKey, &kp.PublicKey, enc)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(msg, dec) {
		t.Error("Decrypted message does not match")
	}

	enc.Encrypted[0] ^= 1
	if _, err = Decrypt(&kp.SecretKey, &kp.PublicKey, enc); err == nil {
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
	if !bytes.Equal(SerializePublicKey(&kp1.PublicKey), SerializePublicKey(&kp2.PublicKey)) {
		t.Error("GenerateKeyPairFromSeed not deterministic")
	}

	eph := make([]byte, 32)
	for i := range eph {
		eph[i] = byte(i * 3)
	}
	r1, _ := EncapsulateDeterministic(&kp1.PublicKey, eph)
	r2, _ := EncapsulateDeterministic(&kp1.PublicKey, eph)
	if !bytes.Equal(SerializeCiphertext(&r1.Ciphertext, params), SerializeCiphertext(&r2.Ciphertext, params)) {
		t.Error("EncapsulateDeterministic not deterministic")
	}
}

func TestRoundTripAllLevels(t *testing.T) {
	for _, level := range []kmosaic.SecurityLevel{kmosaic.MOS_128, kmosaic.MOS_256} {
		t.Run(string(level), func(t *testing.T) {
			kp, err := GenerateKeyPair(level)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 5; i++ {
				res, err := Encapsulate(&kp.PublicKey)
				if err != nil {
					t.Fatal(err)
				}
				ss, err := Decapsulate(&kp.SecretKey, &kp.PublicKey, &res.Ciphertext)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(ss, res.SharedSecret) {
					t.Fatal("shared secret mismatch")
				}
			}
		})
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
			res, _ := Encapsulate(deserialized)
			ss, _ := Decapsulate(&kp.SecretKey, &kp.PublicKey, &res.Ciphertext)
			if !bytes.Equal(ss, res.SharedSecret) {
				t.Error("encapsulation under the deserialized key does not decapsulate")
			}
			t.Logf("public key: %d bytes", len(serialized))
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
			params := kp.PublicKey.Params
			serialized := SerializeSecretKey(&kp.SecretKey, params)
			deserialized, err := DeserializeSecretKey(serialized)
			if err != nil {
				t.Fatalf("DeserializeSecretKey failed: %v", err)
			}
			if !bytes.Equal(serialized, SerializeSecretKey(deserialized, params)) {
				t.Error("Round-trip serialization of secret key failed")
			}
			res, _ := Encapsulate(&kp.PublicKey)
			ss1, _ := Decapsulate(&kp.SecretKey, &kp.PublicKey, &res.Ciphertext)
			ss2, _ := Decapsulate(deserialized, &kp.PublicKey, &res.Ciphertext)
			if !bytes.Equal(ss1, ss2) || !bytes.Equal(ss1, res.SharedSecret) {
				t.Error("Shared secrets differ with deserialized secret key")
			}
		})
	}
}

func TestSerializeDeserializeCiphertext(t *testing.T) {
	for _, level := range []kmosaic.SecurityLevel{kmosaic.MOS_128, kmosaic.MOS_256} {
		t.Run(string(level), func(t *testing.T) {
			kp, _ := GenerateKeyPair(level)
			params := kp.PublicKey.Params
			res, _ := Encapsulate(&kp.PublicKey)
			serialized := SerializeCiphertext(&res.Ciphertext, params)
			deserialized, err := DeserializeCiphertext(serialized, params)
			if err != nil {
				t.Fatalf("DeserializeCiphertext failed: %v", err)
			}
			if !bytes.Equal(serialized, SerializeCiphertext(deserialized, params)) {
				t.Error("Round-trip serialization of ciphertext failed")
			}
			ss, _ := Decapsulate(&kp.SecretKey, &kp.PublicKey, deserialized)
			if !bytes.Equal(ss, res.SharedSecret) {
				t.Error("deserialized ciphertext does not decapsulate")
			}
			t.Logf("ciphertext: %d bytes", len(serialized))
		})
	}
}

func TestSerializeDeserializeEncryptedMessage(t *testing.T) {
	kp, _ := GenerateKeyPair(kmosaic.MOS_128)
	params := kp.PublicKey.Params
	msg := []byte("hybrid encryption round trip")
	encrypted, err := Encrypt(&kp.PublicKey, msg)
	if err != nil {
		t.Fatal(err)
	}
	serialized := SerializeEncryptedMessage(encrypted, params)
	deserialized, err := DeserializeEncryptedMessage(serialized, params)
	if err != nil {
		t.Fatalf("DeserializeEncryptedMessage failed: %v", err)
	}
	if !bytes.Equal(serialized, SerializeEncryptedMessage(deserialized, params)) {
		t.Error("Round-trip serialization of encrypted message failed")
	}
	dec, err := Decrypt(&kp.SecretKey, &kp.PublicKey, deserialized)
	if err != nil || !bytes.Equal(dec, msg) {
		t.Errorf("decryption of deserialized message failed: %v", err)
	}
}

func TestDeserializeErrors(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS_128)
	if _, err := DeserializePublicKey([]byte{1, 2, 3}); err == nil {
		t.Error("DeserializePublicKey should fail with invalid data")
	}
	if _, err := DeserializeSecretKey([]byte{1, 2, 3}); err == nil {
		t.Error("DeserializeSecretKey should fail with invalid data")
	}
	if _, err := DeserializeCiphertext([]byte{1, 2, 3}, params); err == nil {
		t.Error("DeserializeCiphertext should fail with invalid data")
	}
	if _, err := DeserializeEncryptedMessage([]byte{1, 2, 3}, params); err == nil {
		t.Error("DeserializeEncryptedMessage should fail with invalid data")
	}
	badData := make([]byte, 100)
	badData[0] = 99
	if _, err := DeserializePublicKey(badData); err == nil {
		t.Error("DeserializePublicKey should fail with invalid security level")
	}
}

func TestDeserializePublicKeyRejectsInvalidBinding(t *testing.T) {
	kp, err := GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	serialized := SerializePublicKey(&kp.PublicKey)
	bad := append([]byte{}, serialized...)
	bad[len(bad)-1] ^= 0xFF
	if _, err = DeserializePublicKey(bad); err == nil {
		t.Error("DeserializePublicKey should reject invalid binding")
	}
	// Tampering inside a component must also break the binding.
	bad = append([]byte{}, serialized...)
	bad[len(bad)/2] ^= 0x01
	if _, err = DeserializePublicKey(bad); err == nil {
		t.Error("DeserializePublicKey should reject a modified component")
	}
}
