package slss

import (
	"bytes"
	"encoding/binary"
	"slices"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

func testMessage(params kmosaic.SLSSParams) []byte {
	msg := make([]byte, MessageSize(params))
	for i := range msg {
		msg[i] = byte(i*37 + 11)
	}
	return msg
}

func TestSLSS(t *testing.T) {
	for _, level := range []kmosaic.SecurityLevel{kmosaic.MOS_128, kmosaic.MOS_256} {
		t.Run(string(level), func(t *testing.T) {
			params, _ := core.GetParams(level)

			seed, _ := utils.SecureRandomBytes(32)
			kp, err := KeyGen(params.SLSS, seed)
			if err != nil {
				t.Fatalf("KeyGen failed: %v", err)
			}
			if len(kp.PublicKey.T) != params.SLSS.L*params.SLSS.M || len(kp.SecretKey.S) != params.SLSS.L*params.SLSS.N {
				t.Fatal("key dimensions do not match params")
			}

			for trial := 0; trial < 5; trial++ {
				msg := testMessage(params.SLSS)
				msg[0] = byte(trial)
				randomness, _ := utils.SecureRandomBytes(32)
				ct, err := Encrypt(kp.PublicKey, msg, params.SLSS, randomness)
				if err != nil {
					t.Fatalf("Encrypt failed: %v", err)
				}
				dec := Decrypt(ct, kp.SecretKey, params.SLSS)
				if !bytes.Equal(msg, dec) {
					t.Fatalf("decryption mismatch: got %x want %x", dec, msg)
				}
			}
		})
	}
}

func TestEncrypt_RejectsWrongMessageSize(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS_128)
	seed, _ := utils.SecureRandomBytes(32)
	kp, _ := KeyGen(params.SLSS, seed)
	randomness, _ := utils.SecureRandomBytes(32)
	for _, n := range []int{0, 4, 31, 33, 64} {
		if _, err := Encrypt(kp.PublicKey, make([]byte, n), params.SLSS, randomness); err == nil {
			t.Errorf("Encrypt accepted a %d-byte message", n)
		}
	}
}

// TestCiphertextDoesNotLeakMessage checks that the v component no longer
// clusters around two values: in the original design every v_i shared one
// inner product, so the bits were readable from the ciphertext alone.
func TestCiphertextDoesNotLeakMessage(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS_128)
	seed, _ := utils.SecureRandomBytes(32)
	kp, _ := KeyGen(params.SLSS, seed)
	randomness, _ := utils.SecureRandomBytes(32)
	msg := testMessage(params.SLSS)
	ct, _ := Encrypt(kp.PublicKey, msg, params.SLSS, randomness)

	q := params.SLSS.Q
	// Decode the way the old attack did: cluster v relative to v[0].
	correct := 0
	for j := range ct.V {
		d := int(ct.V[j]) - int(ct.V[0])
		d = ((d % q) + q) % q
		bit := byte(0)
		if d > q/4 && d < 3*q/4 {
			bit = 1
		}
		if bit == (msg[j/8]>>(j%8))&1 {
			correct++
		}
	}
	// Either polarity must look like a coin flip, not a decryption.
	if correct > 3*len(ct.V)/4 || correct < len(ct.V)/4 {
		t.Fatalf("clustering attack recovered %d/%d bits", correct, len(ct.V))
	}
}

func TestMathOps(t *testing.T) {
	if mod(-5, 3) != 1 {
		t.Error("mod(-5, 3) should be 1")
	}
	if mod(5, 3) != 2 {
		t.Error("mod(5, 3) should be 2")
	}
	if centerMod(13, 5) != -2 {
		t.Errorf("centerMod(13, 5) = %d, want -2", centerMod(13, 5))
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

			serialized := SerializePublicKey(kp.PublicKey)
			if len(serialized) != SeedSize+4+2*len(kp.PublicKey.T) {
				t.Fatalf("unexpected serialized size %d", len(serialized))
			}

			deserialized, err := DeserializePublicKey(serialized, params.SLSS)
			if err != nil {
				t.Fatalf("DeserializePublicKey failed: %v", err)
			}
			if !bytes.Equal(serialized, SerializePublicKey(*deserialized)) {
				t.Error("Round-trip serialization of SLSS public key failed")
			}
			if !slices.Equal(deserialized.A, kp.PublicKey.A) {
				t.Error("matrix re-expanded from seed differs")
			}

			msg := testMessage(params.SLSS)
			randomness, _ := utils.SecureRandomBytes(32)
			ct, err := Encrypt(*deserialized, msg, params.SLSS, randomness)
			if err != nil {
				t.Fatalf("Encrypt with deserialized key failed: %v", err)
			}
			if !bytes.Equal(msg, Decrypt(ct, kp.SecretKey, params.SLSS)) {
				t.Error("Decryption with deserialized public key failed")
			}
		})
	}
}

func TestDeserializePublicKeyErrors(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS_128)

	if _, err := DeserializePublicKey([]byte{1, 2, 3}, params.SLSS); err == nil {
		t.Error("DeserializePublicKey should fail with too short data")
	}

	// Wrong T count
	bad := make([]byte, SeedSize+4)
	binary.LittleEndian.PutUint32(bad[SeedSize:], 1000000)
	if _, err := DeserializePublicKey(bad, params.SLSS); err == nil {
		t.Error("DeserializePublicKey should fail with wrong T count")
	}

	// Correct count but truncated data
	binary.LittleEndian.PutUint32(bad[SeedSize:], uint32(params.SLSS.L*params.SLSS.M))
	if _, err := DeserializePublicKey(bad, params.SLSS); err == nil {
		t.Error("DeserializePublicKey should fail with truncated T data")
	}

	// Entry out of range
	full := append(bad, make([]byte, 2*params.SLSS.L*params.SLSS.M)...)
	full[len(full)-1] = 0xFF
	if _, err := DeserializePublicKey(full, params.SLSS); err == nil {
		t.Error("DeserializePublicKey should fail with out-of-range entry")
	}
}
