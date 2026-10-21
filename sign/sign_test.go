package sign

import (
	"bytes"
	"testing"
	"time"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

func cloneSig(sig *kmosaic.MOSAICSignature) *kmosaic.MOSAICSignature {
	return &kmosaic.MOSAICSignature{
		Lattice: kmosaic.LatticeSignature{Challenge: append([]byte{}, sig.Lattice.Challenge...), Z: append([]int32{}, sig.Lattice.Z...)},
		MQ:      kmosaic.MQSignature{S: append([]byte{}, sig.MQ.S...), Salt: append([]byte{}, sig.MQ.Salt...)},
		Hash:    kmosaic.HashSignature{Data: append([]byte{}, sig.Hash.Data...)},
	}
}

func TestRoundTripAllLevels(t *testing.T) {
	for _, level := range []kmosaic.SecurityLevel{kmosaic.MOS_128, kmosaic.MOS_256} {
		t.Run(string(level), func(t *testing.T) {
			st := time.Now()
			kp, err := GenerateKeyPair(level)
			if err != nil {
				t.Fatal(err)
			}
			tk := time.Since(st)
			msg := []byte("composite signature message")
			st = time.Now()
			sig, err := Sign(&kp.SecretKey, &kp.PublicKey, msg)
			if err != nil {
				t.Fatal(err)
			}
			ts := time.Since(st)
			st = time.Now()
			if !Verify(&kp.PublicKey, msg, sig) {
				t.Fatal("valid signature rejected")
			}
			tv := time.Since(st)
			pkb := SerializePublicKey(&kp.PublicKey)
			skb := SerializeSecretKey(&kp.SecretKey)
			sb := SerializeSignature(sig)
			t.Logf("keygen=%v sign=%v verify=%v pk=%d sk=%d sig=%d", tk, ts, tv, len(pkb), len(skb), len(sb))

			if Verify(&kp.PublicKey, []byte("other message"), sig) {
				t.Fatal("wrong message accepted")
			}

			// Every component must be checked: tamper with each one.
			bad := cloneSig(sig)
			bad.Lattice.Z[1]++
			if Verify(&kp.PublicKey, msg, bad) {
				t.Fatal("tampered lattice component accepted")
			}
			bad = cloneSig(sig)
			bad.MQ.S[2] ^= 1
			if Verify(&kp.PublicKey, msg, bad) {
				t.Fatal("tampered MQ component accepted")
			}
			bad = cloneSig(sig)
			bad.Hash.Data[len(bad.Hash.Data)-1] ^= 1
			if Verify(&kp.PublicKey, msg, bad) {
				t.Fatal("tampered hash component accepted")
			}

			// Serialization round trips.
			pk2, err := DeserializePublicKey(pkb)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(SerializePublicKey(pk2), pkb) {
				t.Fatal("public key round trip failed")
			}
			sig2, err := DeserializeSignature(sb, pk2.Params)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(SerializeSignature(sig2), sb) {
				t.Fatal("signature round trip failed")
			}
			if !Verify(pk2, msg, sig2) {
				t.Fatal("round-tripped signature rejected")
			}
			sk2, err := DeserializeSecretKey(skb)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(SerializeSecretKey(sk2), skb) {
				t.Fatal("secret key round trip failed")
			}
			sig3, err := Sign(sk2, pk2, msg)
			if err != nil {
				t.Fatal(err)
			}
			if !Verify(&kp.PublicKey, msg, sig3) {
				t.Fatal("signature from deserialized secret key rejected")
			}
		})
	}
}

func TestDeterministicKeyGen(t *testing.T) {
	seed, _ := utils.SecureRandomBytes(32)
	params, _ := core.GetSignParams(kmosaic.MOS_128)
	kp1, err := GenerateKeyPairFromSeed(params, seed)
	if err != nil {
		t.Fatal(err)
	}
	kp2, _ := GenerateKeyPairFromSeed(params, seed)
	if !bytes.Equal(SerializePublicKey(&kp1.PublicKey), SerializePublicKey(&kp2.PublicKey)) {
		t.Fatal("key generation not deterministic")
	}
	if !bytes.Equal(SerializeSecretKey(&kp1.SecretKey), SerializeSecretKey(&kp2.SecretKey)) {
		t.Fatal("secret key generation not deterministic")
	}
	if _, err := GenerateKeyPairFromSeed(params, make([]byte, 10)); err == nil {
		t.Fatal("short seed accepted")
	}
	bad := params
	bad.Level = "MOS-999"
	if _, err := GenerateKeyPairFromSeed(bad, seed); err == nil {
		t.Fatal("unknown level accepted")
	}
}

func TestKeyMismatchAndBinding(t *testing.T) {
	kp1, _ := GenerateKeyPair(kmosaic.MOS_128)
	kp2, _ := GenerateKeyPair(kmosaic.MOS_128)
	msg := []byte("m")

	if _, err := Sign(&kp1.SecretKey, &kp2.PublicKey, msg); err == nil {
		t.Fatal("Sign accepted a mismatched public key")
	}
	sig, _ := Sign(&kp1.SecretKey, nil, msg)
	if !Verify(&kp1.PublicKey, msg, sig) {
		t.Fatal("signature made without pk rejected")
	}
	if Verify(&kp2.PublicKey, msg, sig) {
		t.Fatal("signature accepted under a different key")
	}

	// A public key assembled from components of two key pairs must fail the binding check.
	hybrid := kp1.PublicKey
	hybrid.MQ = kp2.PublicKey.MQ
	if _, err := DeserializePublicKey(SerializePublicKey(&hybrid)); err == nil {
		t.Fatal("hybrid public key passed binding validation")
	}
	data := SerializePublicKey(&kp1.PublicKey)
	data[len(data)-1] ^= 1
	if _, err := DeserializePublicKey(data); err == nil {
		t.Fatal("tampered binding accepted")
	}
}

func TestDeserializeErrors(t *testing.T) {
	params, _ := core.GetSignParams(kmosaic.MOS_128)
	if _, err := DeserializePublicKey([]byte{1, 2, 3}); err == nil {
		t.Error("DeserializePublicKey should fail with invalid data")
	}
	if _, err := DeserializeSecretKey([]byte{1, 2, 3}); err == nil {
		t.Error("DeserializeSecretKey should fail with invalid data")
	}
	if _, err := DeserializeSignature([]byte{1, 2, 3}, params); err == nil {
		t.Error("DeserializeSignature should fail with invalid data")
	}
	kp, _ := GenerateKeyPair(kmosaic.MOS_128)
	sig, _ := Sign(&kp.SecretKey, &kp.PublicKey, []byte("x"))
	sb := SerializeSignature(sig)
	for _, cut := range []int{3, 50, len(sb) / 2, len(sb) - 1} {
		if _, err := DeserializeSignature(sb[:cut], params); err == nil {
			t.Errorf("truncated signature (%d bytes) accepted", cut)
		}
	}
	if _, err := DeserializeSignature(append(sb, 0), params); err == nil {
		t.Error("signature with trailing data accepted")
	}
	if Verify(nil, []byte("x"), sig) || Verify(&kp.PublicKey, []byte("x"), nil) {
		t.Error("nil inputs verified")
	}
}

func TestRandError(t *testing.T) {
	old := utils.RandReader
	utils.RandReader = &errorReader{}
	defer func() { utils.RandReader = old }()
	if _, err := GenerateKeyPair(kmosaic.MOS128); err == nil {
		t.Error("expected error from rand failure in key generation")
	}
	utils.RandReader = old
	kp, _ := GenerateKeyPair(kmosaic.MOS128)
	utils.RandReader = &errorReader{}
	if _, err := Sign(&kp.SecretKey, &kp.PublicKey, []byte("test")); err == nil {
		t.Error("expected error from rand failure in signing")
	}
}

type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, errReader
}

var errReader = &readError{}

type readError struct{}

func (*readError) Error() string { return "simulated rand error" }
