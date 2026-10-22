package slss

import (
	"bytes"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
)

func smallParams() kmosaic.SLSSParams {
	p := core.MOS128Params.SLSS
	p.N, p.M, p.W, p.L = 9, 8, 2, 8 // 9·11 bits: U has padding
	return p
}

// FuzzDeserializePublicKey checks that public key parsing never panics and
// that every accepted encoding is canonical.
func FuzzDeserializePublicKey(f *testing.F) {
	small := smallParams()
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add(make([]byte, PublicKeySize(small)))
	f.Add(bytes.Repeat([]byte{0xff}, PublicKeySize(small)))

	f.Fuzz(func(t *testing.T, data []byte) {
		pk, err := DeserializePublicKey(data, small)
		if err != nil {
			return
		}
		if !bytes.Equal(SerializePublicKey(*pk), data) {
			t.Fatal("accepted a non-canonical public key encoding")
		}
	})
}

// FuzzDeserializeCiphertext checks that ciphertext parsing never panics,
// that every accepted encoding is canonical, and that it decrypts.
func FuzzDeserializeCiphertext(f *testing.F) {
	small := smallParams()
	kp, err := KeyGen(small, make([]byte, 32))
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte{})
	f.Add(make([]byte, CiphertextSize(small)))
	f.Add(bytes.Repeat([]byte{0xff}, CiphertextSize(small)))

	f.Fuzz(func(t *testing.T, data []byte) {
		ct, err := DeserializeCiphertext(data, small)
		if err != nil {
			return
		}
		if !bytes.Equal(SerializeCiphertext(ct, small), data) {
			t.Fatal("accepted a non-canonical ciphertext encoding")
		}
		if len(Decrypt(ct, kp.SecretKey, small)) != MessageSize(small) {
			t.Fatal("Decrypt rejected a parsed ciphertext")
		}
	})
}

// FuzzDeserializeSecretKey checks that secret key parsing never panics and
// that every accepted encoding is canonical.
func FuzzDeserializeSecretKey(f *testing.F) {
	small := smallParams()
	f.Add([]byte{})
	f.Add(make([]byte, SecretKeySize(small)))
	f.Add(bytes.Repeat([]byte{0x55}, SecretKeySize(small)))
	f.Add(bytes.Repeat([]byte{0xff}, SecretKeySize(small)))

	f.Fuzz(func(t *testing.T, data []byte) {
		sk, err := DeserializeSecretKey(data, small)
		if err != nil {
			return
		}
		if !bytes.Equal(SerializeSecretKey(*sk, small), data) {
			t.Fatal("accepted a non-canonical secret key encoding")
		}
	})
}
