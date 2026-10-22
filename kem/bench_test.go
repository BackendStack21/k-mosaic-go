package kem

import (
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
)

func benchLevel(b *testing.B, level kmosaic.SecurityLevel) {
	kp, _ := GenerateKeyPair(level)
	res, _ := Encapsulate(&kp.PublicKey)
	pkBytes := SerializePublicKey(&kp.PublicKey)
	b.Run("KeyGen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = GenerateKeyPair(level)
		}
	})
	b.Run("Encapsulate", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = Encapsulate(&kp.PublicKey)
		}
	})
	b.Run("Decapsulate", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = Decapsulate(&kp.SecretKey, &kp.PublicKey, &res.Ciphertext)
		}
	})
	b.Run("DeserializePublicKey", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = DeserializePublicKey(pkBytes)
		}
	})
}

func BenchmarkMOS128(b *testing.B) { benchLevel(b, kmosaic.MOS_128) }
func BenchmarkMOS256(b *testing.B) { benchLevel(b, kmosaic.MOS_256) }
