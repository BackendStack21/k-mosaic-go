package sign

import (
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
)

func benchLevel(b *testing.B, level kmosaic.SecurityLevel) {
	kp, _ := GenerateKeyPair(level)
	msg := []byte("benchmark message")
	sig, _ := Sign(&kp.SecretKey, &kp.PublicKey, msg)
	pkBytes := SerializePublicKey(&kp.PublicKey)
	skBytes := SerializeSecretKey(&kp.SecretKey)
	b.Logf("%s: pk=%d sk=%d sig=%d bytes", level, len(pkBytes), len(skBytes), len(SerializeSignature(sig, kp.PublicKey.Params)))
	b.Run("KeyGen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = GenerateKeyPair(level)
		}
	})
	b.Run("Sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = Sign(&kp.SecretKey, &kp.PublicKey, msg)
		}
	})
	b.Run("Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if !Verify(&kp.PublicKey, msg, sig) {
				b.Fatal("verify failed")
			}
		}
	})
	b.Run("DeserializePublicKey", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = DeserializePublicKey(pkBytes)
		}
	})
	b.Run("DeserializeSecretKey", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = DeserializeSecretKey(skBytes)
		}
	})
}

func BenchmarkMOS128(b *testing.B) { benchLevel(b, kmosaic.MOS_128) }
func BenchmarkMOS256(b *testing.B) { benchLevel(b, kmosaic.MOS_256) }
