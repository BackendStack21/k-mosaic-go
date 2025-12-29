package test

import (
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/kem"
	"github.com/BackendStack21/k-mosaic-go/sign"
)

// =============================================================================
// KEM Benchmarks - MOS-128
// =============================================================================

func BenchmarkKEM_GenerateKeyPair_MOS128(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := kem.GenerateKeyPair(kmosaic.MOS_128)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKEM_Encapsulate_MOS128(b *testing.B) {
	kp, err := kem.GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := kem.Encapsulate(&kp.PublicKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKEM_Decapsulate_MOS128(b *testing.B) {
	kp, err := kem.GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		b.Fatal(err)
	}

	result, err := kem.Encapsulate(&kp.PublicKey)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := kem.Decapsulate(&kp.SecretKey, &kp.PublicKey, &result.Ciphertext)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKEM_Encrypt_MOS128(b *testing.B) {
	kp, err := kem.GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		b.Fatal(err)
	}

	plaintext := []byte("This is a test message for encryption benchmarking")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := kem.Encrypt(&kp.PublicKey, plaintext)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKEM_Decrypt_MOS128(b *testing.B) {
	kp, err := kem.GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		b.Fatal(err)
	}

	plaintext := []byte("This is a test message for encryption benchmarking")
	encrypted, err := kem.Encrypt(&kp.PublicKey, plaintext)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := kem.Decrypt(&kp.SecretKey, &kp.PublicKey, encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// =============================================================================
// KEM Benchmarks - MOS-256
// =============================================================================

func BenchmarkKEM_GenerateKeyPair_MOS256(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := kem.GenerateKeyPair(kmosaic.MOS_256)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKEM_Encapsulate_MOS256(b *testing.B) {
	kp, err := kem.GenerateKeyPair(kmosaic.MOS_256)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := kem.Encapsulate(&kp.PublicKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKEM_Decapsulate_MOS256(b *testing.B) {
	kp, err := kem.GenerateKeyPair(kmosaic.MOS_256)
	if err != nil {
		b.Fatal(err)
	}

	result, err := kem.Encapsulate(&kp.PublicKey)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := kem.Decapsulate(&kp.SecretKey, &kp.PublicKey, &result.Ciphertext)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKEM_Encrypt_MOS256(b *testing.B) {
	kp, err := kem.GenerateKeyPair(kmosaic.MOS_256)
	if err != nil {
		b.Fatal(err)
	}

	plaintext := []byte("This is a test message for encryption benchmarking")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := kem.Encrypt(&kp.PublicKey, plaintext)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKEM_Decrypt_MOS256(b *testing.B) {
	kp, err := kem.GenerateKeyPair(kmosaic.MOS_256)
	if err != nil {
		b.Fatal(err)
	}

	plaintext := []byte("This is a test message for encryption benchmarking")
	encrypted, err := kem.Encrypt(&kp.PublicKey, plaintext)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := kem.Decrypt(&kp.SecretKey, &kp.PublicKey, encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// =============================================================================
// Signature Benchmarks - MOS-128
// =============================================================================

func BenchmarkSign_GenerateKeyPair_MOS128(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := sign.GenerateKeyPair(kmosaic.MOS_128)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign_Sign_MOS128(b *testing.B) {
	kp, err := sign.GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		b.Fatal(err)
	}

	message := []byte("This is a test message for signature benchmarking")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := sign.Sign(&kp.SecretKey, &kp.PublicKey, message)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign_Verify_MOS128(b *testing.B) {
	kp, err := sign.GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		b.Fatal(err)
	}

	message := []byte("This is a test message for signature benchmarking")
	signature, err := sign.Sign(&kp.SecretKey, &kp.PublicKey, message)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		valid := sign.Verify(&kp.PublicKey, message, signature)
		if !valid {
			b.Fatal("signature verification failed")
		}
	}
}

// =============================================================================
// Signature Benchmarks - MOS-256
// =============================================================================

func BenchmarkSign_GenerateKeyPair_MOS256(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := sign.GenerateKeyPair(kmosaic.MOS_256)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign_Sign_MOS256(b *testing.B) {
	kp, err := sign.GenerateKeyPair(kmosaic.MOS_256)
	if err != nil {
		b.Fatal(err)
	}

	message := []byte("This is a test message for signature benchmarking")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := sign.Sign(&kp.SecretKey, &kp.PublicKey, message)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign_Verify_MOS256(b *testing.B) {
	kp, err := sign.GenerateKeyPair(kmosaic.MOS_256)
	if err != nil {
		b.Fatal(err)
	}

	message := []byte("This is a test message for signature benchmarking")
	signature, err := sign.Sign(&kp.SecretKey, &kp.PublicKey, message)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		valid := sign.Verify(&kp.PublicKey, message, signature)
		if !valid {
			b.Fatal("signature verification failed")
		}
	}
}

// =============================================================================
// Full Round-Trip Benchmarks
// =============================================================================

func BenchmarkKEM_FullRoundTrip_MOS128(b *testing.B) {
	plaintext := []byte("Round-trip benchmark message")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		kp, err := kem.GenerateKeyPair(kmosaic.MOS_128)
		if err != nil {
			b.Fatal(err)
		}

		encrypted, err := kem.Encrypt(&kp.PublicKey, plaintext)
		if err != nil {
			b.Fatal(err)
		}

		_, err = kem.Decrypt(&kp.SecretKey, &kp.PublicKey, encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKEM_FullRoundTrip_MOS256(b *testing.B) {
	plaintext := []byte("Round-trip benchmark message")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		kp, err := kem.GenerateKeyPair(kmosaic.MOS_256)
		if err != nil {
			b.Fatal(err)
		}

		encrypted, err := kem.Encrypt(&kp.PublicKey, plaintext)
		if err != nil {
			b.Fatal(err)
		}

		_, err = kem.Decrypt(&kp.SecretKey, &kp.PublicKey, encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign_FullRoundTrip_MOS128(b *testing.B) {
	message := []byte("Round-trip benchmark message")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		kp, err := sign.GenerateKeyPair(kmosaic.MOS_128)
		if err != nil {
			b.Fatal(err)
		}

		signature, err := sign.Sign(&kp.SecretKey, &kp.PublicKey, message)
		if err != nil {
			b.Fatal(err)
		}

		valid := sign.Verify(&kp.PublicKey, message, signature)
		if !valid {
			b.Fatal("signature verification failed")
		}
	}
}

func BenchmarkSign_FullRoundTrip_MOS256(b *testing.B) {
	message := []byte("Round-trip benchmark message")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		kp, err := sign.GenerateKeyPair(kmosaic.MOS_256)
		if err != nil {
			b.Fatal(err)
		}

		signature, err := sign.Sign(&kp.SecretKey, &kp.PublicKey, message)
		if err != nil {
			b.Fatal(err)
		}

		valid := sign.Verify(&kp.PublicKey, message, signature)
		if !valid {
			b.Fatal("signature verification failed")
		}
	}
}
