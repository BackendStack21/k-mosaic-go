package test

import (
	"bytes"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/kem"
	"github.com/BackendStack21/k-mosaic-go/sign"
)

func TestKEMRoundTrip128(t *testing.T) {
	kp, err := kem.GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	result, err := kem.Encapsulate(&kp.PublicKey)
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}

	sharedSecret, err := kem.Decapsulate(&kp.SecretKey, &kp.PublicKey, &result.Ciphertext)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}

	if !bytes.Equal(result.SharedSecret, sharedSecret) {
		t.Errorf("Shared secrets don't match")
	}
}

func TestKEMRoundTrip256(t *testing.T) {
	kp, err := kem.GenerateKeyPair(kmosaic.MOS_256)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	result, err := kem.Encapsulate(&kp.PublicKey)
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}

	sharedSecret, err := kem.Decapsulate(&kp.SecretKey, &kp.PublicKey, &result.Ciphertext)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}

	if !bytes.Equal(result.SharedSecret, sharedSecret) {
		t.Errorf("Shared secrets don't match")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	kp, err := kem.GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	message := []byte("Hello, post-quantum world! This is a test message.")

	encrypted, err := kem.Encrypt(&kp.PublicKey, message)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := kem.Decrypt(&kp.SecretKey, &kp.PublicKey, encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(message, decrypted) {
		t.Errorf("Decrypted message doesn't match original")
	}
}

func TestSignVerify128(t *testing.T) {
	kp, err := sign.GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	message := []byte("This is a message to sign")

	signature, err := sign.Sign(&kp.SecretKey, &kp.PublicKey, message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if !sign.Verify(&kp.PublicKey, message, signature) {
		t.Errorf("Signature verification failed")
	}

	// Test that wrong message fails
	wrongMessage := []byte("This is a different message")
	if sign.Verify(&kp.PublicKey, wrongMessage, signature) {
		t.Errorf("Signature verified for wrong message")
	}
}

func TestSignVerify256(t *testing.T) {
	kp, err := sign.GenerateKeyPair(kmosaic.MOS_256)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	message := []byte("This is a message to sign with 256-bit security")

	signature, err := sign.Sign(&kp.SecretKey, &kp.PublicKey, message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if !sign.Verify(&kp.PublicKey, message, signature) {
		t.Errorf("Signature verification failed")
	}
}

func BenchmarkKEMKeyGen128(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = kem.GenerateKeyPair(kmosaic.MOS_128)
	}
}

func BenchmarkKEMEncapsulate128(b *testing.B) {
	kp, _ := kem.GenerateKeyPair(kmosaic.MOS_128)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = kem.Encapsulate(&kp.PublicKey)
	}
}

func BenchmarkKEMDecapsulate128(b *testing.B) {
	kp, _ := kem.GenerateKeyPair(kmosaic.MOS_128)
	result, _ := kem.Encapsulate(&kp.PublicKey)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = kem.Decapsulate(&kp.SecretKey, &kp.PublicKey, &result.Ciphertext)
	}
}

func BenchmarkSignKeyGen128(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = sign.GenerateKeyPair(kmosaic.MOS_128)
	}
}

func BenchmarkSign128(b *testing.B) {
	kp, _ := sign.GenerateKeyPair(kmosaic.MOS_128)
	message := []byte("This is a message to sign")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = sign.Sign(&kp.SecretKey, &kp.PublicKey, message)
	}
}

func BenchmarkVerify128(b *testing.B) {
	kp, _ := sign.GenerateKeyPair(kmosaic.MOS_128)
	message := []byte("This is a message to sign")
	signature, _ := sign.Sign(&kp.SecretKey, &kp.PublicKey, message)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sign.Verify(&kp.PublicKey, message, signature)
	}
}
