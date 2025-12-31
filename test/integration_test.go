// Package test provides integration tests for kMOSAIC implementation.
// These tests verify cross-component integration and protocol compliance.
package test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/kem"
	"github.com/BackendStack21/k-mosaic-go/sign"
)

// TestKEMRoundtrip tests key generation, encapsulation, and decapsulation.
func TestKEMRoundtrip(t *testing.T) {
	levels := []kmosaic.SecurityLevel{kmosaic.MOS_128, kmosaic.MOS_256}

	for _, level := range levels {
		t.Run(string(level), func(t *testing.T) {
			// Generate key pair
			kp, err := kem.GenerateKeyPair(level)
			if err != nil {
				t.Fatalf("GenerateKeyPair failed: %v", err)
			}

			// Encapsulate
			result, err := kem.Encapsulate(&kp.PublicKey)
			if err != nil {
				t.Fatalf("Encapsulate failed: %v", err)
			}

			if len(result.SharedSecret) != 32 {
				t.Errorf("SharedSecret length = %d, want 32", len(result.SharedSecret))
			}

			// Decapsulate
			recoveredSecret, err := kem.Decapsulate(&kp.SecretKey, &kp.PublicKey, &result.Ciphertext)
			if err != nil {
				t.Fatalf("Decapsulate failed: %v", err)
			}

			// Verify secrets match
			if !bytes.Equal(result.SharedSecret, recoveredSecret) {
				t.Error("Shared secrets do not match")
			}
		})
	}
}

// TestKEMSerialization tests public key and ciphertext serialization.
func TestKEMSerialization(t *testing.T) {
	levels := []kmosaic.SecurityLevel{kmosaic.MOS_128, kmosaic.MOS_256}

	for _, level := range levels {
		t.Run(string(level), func(t *testing.T) {
			// Generate key pair
			kp, err := kem.GenerateKeyPair(level)
			if err != nil {
				t.Fatalf("GenerateKeyPair failed: %v", err)
			}

			// Serialize public key
			pkBytes := kem.SerializePublicKey(&kp.PublicKey)

			// Deserialize public key
			pk2, err := kem.DeserializePublicKey(pkBytes)
			if err != nil {
				t.Fatalf("DeserializePublicKey failed: %v", err)
			}

			// Verify params match
			if pk2.Params.Level != level {
				t.Errorf("Level mismatch: got %s, want %s", pk2.Params.Level, level)
			}

			// Verify binding matches
			if !bytes.Equal(kp.PublicKey.Binding, pk2.Binding) {
				t.Error("Binding mismatch after serialization")
			}

			// Encapsulate with original key
			result, err := kem.Encapsulate(&kp.PublicKey)
			if err != nil {
				t.Fatalf("Encapsulate failed: %v", err)
			}

			// Serialize ciphertext
			ctBytes := kem.SerializeCiphertext(&result.Ciphertext)

			// Deserialize ciphertext
			ct2, err := kem.DeserializeCiphertext(ctBytes)
			if err != nil {
				t.Fatalf("DeserializeCiphertext failed: %v", err)
			}

			// Decapsulate with deserialized ciphertext
			recoveredSecret, err := kem.Decapsulate(&kp.SecretKey, &kp.PublicKey, ct2)
			if err != nil {
				t.Fatalf("Decapsulate with deserialized ciphertext failed: %v", err)
			}

			// Verify secrets match
			if !bytes.Equal(result.SharedSecret, recoveredSecret) {
				t.Error("Shared secrets do not match after serialization roundtrip")
			}
		})
	}
}

// TestKEMInvalidCiphertext tests implicit rejection on invalid ciphertext.
func TestKEMInvalidCiphertext(t *testing.T) {
	kp, err := kem.GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Create valid ciphertext
	result, err := kem.Encapsulate(&kp.PublicKey)
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}

	// Tamper with ciphertext (modify first byte of proof)
	tamperedCT := result.Ciphertext
	if len(tamperedCT.Proof) > 0 {
		tamperedCT.Proof[0] ^= 0xFF
	}

	// Decapsulate tampered ciphertext
	rejectedSecret, err := kem.Decapsulate(&kp.SecretKey, &kp.PublicKey, &tamperedCT)
	if err != nil {
		t.Fatalf("Decapsulate with tampered ciphertext failed: %v", err)
	}

	// Verify rejected secret differs from correct secret
	if bytes.Equal(result.SharedSecret, rejectedSecret) {
		t.Error("Tampered ciphertext produced same shared secret (implicit rejection failed)")
	}

	// Verify rejected secret is deterministic
	rejectedSecret2, err := kem.Decapsulate(&kp.SecretKey, &kp.PublicKey, &tamperedCT)
	if err != nil {
		t.Fatalf("Second decapsulate with tampered ciphertext failed: %v", err)
	}

	if !bytes.Equal(rejectedSecret, rejectedSecret2) {
		t.Error("Implicit rejection not deterministic")
	}
}

// TestSignRoundtrip tests signature generation and verification.
func TestSignRoundtrip(t *testing.T) {
	levels := []kmosaic.SecurityLevel{kmosaic.MOS_128, kmosaic.MOS_256}

	for _, level := range levels {
		t.Run(string(level), func(t *testing.T) {
			// Generate signing key pair
			kp, err := sign.GenerateKeyPair(level)
			if err != nil {
				t.Fatalf("GenerateKeyPair failed: %v", err)
			}

			// Message to sign
			message := []byte("Hello, kMOSAIC! This is a test message for digital signatures.")

			// Sign message
			sig, err := sign.Sign(&kp.SecretKey, &kp.PublicKey, message)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			// Verify signature
			valid := sign.Verify(&kp.PublicKey, message, sig)

			if !valid {
				t.Error("Valid signature rejected")
			}

			// Tamper with message
			tamperedMessage := append([]byte{}, message...)
			tamperedMessage[0] ^= 0xFF

			// Verify should fail on tampered message
			valid = sign.Verify(&kp.PublicKey, tamperedMessage, sig)

			if valid {
				t.Error("Tampered message signature accepted")
			}
		})
	}
}

// TestHybridEncryption tests full encryption/decryption flow.
func TestHybridEncryption(t *testing.T) {
	kp, err := kem.GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Test various message sizes
	testCases := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"small", 16},
		{"medium", 1024},
		{"large", 64 * 1024},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create test message
			plaintext := make([]byte, tc.size)
			for i := range plaintext {
				plaintext[i] = byte(i % 256)
			}

			// Encrypt
			em, err := kem.Encrypt(&kp.PublicKey, plaintext)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			// Decrypt
			decrypted, err := kem.Decrypt(&kp.SecretKey, &kp.PublicKey, em)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			// Verify plaintext matches
			if !bytes.Equal(plaintext, decrypted) {
				t.Error("Decrypted plaintext does not match original")
			}
		})
	}
}

// TestCLICommands tests CLI command integration.
func TestCLICommands(t *testing.T) {
	// Build CLI if not already built
	cliPath := filepath.Join("..", "cmd", "k-mosaic-cli", "k-mosaic-cli")
	if _, err := os.Stat(cliPath); os.IsNotExist(err) {
		// Try to build
		cmd := exec.Command("go", "build", "-o", cliPath, "./cmd/k-mosaic-cli")
		if err := cmd.Run(); err != nil {
			t.Skipf("Cannot build CLI: %v", err)
		}
	}

	// Create temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "kmosaic-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Test key generation
	t.Run("keygen", func(t *testing.T) {
		keyFile := filepath.Join(tmpDir, "test")

		cmd := exec.Command(cliPath, "kem", "keygen", "--level", "MOS-128", "--output", keyFile)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("keygen failed: %v\nOutput: %s", err, output)
		}

		// Check file exists (output is JSON with both keys)
		if _, err := os.Stat(keyFile); err != nil {
			t.Errorf("Key file not created: %v", err)
		}
	})

	// Test encryption/decryption
	t.Run("encrypt-decrypt", func(t *testing.T) {
		// Generate keys first
		cmd := exec.Command(cliPath, "kem", "keygen", "--level", "MOS-128", "--output", filepath.Join(tmpDir, "enc-test"))
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("keygen failed: %v\nOutput: %s", err, output)
		}

		// Create test file
		plaintext := []byte("This is a test message for CLI encryption.")
		plaintextPath := filepath.Join(tmpDir, "plaintext.txt")
		if err := os.WriteFile(plaintextPath, plaintext, 0644); err != nil {
			t.Fatalf("Failed to write plaintext file: %v", err)
		}

		// Encrypt
		encryptedPath := filepath.Join(tmpDir, "encrypted.bin")
		cmd = exec.Command(cliPath, "kem", "encrypt",
			"--public-key", filepath.Join(tmpDir, "enc-test"),
			"--input", plaintextPath,
			"--output", encryptedPath)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("encrypt failed: %v\nOutput: %s", err, output)
		}

		// Decrypt
		decryptedPath := filepath.Join(tmpDir, "decrypted.txt")
		cmd = exec.Command(cliPath, "kem", "decrypt",
			"--secret-key", filepath.Join(tmpDir, "enc-test"),
			"--public-key", filepath.Join(tmpDir, "enc-test"),
			"--ciphertext", encryptedPath,
			"--output", decryptedPath)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("decrypt failed: %v\nOutput: %s", err, output)
		}

		// Verify decrypted matches original
		decrypted, err := os.ReadFile(decryptedPath)
		if err != nil {
			t.Fatalf("Failed to read decrypted file: %v", err)
		}

		if !bytes.Equal(plaintext, decrypted) {
			t.Error("Decrypted content does not match original")
		}
	})

	// Test signing/verification
	t.Run("sign-verify", func(t *testing.T) {
		// Generate signing keys
		cmd := exec.Command(cliPath, "sign", "keygen", "--level", "MOS-128", "--output", filepath.Join(tmpDir, "sign-test"))
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("sign keygen failed: %v\nOutput: %s", err, output)
		}

		// Create test file
		message := []byte("This is a test message for CLI signing.")
		messagePath := filepath.Join(tmpDir, "message.txt")
		if err := os.WriteFile(messagePath, message, 0644); err != nil {
			t.Fatalf("Failed to write message file: %v", err)
		}

		// Sign
		sigPath := filepath.Join(tmpDir, "message.sig")
		cmd = exec.Command(cliPath, "sign", "sign",
			"--secret-key", filepath.Join(tmpDir, "sign-test"),
			"--public-key", filepath.Join(tmpDir, "sign-test"),
			"--input", messagePath,
			"--output", sigPath)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("sign failed: %v\nOutput: %s", err, output)
		}

		// Verify
		cmd = exec.Command(cliPath, "sign", "verify",
			"--public-key", filepath.Join(tmpDir, "sign-test"),
			"--input", messagePath,
			"--signature", sigPath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("verify failed: %v\nOutput: %s", err, output)
		}

		if !bytes.Contains(output, []byte("valid")) && !bytes.Contains(output, []byte("Valid")) {
			t.Errorf("Verification did not report valid signature. Output: %s", output)
		}
	})
}

// TestBindingValidation tests that binding validation prevents component substitution.
func TestBindingValidation(t *testing.T) {
	// Generate two different key pairs
	kp1, err := kem.GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		t.Fatalf("GenerateKeyPair 1 failed: %v", err)
	}

	kp2, err := kem.GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		t.Fatalf("GenerateKeyPair 2 failed: %v", err)
	}

	// Create hybrid public key with mismatched components
	hybridPK := kp1.PublicKey
	hybridPK.SLSS = kp2.PublicKey.SLSS // Substitute SLSS component

	// Serialize and attempt to deserialize
	pkBytes := kem.SerializePublicKey(&hybridPK)
	_, err = kem.DeserializePublicKey(pkBytes)

	// Should fail binding validation
	if err == nil {
		t.Error("Hybrid public key with substituted component should fail validation")
	} else if !bytes.Contains([]byte(err.Error()), []byte("binding")) {
		t.Errorf("Expected binding error, got: %v", err)
	}
}

// BenchmarkKEM benchmarks KEM operations.
func BenchmarkKEM(b *testing.B) {
	kp, err := kem.GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		b.Fatalf("GenerateKeyPair failed: %v", err)
	}

	b.Run("Encapsulate", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := kem.Encapsulate(&kp.PublicKey)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	result, _ := kem.Encapsulate(&kp.PublicKey)

	b.Run("Decapsulate", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := kem.Decapsulate(&kp.SecretKey, &kp.PublicKey, &result.Ciphertext)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkSign benchmarks signature operations.
func BenchmarkSign(b *testing.B) {
	kp, err := sign.GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		b.Fatalf("GenerateKeyPair failed: %v", err)
	}

	message := []byte("Benchmark message for signing performance test")

	b.Run("Sign", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := sign.Sign(&kp.SecretKey, &kp.PublicKey, message)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	sig, _ := sign.Sign(&kp.SecretKey, &kp.PublicKey, message)

	b.Run("Verify", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			valid := sign.Verify(&kp.PublicKey, message, sig)
			if !valid {
				b.Fatal("signature verification failed")
			}
		}
	})
}

// TestDeterministicNIZK tests NIZK proof generation and validation with fixed seed
// This allows reproducible debugging of NIZK proofs for cross-implementation comparison
func TestDeterministicNIZK(t *testing.T) {
	// Fixed seed for deterministic NIZK proof generation
	fixedSeed := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}

	t.Run("MOS-128", func(t *testing.T) {
		testDeterministicNIZKLevel(t, kmosaic.MOS_128, fixedSeed)
	})

	t.Run("MOS-256", func(t *testing.T) {
		testDeterministicNIZKLevel(t, kmosaic.MOS_256, fixedSeed)
	})
}

func testDeterministicNIZKLevel(t *testing.T, level kmosaic.SecurityLevel, fixedSeed []byte) {
	// Generate key pair
	kp, err := kem.GenerateKeyPair(level)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Use fixed ephemeral secret for deterministic output
	// This ensures the NIZK proof is reproducible for debugging
	result, err := kem.EncapsulateDeterministic(&kp.PublicKey, fixedSeed)
	if err != nil {
		t.Fatalf("EncapsulateDeterministic failed: %v", err)
	}

	// Verify decapsulation works
	recoveredSecret, err := kem.Decapsulate(&kp.SecretKey, &kp.PublicKey, &result.Ciphertext)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}

	if !bytes.Equal(result.SharedSecret, recoveredSecret) {
		t.Error("Shared secrets do not match after roundtrip")
	}

	// Write proof data for debugging
	if os.Getenv("DEBUG_NIZK") != "" {
		t.Logf("Level: %s", level)
		t.Logf("Ciphertext: %x", result.Ciphertext)
		t.Logf("SharedSecret: %x", result.SharedSecret)
	}
}
