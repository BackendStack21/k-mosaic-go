// Package main demonstrates basic usage of the kMOSAIC library.
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	kmosaic "github.com/BackendStack21/k-mosaic-go/v4"
	"github.com/BackendStack21/k-mosaic-go/v4/kem"
	"github.com/BackendStack21/k-mosaic-go/v4/sign"
)

func main() {
	fmt.Println("kMOSAIC Go Implementation Demo")
	fmt.Println("================================")
	fmt.Println()

	// Demonstrate KEM
	fmt.Println("1. Key Encapsulation Mechanism (KEM)")
	fmt.Println("------------------------------------")

	start := time.Now()
	kemKP, err := kem.GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		log.Fatalf("KEM key generation failed: %v", err)
	}
	fmt.Printf("Key generation: %v\n", time.Since(start))

	start = time.Now()
	encResult, err := kem.Encapsulate(&kemKP.PublicKey)
	if err != nil {
		log.Fatalf("Encapsulation failed: %v", err)
	}
	fmt.Printf("Encapsulation: %v\n", time.Since(start))
	fmt.Printf("Shared secret (sender): %s\n", hex.EncodeToString(encResult.SharedSecret[:16]))

	start = time.Now()
	sharedSecret, err := kem.Decapsulate(&kemKP.SecretKey, &kemKP.PublicKey, &encResult.Ciphertext)
	if err != nil {
		log.Fatalf("Decapsulation failed: %v", err)
	}
	fmt.Printf("Decapsulation: %v\n", time.Since(start))
	fmt.Printf("Shared secret (receiver): %s\n", hex.EncodeToString(sharedSecret[:16]))

	// Verify shared secrets match
	if !bytes.Equal(encResult.SharedSecret, sharedSecret) {
		log.Fatal("shared secrets do not match")
	}
	fmt.Println("✓ Shared secrets match!")
	fmt.Println()

	// Demonstrate encryption/decryption
	fmt.Println("2. Encryption/Decryption")
	fmt.Println("------------------------")

	message := []byte("Hello, post-quantum world!")
	fmt.Printf("Original message: %s\n", string(message))

	start = time.Now()
	encrypted, err := kem.Encrypt(&kemKP.PublicKey, message)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}
	fmt.Printf("Encryption: %v\n", time.Since(start))

	start = time.Now()
	decrypted, err := kem.Decrypt(&kemKP.SecretKey, &kemKP.PublicKey, encrypted)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}
	fmt.Printf("Decryption: %v\n", time.Since(start))
	fmt.Printf("Decrypted message: %s\n", string(decrypted))

	if !bytes.Equal(decrypted, message) {
		log.Fatal("decrypted message differs from the original")
	}
	fmt.Println("✓ Decryption successful!")
	fmt.Println()

	// Demonstrate signatures
	fmt.Println("3. Digital Signatures")
	fmt.Println("---------------------")

	start = time.Now()
	signKP, err := sign.GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		log.Fatalf("Sign key generation failed: %v", err)
	}
	fmt.Printf("Key generation: %v\n", time.Since(start))

	msgToSign := []byte("This is a message to sign")
	start = time.Now()
	signature, err := sign.Sign(&signKP.SecretKey, &signKP.PublicKey, msgToSign)
	if err != nil {
		log.Fatalf("Signing failed: %v", err)
	}
	fmt.Printf("Signing: %v\n", time.Since(start))

	start = time.Now()
	valid := sign.Verify(&signKP.PublicKey, msgToSign, signature)
	fmt.Printf("Verification: %v\n", time.Since(start))

	if !valid {
		log.Fatal("signature is invalid")
	}
	fmt.Println("✓ Signature is valid!")
	fmt.Println()

	fmt.Println("Demo complete!")
}
