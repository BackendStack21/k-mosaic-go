# kMOSAIC - Go Implementation

[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A Go implementation of the kMOSAIC post-quantum cryptographic library.

> A TypeScript/JavaScript version is also available at [https://github.com/BackendStack21/k-mosaic](https://github.com/BackendStack21/k-mosaic).

## Documentation

- [kMOSAIC White Paper](https://github.com/BackendStack21/k-mosaic/blob/main/kMOSAIC_WHITE_PAPER.md) - Detailed technical specification and cryptographic design
- [Developer Guide - TypeScript Reference](https://github.com/BackendStack21/k-mosaic/blob/main/DEVELOPER_GUIDE.md) - Implementation guidelines and best practices

## ⚠️ Security Warning

**kMOSAIC is an experimental cryptographic construction that has NOT been formally verified by academic peer review. DO NOT use in production systems protecting sensitive data.**

## Overview

kMOSAIC (Key Mosaic) is a post-quantum secure cryptographic framework that combines three distinct hard mathematical problems to provide defense-in-depth security:

- **SLSS** - Sparse Lattice Subset Sum Problem
- **TDD** - Tensor Decomposition Decisional Problem
- **EGRW** - Expander Graph Random Walk Problem

## Features

- **Key Encapsulation Mechanism (KEM)**: Post-quantum secure key exchange
- **Encryption/Decryption**: Hybrid encryption using KEM and AES-GCM (symmetric payload encryption)
- **Digital Signatures**: Post-quantum secure signatures
- **Parallel Execution**: Uses Go goroutines for improved performance
- **Two Security Levels**: MOS_128 (128-bit) and MOS_256 (256-bit)

## Installation

```bash
go get github.com/BackendStack21/k-mosaic-go
```

## Command-line Interface

Use the `k-mosaic-cli` for common tasks such as key generation, encryption/decryption, and signing/verification.

### Quick Start

```bash
# Install the CLI
go install github.com/BackendStack21/k-mosaic-go/cmd/k-mosaic-cli@latest

# Generate keys, encrypt, decrypt
k-mosaic-cli kem keygen -l 128 -o keys.json
k-mosaic-cli kem encrypt -pk keys.json -m "Secret message" -o enc.json
k-mosaic-cli kem decrypt -sk keys.json -pk keys.json -ct enc.json

# Generate keys, sign, verify
k-mosaic-cli sign keygen -l 128 -o sign.json
k-mosaic-cli sign sign -sk sign.json -pk sign.json -m "Document" -o sig.json
k-mosaic-cli sign verify -pk sign.json -sig sig.json
```

### Full Documentation

For comprehensive CLI documentation, installation methods, security best practices, key management workflows, and detailed command reference, see: **[CLI.md](CLI.md)**

Key topics in CLI.md:
- Installation methods (source, go install, multi-platform builds)
- Complete encryption and signature workflows
- Security best practices and key management
- Troubleshooting and FAQ

## Quick Start

```go
package main

import (
    "fmt"
    kmosaic "github.com/BackendStack21/k-mosaic-go"
    "github.com/BackendStack21/k-mosaic-go/kem"
    "github.com/BackendStack21/k-mosaic-go/sign"
)

func main() {
    // Key Encapsulation
    kp, _ := kem.GenerateKeyPair(kmosaic.MOS_128)
    ct, ss1, _ := kem.Encapsulate(&kp.PublicKey)
    ss2, _ := kem.Decapsulate(&kp.SecretKey, &kp.PublicKey, ct)
    fmt.Printf("Shared secrets match: %v\n", bytes.Equal(ss1, ss2))

    // Digital Signatures
    signKP, _ := sign.GenerateKeyPair(kmosaic.MOS_128)
    message := []byte("Hello, post-quantum world!")
    sig, _ := sign.Sign(&signKP.SecretKey, &signKP.PublicKey, message)
    valid := sign.Verify(&signKP.PublicKey, message, sig)
    fmt.Printf("Signature valid: %v\n", valid)
}
```

## Benchmarks (Apple M2 Pro)

| Operation       | MOS_128   | MOS_256   |
| --------------- | --------- | --------- |
| KEM KeyGen      | 6.29 ms   | 22.43 ms  |
| KEM Encapsulate | 0.32 ms   | 0.95 ms   |
| KEM Decapsulate | 0.38 ms   | 1.06 ms   |
| Sign KeyGen     | 6.22 ms   | 22.49 ms  |
| Sign            | 12.07 μs  | 21.95 μs  |
| Verify          | 2.44 ms   | 9.13 ms   |

_See [BenchmarkReport.md](BenchmarkReport.md) for comprehensive detailed benchmark results, performance analysis, and methodology._

## API Reference

### KEM Package

```go
import "github.com/BackendStack21/k-mosaic-go/kem"

// Generate a new key pair
kp, err := kem.GenerateKeyPair(level)

// Encapsulate (create ciphertext and shared secret)
ciphertext, sharedSecret, err := kem.Encapsulate(&publicKey)

// Decapsulate (recover shared secret)
sharedSecret, err := kem.Decapsulate(&secretKey, &publicKey, ciphertext)

// Encrypt a message (hybrid: KEM + AES-GCM for symmetric payload encryption)
ciphertext, err := kem.Encrypt(&publicKey, plaintext)

// Decrypt a message (hybrid: KEM + AES-GCM for symmetric payload decryption)
plaintext, err := kem.Decrypt(&secretKey, &publicKey, ciphertext)
```

### Sign Package

```go
import "github.com/BackendStack21/k-mosaic-go/sign"

// Generate a signing key pair
kp, err := sign.GenerateKeyPair(level)

// Sign a message
signature, err := sign.Sign(&secretKey, &publicKey, message)

// Verify a signature
valid := sign.Verify(&publicKey, message, signature)
```

## Security Levels

- **MOS_128**: 128-bit post-quantum security
- **MOS_256**: 256-bit post-quantum security

## Requirements

- Go 1.21 or later
- golang.org/x/crypto/sha3

## License

MIT License - See LICENSE file for details.
