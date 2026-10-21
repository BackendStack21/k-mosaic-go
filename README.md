# kMOSAIC - Go Implementation

[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A Go implementation of the kMOSAIC post-quantum cryptographic library.

> A TypeScript/JavaScript version is also available at [https://github.com/BackendStack21/k-mosaic](https://github.com/BackendStack21/k-mosaic).

## Documentation

- [kMOSAIC White Paper](https://github.com/BackendStack21/k-mosaic/blob/main/kMOSAIC_WHITE_PAPER.md) - Detailed technical specification and cryptographic design
- [Developer Guide - TypeScript Reference](https://github.com/BackendStack21/k-mosaic/blob/main/DEVELOPER_GUIDE.md) - Implementation guidelines and best practices

## ⚠️ Security Warning

**kMOSAIC is an experimental cryptographic construction that has NOT been reviewed by anyone outside this repository. DO NOT use in production systems protecting sensitive data.**

**Versions before 2.0.0 (and the TypeScript implementation) are broken:** the
KEM shared secret could be recovered from the public key and ciphertext alone,
and signatures could be forged by anyone holding the public key. See
[SECURITY_ASSESSMENT.md](SECURITY_ASSESSMENT.md) for the reproduced attacks,
a claim-by-claim review of the original design, and what 2.0.0 changes.
Keys, ciphertexts and signatures from earlier versions must be discarded.

## Overview

kMOSAIC 2.x is built on unstructured lattice assumptions:

- **KEM / encryption**: plain LWE with sparse ternary secrets (the "SLSS"
  component), one secret column per message bit, with a Fujisaki-Okamoto
  transform for CCA security.
- **Signatures**: the CRYSTALS-Dilithium / FIPS 204 construction over
  unstructured matrices, with ML-DSA-65 and ML-DSA-87 parameter shapes.

The original design advertised two further "hard problems", TDD (tensor
decomposition) and EGRW (expander-graph walks). Neither contributes any
security: their component ciphertexts are decryptable without the secret key
and the EGRW group is small enough to search exhaustively. They remain in the
KEM ciphertext layout only for continuity and are documented as such.

## Features

- **Key Encapsulation Mechanism (KEM)**: LWE-based key exchange with implicit rejection
- **Encryption/Decryption**: Hybrid encryption using KEM and AES-256-GCM
- **Digital Signatures**: Fiat-Shamir-with-aborts lattice signatures
- **Parallel Execution**: Uses Go goroutines for matrix operations
- **Two Security Levels**: MOS_128 and MOS_256 (see "Security Levels" for what they mean)

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
    "bytes"
    "fmt"
    kmosaic "github.com/BackendStack21/k-mosaic-go"
    "github.com/BackendStack21/k-mosaic-go/kem"
    "github.com/BackendStack21/k-mosaic-go/sign"
)

func main() {
    // Key Encapsulation
    kemKeyPair, _ := kem.GenerateKeyPair(kmosaic.MOS_128)
    ciphertext, senderSecret, _ := kem.Encapsulate(&kemKeyPair.PublicKey)
    recipientSecret, _ := kem.Decapsulate(&kemKeyPair.SecretKey, &kemKeyPair.PublicKey, ciphertext)
    fmt.Printf("Shared secrets match: %v\n", bytes.Equal(senderSecret, recipientSecret))

    // Digital Signatures
    signKeyPair, _ := sign.GenerateKeyPair(kmosaic.MOS_128)
    message := []byte("Hello, post-quantum world!")
    signature, _ := sign.Sign(&signKeyPair.SecretKey, &signKeyPair.PublicKey, message)
    isValid := sign.Verify(&signKeyPair.PublicKey, message, signature)
    fmt.Printf("Signature valid: %v\n", isValid)
}
```

## Performance and sizes (2.0.0, 4-core x86-64 container)

| Operation       | MOS_128 | MOS_256 |
| --------------- | ------- | ------- |
| KEM KeyGen      | 36 ms   | 81 ms   |
| KEM Encapsulate | 0.4 ms  | 0.8 ms  |
| KEM Decapsulate | 0.8 ms  | 1.1 ms  |
| Sign KeyGen     | 197 ms  | 221 ms  |
| Sign            | 14 ms   | 27 ms   |
| Verify          | 9 ms    | 10 ms   |

| Object               | MOS_128 | MOS_256 |
| -------------------- | ------- | ------- |
| KEM public key       | 449 KB  | 777 KB  |
| KEM ciphertext       | 6.9 KB  | 11.3 KB |
| Signature public key | 1.18 MB | 1.57 MB |
| Signature            | 3.9 KB  | 5.4 KB  |

Keys are large because the schemes are unstructured (no polynomial rings).
The figures in [BenchmarkReport.md](BenchmarkReport.md) describe the broken
1.x design and are kept for the record only.

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

The names are historical. Estimated strength under a core-SVP model (see
SECURITY_ASSESSMENT.md §1.4 and §3 for the model and its limits):

- **MOS_128**: KEM ≈ 2^146 quantum core-SVP (n = m = 768 LWE); signatures use the ML-DSA-65 shape (≈ 2^165).
- **MOS_256**: KEM ≈ 2^236 quantum core-SVP (n = m = 1152 LWE); signatures use the ML-DSA-87 shape (≈ 2^229).

These are estimates from this repository's own review, not from an external
analysis, and hybrid attacks on the sparse secret were not modelled.

## Requirements

- Go 1.21 or later
- golang.org/x/crypto/sha3

## License

MIT License - See LICENSE file for details.
