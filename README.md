# kMOSAIC - Go Implementation

[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A Go implementation of the kMOSAIC post-quantum cryptographic library.

> A TypeScript/JavaScript version is also available at [https://github.com/BackendStack21/k-mosaic](https://github.com/BackendStack21/k-mosaic).

## Documentation

- [kMOSAIC White Paper](https://github.com/BackendStack21/k-mosaic/blob/main/kMOSAIC_WHITE_PAPER.md) - Detailed technical specification and cryptographic design
- [Developer Guide - TypeScript Reference](https://github.com/BackendStack21/k-mosaic/blob/main/DEVELOPER_GUIDE.md) - Implementation guidelines and best practices

## ⚠️ Security Warning

**kMOSAIC is an experimental library that has not been reviewed by anyone
outside this repository. DO NOT use in production systems protecting sensitive
data.**

Versions before 4.0.0 are broken. In 1.x the KEM shared secret could be
recovered from the public key and ciphertext alone and signatures could be
forged by anyone holding the public key; 3.0.0 reintroduced a ciphertext field
that leaked the KEM shares. See [SECURITY_ASSESSMENT.md](SECURITY_ASSESSMENT.md)
for the reproduced attacks, a claim-by-claim review of the original design, the
3.0 redesign and the 4.0 expert-panel review. Keys, ciphertexts and signatures
from earlier versions must be discarded; 4.0.0 refuses to parse them.

## Overview

kMOSAIC 3.x composes independent post-quantum hard problems so that breaking a
primitive requires breaking **every** problem it is built from. The components
are standard constructions, instantiated here without algebraic structure
where the construction allows it, and combined so that the composite is at
least as strong as its strongest component.

| Primitive  | Component                                   | Hard problem                                   |
| ---------- | ------------------------------------------- | ---------------------------------------------- |
| KEM        | SLSS: plain LWE with sparse ternary secrets | Learning With Errors (unstructured lattices)   |
| KEM        | QCSD: the HQC public-key encryption scheme  | Quasi-cyclic syndrome decoding (codes)         |
| Signatures | latsig: ML-DSA over unstructured matrices   | Module-free SIS / LWE (lattices)               |
| Signatures | uov: Unbalanced Oil and Vinegar over F_256  | Multivariate quadratic equations (MQ)          |
| Signatures | slhdsa: SLH-DSA / SPHINCS+ with SHAKE256    | Hash-function (second-)preimage resistance     |

- **KEM**: a 32-byte ephemeral secret is split into two XOR shares, one
  encrypted by each component. The ephemeral secret stays hidden as long as
  *either* LWE or syndrome decoding is hard. A Fujisaki-Okamoto transform
  (derandomization, re-encryption check, implicit rejection) gives IND-CCA
  security in the random-oracle model. The hybrid `Encrypt`/`Decrypt` API
  wraps the KEM with AES-256-GCM.
- **Signatures**: the message is hashed together with the composite public
  key, and the digest is signed by all three components. A signature verifies
  only if all three component signatures verify, so a forger must break
  lattices, MQ **and** hash functions. Public keys carry a binding hash of
  their components, and the digest includes the public-key hash, so
  components cannot be mixed across key pairs.

There is no third practical post-quantum *encryption* family (isogenies are
too slow and contested, multivariate encryption is broken), which is why the
KEM composes two problems and the signature three.

## Features

- **Key Encapsulation Mechanism (KEM)**: LWE + code-based combiner with implicit rejection
- **Encryption/Decryption**: Hybrid encryption using the KEM and AES-256-GCM
- **Digital Signatures**: lattice + multivariate + hash-based combiner
- **Parallel Execution**: Components run concurrently with Go goroutines
- **Two Parameter Sets**: MOS_128 and MOS_256 (see "Security Levels")

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

# Generate keys (writes keys.json with both keys and keys.json.pub with the public key), encrypt, decrypt
k-mosaic-cli kem keygen -l 128 -o keys.json
k-mosaic-cli kem encrypt -pk keys.json.pub -m "Secret message" -o enc.json
k-mosaic-cli kem decrypt -sk keys.json -pk keys.json.pub -ct enc.json

# Generate keys, sign, verify (the message must be given explicitly to verify)
k-mosaic-cli sign keygen -l 128 -o sign.json
k-mosaic-cli sign sign -sk sign.json -pk sign.json.pub -m "Document" -o sig.json
k-mosaic-cli sign verify -pk sign.json.pub -sig sig.json -m "Document"
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
    enc, _ := kem.Encapsulate(&kemKeyPair.PublicKey)
    recipientSecret, _ := kem.Decapsulate(&kemKeyPair.SecretKey, &kemKeyPair.PublicKey, &enc.Ciphertext)
    fmt.Printf("Shared secrets match: %v\n", bytes.Equal(enc.SharedSecret, recipientSecret))

    // Digital Signatures
    signKeyPair, _ := sign.GenerateKeyPair(kmosaic.MOS_128)
    message := []byte("Hello, post-quantum world!")
    signature, _ := sign.Sign(&signKeyPair.SecretKey, &signKeyPair.PublicKey, message)
    isValid := sign.Verify(&signKeyPair.PublicKey, message, signature)
    fmt.Printf("Signature valid: %v\n", isValid)
}
```

## Performance and sizes (4.0.0, 4-core x86-64 container, shared and loaded; treat as ±30%)

| Operation            | MOS_128 | MOS_256 |
| -------------------- | ------- | ------- |
| KEM KeyGen           | 23 ms   | 43 ms   |
| KEM Encapsulate      | 0.6 ms  | 1.0 ms  |
| KEM Decapsulate      | 1.0 ms  | 1.7 ms  |
| KEM DeserializePK    | 8 ms    | 13 ms   |
| Sign KeyGen          | 133 ms  | 238 ms  |
| Sign                 | 19 ms   | 53 ms   |
| Verify               | 3.1 ms  | 4.8 ms  |
| Sign DeserializePK   | 22 ms   | 42 ms   |

| Object               | MOS_128 | MOS_256 |
| -------------------- | ------- | ------- |
| KEM public key       | 351 KB  | 523 KB  |
| KEM secret key       | 49 KB   | 74 KB   |
| KEM ciphertext       | 15.6 KB | 16.2 KB |
| Signature public key | 535 KB  | 1.10 MB |
| Signature secret key | 1.0 MB  | 1.2 MB  |
| Signature            | 20.6 KB | 54.8 KB |

Keys are large because the lattice components are unstructured (no polynomial
rings); the KEM ciphertext is dominated by the 14.4 KB HQC component and the
signature by the SLH-DSA component (17 KB / 50 KB). The figures in
[BenchmarkReport.md](BenchmarkReport.md) describe the broken 1.x design and
are kept for the record only.

## Formats and API (4.0.0)

Every serialized object starts with an 8-byte header (`"kMOS"`, format
version 4, object type, parameter level), so `Deserialize*` functions take no
parameters and reject anything from another version. Length prefixes are
checked as 64-bit values (safe on 32-bit platforms) and every parser requires
an exact length. Errors wrap the sentinels in `errors.go`
(`ErrInvalidKey`, `ErrInvalidCiphertext`, `ErrInvalidSignature`,
`ErrKeyMismatch`, `ErrAuthentication`, `ErrInvalidParams`).

## API Reference

### KEM Package

```go
import "github.com/BackendStack21/k-mosaic-go/kem"

// Generate a new key pair
kp, err := kem.GenerateKeyPair(level)

// Encapsulate (create ciphertext and shared secret)
result, err := kem.Encapsulate(&publicKey)      // result.Ciphertext, result.SharedSecret

// Decapsulate (recover shared secret); the public key must belong to the secret key
sharedSecret, err := kem.Decapsulate(&secretKey, &publicKey, &result.Ciphertext)

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

The names are historical. Each composite is at least as strong as its
strongest component, since every component must be broken.

| Level   | SLSS (LWE)                 | QCSD (code)            | latsig            | uov               | slhdsa            |
| ------- | -------------------------- | ---------------------- | ----------------- | ----------------- | ----------------- |
| MOS_128 | n = m = 768, ≈2^146 quantum core-SVP | hqc-256 (NIST level 5) | ML-DSA-65 shape (level 3) | uov-Ip (level 1)  | SLH-DSA-128f (level 1) |
| MOS_256 | n = m = 1152, ≈2^236 quantum core-SVP | hqc-256 (NIST level 5) | ML-DSA-87 shape (level 5) | uov-V (level 5)   | SLH-DSA-256f (level 5) |

The SLSS estimates come from this repository's own core-SVP model and do not
account for hybrid attacks on the sparse secret; the other figures are the
published security levels of the parameter sets the components reuse.

## Requirements

- Go 1.21 or later
- golang.org/x/crypto/sha3

## License

MIT License - See LICENSE file for details.
