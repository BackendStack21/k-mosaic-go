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
forged by anyone holding the public key; every version before 4.0.0 carried
a share-leaking "proof" field in the KEM ciphertext. See
[SECURITY_ASSESSMENT.md](SECURITY_ASSESSMENT.md) for the reproduced attacks,
a claim-by-claim review of the original design, the 3.0 redesign, the 4.0
review and the 4.1 validation pass (§6), which states what has and has not
been verified. Keys, ciphertexts and signatures from earlier versions must be
discarded; 4.x refuses to parse them. 4.1.0 changed the sparse-vector
samplers to constant-time ones, so keys derived from a seed differ from
4.0.0 (the wire format is unchanged). 4.2.0 made the remaining secret-data
paths (the code component's ring multiplication, UOV signing and key
generation) memory-oblivious without changing any key or signature.

## Overview

kMOSAIC 4.x composes post-quantum hard problems so that a *mathematical*
break of a primitive requires breaking **every** problem it is built from.
The components are standard constructions, instantiated here without
algebraic structure where the construction allows it. In the classical
random-oracle model and under the standard combiner arguments, KEM
confidentiality holds if either of its two problems is hard and signature
unforgeability holds if any one of its three problems is hard. These are
statements about the hard problems, not about this implementation: the
combiner gives no protection against implementation or side-channel attacks,
which can target each component separately, and the independence of the
problems is a heuristic. The library is experimental and has not been
reviewed outside this repository.

| Primitive  | Component                                   | Hard problem                                   |
| ---------- | ------------------------------------------- | ---------------------------------------------- |
| KEM        | SLSS: plain LWE with sparse ternary secrets | Learning With Errors (unstructured lattices)   |
| KEM        | QCSD: the HQC public-key encryption scheme  | Quasi-cyclic syndrome decoding (codes)         |
| Signatures | latsig: ML-DSA over unstructured matrices   | Module-free SIS / LWE (lattices)               |
| Signatures | uov: Unbalanced Oil and Vinegar over F_256  | Multivariate quadratic equations (MQ)          |
| Signatures | slhdsa: SLH-DSA / SPHINCS+ with SHAKE256    | Hash-function (second-)preimage resistance     |

- **KEM**: a 32-byte ephemeral secret is split into two XOR shares, one
  encrypted by each component. Against cryptanalysis, the ephemeral secret
  stays hidden as long as *either* LWE or syndrome decoding is hard. A
  Fujisaki-Okamoto transform (derandomization, re-encryption check, implicit
  rejection) gives IND-CCA security in the classical random-oracle model;
  security against quantum-accessible random oracles follows only from the
  known non-tight FO results. The hybrid `Encrypt`/`Decrypt` API wraps the
  KEM with AES-256-GCM.
- **Signatures**: the message is hashed together with the composite public
  key and a fresh nonce, and the 64-byte digest is signed by all three
  components. A signature verifies only if all three component signatures
  verify, so a forger must break lattices, MQ **and** hash functions (or find
  a second preimage of the SHAKE256 digest). Public keys carry a binding hash
  of their components, and the digest includes the public-key hash, so
  components cannot be mixed across key pairs. Strong unforgeability needs
  every component to be strongly unforgeable; this is assumed, not tested.

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

```sh
go get github.com/BackendStack21/k-mosaic-go
```

Requires Go 1.24 or later; the library has no dependencies outside the
standard library.

## Command-line Interface

Use the `k-mosaic-cli` for common tasks such as key generation, encryption/decryption, and signing/verification.

### Quick Start

```sh
# Install the CLI
go install github.com/BackendStack21/k-mosaic-go/cmd/k-mosaic-cli@latest
```

```bash
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
- File formats, exit codes and key management
- Troubleshooting and FAQ

Every `go` and `bash` block in CLI.md and in this README is executed by
`go test ./test/ -run TestDocumentationSnippets` against the current tree;
`sh`, `json` and `text` blocks are illustrative and not checked.

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

## Performance and sizes (4.2.0, 4-core x86-64 container, shared and loaded; treat as ±30%)

| Operation            | MOS_128 | MOS_256 |
| -------------------- | ------- | ------- |
| KEM KeyGen           | 56 ms   | 113 ms  |
| KEM Encapsulate      | 2.1 ms  | 2.0 ms  |
| KEM Decapsulate      | 6.7 ms  | 7.2 ms  |
| KEM DeserializePK    | 9 ms    | 16 ms   |
| Sign KeyGen          | 186 ms  | 335 ms  |
| Sign                 | 22 ms   | 56 ms   |
| Verify               | 4–6 ms  | 4–6 ms  |
| Sign DeserializePK   | 24 ms   | 46 ms   |
| Sign DeserializeSK   | 21 ms   | 84 ms   |

The KEM is 3× (key generation, encapsulation) to 5× (decapsulation) slower than 4.0.0
because every secret-dependent operation is now dense or memory-oblivious
(SECURITY_ASSESSMENT.md §6.2 and §7).

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
signature by the SLH-DSA component (17 KB / 50 KB).
[BenchmarkReport.md](BenchmarkReport.md) holds the full 4.2.0 measurements.

## Formats and API (4.x)

Every serialized object starts with an 8-byte header (`"kMOS"`, format
version 4, object type, parameter level), so `Deserialize*` functions take no
parameters and reject anything from another version. Length prefixes are
checked as 64-bit values (safe on 32-bit platforms) and every parser requires
an exact length. Errors wrap the sentinels in `errors.go`
(`ErrInvalidKey`, `ErrInvalidCiphertext`, `ErrInvalidSignature`,
`ErrKeyMismatch`, `ErrAuthentication`, `ErrInvalidParams`).

## API Reference

Both programs below are complete and are built and run by the test suite
(`go test ./test/ -run TestDocumentationSnippets`).

### KEM Package

```go
package main

import (
	"bytes"
	"fmt"
	"log"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/kem"
)

func main() {
	// Generate a key pair for the MOS-128 parameter set.
	kp, err := kem.GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		log.Fatal(err)
	}

	// Encapsulate: a ciphertext and a 32-byte shared secret for the public key.
	result, err := kem.Encapsulate(&kp.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	// Decapsulate: the public key must belong to the secret key (checked).
	shared, err := kem.Decapsulate(&kp.SecretKey, &kp.PublicKey, &result.Ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("shared secrets match:", bytes.Equal(shared, result.SharedSecret))

	// Hybrid encryption: KEM + AES-256-GCM.
	em, err := kem.Encrypt(&kp.PublicKey, []byte("hello"))
	if err != nil {
		log.Fatal(err)
	}
	plaintext, err := kem.Decrypt(&kp.SecretKey, &kp.PublicKey, em)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("decrypted:", string(plaintext))

	// Serialization. Every object carries a self-describing header, so the
	// parsers need no parameters; ciphertext parsers return the parameters.
	pk, err := kem.DeserializePublicKey(kem.SerializePublicKey(&kp.PublicKey))
	if err != nil {
		log.Fatal(err)
	}
	sk, err := kem.DeserializeSecretKey(kem.SerializeSecretKey(&kp.SecretKey, kp.PublicKey.Params))
	if err != nil {
		log.Fatal(err)
	}
	ct, params, err := kem.DeserializeCiphertext(kem.SerializeCiphertext(&result.Ciphertext, kp.PublicKey.Params))
	if err != nil {
		log.Fatal(err)
	}
	shared2, err := kem.Decapsulate(sk, pk, ct)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("round trip at level", params.Level, "ok:", bytes.Equal(shared2, result.SharedSecret))
}
```

### Sign Package

```go
package main

import (
	"errors"
	"fmt"
	"log"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/sign"
)

func main() {
	kp, err := sign.GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		log.Fatal(err)
	}
	message := []byte("Hello, post-quantum world!")

	// Sign with the secret key; the public key is optional and, when given,
	// is checked against the hash stored in the secret key.
	sig, err := sign.Sign(&kp.SecretKey, &kp.PublicKey, message)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("valid:", sign.Verify(&kp.PublicKey, message, sig))
	fmt.Println("valid for another message:", sign.Verify(&kp.PublicKey, []byte("other"), sig))

	// Serialization round trip.
	pk, err := sign.DeserializePublicKey(sign.SerializePublicKey(&kp.PublicKey))
	if err != nil {
		log.Fatal(err)
	}
	sig2, params, err := sign.DeserializeSignature(sign.SerializeSignature(sig, kp.PublicKey.Params))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("level:", params.Level, "valid after round trip:", sign.Verify(pk, message, sig2))

	// Errors wrap sentinels from the root package.
	other, _ := sign.GenerateKeyPair(kmosaic.MOS_128)
	if _, err := sign.Sign(&kp.SecretKey, &other.PublicKey, message); errors.Is(err, kmosaic.ErrKeyMismatch) {
		fmt.Println("mismatched key pair rejected")
	}
}
```

## Security Levels

The names are historical. Against cryptanalysis each composite is as strong
as its strongest component, because every component must be broken; it is
*not* stronger than that component, and if the strongest component falls the
composite drops to the next one (for the MOS_128 KEM, from HQC-256 to an
LWE instance at NIST level 1).

| Level   | SLSS (LWE)                 | QCSD (code)            | latsig            | uov               | slhdsa            |
| ------- | -------------------------- | ---------------------- | ----------------- | ----------------- | ----------------- |
| MOS_128 | n = m = 768: ≈2^159 classical / 2^145 quantum core-SVP (level 1) | hqc-256 (NIST level 5) | ML-DSA-65 shape (level 3 by analogy) | uov-Ip (level 1)  | SLH-DSA-128f (level 1) |
| MOS_256 | n = m = 1152: ≈2^251 classical / 2^234 quantum core-SVP (≈ level 5) | hqc-256 (NIST level 5) | ML-DSA-87 shape (level 5 by analogy) | uov-V (level 5)   | SLH-DSA-256f (level 5) |

Provenance of the figures:

- **SLSS**: this repository's own core-SVP model (`docs/estimator/`, primal,
  dual, zero-guessing and an idealised sparse-secret hybrid; ±10 bits; not
  the Lattice Estimator). The sparse secret costs under 2 bits at MOS_128
  and up to 8 bits classically at MOS_256. The LWE decryption-failure bound
  is below 2^-1000 per ciphertext; the composite rate is HQC's (< 2^-256).
- **latsig**: the published ML-DSA levels are applied *by analogy* to a
  transplant onto unstructured matrices that has no published analysis.
- **QCSD, uov, slhdsa**: the published levels of the parameter sets they
  reuse. The SLH-DSA component is checked bit-exactly against NIST ACVP
  vectors in `problems/slhdsa/acvp_test.go`; the HQC component follows the
  HQC construction and parameters but is not bit-compatible with the HQC
  reference (own XOF domains, sampler and bit order).

Side channels: since 4.2.0 every operation on secret data (the samplers,
the LWE products, the code component's ring multiplication and decoders,
the lattice signature's arithmetic, UOV signing and key generation) is
constant-time by construction: no branch, loop bound, memory address or
shift amount depends on a secret (see §6.3 and §7 of the assessment for
the arguments and measurements). What remains outside the guarantee is the
Go runtime and compiler, the hash and AES implementations of the standard
library, and hardware where multiplication latency depends on operands.

## Requirements

- Go 1.24 or later (standard-library `crypto/sha3`; no external modules)

## License

MIT License - See LICENSE file for details.
