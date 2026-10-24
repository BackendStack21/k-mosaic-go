# kMOSAIC — Go implementation

[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![CI](https://github.com/BackendStack21/k-mosaic-go/actions/workflows/ci.yml/badge.svg)](https://github.com/BackendStack21/k-mosaic-go/actions/workflows/ci.yml)

A post-quantum key encapsulation mechanism and digital signature in pure Go,
built by composing standard constructions over distinct hard problems
(unstructured lattices, quasi-cyclic codes, multivariate quadratics and hash
functions) so that a mathematical break of one problem does not break the
primitive. Version 2.0.0 (module path `github.com/BackendStack21/k-mosaic-go/v2`;
the `v1.0.x` tags are the broken original design), wire format 4, Go 1.24,
no dependencies outside the standard library.

## Status: experimental, unreviewed, not for production

**Do not use this library to protect real data.** It has not been reviewed
by anyone outside this repository. Its two custom pieces, the LWE component
and the lattice signature over unstructured matrices, have no published
analysis; their security figures come from a script in this repository.
Three earlier versions were totally broken while their own documentation
said otherwise.

What *has* been done, all of it from inside the project: five rounds of
attack-and-fix, an adversarial review of 2.0.0-dev.3 by seven separately briefed
reviewers (no cryptographic break found; every defect found was fixed), a
constant-time rewrite of every operation on secret data, NIST ACVP
conformance of the SLH-DSA component, 32-bit and race-detector CI, fuzzing of
every parser, and documentation whose claims are cross-checked against the
code. [SECURITY_ASSESSMENT.md](SECURITY_ASSESSMENT.md) is the complete
record; §6 and §7 describe the current state and what remains open.

What it is good for today: as a reference for the two-assumption KEM and
three-assumption signature design and their combiner arguments; as a worked
example of side-channel hardening in Go (constant-time samplers,
memory-oblivious ring multiplication, masked Gauss-Jordan elimination, with
interleaved timing tests); and as a usable pure-Go FIPS 205 SLH-DSA
implementation (`problems/slhdsa`). If you need a hedged post-quantum KEM in
production, combine ML-KEM with a second standardized KEM through a standard
combiner instead.

What would make it usable: an independent cryptanalysis of the SLSS
parameters and the lattice-signature transplant, a third-party
implementation audit, and interoperability vectors for every component.

> The TypeScript project at
> [BackendStack21/k-mosaic](https://github.com/BackendStack21/k-mosaic) and
> its white paper describe the **original 1.x design**, which this implementation
> replaced because it was insecure. The two are not compatible, and the white
> paper does not describe this code.

## Documentation

- [SECURITY_ASSESSMENT.md](SECURITY_ASSESSMENT.md): attacks reproduced
  against earlier versions, the redesign, the reviews, the current
  guarantees and the open items.
- [SECURITY.md](SECURITY.md): supported versions and how to report.
- [CLI.md](CLI.md): the `k-mosaic-cli` guide; every command in it is executed
  by the test suite.
- [BenchmarkReport.md](BenchmarkReport.md): measurements for 2.0.0.
- [CHANGELOG.md](CHANGELOG.md), [CONTRIBUTING.md](CONTRIBUTING.md).
- [docs/estimator/](docs/estimator/): the scripts behind the LWE security
  and failure-rate figures.

The 1.x releases are broken: the KEM shared secret could be recovered from
the public key and ciphertext alone, signatures could be forged by anyone
holding the public key, and the KEM ciphertext carried a share-leaking
"proof" field (as did the unreleased development revisions 2.0.0-dev.1 and
2.0.0-dev.2). Keys, ciphertexts and signatures from 1.x must be discarded;
2.x refuses to parse them. The development revisions 2.0.0-dev.1 to
2.0.0-dev.4 were never tagged; the history and the security assessment refer
to them by those names.

The protocol identifiers are versioned separately from the release: the wire
header carries format version 4 and the XOF domain strings and SLH-DSA
context end in `-v4` (protocol revision 4, introduced in 2.0.0-dev.3). They
do not change with the release number.

## Overview

kMOSAIC 2.x composes post-quantum hard problems so that a *mathematical*
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

- **KEM**: LWE + code-based combiner under a Fujisaki-Okamoto transform with
  implicit rejection; `Encrypt`/`Decrypt` wrap it with AES-256-GCM.
- **Signatures**: lattice + multivariate + hash-based combiner with a
  per-signature nonce.
- **Written to be constant-time on secret data**: no secret-dependent
  branch, loop bound, memory address or shift amount in the library's own
  code (compiler, runtime and hardware are outside the claim; see
  "Security Levels").
- **Self-describing formats**: an 8-byte header on every object; parsers
  take no parameters, reject other versions, and allocate nothing before
  validating lengths.
- **Parallel execution** of the components on the available cores.
- **Two parameter sets**, MOS_128 and MOS_256 (see "Security Levels").

## Installation

```sh
go get github.com/BackendStack21/k-mosaic-go/v2
```

Requires Go 1.24 or later; the library has no dependencies outside the
standard library.

## Command-line Interface

Use the `k-mosaic-cli` for common tasks such as key generation, encryption/decryption, and signing/verification.

### CLI quick start

```sh
# Install the CLI
go install github.com/BackendStack21/k-mosaic-go/v2/cmd/k-mosaic-cli@latest
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
`go test ./test/ -run TestDocumentationSnippets` against the current tree
(`bash` blocks run in order in one working directory per document); `sh`,
`json` and `text` blocks are illustrative and not checked.

## Quick Start

```go
package main

import (
    "bytes"
    "fmt"
    "log"

    kmosaic "github.com/BackendStack21/k-mosaic-go/v2"
    "github.com/BackendStack21/k-mosaic-go/v2/kem"
    "github.com/BackendStack21/k-mosaic-go/v2/sign"
)

func main() {
    // Key encapsulation.
    kemKeyPair, err := kem.GenerateKeyPair(kmosaic.MOS_128)
    if err != nil {
        log.Fatal(err)
    }
    enc, err := kem.Encapsulate(&kemKeyPair.PublicKey)
    if err != nil {
        log.Fatal(err)
    }
    recipientSecret, err := kem.Decapsulate(&kemKeyPair.SecretKey, &kemKeyPair.PublicKey, &enc.Ciphertext)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Shared secrets match: %v\n", bytes.Equal(enc.SharedSecret, recipientSecret))

    // Digital signatures.
    signKeyPair, err := sign.GenerateKeyPair(kmosaic.MOS_128)
    if err != nil {
        log.Fatal(err)
    }
    message := []byte("Hello, post-quantum world!")
    signature, err := sign.Sign(&signKeyPair.SecretKey, &signKeyPair.PublicKey, message)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Signature valid: %v\n", sign.Verify(&signKeyPair.PublicKey, message, signature))
}
```

## Performance and sizes (2.0.0, 4-core x86-64 container, shared and loaded; treat as ±30%)

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

The KEM is 2.5–3.5× (key generation, encapsulation) to 3–5× (decapsulation) slower than 2.0.0-dev.3
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
[BenchmarkReport.md](BenchmarkReport.md) holds the full 2.0.0 measurements.

## Formats and API (2.x)

Every serialized object starts with an 8-byte header (`"kMOS"`, format
version 4, object type, parameter level), so `Deserialize*` functions take no
parameters and reject anything from another version. Length prefixes are
checked as 64-bit values (safe on 32-bit platforms) and every parser requires
an exact length. Errors wrap the sentinels in `errors.go`
(`ErrInvalidKey`, `ErrInvalidCiphertext`, `ErrInvalidSignature`,
`ErrKeyMismatch`, `ErrAuthentication`, `ErrInvalidParams`,
`ErrMessageTooLarge`).

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

	kmosaic "github.com/BackendStack21/k-mosaic-go/v2"
	"github.com/BackendStack21/k-mosaic-go/v2/kem"
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

	kmosaic "github.com/BackendStack21/k-mosaic-go/v2"
	"github.com/BackendStack21/k-mosaic-go/v2/sign"
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
| MOS_128 | n = m = 768: ≈2^160 classical / 2^145 quantum core-SVP (level 1) | hqc-256 (NIST level 5) | ML-DSA-65 shape (level 3 by analogy) | uov-Ip (level 1)  | SLH-DSA-128f (level 1) |
| MOS_256 | n = m = 1152: ≈2^251 classical / 2^234 quantum core-SVP (≈ level 5) | hqc-256 (NIST level 5) | ML-DSA-87 shape (level 5 by analogy) | uov-V (level 5)   | SLH-DSA-256f (level 5) |

Provenance of the figures:

- **SLSS**: this repository's own core-SVP model (`docs/estimator/`, primal,
  dual, zero-guessing and an idealised sparse-secret hybrid; ±10 bits; not
  the Lattice Estimator). The sparse secret costs under 2 bits at MOS_128
  and up to 8 bits classically at MOS_256. The LWE decryption-failure bound
  is below 2^-1000 (MOS_128) and 2^-500 (MOS_256) per ciphertext; the
  composite rate is HQC's (< 2^-256).
- **latsig**: the published ML-DSA levels are applied *by analogy* to a
  transplant onto unstructured matrices that has no published analysis.
- **QCSD, uov, slhdsa**: the published levels of the parameter sets they
  reuse. The SLH-DSA component is checked bit-exactly against NIST ACVP
  vectors in `problems/slhdsa/acvp_test.go`; the HQC component follows the
  HQC construction and parameters but is not bit-compatible with the HQC
  reference (own XOF domains, sampler and bit order).

Side channels: in 2.0.0 every operation on secret data (the samplers,
the LWE products, the code component's ring multiplication and decoders,
the lattice signature's arithmetic, UOV signing and key generation) is
written to be constant-time: no branch, loop bound, memory address or shift
amount depends on a secret in the library's own code (see §7.1 and §7.3 of
the assessment for the arguments and measurements). Outside that claim: the
Go compiler and runtime, the standard library's SHA-3 and AES, hardware
whose multiply latency depends on operands, 32-bit targets (where 64-bit
multiplies are compiled from 32-bit ones), the lattice signature's rejection
sampling (which branches exactly as FIPS 204 does) and the visible retry of
UOV signing on a singular system.

## Requirements

- Go 1.24 or later (standard-library `crypto/sha3`; no external modules).
- Tested on linux/amd64 and, in CI, on the 32-bit `386` target; it
  cross-compiles for arm, arm64, riscv64, windows/amd64 and darwin/arm64.

## Contributing and security reports

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

MIT License, see [LICENSE](LICENSE).
