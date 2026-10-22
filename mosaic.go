// Package kmosaic is the root of the kMOSAIC post-quantum cryptographic
// library: a key encapsulation mechanism and a digital signature built by
// composing standard post-quantum constructions over distinct hard problems,
// so that a mathematical break of one problem does not break the primitive.
//
//   - KEM (package kem): a 32-byte ephemeral secret is split into two XOR
//     shares, one encrypted with unstructured LWE with sparse ternary secrets
//     (package problems/slss) and one with the HQC code-based scheme
//     (package problems/qcsd), under a Fujisaki-Okamoto transform with
//     implicit rejection. Hybrid encryption wraps the KEM with AES-256-GCM.
//   - Signature (package sign): a 64-byte digest of the message, the public
//     key hash and a fresh nonce is signed by an ML-DSA-style lattice
//     signature over unstructured matrices (problems/latsig), Unbalanced Oil
//     and Vinegar over F_256 (problems/uov) and SLH-DSA-SHAKE (problems/slhdsa);
//     all three must verify.
//
// Two parameter sets exist, MOS128 and MOS256 (package core). This package
// holds the shared types, the error sentinels and the version; all
// operations live in the sub-packages. Every serialized object starts with
// a self-describing header, so the Deserialize functions take no parameters.
//
// # Status
//
// This library is experimental and has not been reviewed by anyone outside
// its repository. It must not be used to protect real data. What has been
// verified, what has not, and what remains open is recorded in
// SECURITY_ASSESSMENT.md; the short version is in README.md and SECURITY.md.
package kmosaic

// Version of the kMOSAIC Go implementation. The wire format version (4) is
// carried in every serialized object independently of this string.
const Version = "4.2.0"
