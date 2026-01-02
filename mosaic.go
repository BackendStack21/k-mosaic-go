// Package kmosaic implements the kMOSAIC post-quantum cryptographic algorithm.
// This package provides high-level exports for key encapsulation and digital signatures
// using the kMOSAIC hybrid approach combining three independent hard problems:
// SLSS (Sparse Lattice Subset Sum), TDD (Tensor Decomposition Distinguishing),
// and EGRW (Expander Graph Random Walk).
package kmosaic

// Re-export commonly used functions through package-level wrappers.
// Users can also import specific sub-packages directly for more control.

// Version of the kMOSAIC Go implementation.
const Version = "1.0.3"

// API summary:
//
// Key Encapsulation (KEM):
//   - kem.GenerateKeyPair(level) - Generate a key pair for the given security level
//   - kem.Encapsulate(pk) - Generate shared secret and ciphertext
//   - kem.Decapsulate(sk, pk, ct) - Recover shared secret from ciphertext
//   - kem.Encrypt(pk, plaintext) - Encrypt a message
//   - kem.Decrypt(sk, pk, encrypted) - Decrypt an encrypted message
//
// Digital Signatures:
//   - sign.GenerateKeyPair(level) - Generate a signature key pair
//   - sign.Sign(sk, pk, message) - Sign a message
//   - sign.Verify(pk, message, signature) - Verify a signature
//
// Parameters:
//   - core.GetParams(level) - Get parameters for security level
//   - MOS_128 - 128-bit post-quantum security
//   - MOS_256 - 256-bit post-quantum security
