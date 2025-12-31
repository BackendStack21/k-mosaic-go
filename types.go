// Package kmosaic implements the kMOSAIC post-quantum cryptographic algorithm.
//
// kMOSAIC (Multi-Oracle Structured Algebraic Intractability Composition)
// is a novel post-quantum cryptographic construction that achieves defense-in-depth
// security by cryptographically entangling three independent mathematical hard problems.
//
// WARNING: This is an experimental cryptographic construction that has NOT been
// formally verified by academic peer review. DO NOT use in production systems
// protecting sensitive data.
package kmosaic

// SecurityLevel represents the security level of kMOSAIC parameters.
type SecurityLevel string

const (
	// MOS128 provides 128-bit post-quantum security.
	MOS128 SecurityLevel = "MOS-128"
	// MOS256 provides 256-bit post-quantum security.
	MOS256 SecurityLevel = "MOS-256"
	// Aliases with underscore for convenience
	MOS_128 SecurityLevel = MOS128
	MOS_256 SecurityLevel = MOS256
)

// =============================================================================
// Parameter Types
// =============================================================================

// SLSSParams contains parameters for the Sparse Lattice Subset Sum problem.
type SLSSParams struct {
	N     int     `json:"n"`     // Lattice dimension
	M     int     `json:"m"`     // Number of equations
	Q     int     `json:"q"`     // Prime modulus
	W     int     `json:"w"`     // Sparsity weight
	Sigma float64 `json:"sigma"` // Error standard deviation
}

// TDDParams contains parameters for the Tensor Decomposition Distinguishing problem.
type TDDParams struct {
	N     int     `json:"n"`     // Tensor dimension
	R     int     `json:"r"`     // Tensor rank
	Q     int     `json:"q"`     // Modulus
	Sigma float64 `json:"sigma"` // Noise standard deviation
}

// EGRWParams contains parameters for the Expander Graph Random Walk problem.
type EGRWParams struct {
	P int `json:"p"` // Prime for SL(2, Z_p)
	K int `json:"k"` // Walk length
}

// MOSAICParams contains the complete parameter set for a security level.
type MOSAICParams struct {
	Level SecurityLevel `json:"level"`
	SLSS  SLSSParams    `json:"slss"`
	TDD   TDDParams     `json:"tdd"`
	EGRW  EGRWParams    `json:"egrw"`
}

// =============================================================================
// SL(2, Z_p) Element
// =============================================================================

// SL2Element represents an element of the special linear group SL(2, Z_p).
// It is a 2x2 matrix [[A, B], [C, D]] with determinant 1.
type SL2Element struct {
	A, B, C, D int
}

// =============================================================================
// SLSS Key Types
// =============================================================================

// SLSSPublicKey is the public key for SLSS.
type SLSSPublicKey struct {
	A []int32 // m x n matrix (flattened, row-major)
	T []int32 // m-vector
}

// SLSSSecretKey is the secret key for SLSS.
type SLSSSecretKey struct {
	S []int8 // Sparse n-vector in {-1, 0, 1}
}

// SLSSCiphertext is the ciphertext for SLSS encryption.
type SLSSCiphertext struct {
	U []int32
	V []int32
}

// SLSSKeyPair contains both public and secret keys for SLSS.
type SLSSKeyPair struct {
	PublicKey SLSSPublicKey
	SecretKey SLSSSecretKey
}

// =============================================================================
// TDD Key Types
// =============================================================================

// TDDFactors contains the rank-r factor triples for tensor decomposition.
type TDDFactors struct {
	A [][]int32 // r vectors of dimension n
	B [][]int32
	C [][]int32
}

// TDDPublicKey is the public key for TDD.
type TDDPublicKey struct {
	T []int32 // n x n x n tensor (flattened)
}

// TDDSecretKey is the secret key for TDD.
type TDDSecretKey struct {
	Factors TDDFactors
}

// TDDCiphertext is the ciphertext for TDD encryption.
type TDDCiphertext struct {
	Data []int32
}

// TDDKeyPair contains both public and secret keys for TDD.
type TDDKeyPair struct {
	PublicKey TDDPublicKey
	SecretKey TDDSecretKey
}

// =============================================================================
// EGRW Key Types
// =============================================================================

// EGRWPublicKey is the public key for EGRW.
type EGRWPublicKey struct {
	VStart SL2Element
	VEnd   SL2Element
}

// EGRWSecretKey is the secret key for EGRW.
type EGRWSecretKey struct {
	Walk []int // Sequence of generator indices (0-3)
}

// EGRWCiphertext is the ciphertext for EGRW encryption.
type EGRWCiphertext struct {
	Vertex     SL2Element
	Commitment []byte
}

// EGRWKeyPair contains both public and secret keys for EGRW.
type EGRWKeyPair struct {
	PublicKey EGRWPublicKey
	SecretKey EGRWSecretKey
}

// =============================================================================
// Composite MOSAIC Types
// =============================================================================

// MOSAICPublicKey is the composite public key for the full kMOSAIC scheme.
type MOSAICPublicKey struct {
	SLSS    SLSSPublicKey
	TDD     TDDPublicKey
	EGRW    EGRWPublicKey
	Binding []byte // 32-byte binding hash
	Params  MOSAICParams
}

// MOSAICSecretKey is the composite secret key for the full kMOSAIC scheme.
type MOSAICSecretKey struct {
	SLSS          SLSSSecretKey
	TDD           TDDSecretKey
	EGRW          EGRWSecretKey
	Seed          []byte // Original seed for implicit rejection
	PublicKeyHash []byte // Hash of public key for CCA security
}

// MOSAICKeyPair contains both public and secret keys.
type MOSAICKeyPair struct {
	PublicKey MOSAICPublicKey
	SecretKey MOSAICSecretKey
}

// =============================================================================
// KEM Types
// =============================================================================

// MOSAICCiphertext is the composite ciphertext from KEM encapsulation.
type MOSAICCiphertext struct {
	C1    SLSSCiphertext
	C2    TDDCiphertext
	C3    EGRWCiphertext
	Proof []byte
}

// EncapsulationResult contains the result of KEM encapsulation.
type EncapsulationResult struct {
	SharedSecret []byte
	Ciphertext   MOSAICCiphertext
}

// EncryptedMessage contains an encrypted message with its ciphertext.
type EncryptedMessage struct {
	Ciphertext MOSAICCiphertext
	Encrypted  []byte // Encrypted payload
	Nonce      []byte // Nonce for symmetric encryption
}

// =============================================================================
// Signature Key Types
// =============================================================================

// MOSAICSignPublicKey is the public key for signature operations.
type MOSAICSignPublicKey struct {
	SLSS    SLSSPublicKey
	TDD     TDDPublicKey
	EGRW    EGRWPublicKey
	Binding []byte
	Params  MOSAICParams
}

// MOSAICSignSecretKey is the secret key for signature operations.
type MOSAICSignSecretKey struct {
	SLSS          SLSSSecretKey
	TDD           TDDSecretKey
	EGRW          EGRWSecretKey
	Seed          []byte
	PublicKeyHash []byte
}

// MOSAICSignKeyPair contains both public and secret keys for signatures.
type MOSAICSignKeyPair struct {
	PublicKey MOSAICSignPublicKey
	SecretKey MOSAICSignSecretKey
}

// =============================================================================
// Signature Types
// =============================================================================

// SLSSCommitment is the commitment for SLSS in signatures.
type SLSSCommitment struct {
	W []int32
}

// TDDCommitment is the commitment for TDD in signatures.
type TDDCommitment struct {
	W []int32
}

// EGRWCommitment is the commitment for EGRW in signatures.
type EGRWCommitment struct {
	Vertex SL2Element
}

// SLSSResponse is the response for SLSS in signatures.
type SLSSResponse struct {
	Z          []int32
	Commitment []byte // w1 commitment for verification
}

// TDDResponse is the response for TDD in signatures.
type TDDResponse struct {
	Z          []int32
	Commitment []byte // w2 commitment for verification
}

// EGRWResponse is the response for EGRW in signatures.
type EGRWResponse struct {
	Combined []int
	Hints    []byte
}

// MOSAICSignature is the complete signature.
type MOSAICSignature struct {
	Commitment []byte
	Challenge  []byte
	Response   []byte
}

// =============================================================================
// Analysis Types
// =============================================================================

// SecurityAnalysis provides security estimates for a public key.
type SecurityAnalysis struct {
	SLSS struct {
		Dimension         int
		Sparsity          int
		EstimatedSecurity int
	}
	TDD struct {
		TensorDim         int
		Rank              int
		EstimatedSecurity int
	}
	EGRW struct {
		GraphSize         int
		WalkLength        int
		EstimatedSecurity int
	}
	Combined struct {
		EstimatedSecurity int
		QuantumSecurity   int
	}
}
