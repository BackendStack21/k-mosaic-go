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

// SLSSParams contains parameters for the Sparse Lattice Subset Sum problem,
// an LWE instance with sparse ternary secrets.
//
// The public key is (A, T = A·S + E) with A ∈ Z_q^{M×N} expanded from a public
// seed, S ∈ {-1,0,1}^{N×L} with W non-zero entries per column and E ∈ Z^{M×L}
// discrete Gaussian. Each of the L secret columns protects one message bit,
// so a ciphertext never reuses an inner product across bits.
type SLSSParams struct {
	N     int     `json:"n"`     // Secret dimension (columns of A)
	M     int     `json:"m"`     // Number of LWE samples (rows of A)
	Q     int     `json:"q"`     // Prime modulus
	W     int     `json:"w"`     // Non-zero entries per secret column
	Sigma float64 `json:"sigma"` // Error standard deviation
	L     int     `json:"l"`     // Secret columns = message bits per ciphertext
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
	Seed []byte  // 32-byte public seed from which A is expanded
	A    []int32 // M x N matrix (flattened, row-major); derived from Seed, not serialized
	T    []int32 // L x M matrix (flattened, row-major): T[j*M+i] = (A·s_j + e_j)[i]
}

// SLSSSecretKey is the secret key for SLSS.
type SLSSSecretKey struct {
	S []int8 // L x N matrix (flattened, row-major) of sparse ternary columns: S[j*N+i] = s_j[i]
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
// Signature Types
// =============================================================================

// SignParams contains the parameters of the lattice signature scheme.
//
// The scheme is a Fiat-Shamir-with-aborts signature over unstructured
// module-free LWE/SIS (the construction of CRYSTALS-Dilithium, FIPS 204, with
// matrices over Z_q instead of polynomial rings). It proves knowledge of the
// short matrices (S1, S2) with T = A·S1 + S2 (mod Q).
type SignParams struct {
	N          int `json:"n"`           // Columns of A; dimension of the mask y and response z
	M          int `json:"m"`           // Rows of A; dimension of the commitment w
	L          int `json:"l"`           // Columns of S1/S2/T; length of the challenge vector c
	Q          int `json:"q"`           // Prime modulus
	Eta        int `json:"eta"`         // Secret entries are uniform in [-Eta, Eta]
	Tau        int `json:"tau"`         // Number of ±1 entries in the challenge c
	Gamma1     int `json:"gamma1"`      // Mask y is uniform in (-Gamma1, Gamma1]
	Gamma2     int `json:"gamma2"`      // Low-order rounding range; HighBits use alpha = 2*Gamma2
	Beta       int `json:"beta"`        // Tau*Eta: bound on ||S1·c||∞ and ||S2·c||∞
	CTildeSize int `json:"ctilde_size"` // Bytes of the challenge hash c̃
}

// MOSAICSignPublicKey is the public key for signature operations.
type MOSAICSignPublicKey struct {
	Params SignParams
	Rho    []byte  // 32-byte public seed from which A is expanded
	T      []int32 // M x L matrix (flattened, row-major): T = A·S1 + S2 mod Q
	A      []int32 // M x N matrix expanded from Rho; derived, not serialized
}

// MOSAICSignSecretKey is the secret key for signature operations.
type MOSAICSignSecretKey struct {
	Params SignParams
	Rho    []byte  // Public seed of A
	K      []byte  // 32-byte signing PRF key
	Tr     []byte  // 64-byte hash of the serialized public key
	S1     []int8  // N x L matrix (flattened, row-major), entries in [-Eta, Eta]
	S2     []int8  // M x L matrix (flattened, row-major), entries in [-Eta, Eta]
	A      []int32 // M x N matrix expanded from Rho; derived, not serialized
}

// MOSAICSignKeyPair contains both public and secret keys for signatures.
type MOSAICSignKeyPair struct {
	PublicKey MOSAICSignPublicKey
	SecretKey MOSAICSignSecretKey
}

// MOSAICSignature is a signature: the challenge hash c̃ and the response z.
type MOSAICSignature struct {
	Challenge []byte  // c̃ = H(μ || HighBits(A·y)), CTildeSize bytes
	Z         []int32 // z = y + S1·c, N entries with ||z||∞ < Gamma1 - Beta
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
