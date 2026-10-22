// Package kmosaic implements the kMOSAIC post-quantum cryptographic library.
//
// kMOSAIC composes independent post-quantum hard problems so that breaking a
// primitive requires breaking every component it is built from:
//
//   - KEM: unstructured LWE with sparse ternary secrets (SLSS) and quasi-cyclic
//     syndrome decoding (QCSD, the HQC construction). The ephemeral secret is
//     split into one share per component; recovering it needs both.
//   - Signatures: an unstructured Fiat-Shamir-with-aborts lattice signature
//     (SIS/LWE), an Unbalanced Oil-and-Vinegar multivariate signature (MQ), and
//     a stateless hash-based signature (SLH-DSA). A composite signature is
//     valid only if all three are valid, so a forger must forge all three.
//
// WARNING: This is an experimental library that has not been reviewed outside
// this repository. DO NOT use in production systems protecting sensitive data.
package kmosaic

// SecurityLevel represents the security level of kMOSAIC parameters.
type SecurityLevel string

const (
	// MOS128 is the smaller parameter set.
	MOS128 SecurityLevel = "MOS-128"
	// MOS256 is the larger parameter set.
	MOS256 SecurityLevel = "MOS-256"
	// Aliases with underscore for convenience
	MOS_128 SecurityLevel = MOS128
	MOS_256 SecurityLevel = MOS256
)

// =============================================================================
// SLSS: unstructured LWE encryption with sparse ternary secrets
// =============================================================================

// SLSSParams contains parameters for the SLSS component, an LWE instance with
// sparse ternary secrets.
//
// The public key is (A, T = A·S + E) with A ∈ Z_q^{M×N} expanded from a public
// seed, S ∈ {-1,0,1}^{N×L} with W non-zero entries per column and E ∈ Z^{M×L}
// discrete Gaussian. Each of the L secret columns protects one message bit.
type SLSSParams struct {
	N   int `json:"n"`   // Secret dimension (columns of A)
	M   int `json:"m"`   // Number of LWE samples (rows of A)
	Q   int `json:"q"`   // Prime modulus (must be 12289)
	W   int `json:"w"`   // Non-zero entries per secret column
	Eta int `json:"eta"` // Errors are centered binomial with parameter Eta (variance Eta/2)
	L   int `json:"l"`   // Secret columns = message bits per ciphertext
	DU  int `json:"du"`  // Bits kept per coefficient of u after compression
	DV  int `json:"dv"`  // Bits kept per coefficient of v after compression
}

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

// SLSSCiphertext is the ciphertext for SLSS encryption. U and V hold the
// compressed coefficients (DU and DV bits each) exactly as serialized.
type SLSSCiphertext struct {
	U []int32 // N entries in [0, 2^DU)
	V []int32 // L entries in [0, 2^DV)
}

// SLSSKeyPair contains both public and secret keys for SLSS.
type SLSSKeyPair struct {
	PublicKey SLSSPublicKey
	SecretKey SLSSSecretKey
}

// =============================================================================
// QCSD: quasi-cyclic syndrome decoding encryption (HQC construction)
// =============================================================================

// CodeParams contains parameters for the code-based component. Arithmetic is
// in F_2[X]/(X^N - 1); the message is protected by a Reed-Solomon [N1, K]
// outer code over F_256 whose symbols are encoded with a duplicated first-order
// Reed-Muller RM(1,7) inner code.
type CodeParams struct {
	N     int `json:"n"`     // Length of the quasi-cyclic ring (a prime)
	N1    int `json:"n1"`    // Reed-Solomon code length in bytes
	K     int `json:"k"`     // Reed-Solomon dimension in bytes = message bytes
	Delta int `json:"delta"` // Reed-Solomon correction capability: N1 - K = 2*Delta
	Mult  int `json:"mult"`  // Reed-Muller duplication multiplicity; N2 = 128*Mult bits
	W     int `json:"w"`     // Hamming weight of the secret vectors x, y
	WR    int `json:"wr"`    // Hamming weight of the ephemeral vectors r1, r2
	WE    int `json:"we"`    // Hamming weight of the ephemeral error e
}

// CodePublicKey is the public key for the code-based component: (h, s = x + h·y).
type CodePublicKey struct {
	Seed []byte   // 32-byte public seed from which h is expanded
	H    []uint64 // h as an N-bit vector; derived from Seed, not serialized
	S    []uint64 // s as an N-bit vector
}

// CodeSecretKey is the secret key for the code-based component.
type CodeSecretKey struct {
	X    []uint64 // x as an N-bit vector of weight W
	Y    []uint64 // y as an N-bit vector of weight W
	YPos []int    // Sorted positions of the set bits of y; derived, not serialized
}

// CodeCiphertext is the ciphertext for the code-based component.
type CodeCiphertext struct {
	U []uint64 // u = r1 + h·r2, N bits
	V []uint64 // v = truncate(mG + s·r2 + e), N1*N2 bits
}

// CodeKeyPair contains both public and secret keys for the code-based component.
type CodeKeyPair struct {
	PublicKey CodePublicKey
	SecretKey CodeSecretKey
}

// =============================================================================
// Lattice signature: Fiat-Shamir with aborts over unstructured matrices
// =============================================================================

// LatticeSignParams contains the parameters of the lattice signature component.
//
// The scheme is a Fiat-Shamir-with-aborts signature over unstructured LWE/SIS
// (the construction of CRYSTALS-Dilithium, FIPS 204, with matrices over Z_q
// instead of polynomial rings). It proves knowledge of the short matrices
// (S1, S2) with T = A·S1 + S2 (mod Q).
type LatticeSignParams struct {
	N          int `json:"n"`           // Columns of A; dimension of the mask y and response z
	M          int `json:"m"`           // Rows of A; dimension of the commitment w
	L          int `json:"l"`           // Columns of S1/S2/T; length of the challenge vector c (256)
	Q          int `json:"q"`           // Prime modulus (must be 8380417)
	Eta        int `json:"eta"`         // Secret entries are uniform in [-Eta, Eta]
	Tau        int `json:"tau"`         // Number of ±1 entries in the challenge c (at most 64)
	Gamma1     int `json:"gamma1"`      // Mask y is uniform in (-Gamma1, Gamma1] (2^19)
	Gamma2     int `json:"gamma2"`      // Low-order rounding range; HighBits use alpha = 2*Gamma2 ((Q-1)/32)
	Beta       int `json:"beta"`        // Tau*Eta: bound on ||S1·c||∞ and ||S2·c||∞
	D          int `json:"d"`           // Dropped bits of T (Power2Round), 13
	Omega      int `json:"omega"`       // Maximum number of hint bits in a signature
	CTildeSize int `json:"ctilde_size"` // Bytes of the challenge hash c̃
}

// LatticeSignPublicKey is the public key of the lattice signature component.
// T = A·S1 + S2 is split by Power2Round into T1 (high bits, public) and T0
// (low bits, kept in the secret key), as in FIPS 204.
type LatticeSignPublicKey struct {
	Params LatticeSignParams
	Rho    []byte  // 32-byte public seed from which A is expanded
	T1     []int32 // M x L matrix (flattened, row-major) of 10-bit high parts of T
	Tr     []byte  // 64-byte hash of the serialized public key; derived, not serialized
	A      []int32 // M x N matrix expanded from Rho; derived, not serialized
}

// LatticeSignSecretKey is the secret key of the lattice signature component.
type LatticeSignSecretKey struct {
	Params LatticeSignParams
	Rho    []byte  // Public seed of A
	K      []byte  // 32-byte signing PRF key
	Tr     []byte  // 64-byte hash of the serialized public key
	S1     []int8  // N x L matrix (flattened, row-major), entries in [-Eta, Eta]
	S2     []int8  // M x L matrix (flattened, row-major), entries in [-Eta, Eta]
	T0     []int32 // M x L matrix of low parts of T, entries in (-2^(D-1), 2^(D-1)]
	A      []int32 // M x N matrix expanded from Rho; derived, not serialized
}

// LatticeSignKeyPair contains both keys of the lattice signature component.
type LatticeSignKeyPair struct {
	PublicKey LatticeSignPublicKey
	SecretKey LatticeSignSecretKey
}

// LatticeSignature is a lattice signature: the challenge hash c̃, the
// response z and the hint vector that lets the verifier recover HighBits(A·y)
// from the compressed public key.
type LatticeSignature struct {
	Challenge []byte   // c̃ = H(μ || HighBits(A·y)), CTildeSize bytes
	Z         []int32  // z = y + S1·c, N entries with ||z||∞ < Gamma1 - Beta
	Hint      []uint16 // Sorted indices (into the M-vector w) of set hint bits, at most Omega
}

// =============================================================================
// MQ signature: Unbalanced Oil and Vinegar over F_256
// =============================================================================

// MQParams contains the parameters of the multivariate (UOV) signature component.
// There are N variables (V = N - M vinegar, M oil) and M quadratic equations
// over F_256.
type MQParams struct {
	N int `json:"n"` // Number of variables
	M int `json:"m"` // Number of equations = oil variables
}

// MQPublicKey is a compressed UOV public key: the seed that expands the P1
// and P2 blocks of every public quadratic form, plus the P3 blocks.
type MQPublicKey struct {
	Seed     []byte // 16-byte public seed
	P3       []byte // M blocks of M(M+1)/2 upper-triangular entries
	P1       []byte // M blocks of V(V+1)/2 entries, expanded from Seed; not serialized
	P2       []byte // M blocks of V*M entries, expanded from Seed; not serialized
	Prepared []byte // Evaluation-optimized layout of all forms; derived, not serialized
}

// MQSecretKey is an expanded UOV secret key.
type MQSecretKey struct {
	Seed     []byte // 32-byte secret seed
	PKSeed   []byte // 16-byte public seed
	O        []byte // V x M oil matrix (row-major)
	P1       []byte // as in the public key
	S        []byte // M blocks of V x M matrices S_i = (P1_i + P1_i^T)·O + P2_i
	Prepared []byte // Signing-optimized layout; derived, not serialized
}

// MQKeyPair contains both keys of the MQ signature component.
type MQKeyPair struct {
	PublicKey MQPublicKey
	SecretKey MQSecretKey
}

// MQSignature is a UOV signature: the preimage s and the salt.
type MQSignature struct {
	S    []byte // N field elements
	Salt []byte // 16 bytes
}

// =============================================================================
// Hash-based signature: SLH-DSA (SPHINCS+) with SHAKE256
// =============================================================================

// HashSignParams contains the parameters of the stateless hash-based signature
// component (FIPS 205 SLH-DSA with SHAKE256).
type HashSignParams struct {
	N   int `json:"n"`    // Security parameter in bytes (hash output size)
	H   int `json:"h"`    // Total hypertree height
	D   int `json:"d"`    // Number of hypertree layers
	A   int `json:"a"`    // FORS tree height
	K   int `json:"k"`    // Number of FORS trees
	LgW int `json:"lg_w"` // log2 of the Winternitz parameter (4)
	M   int `json:"m"`    // Message digest length in bytes
}

// HashSignPublicKey is an SLH-DSA public key.
type HashSignPublicKey struct {
	Seed []byte // PK.seed, N bytes
	Root []byte // PK.root, N bytes
}

// HashSignSecretKey is an SLH-DSA secret key.
type HashSignSecretKey struct {
	Seed   []byte // SK.seed, N bytes
	PRF    []byte // SK.prf, N bytes
	PKSeed []byte // PK.seed, N bytes
	PKRoot []byte // PK.root, N bytes
}

// HashSignKeyPair contains both keys of the hash-based signature component.
type HashSignKeyPair struct {
	PublicKey HashSignPublicKey
	SecretKey HashSignSecretKey
}

// HashSignature is an SLH-DSA signature (R || FORS signature || hypertree signature).
type HashSignature struct {
	Data []byte
}

// =============================================================================
// Composite KEM types
// =============================================================================

// MOSAICParams contains the complete KEM parameter set for a security level.
type MOSAICParams struct {
	Level SecurityLevel `json:"level"`
	SLSS  SLSSParams    `json:"slss"`
	Code  CodeParams    `json:"code"`
}

// MOSAICPublicKey is the composite KEM public key.
type MOSAICPublicKey struct {
	SLSS    SLSSPublicKey
	Code    CodePublicKey
	Binding []byte // 32-byte binding hash of the component public keys
	Params  MOSAICParams
	Hash    []byte // 32-byte hash of the serialized public key; derived, not serialized
}

// MOSAICSecretKey is the composite KEM secret key.
type MOSAICSecretKey struct {
	SLSS          SLSSSecretKey
	Code          CodeSecretKey
	Seed          []byte // Original seed; also keys the implicit-rejection value
	PublicKeyHash []byte // Hash of public key for CCA security
}

// MOSAICKeyPair contains both composite KEM keys.
type MOSAICKeyPair struct {
	PublicKey MOSAICPublicKey
	SecretKey MOSAICSecretKey
}

// MOSAICCiphertext is the composite ciphertext from KEM encapsulation.
type MOSAICCiphertext struct {
	C1 SLSSCiphertext
	C2 CodeCiphertext
}

// EncapsulationResult contains the result of KEM encapsulation.
type EncapsulationResult struct {
	SharedSecret []byte
	Ciphertext   MOSAICCiphertext
}

// EncryptedMessage contains an encrypted message with its KEM ciphertext.
// The AES-GCM nonce is derived from the shared secret and is not stored.
type EncryptedMessage struct {
	Ciphertext MOSAICCiphertext
	Encrypted  []byte // AES-256-GCM payload including the authentication tag
}

// =============================================================================
// Composite signature types
// =============================================================================

// SignParams contains the complete signature parameter set for a security level.
type SignParams struct {
	Level   SecurityLevel     `json:"level"`
	Lattice LatticeSignParams `json:"lattice"`
	MQ      MQParams          `json:"mq"`
	Hash    HashSignParams    `json:"hash"`
}

// MOSAICSignPublicKey is the composite signature public key.
type MOSAICSignPublicKey struct {
	Params  SignParams
	Lattice LatticeSignPublicKey
	MQ      MQPublicKey
	Hash    HashSignPublicKey
	Binding []byte // 32-byte binding hash of the component public keys
	KeyHash []byte // 64-byte hash of the serialized public key; derived, not serialized
}

// MOSAICSignSecretKey is the composite signature secret key.
type MOSAICSignSecretKey struct {
	Params        SignParams
	Lattice       LatticeSignSecretKey
	MQ            MQSecretKey
	Hash          HashSignSecretKey
	Seed          []byte
	PublicKeyHash []byte // 64-byte hash of the serialized composite public key
}

// MOSAICSignKeyPair contains both composite signature keys.
type MOSAICSignKeyPair struct {
	PublicKey MOSAICSignPublicKey
	SecretKey MOSAICSignSecretKey
}

// MOSAICSignature is the composite signature: a fresh nonce and all three
// component signatures on the digest H(pk hash || nonce || message).
// Verification requires all three to be valid; the nonce binds the three
// components to one another so they cannot be recombined across signatures.
type MOSAICSignature struct {
	Nonce   []byte // 32 bytes
	Lattice LatticeSignature
	MQ      MQSignature
	Hash    HashSignature
}
