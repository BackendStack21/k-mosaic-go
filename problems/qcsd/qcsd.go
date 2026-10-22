// Package qcsd implements the code-based component of the kMOSAIC KEM: the
// HQC public-key encryption scheme (Hamming Quasi-Cyclic), whose security
// rests on the quasi-cyclic syndrome decoding problem.
//
//	KeyGen:  h ← F_2[X]/(X^N-1) uniform (from a public seed),
//	         x, y ← weight-W vectors,  s = x + h·y
//	Encrypt: r1, r2 ← weight-WR, e ← weight-WE
//	         u = r1 + h·r2,  v = truncate(C(m) + s·r2 + e)
//	Decrypt: C(m) + x·r2 - r1·y + e  =  v - truncate(u·y)   → decode with C
//
// C is the concatenation of a Reed-Solomon [N1, K] code over F_256 with a
// duplicated Reed-Muller RM(1,7) inner code, exactly as in HQC. The hqc-256
// parameter set (core.CodeHQC256) is used; its published decryption failure
// rate is below 2^-256.
//
// Decryption never exits early on secret data: for well-shaped inputs it
// always performs the full decoding and returns K bytes together with a
// success flag. The Reed-Solomon and Reed-Muller decoders and the field
// arithmetic are branch-free and table-free on secret data (see
// reedsolomon.go). The sparse-dense ring product does the same work for every
// sparse position, but the start of the window it reads depends on the
// position, so it is not hardened against fine-grained cache attacks; Go
// itself gives no constant-time guarantees.
package qcsd

import (
	"encoding/binary"
	"errors"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

const (
	DomainH  = "kmosaic-qcsd-h-v4"
	DomainX  = "kmosaic-qcsd-x-v4"
	DomainY  = "kmosaic-qcsd-y-v4"
	DomainR1 = "kmosaic-qcsd-r1-v4"
	DomainR2 = "kmosaic-qcsd-r2-v4"
	DomainE  = "kmosaic-qcsd-e-v4"
	SeedSize = 32
	rmLength = 128 // RM(1,7) codeword length in bits
	maxRingN = 1 << 16
)

// checkParams validates the dimensions used by this package.
func checkParams(p kmosaic.CodeParams) error {
	if p.N <= 0 || p.N1 <= 0 || p.K <= 0 || p.Delta <= 0 || p.Mult <= 0 {
		return errors.New("qcsd: parameters must be positive")
	}
	if p.N > maxRingN {
		return errors.New("qcsd: ring length exceeds 2^16")
	}
	if p.N1 > maxN1 || p.K >= p.N1 || p.N1-p.K != 2*p.Delta {
		return errors.New("qcsd: inconsistent Reed-Solomon parameters")
	}
	if p.Mult > p.N/(p.N1*rmLength) {
		return errors.New("qcsd: code length exceeds ring length")
	}
	if p.W <= 0 || p.WR <= 0 || p.WE <= 0 || p.W > p.N || p.WR > p.N || p.WE > p.N {
		return errors.New("qcsd: weights out of range")
	}
	return nil
}

// MessageSize returns the exact message length in bytes that Encrypt accepts.
func MessageSize(p kmosaic.CodeParams) int { return p.K }

// CodeLength returns the length in bits of the concatenated code (N1 * N2).
func CodeLength(p kmosaic.CodeParams) int { return p.N1 * rmLength * p.Mult }

// encodeInto writes the N1*N2-bit codeword of a K-byte message into cw
// (at least words(CodeLength) words, overwritten).
func encodeInto(cw []uint64, msg []byte, p kmosaic.CodeParams) {
	var rs [maxN1]byte
	rsEncodeInto(rs[:p.N1], msg, p.N1, p.Delta)
	n2w := rmLength * p.Mult / 64
	for i := 0; i < p.N1; i++ {
		rmEncodeByte(cw, i*n2w, rs[i], p.Mult)
	}
	clear(rs[:])
}

// decodeInto recovers the K message bytes from a noisy codeword (the first
// N1*N2 bits of v) into msg. It returns 1 on success and 0 on a decoding
// failure, in constant time.
func decodeInto(msg []byte, v []uint64, p kmosaic.CodeParams) int {
	var rs [maxN1]byte
	n2w := rmLength * p.Mult / 64
	for i := 0; i < p.N1; i++ {
		rs[i] = rmDecodeByte(v, i*n2w, p.Mult)
	}
	ok := rsDecodeInto(msg, rs[:p.N1], p.N1, p.Delta)
	clear(rs[:])
	return ok
}

// ExpandH derives the public polynomial h from a public key seed.
func ExpandH(seed []byte, p kmosaic.CodeParams) []uint64 {
	return sampleUniform(seed, p.N)
}

// KeyGen generates a key pair from a secret seed of at least 32 bytes.
func KeyGen(p kmosaic.CodeParams, seed []byte) (*kmosaic.CodeKeyPair, error) {
	if len(seed) < SeedSize {
		return nil, errors.New("seed must be at least 32 bytes")
	}
	if err := checkParams(p); err != nil {
		return nil, err
	}
	hSeed := utils.HashWithDomain(DomainH, seed)
	h := ExpandH(hSeed, p)
	xSeed := utils.HashWithDomain(DomainX, seed)
	ySeed := utils.HashWithDomain(DomainY, seed)
	x := sampleFixedWeight(xSeed, p.N, p.W)
	y, yPos := sampleFixedWeightPos(ySeed, p.N, p.W)
	utils.Zeroize(xSeed)
	utils.Zeroize(ySeed)
	ctSortInts(yPos) // the serialized key lists positions in increasing order

	s := mulSparse(h, yPos, p.N)
	xorInto(s, x)

	return &kmosaic.CodeKeyPair{
		PublicKey: kmosaic.CodePublicKey{Seed: hSeed, H: h, S: s},
		SecretKey: kmosaic.CodeSecretKey{X: x, Y: y, YPos: yPos},
	}, nil
}

// Encrypt encrypts a K-byte message. randomness (at least 32 bytes)
// deterministically selects r1, r2 and e.
func Encrypt(pk kmosaic.CodePublicKey, message []byte, p kmosaic.CodeParams, randomness []byte) (*kmosaic.CodeCiphertext, error) {
	if len(randomness) < 32 {
		return nil, errors.New("randomness must be at least 32 bytes")
	}
	if err := checkParams(p); err != nil {
		return nil, err
	}
	if len(message) != p.K {
		return nil, errors.New("message must be exactly K bytes")
	}
	nw := words(p.N)
	if len(pk.H) != nw || len(pk.S) != nw {
		return nil, errors.New("public key has wrong dimensions")
	}
	if !isCanonical(pk.H, p.N) || !isCanonical(pk.S, p.N) {
		return nil, errors.New("public key has non-zero padding bits")
	}

	r1Seed := utils.HashWithDomain(DomainR1, randomness)
	r2Seed := utils.HashWithDomain(DomainR2, randomness)
	eSeed := utils.HashWithDomain(DomainE, randomness)
	r1 := sampleFixedWeight(r1Seed, p.N, p.WR)
	r2, r2Pos := sampleFixedWeightPos(r2Seed, p.N, p.WR)
	e := sampleFixedWeight(eSeed, p.N, p.WE)
	utils.Zeroize(r1Seed)
	utils.Zeroize(r2Seed)
	utils.Zeroize(eSeed)
	defer zeroInts(r2Pos)

	u, sr2 := mulSparse2(pk.H, pk.S, r2Pos, p.N)
	xorInto(u, r1)

	cl := CodeLength(p)
	v := make([]uint64, words(cl))
	encodeInto(v, message, p)
	xorInto(v, sr2[:len(v)])
	xorInto(v, e[:len(v)])
	maskTop(v, cl)

	zeroWords(r1)
	zeroWords(r2)
	zeroWords(e)
	zeroWords(sr2)
	zeroInts(r2Pos)
	return &kmosaic.CodeCiphertext{U: u, V: v}, nil
}

// secretPositions returns the sorted positions of y, from sk.YPos when it is
// set and otherwise derived from sk.Y. ok is false if they are malformed.
// The validity check accumulates without early exits.
func secretPositions(sk kmosaic.CodeSecretKey, p kmosaic.CodeParams) (pos []int, derived bool, ok bool) {
	pos = sk.YPos
	if len(pos) == 0 && len(sk.Y) == words(p.N) {
		pos, derived = positions(sk.Y, p.N), true
	}
	if len(pos) != p.W {
		return nil, derived, false
	}
	bad, prev := 0, -1
	for _, q := range pos {
		bad |= (q - prev - 1) | (p.N - 1 - q) // negative iff q <= prev or q >= N
		prev = q
	}
	return pos, derived, bad >= 0
}

// Decrypt decrypts a ciphertext. For well-shaped inputs it always performs
// the full decryption and returns exactly K bytes with ok = 1 if the code
// decoded successfully and ok = 0 otherwise; on failure msg holds the
// systematic bytes of the uncorrected Reed-Solomon word. The flag and the
// running time do not depend on secret data. It returns (nil, 0) only if the
// parameters, the ciphertext or the secret key have the wrong shape
// (including non-zero padding bits in the ciphertext).
func Decrypt(ct *kmosaic.CodeCiphertext, sk kmosaic.CodeSecretKey, p kmosaic.CodeParams) (msg []byte, ok int) {
	if ct == nil || checkParams(p) != nil {
		return nil, 0
	}
	cl := CodeLength(p)
	if len(ct.U) != words(p.N) || len(ct.V) != words(cl) ||
		!isCanonical(ct.U, p.N) || !isCanonical(ct.V, cl) {
		return nil, 0
	}
	yPos, derived, valid := secretPositions(sk, p)
	if !valid {
		return nil, 0
	}
	uy := mulSparse(ct.U, yPos, p.N)
	if derived {
		zeroInts(yPos)
	}
	w := uy[:words(cl)]
	maskTop(w, cl)
	xorInto(w, ct.V)
	msg = make([]byte, p.K)
	ok = decodeInto(msg, w, p)
	zeroWords(uy)
	return msg, ok
}

// SerializePublicKey serializes a public key as [seed:32][s bits].
func SerializePublicKey(pk kmosaic.CodePublicKey, p kmosaic.CodeParams) []byte {
	out := make([]byte, 0, SeedSize+(p.N+7)/8)
	out = append(out, pk.Seed...)
	out = append(out, bitsToBytes(pk.S, p.N)...)
	return out
}

// DeserializePublicKey parses a public key and expands h from its seed.
func DeserializePublicKey(data []byte, p kmosaic.CodeParams) (*kmosaic.CodePublicKey, error) {
	if err := checkParams(p); err != nil {
		return nil, err
	}
	nb := (p.N + 7) / 8
	if len(data) != SeedSize+nb {
		return nil, errors.New("invalid code public key: wrong length")
	}
	seed := append([]byte{}, data[:SeedSize]...)
	s, err := bytesToBits(data[SeedSize:], p.N)
	if err != nil {
		return nil, errors.New("invalid code public key: " + err.Error())
	}
	return &kmosaic.CodePublicKey{Seed: seed, H: ExpandH(seed, p), S: s}, nil
}

// SecretKeySize returns the serialized secret key length: 2·W bytes.
func SecretKeySize(p kmosaic.CodeParams) int { return 2 * p.W }

// SerializeSecretKey serializes a secret key as the W sorted positions of y,
// each a little-endian uint16. x is not stored: it is only needed to build
// s. It returns nil if the key is malformed.
func SerializeSecretKey(sk kmosaic.CodeSecretKey, p kmosaic.CodeParams) []byte {
	if checkParams(p) != nil {
		return nil
	}
	pos, derived, ok := secretPositions(sk, p)
	if !ok {
		return nil
	}
	out := make([]byte, SecretKeySize(p))
	for i, q := range pos {
		binary.LittleEndian.PutUint16(out[2*i:], uint16(q))
	}
	if derived {
		zeroInts(pos)
	}
	return out
}

// DeserializeSecretKey parses a secret key: exactly W strictly increasing
// little-endian uint16 positions, all below N. It rebuilds Y and YPos; X is
// left nil.
func DeserializeSecretKey(data []byte, p kmosaic.CodeParams) (*kmosaic.CodeSecretKey, error) {
	if err := checkParams(p); err != nil {
		return nil, err
	}
	if len(data) != SecretKeySize(p) {
		return nil, errors.New("invalid code secret key: wrong length")
	}
	pos := make([]int, p.W)
	for i := range pos {
		pos[i] = int(binary.LittleEndian.Uint16(data[2*i:]))
	}
	if _, _, ok := secretPositions(kmosaic.CodeSecretKey{YPos: pos}, p); !ok {
		zeroInts(pos)
		return nil, errors.New("invalid code secret key: positions must be strictly increasing and below N")
	}
	y := make([]uint64, words(p.N))
	for _, q := range pos {
		setBit(y, q)
	}
	return &kmosaic.CodeSecretKey{Y: y, YPos: pos}, nil
}

// CiphertextCanonical reports whether ct has the shape that Encrypt under p
// produces and no padding bit set, i.e. whether it is the unique in-memory
// form of its serialization. Shapes are public.
func CiphertextCanonical(ct *kmosaic.CodeCiphertext, p kmosaic.CodeParams) bool {
	if ct == nil || checkParams(p) != nil {
		return false
	}
	cl := CodeLength(p)
	return len(ct.U) == words(p.N) && len(ct.V) == words(cl) &&
		isCanonical(ct.U, p.N) && isCanonical(ct.V, cl)
}

// SerializeCiphertext serializes a ciphertext as [u bits][v bits].
func SerializeCiphertext(ct *kmosaic.CodeCiphertext, p kmosaic.CodeParams) []byte {
	out := make([]byte, 0, (p.N+7)/8+(CodeLength(p)+7)/8)
	out = append(out, bitsToBytes(ct.U, p.N)...)
	out = append(out, bitsToBytes(ct.V, CodeLength(p))...)
	return out
}

// DeserializeCiphertext parses a ciphertext.
func DeserializeCiphertext(data []byte, p kmosaic.CodeParams) (*kmosaic.CodeCiphertext, error) {
	if err := checkParams(p); err != nil {
		return nil, err
	}
	nbU := (p.N + 7) / 8
	nbV := (CodeLength(p) + 7) / 8
	if len(data) != nbU+nbV {
		return nil, errors.New("invalid code ciphertext: wrong length")
	}
	u, err := bytesToBits(data[:nbU], p.N)
	if err != nil {
		return nil, err
	}
	v, err := bytesToBits(data[nbU:], CodeLength(p))
	if err != nil {
		return nil, err
	}
	return &kmosaic.CodeCiphertext{U: u, V: v}, nil
}
