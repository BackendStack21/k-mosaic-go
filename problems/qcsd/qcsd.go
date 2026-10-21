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
package qcsd

import (
	"errors"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

const (
	DomainH  = "kmosaic-qcsd-h-v3"
	DomainX  = "kmosaic-qcsd-x-v3"
	DomainY  = "kmosaic-qcsd-y-v3"
	DomainR1 = "kmosaic-qcsd-r1-v3"
	DomainR2 = "kmosaic-qcsd-r2-v3"
	DomainE  = "kmosaic-qcsd-e-v3"
	SeedSize = 32
	rmLength = 128 // RM(1,7) codeword length in bits
)

// checkParams validates the dimensions used by this package.
func checkParams(p kmosaic.CodeParams) error {
	if p.N <= 0 || p.N1 <= 0 || p.K <= 0 || p.Delta <= 0 || p.Mult <= 0 {
		return errors.New("qcsd: parameters must be positive")
	}
	if p.N1 > 255 || p.K >= p.N1 || p.N1-p.K != 2*p.Delta {
		return errors.New("qcsd: inconsistent Reed-Solomon parameters")
	}
	if p.N1*rmLength*p.Mult > p.N {
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

// encode maps a K-byte message to its N1*N2-bit codeword, returned as an N-bit vector.
func encode(msg []byte, p kmosaic.CodeParams) []uint64 {
	rs := rsEncode(msg, p.N1, p.Delta)
	n2 := rmLength * p.Mult
	cw := make([]uint64, words(p.N))
	for i, b := range rs {
		rmEncodeByte(cw, i*n2, b, p.Mult)
	}
	return cw
}

// decode recovers the message from a noisy codeword (first N1*N2 bits of v).
func decode(v []uint64, p kmosaic.CodeParams) ([]byte, error) {
	n2 := rmLength * p.Mult
	rs := make([]byte, p.N1)
	for i := range rs {
		rs[i] = rmDecodeByte(v, i*n2, p.Mult)
	}
	return rsDecode(rs, p.N1, p.Delta)
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
	y := sampleFixedWeight(ySeed, p.N, p.W)
	utils.Zeroize(xSeed)
	utils.Zeroize(ySeed)

	s := mulSparse(h, positions(y, p.N), p.N)
	xorInto(s, x)

	return &kmosaic.CodeKeyPair{
		PublicKey: kmosaic.CodePublicKey{Seed: hSeed, H: h, S: s},
		SecretKey: kmosaic.CodeSecretKey{X: x, Y: y},
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

	r1Seed := utils.HashWithDomain(DomainR1, randomness)
	r2Seed := utils.HashWithDomain(DomainR2, randomness)
	eSeed := utils.HashWithDomain(DomainE, randomness)
	defer func() {
		utils.Zeroize(r1Seed)
		utils.Zeroize(r2Seed)
		utils.Zeroize(eSeed)
	}()
	r1 := sampleFixedWeight(r1Seed, p.N, p.WR)
	r2 := sampleFixedWeight(r2Seed, p.N, p.WR)
	e := sampleFixedWeight(eSeed, p.N, p.WE)
	r2Pos := positions(r2, p.N)

	u := mulSparse(pk.H, r2Pos, p.N)
	xorInto(u, r1)

	v := encode(message, p)
	xorInto(v, mulSparse(pk.S, r2Pos, p.N))
	xorInto(v, e)
	v = truncate(v, CodeLength(p))

	return &kmosaic.CodeCiphertext{U: u, V: v}, nil
}

// truncate returns the first nbits bits of v as a vector of exactly words(nbits) words.
func truncate(v []uint64, nbits int) []uint64 {
	out := make([]uint64, words(nbits))
	copy(out, v)
	maskTop(out, nbits)
	return out
}

// Decrypt decrypts a ciphertext. It returns nil if the ciphertext has the
// wrong shape or the code fails to decode.
func Decrypt(ct *kmosaic.CodeCiphertext, sk kmosaic.CodeSecretKey, p kmosaic.CodeParams) []byte {
	if err := checkParams(p); err != nil {
		return nil
	}
	nw := words(p.N)
	if len(ct.U) != nw || len(ct.V) != words(CodeLength(p)) || len(sk.Y) != nw {
		return nil
	}
	uy := truncate(mulSparse(ct.U, positions(sk.Y, p.N), p.N), CodeLength(p))
	xorInto(uy, ct.V)
	msg, err := decode(uy, p)
	if err != nil {
		return nil
	}
	return msg
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

// SerializeSecretKey serializes a secret key as [x bits][y bits].
func SerializeSecretKey(sk kmosaic.CodeSecretKey, p kmosaic.CodeParams) []byte {
	out := make([]byte, 0, 2*(p.N+7)/8)
	out = append(out, bitsToBytes(sk.X, p.N)...)
	out = append(out, bitsToBytes(sk.Y, p.N)...)
	return out
}

// DeserializeSecretKey parses a secret key.
func DeserializeSecretKey(data []byte, p kmosaic.CodeParams) (*kmosaic.CodeSecretKey, error) {
	if err := checkParams(p); err != nil {
		return nil, err
	}
	nb := (p.N + 7) / 8
	if len(data) != 2*nb {
		return nil, errors.New("invalid code secret key: wrong length")
	}
	x, err := bytesToBits(data[:nb], p.N)
	if err != nil {
		return nil, err
	}
	y, err := bytesToBits(data[nb:], p.N)
	if err != nil {
		return nil, err
	}
	if weight(x) != p.W || weight(y) != p.W {
		return nil, errors.New("invalid code secret key: wrong weight")
	}
	return &kmosaic.CodeSecretKey{X: x, Y: y}, nil
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
