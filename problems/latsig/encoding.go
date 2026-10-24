package latsig

import (
	"encoding/binary"
	"errors"

	kmosaic "github.com/BackendStack21/k-mosaic-go/v2"
	"github.com/BackendStack21/k-mosaic-go/v2/core"
	"github.com/BackendStack21/k-mosaic-go/v2/utils"
)

// Wire formats (all integers little-endian, bit packing in FIPS 204
// little-endian bit order: entry i occupies bits [i·b, (i+1)·b) of the field):
//
//	public key = [level_len:4][level][rho:32][T1: M·L entries, 10 bits]
//	secret key = [level_len:4][level][rho:32][K:32][tr:64]
//	             [S1: N·L entries as eta - s, 3 bits (eta = 2) or 4 bits (eta = 4)]
//	             [S2: M·L entries, same encoding]
//	             [T0: M·L entries as 2^12 - t0, 13 bits]
//	signature  = [c̃: CTildeSize][z: N entries as γ1 - z, 20 bits]
//	             [hint: Omega index bytes || M/256 cumulative counts] (FIPS 204 HintBitPack)
//
// Every parser requires the exact total length and canonical field values.

// maxLevelLen bounds the security-level string of a serialized key.
const maxLevelLen = 32

var (
	errTruncated = errors.New("latsig: truncated length-prefixed field")
	errLevelLen  = errors.New("latsig: security level string too long")
)

// bitWriter appends values of a fixed bit width in little-endian bit order.
// The number of bytes written depends only on the widths, not on the values.
type bitWriter struct {
	buf []byte
	acc uint64
	n   uint
}

func (w *bitWriter) put(v uint32, bits uint) {
	w.acc |= uint64(v) << w.n
	w.n += bits
	for w.n >= 8 {
		w.buf = append(w.buf, byte(w.acc))
		w.acc >>= 8
		w.n -= 8
	}
}

// bitReader reads values of a fixed bit width in little-endian bit order. The
// caller guarantees that data holds enough bytes.
type bitReader struct {
	data []byte
	off  int
	acc  uint64
	n    uint
}

func (r *bitReader) get(bits uint) uint32 {
	for r.n < bits {
		r.acc |= uint64(r.data[r.off]) << r.n
		r.off++
		r.n += 8
	}
	v := uint32(r.acc & (1<<bits - 1))
	r.acc >>= bits
	r.n -= bits
	return v
}

// readLength reads the 4-byte little-endian length at off and checks that
// that many bytes follow. The comparison is done in 64 bits before any
// conversion to int, so a prefix such as 0xFFFFFFFF cannot turn negative on
// 32-bit platforms (GOARCH=386, arm).
func readLength(data []byte, off int) (length, next int, err error) {
	if off < 0 || off > len(data) || len(data)-off < 4 {
		return 0, 0, errTruncated
	}
	v := binary.LittleEndian.Uint32(data[off:])
	off += 4
	if uint64(v) > uint64(len(data)-off) {
		return 0, 0, errTruncated
	}
	return int(v), off + int(v), nil
}

// readLevel parses the [level_len:4][level] prefix and returns the matching
// parameter set and the offset just past it. Unknown levels are rejected.
func readLevel(data []byte) (kmosaic.LatticeSignParams, int, error) {
	n, next, err := readLength(data, 0)
	if err != nil {
		return kmosaic.LatticeSignParams{}, 0, err
	}
	if n > maxLevelLen {
		return kmosaic.LatticeSignParams{}, 0, errLevelLen
	}
	params, err := core.GetLatticeSignParams(kmosaic.SecurityLevel(data[4:next]))
	if err != nil {
		return kmosaic.LatticeSignParams{}, 0, err
	}
	return params, next, nil
}

// appendLevel writes [level_len:4][level] for params, or reports false if the
// parameters match no known level.
func appendLevel(dst []byte, params kmosaic.LatticeSignParams) ([]byte, bool) {
	level, err := core.LatticeLevelFromParams(params)
	if err != nil {
		return nil, false
	}
	dst = append(dst, uint32LE(uint32(len(level)))...)
	return append(dst, level...), true
}

// etaBits is the packed width of a secret entry.
func etaBits(eta int) uint {
	if eta == 2 {
		return 3
	}
	return 4
}

func levelPrefixSize(params kmosaic.LatticeSignParams) int {
	level, _ := core.LatticeLevelFromParams(params)
	return 4 + len(level)
}

// publicKeySize returns the serialized public-key size for params.
func publicKeySize(p kmosaic.LatticeSignParams) int {
	return levelPrefixSize(p) + SeedSize + p.M*chalLen*t1Bits/8
}

// secretKeySize returns the serialized secret-key size for params.
func secretKeySize(p kmosaic.LatticeSignParams) int {
	eb := int(etaBits(p.Eta))
	return levelPrefixSize(p) + 2*SeedSize + TrSize +
		(p.N+p.M)*chalLen*eb/8 + p.M*chalLen*t0Bits/8
}

// signatureSize returns the serialized signature size for params.
func signatureSize(p kmosaic.LatticeSignParams) int {
	return p.CTildeSize + p.N*zBits/8 + p.Omega + p.M/chalLen
}

// SerializePublicKey serializes a signature public key as
// [level_len:4][level][rho:32][T1 packed with 10 bits per entry]. It returns
// nil if the key has an unknown parameter set, the wrong shape, or a T1 entry
// outside [0, 2^10).
func SerializePublicKey(pk *kmosaic.LatticeSignPublicKey) []byte {
	if pk == nil || len(pk.Rho) != SeedSize {
		return nil
	}
	p := pk.Params
	if len(pk.T1) != p.M*chalLen {
		return nil
	}
	out, ok := appendLevel(make([]byte, 0, publicKeySize(p)), p)
	if !ok {
		return nil
	}
	out = append(out, pk.Rho...)
	w := bitWriter{buf: out}
	for _, t := range pk.T1 {
		if uint32(t) >= t1Limit {
			return nil
		}
		w.put(uint32(t), t1Bits)
	}
	return w.buf
}

// DeserializePublicKey parses a public key written by SerializePublicKey,
// expands the matrix A and caches tr = SHAKE256(pk, 64).
func DeserializePublicKey(data []byte) (*kmosaic.LatticeSignPublicKey, error) {
	params, off, err := readLevel(data)
	if err != nil {
		return nil, err
	}
	if len(data) != publicKeySize(params) {
		return nil, errors.New("invalid public key: wrong length")
	}
	pk := &kmosaic.LatticeSignPublicKey{Params: params}
	pk.Rho = append([]byte{}, data[off:off+SeedSize]...)
	off += SeedSize
	// Every 10-bit value is a valid T1 entry, so the exact length makes the
	// encoding canonical and tr can be hashed from data directly.
	r := bitReader{data: data, off: off}
	pk.T1 = make([]int32, params.M*chalLen)
	for i := range pk.T1 {
		pk.T1[i] = int32(r.get(t1Bits))
	}
	pk.Tr = shake(TrSize, data)
	pk.A = expandA(pk.Rho, params.M, params.N)
	return pk, nil
}

// SerializeSecretKey serializes a signature secret key as
// [level_len:4][level][rho:32][K:32][tr:64][S1][S2][T0] (see the package wire
// format). It returns nil if the key has an unknown parameter set, the wrong
// shape, or an entry out of range. Packing does not branch on secret values.
func SerializeSecretKey(sk *kmosaic.LatticeSignSecretKey) []byte {
	if sk == nil || checkSecretKey(sk) != nil {
		return nil
	}
	p := sk.Params
	out, ok := appendLevel(make([]byte, 0, secretKeySize(p)), p)
	if !ok {
		return nil
	}
	out = append(out, sk.Rho...)
	out = append(out, sk.K...)
	out = append(out, sk.Tr...)
	w := bitWriter{buf: out}
	eb, eta := etaBits(p.Eta), int32(p.Eta)
	var bad uint32
	for _, S := range [2][]int8{sk.S1, sk.S2} {
		for _, s := range S {
			v := eta - int32(s)
			bad |= uint32(v|(2*eta-v)) >> 31
			w.put(uint32(v), eb)
		}
	}
	for _, t := range sk.T0 {
		v := t0Half - t
		bad |= uint32(v|(2*t0Half-1-v)) >> 31
		w.put(uint32(v), t0Bits)
	}
	if bad != 0 {
		utils.Zeroize(w.buf)
		return nil
	}
	return w.buf
}

// DeserializeSecretKey parses a secret key written by SerializeSecretKey,
// checks every S1, S2 and T0 entry and expands the matrix A. Range checks
// accumulate a flag instead of branching on secret values.
func DeserializeSecretKey(data []byte) (*kmosaic.LatticeSignSecretKey, error) {
	params, off, err := readLevel(data)
	if err != nil {
		return nil, err
	}
	if len(data) != secretKeySize(params) {
		return nil, errors.New("invalid secret key: wrong length")
	}
	sk := &kmosaic.LatticeSignSecretKey{Params: params}
	sk.Rho = append([]byte{}, data[off:off+SeedSize]...)
	off += SeedSize
	sk.K = append([]byte{}, data[off:off+SeedSize]...)
	off += SeedSize
	sk.Tr = append([]byte{}, data[off:off+TrSize]...)
	off += TrSize

	r := bitReader{data: data, off: off}
	eb, eta := etaBits(params.Eta), int32(params.Eta)
	var bad uint32
	readS := func(count int) []int8 {
		out := make([]int8, count)
		for i := range out {
			v := int32(r.get(eb))
			bad |= uint32(2*eta-v) >> 31
			out[i] = int8(eta - v)
		}
		return out
	}
	sk.S1 = readS(params.N * chalLen)
	sk.S2 = readS(params.M * chalLen)
	// Every 13-bit value v gives t0 = 2^12 - v ∈ (-2^12, 2^12], the exact
	// Power2Round range, so T0 needs no further check.
	sk.T0 = make([]int32, params.M*chalLen)
	for i := range sk.T0 {
		sk.T0[i] = t0Half - int32(r.get(t0Bits))
	}
	r.acc = 0
	if bad != 0 {
		wipeSecretKey(sk)
		return nil, errors.New("invalid secret key: secret entry out of range")
	}
	sk.A = expandA(sk.Rho, params.M, params.N)
	return sk, nil
}

// wipeSecretKey zeroizes the secret parts of sk.
func wipeSecretKey(sk *kmosaic.LatticeSignSecretKey) {
	utils.Zeroize(sk.K)
	utils.ZeroizeInt8(sk.S1)
	utils.ZeroizeInt8(sk.S2)
	utils.ZeroizeInt32(sk.T0)
}

// checkHints reports whether hint is a valid hint list for params: at most
// Omega strictly increasing indices below M.
func checkHints(hint []uint16, p kmosaic.LatticeSignParams) bool {
	if len(hint) > p.Omega {
		return false
	}
	for i, h := range hint {
		if int(h) >= p.M || (i > 0 && hint[i-1] >= h) {
			return false
		}
	}
	return true
}

// SerializeSignature serializes a signature for the parameter set params as
// [c̃][z packed as γ1 - z, 20 bits each][hint (FIPS 204 HintBitPack with
// M/256 blocks)]. It returns nil if params is not a known parameter set or
// the signature has the wrong shape.
func SerializeSignature(sig *kmosaic.LatticeSignature, params kmosaic.LatticeSignParams) []byte {
	if sig == nil {
		return nil
	}
	if _, err := core.LatticeLevelFromParams(params); err != nil {
		return nil
	}
	if len(sig.Challenge) != params.CTildeSize || len(sig.Z) != params.N || !checkHints(sig.Hint, params) {
		return nil
	}
	out := make([]byte, 0, signatureSize(params))
	out = append(out, sig.Challenge...)
	w := bitWriter{buf: out}
	for _, z := range sig.Z {
		v := gamma1 - z
		if v < 0 || v >= zLimit {
			return nil
		}
		w.put(uint32(v), zBits)
	}
	out = w.buf

	// HintBitPack: in-block indices, then the cumulative count after each block.
	blocks := params.M / chalLen
	hintBytes := make([]byte, params.Omega+blocks)
	idx := 0
	for b := 0; b < blocks; b++ {
		for idx < len(sig.Hint) && int(sig.Hint[idx])/chalLen == b {
			hintBytes[idx] = byte(sig.Hint[idx] % chalLen)
			idx++
		}
		hintBytes[params.Omega+b] = byte(idx)
	}
	return append(out, hintBytes...)
}

// DeserializeSignature parses a signature written by SerializeSignature for
// the parameter set params. It requires the exact length, ||z||∞ < γ1 - β and
// a canonical hint encoding (FIPS 204 HintBitUnpack: counts monotone and at
// most Omega, indices strictly increasing within each block, unused index
// bytes zero).
func DeserializeSignature(data []byte, params kmosaic.LatticeSignParams) (*kmosaic.LatticeSignature, error) {
	if _, err := core.LatticeLevelFromParams(params); err != nil {
		return nil, err
	}
	if len(data) != signatureSize(params) {
		return nil, errors.New("invalid signature: wrong length")
	}
	sig := &kmosaic.LatticeSignature{Challenge: append([]byte{}, data[:params.CTildeSize]...)}
	off := params.CTildeSize

	bound := uint32(gamma1 - params.Beta)
	r := bitReader{data: data, off: off}
	sig.Z = make([]int32, params.N)
	for i := range sig.Z {
		z := gamma1 - int32(r.get(zBits))
		if absU(z) >= bound {
			return nil, errors.New("invalid signature: response out of range")
		}
		sig.Z[i] = z
	}
	off = r.off

	hb := data[off:]
	omega := params.Omega
	blocks := params.M / chalLen
	sig.Hint = make([]uint16, 0, omega)
	idx := 0
	for b := 0; b < blocks; b++ {
		end := int(hb[omega+b])
		if end < idx || end > omega {
			return nil, errors.New("invalid signature: malformed hint counts")
		}
		first := idx
		for ; idx < end; idx++ {
			if idx > first && hb[idx-1] >= hb[idx] {
				return nil, errors.New("invalid signature: hint indices not increasing")
			}
			sig.Hint = append(sig.Hint, uint16(b*chalLen+int(hb[idx])))
		}
	}
	for ; idx < omega; idx++ {
		if hb[idx] != 0 {
			return nil, errors.New("invalid signature: non-zero hint padding")
		}
	}
	return sig, nil
}
