// Package uov implements the multivariate component of the kMOSAIC signature:
// Unbalanced Oil and Vinegar over F_256, following the UOV NIST submission
// (compressed public keys, expanded secret keys, salted signing).
//
// The public key is a system of M quadratic forms P_i(s) = sᵀ P_i s in N
// variables that all vanish on a secret M-dimensional "oil" subspace spanned
// by the columns of [O; I]. Writing s = (v + O·x, x) with vinegar v and oil x,
// each P_i(s) = vᵀ P1_i v + vᵀ S_i x is linear in x, so the signer fixes v
// pseudo-randomly and solves an M×M linear system for x. Security rests on
// the MQ problem and on hiding the oil subspace (uov-Ip ≈ 2^143, uov-V ≈
// 2^272 classical per the submission's analysis).
//
// # Key formats
//
// A secret key serializes as its 32-byte seed; a public key as its 16-byte
// public seed followed by the P3 blocks. Deserialization re-derives the rest.
// Both key structs carry a derived, non-serialized Prepared field: for public
// keys the coefficients of all M forms interleaved per monomial (which lets
// verification compute each product s_r·s_c once), for secret keys the same
// layout for P1 followed by the S_i matrices as packed 64-bit rows. Keys
// returned by KeyGen and the deserializers carry it; keys assembled by hand
// may leave it nil (Verify then uses the plain layout and Sign builds a
// temporary copy). Prepared must not be modified independently of the other
// fields.
//
// # Side channels
//
// Signing is NOT constant-time. It performs memory accesses whose addresses
// depend on secret values: GF(256) multiplications through a 64 KB table,
// the inverse of each pivot through log/exp tables, bucket accumulation
// indexed by the secret products v_r·v_c when evaluating vᵀ P1_i v, and
// nibble-table lookups indexed by secret factors during Gaussian elimination
// (whose pivot search also branches on secret data). The vᵀ S_i products are
// computed with masked bit-plane arithmetic, without secret-dependent
// addresses. In key generation the P1_i·O products use nibble tables of the
// secret oil rows indexed only by the public P1 coefficients; the Oᵀ(P1_i·O +
// P2_i) step needed for P3 indexes those tables by secret values (it runs in
// KeyGen only; DeserializeSecretKey skips it). Verification touches public
// data only.
package uov

import (
	"crypto/rand"
	"crypto/sha3"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
)

const (
	DomainKeyGen = "kmosaic-uov-keygen-v4"
	DomainPK     = "kmosaic-uov-pk-v4"
	DomainTarget = "kmosaic-uov-target-v4"
	DomainVin    = "kmosaic-uov-vinegar-v4"
	DomainSalt   = "kmosaic-uov-salt-v4"

	SeedSize   = 32 // secret seed (the serialized secret key)
	PKSeedSize = 16 // public seed
	SaltSize   = 16 // signature salt
	RandSize   = 16 // fresh randomness mixed into each salt

	// MaxN bounds the number of variables accepted by any function, so that
	// bogus parameters cannot trigger huge allocations or integer overflow.
	MaxN = 512

	maxSignAttempts = 256
)

// triSize is the number of entries of an upper-triangular d×d block.
func triSize(d int) int { return d * (d + 1) / 2 }

// triIndex returns the index of entry (r, c), r <= c, in an upper-triangular
// block of dimension d stored row by row.
func triIndex(d, r, c int) int {
	return r*d - r*(r-1)/2 + (c - r)
}

// dims holds the derived sizes of a parameter set.
type dims struct {
	n, v, m int
	w       int // words per packed M-vector
	stride  int // bytes per packed M-vector (8*w)
	t1, t3  int // triSize(v), triSize(m)
}

func checkParams(p kmosaic.MQParams) (dims, error) {
	if p.M <= 0 || p.N <= 2*p.M || p.N > MaxN {
		return dims{}, errors.New("uov: requires 0 < m, n > 2m and n <= 512")
	}
	d := dims{n: p.N, v: p.N - p.M, m: p.M, w: words(p.M)}
	d.stride = 8 * d.w
	d.t1, d.t3 = triSize(d.v), triSize(d.m)
	return d, nil
}

func (d dims) p1Len() int { return d.m * d.t1 }
func (d dims) p2Len() int { return d.m * d.v * d.m }
func (d dims) p3Len() int { return d.m * d.t3 }

// pkPreparedLen is the size of the interleaved public-key layout: one packed
// M-vector per monomial of the full upper-triangular N×N form.
func (d dims) pkPreparedLen() int { return triSize(d.n) * d.stride }

// skPreparedLen is the size of the signing layout: interleaved P1, then the
// S_i matrices as packed rows.
func (d dims) skPreparedLen() int { return (d.t1 + d.m*d.v) * d.stride }

func newXOF(domain string) *sha3.SHAKE {
	h := sha3.NewSHAKE256()
	_, _ = h.Write([]byte{byte(len(domain))})
	_, _ = h.Write([]byte(domain))
	return h
}

// expandPublic derives P1 (M blocks of V(V+1)/2) and P2 (M blocks of V*M)
// from the public seed.
func expandPublic(pkSeed []byte, d dims) (p1, p2 []byte) {
	h := newXOF(DomainPK)
	_, _ = h.Write(pkSeed)
	buf := make([]byte, d.p1Len()+d.p2Len())
	_, _ = h.Read(buf)
	return buf[:d.p1Len():d.p1Len()], buf[d.p1Len():]
}

// derived is the material computed from a secret seed.
type derived struct {
	pkSeed, O, P1, P2, S, P3, skPrep []byte
}

// interleave writes the forms (M blocks of size blk) into prep so that
// coefficient k of form i lands at prep[k*stride+i].
func interleave(prep, forms []byte, blk int, d dims) {
	const run = 128
	for k := 0; k < blk; k += run {
		transposeRun(prep, k, forms, k, blk, min(run, blk-k), d)
	}
}

// transposeRun copies, for every form i, the run src[i*blk+off : +l] to
// monomials mono..mono+l-1 of the interleaved layout prep, transposing 8×8
// byte blocks in registers.
func transposeRun(prep []byte, mono int, src []byte, off, blk, l int, d dims) {
	st := d.stride
	dst := prep[mono*st : (mono+l)*st]
	m8, l8 := d.m&^7, l&^7
	for i0 := 0; i0 < m8; i0 += 8 {
		s0 := src[(i0+0)*blk+off : (i0+0)*blk+off+l]
		s1 := src[(i0+1)*blk+off : (i0+1)*blk+off+l]
		s2 := src[(i0+2)*blk+off : (i0+2)*blk+off+l]
		s3 := src[(i0+3)*blk+off : (i0+3)*blk+off+l]
		s4 := src[(i0+4)*blk+off : (i0+4)*blk+off+l]
		s5 := src[(i0+5)*blk+off : (i0+5)*blk+off+l]
		s6 := src[(i0+6)*blk+off : (i0+6)*blk+off+l]
		s7 := src[(i0+7)*blk+off : (i0+7)*blk+off+l]
		for j0 := 0; j0 < l8; j0 += 8 {
			r0, r1, r2, r3, r4, r5, r6, r7 := transpose8x8(
				binary.LittleEndian.Uint64(s0[j0:]), binary.LittleEndian.Uint64(s1[j0:]),
				binary.LittleEndian.Uint64(s2[j0:]), binary.LittleEndian.Uint64(s3[j0:]),
				binary.LittleEndian.Uint64(s4[j0:]), binary.LittleEndian.Uint64(s5[j0:]),
				binary.LittleEndian.Uint64(s6[j0:]), binary.LittleEndian.Uint64(s7[j0:]))
			o := j0*st + i0
			binary.LittleEndian.PutUint64(dst[o:], r0)
			binary.LittleEndian.PutUint64(dst[o+st:], r1)
			binary.LittleEndian.PutUint64(dst[o+2*st:], r2)
			binary.LittleEndian.PutUint64(dst[o+3*st:], r3)
			binary.LittleEndian.PutUint64(dst[o+4*st:], r4)
			binary.LittleEndian.PutUint64(dst[o+5*st:], r5)
			binary.LittleEndian.PutUint64(dst[o+6*st:], r6)
			binary.LittleEndian.PutUint64(dst[o+7*st:], r7)
		}
		for i := i0; i < i0+8; i++ {
			for j := l8; j < l; j++ {
				dst[j*st+i] = src[i*blk+off+j]
			}
		}
	}
	for i := m8; i < d.m; i++ {
		run := src[i*blk+off : i*blk+off+l]
		for j, b := range run {
			dst[j*st+i] = b
		}
	}
}

// transpose8x8 transposes the 8×8 byte matrix whose row k is rk (byte j of
// rk is entry (k, j)).
func transpose8x8(r0, r1, r2, r3, r4, r5, r6, r7 uint64) (uint64, uint64, uint64, uint64, uint64, uint64, uint64, uint64) {
	const m1, m2, m4 = 0x00FF00FF00FF00FF, 0x0000FFFF0000FFFF, 0x00000000FFFFFFFF
	t := ((r0 >> 8) ^ r1) & m1
	r1, r0 = r1^t, r0^(t<<8)
	t = ((r2 >> 8) ^ r3) & m1
	r3, r2 = r3^t, r2^(t<<8)
	t = ((r4 >> 8) ^ r5) & m1
	r5, r4 = r5^t, r4^(t<<8)
	t = ((r6 >> 8) ^ r7) & m1
	r7, r6 = r7^t, r6^(t<<8)

	t = ((r0 >> 16) ^ r2) & m2
	r2, r0 = r2^t, r0^(t<<16)
	t = ((r1 >> 16) ^ r3) & m2
	r3, r1 = r3^t, r1^(t<<16)
	t = ((r4 >> 16) ^ r6) & m2
	r6, r4 = r6^t, r4^(t<<16)
	t = ((r5 >> 16) ^ r7) & m2
	r7, r5 = r7^t, r5^(t<<16)

	t = ((r0 >> 32) ^ r4) & m4
	r4, r0 = r4^t, r0^(t<<32)
	t = ((r1 >> 32) ^ r5) & m4
	r5, r1 = r5^t, r1^(t<<32)
	t = ((r2 >> 32) ^ r6) & m4
	r6, r2 = r6^t, r2^(t<<32)
	t = ((r3 >> 32) ^ r7) & m4
	r7, r3 = r7^t, r3^(t<<32)
	return r0, r1, r2, r3, r4, r5, r6, r7
}

// deriveKey expands the secret seed. With wantP3 it also computes the public
// P3 blocks; without, it derives only what signing needs.
func deriveKey(d dims, seed []byte, wantP3 bool) *derived {
	v, m, w := d.v, d.m, d.w
	h := newXOF(DomainKeyGen)
	_, _ = h.Write(seed)
	pkSeed := make([]byte, PKSeedSize)
	_, _ = h.Read(pkSeed)
	O := make([]byte, v*m) // V x M row-major
	_, _ = h.Read(O)
	h.Reset()
	P1, P2 := expandPublic(pkSeed, d)

	// Nibble tables of the packed oil rows, shared by all forms.
	tw := 32 * w
	tabs := make([]uint64, v*tw)
	row := make([]uint64, w)
	for r := 0; r < v; r++ {
		packBytes(row, O[r*m:(r+1)*m])
		buildNibbleTable(tabs[r*tw:(r+1)*tw], row)
	}

	prep := make([]byte, d.skPreparedLen())
	interleave(prep, P1, d.t1, d)
	sPacked := prep[d.t1*d.stride:]
	S := make([]byte, d.p2Len())
	var P3 []byte
	var nt []uint64
	var mt []byte
	if wantP3 {
		P3 = make([]byte, d.p3Len())
		nt = make([]uint64, m*w)
		mt = make([]byte, m*m)
	}
	u := make([]uint64, v*w)  // P1_i · O
	ut := make([]uint64, v*w) // P1_iᵀ · O
	q := make([]uint64, w)

	for i := 0; i < m; i++ {
		clear(u)
		clear(ut)
		p1 := P1[i*d.t1 : (i+1)*d.t1]
		idx := 0
		for r := 0; r < v; r++ {
			ur := u[r*w : (r+1)*w]
			tr := tabs[r*tw : (r+1)*tw]
			for c := r; c < v; c++ {
				a := p1[idx] // public coefficient
				idx++
				if a == 0 {
					continue
				}
				// row r of P1_i·O gains a·O[c]; row c of P1_iᵀ·O gains a·O[r].
				mulRowInto(ur, tabs[c*tw:(c+1)*tw], a)
				mulRowInto(ut[c*w:(c+1)*w], tr, a)
			}
		}

		// S_i = (P1_i + P1_iᵀ)·O + P2_i, and Q = P1_i·O + P2_i.
		p2 := P2[i*v*m : (i+1)*v*m]
		si := S[i*v*m : (i+1)*v*m]
		if wantP3 {
			clear(nt)
		}
		for r := 0; r < v; r++ {
			packBytes(q, p2[r*m:(r+1)*m])
			ur := u[r*w : (r+1)*w]
			utr := ut[r*w : (r+1)*w]
			dst := sPacked[(i*v+r)*d.stride : (i*v+r+1)*d.stride]
			for k := range q {
				binary.LittleEndian.PutUint64(dst[8*k:], ur[k]^utr[k]^q[k])
				q[k] ^= ur[k]
			}
			copy(si[r*m:(r+1)*m], dst)
			if wantP3 {
				// Row b of M_iᵀ = Σ_r Q[r][b]·O[r], with M_i = Oᵀ·Q.
				tr := tabs[r*tw : (r+1)*tw]
				for b := 0; b < m; b++ {
					mulRowInto(nt[b*w:(b+1)*w], tr, byte(q[b>>3]>>(8*(b&7))))
				}
			}
		}
		if wantP3 {
			for b := 0; b < m; b++ {
				unpackBytes(mt[b*m:(b+1)*m], nt[b*w:(b+1)*w])
			}
			// P3_i = Upper(M_i); M_i and M_iᵀ have the same upper part.
			p3 := P3[i*d.t3 : (i+1)*d.t3]
			k := 0
			for r := 0; r < m; r++ {
				p3[k] = mt[r*m+r]
				k++
				for c := r + 1; c < m; c++ {
					p3[k] = mt[r*m+c] ^ mt[c*m+r]
					k++
				}
			}
		}
	}

	clear(tabs)
	clear(row)
	clear(u)
	clear(ut)
	clear(q)
	clear(nt)
	clear(mt)
	return &derived{pkSeed: pkSeed, O: O, P1: P1, P2: P2, S: S, P3: P3, skPrep: prep}
}

// buildPKPrepared builds the interleaved public-key layout: for each monomial
// s_r·s_c (r <= c < N, row by row) the packed vector of its M coefficients.
func buildPKPrepared(d dims, P1, P2, P3 []byte) []byte {
	n, v, m := d.n, d.v, d.m
	prep := make([]byte, d.pkPreparedLen())
	mono := 0
	for r := 0; r < n; r++ {
		// Row r of the full form is one contiguous run of each form's block.
		if r < v {
			transposeRun(prep, mono, P1, triIndex(v, r, r), d.t1, v-r, d)
			mono += v - r
			transposeRun(prep, mono, P2, r*m, v*m, m, d)
			mono += m
		} else {
			transposeRun(prep, mono, P3, triIndex(m, r-v, r-v), d.t3, n-r, d)
			mono += n - r
		}
	}
	return prep
}

// buildSKPrepared builds the signing layout from P1 and S.
func buildSKPrepared(d dims, P1, S []byte) []byte {
	prep := make([]byte, d.skPreparedLen())
	interleave(prep, P1, d.t1, d)
	sPacked := prep[d.t1*d.stride:]
	for k := 0; k < d.m*d.v; k++ {
		copy(sPacked[k*d.stride:], S[k*d.m:(k+1)*d.m])
	}
	return prep
}

// KeyGen generates a key pair from a 32-byte secret seed.
func KeyGen(p kmosaic.MQParams, seed []byte) (*kmosaic.MQKeyPair, error) {
	if len(seed) != SeedSize {
		return nil, errors.New("uov: seed must be exactly 32 bytes")
	}
	d, err := checkParams(p)
	if err != nil {
		return nil, err
	}
	k := deriveKey(d, seed, true)
	pk := kmosaic.MQPublicKey{
		Seed:     k.pkSeed,
		P3:       k.P3,
		P1:       k.P1,
		P2:       k.P2,
		Prepared: buildPKPrepared(d, k.P1, k.P2, k.P3),
	}
	sk := kmosaic.MQSecretKey{
		Seed:     append([]byte{}, seed...),
		PKSeed:   append([]byte{}, k.pkSeed...),
		O:        k.O,
		P1:       append([]byte{}, k.P1...),
		S:        k.S,
		Prepared: k.skPrep,
	}
	return &kmosaic.MQKeyPair{PublicKey: pk, SecretKey: sk}, nil
}

// target derives the M-byte target vector t = H(message || salt).
func target(message, salt []byte, m int) []byte {
	h := newXOF(DomainTarget)
	_, _ = h.Write(message)
	_, _ = h.Write(salt)
	t := make([]byte, m)
	_, _ = h.Read(t)
	return t
}

// evalBuckets computes Σ_{r<=c} s_r s_c · vec(r,c) over the interleaved
// layout prep (one packed vector of len(out) words per monomial) into out.
// Products are accumulated in 256 buckets acc (256*len(out) words) and
// combined once at the end. The bucket index is the product s_r·s_c, so the
// access pattern depends on s (public in verification, secret in signing).
func evalBuckets(out, acc []uint64, prep, s []byte) {
	w := len(out)
	st := 8 * w
	clear(acc)
	n := len(s)
	off := 0
	for r := 0; r < n; r++ {
		tab := &gfMulTab[s[r]]
		for c := r; c < n; c++ {
			b := int(tab[s[c]]) * w
			a := acc[b : b+w]
			vec := prep[off : off+st]
			for k := range a {
				a[k] ^= binary.LittleEndian.Uint64(vec[8*k:])
			}
			off += st
		}
	}
	clear(acc[:w]) // products equal to zero contribute nothing
	combineBuckets(out, acc)
}

// solve solves the M×M system packed in A by Gauss-Jordan elimination. Each
// of the m rows has wa words: the M coefficients followed by the right-hand
// side at element m. On success element m of row j holds x_j. tab is scratch
// space of 32*wa words. It returns false if the system is singular.
func solve(A []uint64, m, wa int, tab []uint64) bool {
	for col := 0; col < m; col++ {
		ci, sh := col>>3, uint(8*(col&7))
		pivot := -1
		for r := col; r < m; r++ {
			if byte(A[r*wa+ci]>>sh) != 0 {
				pivot = r
				break
			}
		}
		if pivot < 0 {
			return false
		}
		prow := A[col*wa : (col+1)*wa]
		if pivot != col {
			other := A[pivot*wa : (pivot+1)*wa]
			for k := range prow {
				prow[k], other[k] = other[k], prow[k]
			}
		}
		inv := gfInv(byte(prow[ci] >> sh))
		// Columns before col are already zero in the pivot row.
		buildNibbleTable(tab[:32*(wa-ci)], prow[ci:])
		for r := 0; r < m; r++ {
			if r == col {
				continue
			}
			f := byte(A[r*wa+ci] >> sh)
			mulRowInto(A[r*wa+ci:(r+1)*wa], tab, gfMul(f, inv))
		}
		// Normalize the pivot row: prow = inv·prow = prow ^ (inv^1)·prow.
		mulRowInto(prow[ci:], tab, inv^1)
	}
	return true
}

// Sign produces a UOV signature on message. The salt is
// H(seed || message || 16 fresh random bytes), so a failing random source
// degrades to deterministic salts rather than repeated ones; the vinegar
// values are H(seed || salt || t || ctr).
func Sign(sk *kmosaic.MQSecretKey, p kmosaic.MQParams, message []byte) (*kmosaic.MQSignature, error) {
	var rnd [RandSize]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, err
	}
	return signWithRand(sk, p, message, rnd[:])
}

func signWithRand(sk *kmosaic.MQSecretKey, p kmosaic.MQParams, message, rnd []byte) (*kmosaic.MQSignature, error) {
	d, err := checkParams(p)
	if err != nil {
		return nil, err
	}
	if sk == nil {
		return nil, errors.New("uov: nil secret key")
	}
	v, m, w := d.v, d.m, d.w
	if len(sk.Seed) != SeedSize || len(sk.O) != v*m || len(sk.P1) != d.p1Len() || len(sk.S) != d.p2Len() {
		return nil, errors.New("uov: malformed secret key")
	}
	prep := sk.Prepared
	if len(prep) != d.skPreparedLen() {
		prep = buildSKPrepared(d, sk.P1, sk.S)
		defer clear(prep)
	}
	p1Prep := prep[:d.t1*d.stride]
	sPacked := prep[d.t1*d.stride:]

	h := newXOF(DomainSalt)
	_, _ = h.Write(sk.Seed)
	_, _ = h.Write(message)
	_, _ = h.Write(rnd)
	salt := make([]byte, SaltSize)
	_, _ = h.Read(salt)
	t := target(message, salt, m)

	// Scratch buffers, allocated once and zeroized on every exit path.
	wa := words(m + 1) // augmented rows: M coefficients and the right-hand side
	vin := make([]byte, v)
	acc := make([]uint64, 256*w)
	yw := make([]uint64, w)
	planes := make([]uint64, 8*w)
	A := make([]uint64, m*wa)
	tab := make([]uint64, 32*wa)
	x := make([]byte, m)
	defer func() {
		clear(vin)
		clear(acc)
		clear(yw)
		clear(planes)
		clear(A)
		clear(tab)
		clear(x)
		h.Reset()
	}()

	vinPrefix := append([]byte{byte(len(DomainVin))}, DomainVin...)
	var ctr [1]byte
	for attempt := 0; attempt < maxSignAttempts; attempt++ {
		ctr[0] = byte(attempt)
		h.Reset()
		_, _ = h.Write(vinPrefix)
		_, _ = h.Write(sk.Seed)
		_, _ = h.Write(salt)
		_, _ = h.Write(t)
		_, _ = h.Write(ctr[:])
		_, _ = h.Read(vin)

		// Row i of L is vᵀ S_i, computed per bit plane of v with masks.
		clear(A)
		p0, p1, p2, p3 := planes[0:w], planes[w:2*w], planes[2*w:3*w], planes[3*w:4*w]
		p4, p5, p6, p7 := planes[4*w:5*w], planes[5*w:6*w], planes[6*w:7*w], planes[7*w:8*w]
		for i := 0; i < m; i++ {
			clear(planes)
			blk := sPacked[i*v*d.stride : (i+1)*v*d.stride]
			for r := 0; r < v; r++ {
				vr := uint64(vin[r])
				m0, m1, m2, m3 := -(vr & 1), -(vr >> 1 & 1), -(vr >> 2 & 1), -(vr >> 3 & 1)
				m4, m5, m6, m7 := -(vr >> 4 & 1), -(vr >> 5 & 1), -(vr >> 6 & 1), -(vr >> 7 & 1)
				srow := blk[r*d.stride : (r+1)*d.stride]
				for k := range p0 {
					s := binary.LittleEndian.Uint64(srow[8*k:])
					p0[k] ^= s & m0
					p1[k] ^= s & m1
					p2[k] ^= s & m2
					p3[k] ^= s & m3
					p4[k] ^= s & m4
					p5[k] ^= s & m5
					p6[k] ^= s & m6
					p7[k] ^= s & m7
				}
			}
			hornerPlanes(A[i*wa:i*wa+w], planes)
		}

		// y = t - vᵀ P1 v goes into the augmented column.
		evalBuckets(yw, acc, p1Prep, vin)
		ci, sh := m>>3, uint(8*(m&7))
		for i := 0; i < m; i++ {
			yi := byte(yw[i>>3]>>(8*(i&7))) ^ t[i]
			A[i*wa+ci] |= uint64(yi) << sh
		}

		if !solve(A, m, wa, tab) {
			continue
		}
		for j := 0; j < m; j++ {
			x[j] = byte(A[j*wa+ci] >> sh)
		}
		s := make([]byte, d.n)
		for r := 0; r < v; r++ {
			orow := sk.O[r*m : (r+1)*m]
			sr := vin[r]
			for j, o := range orow {
				sr ^= gfMul(o, x[j])
			}
			s[r] = sr
		}
		copy(s[v:], x)
		return &kmosaic.MQSignature{S: s, Salt: salt}, nil
	}
	return nil, errors.New("uov: no invertible system found")
}

// Evaluate computes P_i(s) for every public form. It uses the interleaved
// Prepared layout when present and the P1/P2/P3 blocks otherwise, and returns
// nil if the parameters, key or input are malformed.
func Evaluate(pk *kmosaic.MQPublicKey, p kmosaic.MQParams, s []byte) []byte {
	d, err := checkParams(p)
	if err != nil || pk == nil || len(s) != d.n {
		return nil
	}
	if len(pk.Prepared) == d.pkPreparedLen() {
		return evaluatePrepared(d, pk.Prepared, s)
	}
	if len(pk.P1) != d.p1Len() || len(pk.P2) != d.p2Len() || len(pk.P3) != d.p3Len() {
		return nil
	}
	return evaluateBasic(d, pk.P1, pk.P2, pk.P3, s)
}

func evaluatePrepared(d dims, prep, s []byte) []byte {
	out := make([]uint64, d.w)
	acc := make([]uint64, 256*d.w)
	evalBuckets(out, acc, prep, s)
	res := make([]byte, d.m)
	unpackBytes(res, out)
	return res
}

// evaluateBasic evaluates the forms block by block, one form at a time.
func evaluateBasic(d dims, P1, P2, P3, s []byte) []byte {
	v, m := d.v, d.m
	out := make([]byte, m)
	for i := 0; i < m; i++ {
		var acc byte
		p1 := P1[i*d.t1 : (i+1)*d.t1]
		idx := 0
		for r := 0; r < v; r++ {
			sr := s[r]
			for c := r; c < v; c++ {
				acc ^= gfMul(p1[idx], gfMul(sr, s[c]))
				idx++
			}
		}
		p2 := P2[i*v*m : (i+1)*v*m]
		for r := 0; r < v; r++ {
			row := p2[r*m : (r+1)*m]
			var inner byte
			for c := 0; c < m; c++ {
				inner ^= gfMul(row[c], s[v+c])
			}
			acc ^= gfMul(s[r], inner)
		}
		p3 := P3[i*d.t3 : (i+1)*d.t3]
		idx = 0
		for r := 0; r < m; r++ {
			sr := s[v+r]
			for c := r; c < m; c++ {
				acc ^= gfMul(p3[idx], gfMul(sr, s[v+c]))
				idx++
			}
		}
		out[i] = acc
	}
	return out
}

// Verify reports whether sig is a valid signature on message under pk.
func Verify(pk *kmosaic.MQPublicKey, p kmosaic.MQParams, message []byte, sig *kmosaic.MQSignature) bool {
	d, err := checkParams(p)
	if err != nil || pk == nil || sig == nil {
		return false
	}
	if len(sig.S) != d.n || len(sig.Salt) != SaltSize {
		return false
	}
	if len(pk.P3) != d.p3Len() || len(pk.P1) != d.p1Len() || len(pk.P2) != d.p2Len() {
		return false
	}
	e := Evaluate(pk, p, sig.S)
	if e == nil {
		return false
	}
	return subtle.ConstantTimeCompare(e, target(message, sig.Salt, d.m)) == 1
}

// SerializePublicKey serializes a compressed public key as [seed:16][P3].
func SerializePublicKey(pk *kmosaic.MQPublicKey) []byte {
	out := make([]byte, 0, PKSeedSize+len(pk.P3))
	out = append(out, pk.Seed...)
	out = append(out, pk.P3...)
	return out
}

// DeserializePublicKey parses a compressed public key, expands P1 and P2
// from its seed and builds the Prepared layout.
func DeserializePublicKey(data []byte, p kmosaic.MQParams) (*kmosaic.MQPublicKey, error) {
	d, err := checkParams(p)
	if err != nil {
		return nil, err
	}
	if len(data) != PKSeedSize+d.p3Len() {
		return nil, errors.New("invalid UOV public key: wrong length")
	}
	pk := &kmosaic.MQPublicKey{
		Seed: append([]byte{}, data[:PKSeedSize]...),
		P3:   append([]byte{}, data[PKSeedSize:]...),
	}
	pk.P1, pk.P2 = expandPublic(pk.Seed, d)
	pk.Prepared = buildPKPrepared(d, pk.P1, pk.P2, pk.P3)
	return pk, nil
}

// SerializeSecretKey serializes a secret key as its 32-byte seed. It returns
// nil if the key's seed is not 32 bytes.
func SerializeSecretKey(sk *kmosaic.MQSecretKey) []byte {
	if len(sk.Seed) != SeedSize {
		return nil
	}
	return append([]byte{}, sk.Seed...)
}

// DeserializeSecretKey re-derives the parts of the secret key that signing
// needs (O, P1, S and the signing layout) from its 32-byte seed. It skips
// the public P3 blocks, which only KeyGen computes.
func DeserializeSecretKey(data []byte, p kmosaic.MQParams) (*kmosaic.MQSecretKey, error) {
	d, err := checkParams(p)
	if err != nil {
		return nil, err
	}
	if len(data) != SeedSize {
		return nil, errors.New("invalid UOV secret key: wrong length")
	}
	k := deriveKey(d, data, false)
	return &kmosaic.MQSecretKey{
		Seed:     append([]byte{}, data...),
		PKSeed:   k.pkSeed,
		O:        k.O,
		P1:       k.P1,
		S:        k.S,
		Prepared: k.skPrep,
	}, nil
}

// SerializeSignature serializes a signature as [s:N][salt:16].
func SerializeSignature(sig *kmosaic.MQSignature) []byte {
	out := make([]byte, 0, len(sig.S)+SaltSize)
	out = append(out, sig.S...)
	out = append(out, sig.Salt...)
	return out
}

// DeserializeSignature parses a signature.
func DeserializeSignature(data []byte, p kmosaic.MQParams) (*kmosaic.MQSignature, error) {
	d, err := checkParams(p)
	if err != nil {
		return nil, err
	}
	if len(data) != d.n+SaltSize {
		return nil, errors.New("invalid UOV signature: wrong length")
	}
	return &kmosaic.MQSignature{
		S:    append([]byte{}, data[:d.n]...),
		Salt: append([]byte{}, data[d.n:]...),
	}, nil
}
