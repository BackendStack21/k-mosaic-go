// Package uov implements the multivariate component of the kMOSAIC signature:
// Unbalanced Oil and Vinegar over F_256, following the UOV NIST submission
// (compressed public keys, expanded secret keys, salted signing).
//
// The public key is a system of M quadratic forms P_i(s) = sᵀ P_i s in N
// variables that all vanish on a secret M-dimensional "oil" subspace spanned
// by the columns of [O; I]. Writing s = (v + O·x, x) with vinegar v and oil x,
// each P_i(s) = vᵀ P1_i v + vᵀ S_i x is linear in x, so the signer fixes v at
// random and solves an M×M linear system for x. Security rests on the MQ
// problem and on hiding the oil subspace (uov-Ip ≈ 2^143, uov-V ≈ 2^272
// classical per the submission's analysis).
package uov

import (
	"errors"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

const (
	DomainKeyGen = "kmosaic-uov-keygen-v3"
	DomainPK     = "kmosaic-uov-pk-v3"
	DomainTarget = "kmosaic-uov-target-v3"
	DomainVin    = "kmosaic-uov-vinegar-v3"

	SeedSize   = 32
	PKSeedSize = 16
	SaltSize   = 16

	maxSignAttempts = 256
)

// Block sizes.
func triSize(d int) int { return d * (d + 1) / 2 }

// triIndex returns the index of entry (r, c), r <= c, in an upper-triangular
// block of dimension d stored row by row.
func triIndex(d, r, c int) int {
	return r*d - r*(r-1)/2 + (c - r)
}

func checkParams(p kmosaic.MQParams) error {
	if p.M <= 0 || p.N <= 2*p.M {
		return errors.New("uov: requires 0 < m and n > 2m")
	}
	return nil
}

// expandPublic derives P1 (M blocks of V(V+1)/2) and P2 (M blocks of V*M) from the public seed.
func expandPublic(pkSeed []byte, p kmosaic.MQParams) (p1, p2 []byte) {
	v, m := p.N-p.M, p.M
	size1 := m * triSize(v)
	size2 := m * v * m
	buf := utils.Shake256WithDomain(DomainPK, pkSeed, size1+size2)
	return buf[:size1], buf[size1:]
}

// KeyGen generates a key pair from a secret seed of at least 32 bytes.
func KeyGen(p kmosaic.MQParams, seed []byte) (*kmosaic.MQKeyPair, error) {
	if len(seed) < SeedSize {
		return nil, errors.New("seed must be at least 32 bytes")
	}
	if err := checkParams(p); err != nil {
		return nil, err
	}
	v, m := p.N-p.M, p.M

	expanded := utils.Shake256WithDomain(DomainKeyGen, seed, PKSeedSize+v*m)
	pkSeed := append([]byte{}, expanded[:PKSeedSize]...)
	O := append([]byte{}, expanded[PKSeedSize:]...) // V x M row-major
	utils.Zeroize(expanded)

	P1, P2 := expandPublic(pkSeed, p)
	P3 := make([]byte, m*triSize(m))
	S := make([]byte, m*v*m)

	for i := 0; i < m; i++ {
		p1 := P1[i*triSize(v) : (i+1)*triSize(v)]
		p2 := P2[i*v*m : (i+1)*v*m]

		// P1O = P1_i · O  (V x M) and P1TO = P1_iᵀ · O (V x M)
		p1o := make([]byte, v*m)
		p1to := make([]byte, v*m)
		for r := 0; r < v; r++ {
			for c := r; c < v; c++ {
				a := p1[triIndex(v, r, c)]
				if a == 0 {
					continue
				}
				oc := O[c*m : (c+1)*m]
				or := O[r*m : (r+1)*m]
				row := p1o[r*m : (r+1)*m]
				rowT := p1to[c*m : (c+1)*m]
				for j := 0; j < m; j++ {
					row[j] ^= gfMul(a, oc[j])
					rowT[j] ^= gfMul(a, or[j])
				}
			}
		}

		// S_i = (P1_i + P1_iᵀ)·O + P2_i
		si := S[i*v*m : (i+1)*v*m]
		for k := 0; k < v*m; k++ {
			si[k] = p1o[k] ^ p1to[k] ^ p2[k]
		}

		// Mi = Oᵀ·(P1_i·O) + Oᵀ·P2_i  (M x M)
		mi := make([]byte, m*m)
		for r := 0; r < v; r++ {
			orow := O[r*m : (r+1)*m]
			p1orow := p1o[r*m : (r+1)*m]
			p2row := p2[r*m : (r+1)*m]
			for a := 0; a < m; a++ {
				oa := orow[a]
				if oa == 0 {
					continue
				}
				mrow := mi[a*m : (a+1)*m]
				for b := 0; b < m; b++ {
					mrow[b] ^= gfMul(oa, p1orow[b]^p2row[b])
				}
			}
		}
		// P3_i = Upper(Mi): the upper-triangular matrix with the same quadratic form.
		p3 := P3[i*triSize(m) : (i+1)*triSize(m)]
		for r := 0; r < m; r++ {
			p3[triIndex(m, r, r)] = mi[r*m+r]
			for c := r + 1; c < m; c++ {
				p3[triIndex(m, r, c)] = mi[r*m+c] ^ mi[c*m+r]
			}
		}
	}

	return &kmosaic.MQKeyPair{
		PublicKey: kmosaic.MQPublicKey{Seed: pkSeed, P3: P3, P1: P1, P2: P2},
		SecretKey: kmosaic.MQSecretKey{Seed: append([]byte{}, seed[:SeedSize]...), PKSeed: pkSeed, O: O, P1: P1, S: S},
	}, nil
}

// target derives the M-byte target vector t = H(message || salt).
func target(message, salt []byte, m int) []byte {
	return utils.Shake256WithDomain(DomainTarget, append(append([]byte{}, message...), salt...), m)
}

// evalP1 computes vᵀ P1_i v for every i.
func evalP1(P1 []byte, vin []byte, v, m int) []byte {
	out := make([]byte, m)
	// precompute products v_r v_c lazily per pair
	for i := 0; i < m; i++ {
		p1 := P1[i*triSize(v) : (i+1)*triSize(v)]
		var acc byte
		idx := 0
		for r := 0; r < v; r++ {
			vr := vin[r]
			if vr == 0 {
				idx += v - r
				continue
			}
			for c := r; c < v; c++ {
				acc ^= gfMul(p1[idx], gfMul(vr, vin[c]))
				idx++
			}
		}
		out[i] = acc
	}
	return out
}

// solve solves the M×M system L·x = y over F_256 by Gaussian elimination.
// It returns false if L is singular.
func solve(L []byte, y []byte, m int) ([]byte, bool) {
	A := append([]byte{}, L...)
	b := append([]byte{}, y...)
	for col := 0; col < m; col++ {
		pivot := -1
		for r := col; r < m; r++ {
			if A[r*m+col] != 0 {
				pivot = r
				break
			}
		}
		if pivot < 0 {
			return nil, false
		}
		if pivot != col {
			for c := 0; c < m; c++ {
				A[col*m+c], A[pivot*m+c] = A[pivot*m+c], A[col*m+c]
			}
			b[col], b[pivot] = b[pivot], b[col]
		}
		inv := gfInv(A[col*m+col])
		for c := 0; c < m; c++ {
			A[col*m+c] = gfMul(A[col*m+c], inv)
		}
		b[col] = gfMul(b[col], inv)
		for r := 0; r < m; r++ {
			if r == col {
				continue
			}
			f := A[r*m+col]
			if f == 0 {
				continue
			}
			for c := 0; c < m; c++ {
				A[r*m+c] ^= gfMul(f, A[col*m+c])
			}
			b[r] ^= gfMul(f, b[col])
		}
	}
	return b, true
}

// Sign produces a UOV signature on message. Signing is salted with fresh
// randomness; the vinegar values are derived from the secret seed, the salt
// and an attempt counter.
func Sign(sk *kmosaic.MQSecretKey, p kmosaic.MQParams, message []byte) (*kmosaic.MQSignature, error) {
	if err := checkParams(p); err != nil {
		return nil, err
	}
	v, m := p.N-p.M, p.M
	if len(sk.O) != v*m || len(sk.P1) != m*triSize(v) || len(sk.S) != m*v*m || len(sk.Seed) < SeedSize {
		return nil, errors.New("uov: malformed secret key")
	}

	salt, err := utils.SecureRandomBytes(SaltSize)
	if err != nil {
		return nil, err
	}
	t := target(message, salt, m)

	for ctr := 0; ctr < maxSignAttempts; ctr++ {
		vin := utils.Shake256WithDomain(DomainVin,
			append(append(append(append([]byte{}, sk.Seed[:SeedSize]...), salt...), t...), byte(ctr)), v)

		// L[i][j] = (vᵀ S_i)[j]
		L := make([]byte, m*m)
		for i := 0; i < m; i++ {
			si := sk.S[i*v*m : (i+1)*v*m]
			row := L[i*m : (i+1)*m]
			for r := 0; r < v; r++ {
				vr := vin[r]
				if vr == 0 {
					continue
				}
				srow := si[r*m : (r+1)*m]
				for j := 0; j < m; j++ {
					row[j] ^= gfMul(vr, srow[j])
				}
			}
		}
		y := evalP1(sk.P1, vin, v, m)
		for i := range y {
			y[i] ^= t[i]
		}
		x, ok := solve(L, y, m)
		if !ok {
			continue
		}
		s := make([]byte, p.N)
		copy(s, vin)
		for r := 0; r < v; r++ {
			orow := sk.O[r*m : (r+1)*m]
			var acc byte
			for j := 0; j < m; j++ {
				acc ^= gfMul(orow[j], x[j])
			}
			s[r] ^= acc
		}
		copy(s[v:], x)
		utils.Zeroize(vin)
		return &kmosaic.MQSignature{S: s, Salt: salt}, nil
	}
	return nil, errors.New("uov: no invertible system found")
}

// Evaluate computes P_i(s) for every public form.
func Evaluate(pk *kmosaic.MQPublicKey, p kmosaic.MQParams, s []byte) []byte {
	v, m := p.N-p.M, p.M
	out := make([]byte, m)
	// products of s entries are shared across forms; compute per block.
	for i := 0; i < m; i++ {
		var acc byte
		p1 := pk.P1[i*triSize(v) : (i+1)*triSize(v)]
		idx := 0
		for r := 0; r < v; r++ {
			sr := s[r]
			if sr == 0 {
				idx += v - r
				continue
			}
			for c := r; c < v; c++ {
				acc ^= gfMul(p1[idx], gfMul(sr, s[c]))
				idx++
			}
		}
		p2 := pk.P2[i*v*m : (i+1)*v*m]
		for r := 0; r < v; r++ {
			sr := s[r]
			if sr == 0 {
				continue
			}
			row := p2[r*m : (r+1)*m]
			var inner byte
			for c := 0; c < m; c++ {
				inner ^= gfMul(row[c], s[v+c])
			}
			acc ^= gfMul(sr, inner)
		}
		p3 := pk.P3[i*triSize(m) : (i+1)*triSize(m)]
		idx = 0
		for r := 0; r < m; r++ {
			sr := s[v+r]
			if sr == 0 {
				idx += m - r
				continue
			}
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
	if err := checkParams(p); err != nil || pk == nil || sig == nil {
		return false
	}
	v, m := p.N-p.M, p.M
	if len(sig.S) != p.N || len(sig.Salt) != SaltSize {
		return false
	}
	if len(pk.P3) != m*triSize(m) || len(pk.P1) != m*triSize(v) || len(pk.P2) != m*v*m {
		return false
	}
	t := target(message, sig.Salt, m)
	return utils.ConstantTimeEqual(Evaluate(pk, p, sig.S), t)
}

// SerializePublicKey serializes a compressed public key as [seed:16][P3].
func SerializePublicKey(pk *kmosaic.MQPublicKey) []byte {
	out := make([]byte, 0, PKSeedSize+len(pk.P3))
	out = append(out, pk.Seed...)
	out = append(out, pk.P3...)
	return out
}

// DeserializePublicKey parses a compressed public key and expands P1, P2.
func DeserializePublicKey(data []byte, p kmosaic.MQParams) (*kmosaic.MQPublicKey, error) {
	if err := checkParams(p); err != nil {
		return nil, err
	}
	size3 := p.M * triSize(p.M)
	if len(data) != PKSeedSize+size3 {
		return nil, errors.New("invalid UOV public key: wrong length")
	}
	pk := &kmosaic.MQPublicKey{
		Seed: append([]byte{}, data[:PKSeedSize]...),
		P3:   append([]byte{}, data[PKSeedSize:]...),
	}
	pk.P1, pk.P2 = expandPublic(pk.Seed, p)
	return pk, nil
}

// SerializeSecretKey serializes a secret key as its 32-byte seed.
func SerializeSecretKey(sk *kmosaic.MQSecretKey) []byte {
	return append([]byte{}, sk.Seed[:SeedSize]...)
}

// DeserializeSecretKey regenerates the expanded secret key from its seed.
func DeserializeSecretKey(data []byte, p kmosaic.MQParams) (*kmosaic.MQSecretKey, error) {
	if len(data) != SeedSize {
		return nil, errors.New("invalid UOV secret key: wrong length")
	}
	kp, err := KeyGen(p, data)
	if err != nil {
		return nil, err
	}
	return &kp.SecretKey, nil
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
	if len(data) != p.N+SaltSize {
		return nil, errors.New("invalid UOV signature: wrong length")
	}
	return &kmosaic.MQSignature{
		S:    append([]byte{}, data[:p.N]...),
		Salt: append([]byte{}, data[p.N:]...),
	}, nil
}
