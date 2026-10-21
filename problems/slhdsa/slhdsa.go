// Package slhdsa implements the hash-based component of the kMOSAIC
// signature: the stateless hash-based signature SLH-DSA (FIPS 205, the
// standardized SPHINCS+) with SHAKE256, "simple" tweakable hashes.
//
// Its security rests only on the (second-)preimage resistance of SHAKE256,
// making it independent of every algebraic assumption in the library.
package slhdsa

import (
	"encoding/binary"
	"errors"
	"sync"

	"golang.org/x/crypto/sha3"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

const (
	DomainKeyGen = "kmosaic-slhdsa-keygen-v3"

	adrsWOTSHash  = 0
	adrsWOTSPK    = 1
	adrsTree      = 2
	adrsFORSTree  = 3
	adrsFORSRoots = 4
	adrsWOTSPRF   = 5
	adrsFORSPRF   = 6
)

var shakePool = sync.Pool{New: func() interface{} { return sha3.NewShake256() }}

func shake(out []byte, parts ...[]byte) {
	h := shakePool.Get().(sha3.ShakeHash)
	h.Reset()
	for _, p := range parts {
		h.Write(p)
	}
	_, _ = h.Read(out)
	shakePool.Put(h)
}

// params bundles the parameter set with derived quantities.
type params struct {
	kmosaic.HashSignParams
	hp   int // h / d: height of each XMSS tree
	w    int // Winternitz parameter
	len1 int
	len2 int
	wlen int // len1 + len2
}

func newParams(p kmosaic.HashSignParams) (*params, error) {
	if p.N <= 0 || p.D <= 0 || p.H <= 0 || p.H%p.D != 0 || p.LgW != 4 || p.A <= 0 || p.K <= 0 {
		return nil, errors.New("slhdsa: invalid parameters")
	}
	ps := &params{HashSignParams: p, hp: p.H / p.D, w: 1 << p.LgW}
	ps.len1 = (8*p.N + p.LgW - 1) / p.LgW
	// len2 = floor(log2(len1*(w-1)) / lg_w) + 1
	x := ps.len1 * (ps.w - 1)
	lg := 0
	for x > 1 {
		x >>= 1
		lg++
	}
	ps.len2 = lg/p.LgW + 1
	ps.wlen = ps.len1 + ps.len2
	if ps.hp > 32 || p.H-ps.hp > 64 {
		return nil, errors.New("slhdsa: tree indices too large")
	}
	expectedM := (p.K*p.A+7)/8 + (p.H-ps.hp+7)/8 + (ps.hp+7)/8
	if p.M != expectedM {
		return nil, errors.New("slhdsa: m does not match the other parameters")
	}
	return ps, nil
}

// SignatureSize returns the signature length in bytes.
func SignatureSize(p kmosaic.HashSignParams) int {
	ps, err := newParams(p)
	if err != nil {
		return 0
	}
	return ps.N + ps.K*(ps.A+1)*ps.N + ps.D*(ps.wlen+ps.hp)*ps.N
}

// ---------------------------------------------------------------------------
// Addresses (FIPS 205 §4.2)
// ---------------------------------------------------------------------------

type adrs [32]byte

func (a *adrs) setLayer(l uint32) { binary.BigEndian.PutUint32(a[0:4], l) }
func (a *adrs) setTree(t uint64) {
	binary.BigEndian.PutUint32(a[4:8], 0)
	binary.BigEndian.PutUint64(a[8:16], t)
}
func (a *adrs) setType(t uint32) {
	binary.BigEndian.PutUint32(a[16:20], t)
	copy(a[20:32], make([]byte, 12))
}
func (a *adrs) setKeyPair(i uint32)    { binary.BigEndian.PutUint32(a[20:24], i) }
func (a *adrs) setChain(i uint32)      { binary.BigEndian.PutUint32(a[24:28], i) }
func (a *adrs) setHash(i uint32)       { binary.BigEndian.PutUint32(a[28:32], i) }
func (a *adrs) setTreeHeight(i uint32) { binary.BigEndian.PutUint32(a[24:28], i) }
func (a *adrs) setTreeIndex(i uint32)  { binary.BigEndian.PutUint32(a[28:32], i) }
func (a *adrs) keyPair() uint32        { return binary.BigEndian.Uint32(a[20:24]) }
func (a *adrs) treeIndex() uint32      { return binary.BigEndian.Uint32(a[28:32]) }

// ---------------------------------------------------------------------------
// Tweakable hash functions (SHAKE256 instantiation, §11.1)
// ---------------------------------------------------------------------------

func (ps *params) prf(pkSeed, skSeed []byte, a *adrs) []byte {
	out := make([]byte, ps.N)
	shake(out, pkSeed, a[:], skSeed)
	return out
}

func (ps *params) f(pkSeed []byte, a *adrs, m []byte) []byte {
	out := make([]byte, ps.N)
	shake(out, pkSeed, a[:], m)
	return out
}

func (ps *params) h2(pkSeed []byte, a *adrs, m1, m2 []byte) []byte {
	out := make([]byte, ps.N)
	shake(out, pkSeed, a[:], m1, m2)
	return out
}

func (ps *params) tl(pkSeed []byte, a *adrs, m []byte) []byte {
	out := make([]byte, ps.N)
	shake(out, pkSeed, a[:], m)
	return out
}

func (ps *params) prfMsg(skPRF, optRand, msg []byte) []byte {
	out := make([]byte, ps.N)
	shake(out, skPRF, optRand, msg)
	return out
}

func (ps *params) hMsg(r, pkSeed, pkRoot, msg []byte) []byte {
	out := make([]byte, ps.M)
	shake(out, r, pkSeed, pkRoot, msg)
	return out
}

// ---------------------------------------------------------------------------
// base_2b (§4.4)
// ---------------------------------------------------------------------------

func base2b(x []byte, b int, outLen int) []uint32 {
	out := make([]uint32, outLen)
	in := 0
	bits := 0
	var total uint64
	for i := 0; i < outLen; i++ {
		for bits < b {
			total = total<<8 | uint64(x[in])
			in++
			bits += 8
		}
		bits -= b
		out[i] = uint32(total>>uint(bits)) & ((1 << uint(b)) - 1)
	}
	return out
}

// ---------------------------------------------------------------------------
// WOTS+ (§5)
// ---------------------------------------------------------------------------

func (ps *params) chain(x []byte, i, s int, pkSeed []byte, a *adrs) []byte {
	tmp := append([]byte{}, x...)
	for j := i; j < i+s; j++ {
		a.setHash(uint32(j))
		tmp = ps.f(pkSeed, a, tmp)
	}
	return tmp
}

func (ps *params) wotsPKGen(skSeed, pkSeed []byte, a *adrs) []byte {
	skAdrs := *a
	skAdrs.setType(adrsWOTSPRF)
	skAdrs.setKeyPair(a.keyPair())
	tmp := make([]byte, 0, ps.wlen*ps.N)
	for i := 0; i < ps.wlen; i++ {
		skAdrs.setChain(uint32(i))
		sk := ps.prf(pkSeed, skSeed, &skAdrs)
		a.setChain(uint32(i))
		tmp = append(tmp, ps.chain(sk, 0, ps.w-1, pkSeed, a)...)
	}
	pkAdrs := *a
	pkAdrs.setType(adrsWOTSPK)
	pkAdrs.setKeyPair(a.keyPair())
	return ps.tl(pkSeed, &pkAdrs, tmp)
}

// wotsDigits returns the len1 message digits plus the len2 checksum digits.
func (ps *params) wotsDigits(m []byte) []uint32 {
	msg := base2b(m, ps.LgW, ps.len1)
	csum := 0
	for _, d := range msg {
		csum += ps.w - 1 - int(d)
	}
	csum <<= uint((8 - (ps.len2*ps.LgW)%8) % 8)
	csumBytes := (ps.len2*ps.LgW + 7) / 8
	cb := make([]byte, csumBytes)
	for i := csumBytes - 1; i >= 0; i-- {
		cb[i] = byte(csum)
		csum >>= 8
	}
	return append(msg, base2b(cb, ps.LgW, ps.len2)...)
}

func (ps *params) wotsSign(m, skSeed, pkSeed []byte, a *adrs) []byte {
	digits := ps.wotsDigits(m)
	skAdrs := *a
	skAdrs.setType(adrsWOTSPRF)
	skAdrs.setKeyPair(a.keyPair())
	sig := make([]byte, 0, ps.wlen*ps.N)
	for i := 0; i < ps.wlen; i++ {
		skAdrs.setChain(uint32(i))
		sk := ps.prf(pkSeed, skSeed, &skAdrs)
		a.setChain(uint32(i))
		sig = append(sig, ps.chain(sk, 0, int(digits[i]), pkSeed, a)...)
	}
	return sig
}

func (ps *params) wotsPKFromSig(sig, m, pkSeed []byte, a *adrs) []byte {
	digits := ps.wotsDigits(m)
	tmp := make([]byte, 0, ps.wlen*ps.N)
	for i := 0; i < ps.wlen; i++ {
		a.setChain(uint32(i))
		tmp = append(tmp, ps.chain(sig[i*ps.N:(i+1)*ps.N], int(digits[i]), ps.w-1-int(digits[i]), pkSeed, a)...)
	}
	pkAdrs := *a
	pkAdrs.setType(adrsWOTSPK)
	pkAdrs.setKeyPair(a.keyPair())
	return ps.tl(pkSeed, &pkAdrs, tmp)
}

// ---------------------------------------------------------------------------
// XMSS (§6)
// ---------------------------------------------------------------------------

func (ps *params) xmssNode(skSeed []byte, i, z uint32, pkSeed []byte, a *adrs) []byte {
	if z == 0 {
		a.setType(adrsWOTSHash)
		a.setKeyPair(i)
		return ps.wotsPKGen(skSeed, pkSeed, a)
	}
	l := ps.xmssNode(skSeed, 2*i, z-1, pkSeed, a)
	r := ps.xmssNode(skSeed, 2*i+1, z-1, pkSeed, a)
	a.setType(adrsTree)
	a.setTreeHeight(z)
	a.setTreeIndex(i)
	return ps.h2(pkSeed, a, l, r)
}

func (ps *params) xmssSign(m, skSeed []byte, idx uint32, pkSeed []byte, a *adrs) []byte {
	auth := make([]byte, 0, ps.hp*ps.N)
	for j := 0; j < ps.hp; j++ {
		k := (idx >> uint(j)) ^ 1
		auth = append(auth, ps.xmssNode(skSeed, k, uint32(j), pkSeed, a)...)
	}
	a.setType(adrsWOTSHash)
	a.setKeyPair(idx)
	sig := ps.wotsSign(m, skSeed, pkSeed, a)
	return append(sig, auth...)
}

func (ps *params) xmssPKFromSig(idx uint32, sig, m, pkSeed []byte, a *adrs) []byte {
	a.setType(adrsWOTSHash)
	a.setKeyPair(idx)
	wsig := sig[:ps.wlen*ps.N]
	auth := sig[ps.wlen*ps.N:]
	node := ps.wotsPKFromSig(wsig, m, pkSeed, a)
	a.setType(adrsTree)
	a.setTreeIndex(idx)
	for k := 0; k < ps.hp; k++ {
		a.setTreeHeight(uint32(k + 1))
		ak := auth[k*ps.N : (k+1)*ps.N]
		if (idx>>uint(k))&1 == 0 {
			a.setTreeIndex(a.treeIndex() / 2)
			node = ps.h2(pkSeed, a, node, ak)
		} else {
			a.setTreeIndex((a.treeIndex() - 1) / 2)
			node = ps.h2(pkSeed, a, ak, node)
		}
	}
	return node
}

// ---------------------------------------------------------------------------
// Hypertree (§7)
// ---------------------------------------------------------------------------

func (ps *params) htSign(m, skSeed, pkSeed []byte, idxTree uint64, idxLeaf uint32) []byte {
	var a adrs
	a.setLayer(0)
	a.setTree(idxTree)
	sig := ps.xmssSign(m, skSeed, idxLeaf, pkSeed, &a)
	root := ps.xmssPKFromSig(idxLeaf, sig, m, pkSeed, &a)
	out := append([]byte{}, sig...)
	mask := uint64(1)<<uint(ps.hp) - 1
	for j := 1; j < ps.D; j++ {
		idxLeaf = uint32(idxTree & mask)
		idxTree >>= uint(ps.hp)
		a.setLayer(uint32(j))
		a.setTree(idxTree)
		sig = ps.xmssSign(root, skSeed, idxLeaf, pkSeed, &a)
		out = append(out, sig...)
		if j < ps.D-1 {
			root = ps.xmssPKFromSig(idxLeaf, sig, root, pkSeed, &a)
		}
	}
	return out
}

func (ps *params) htVerify(m, sig, pkSeed []byte, idxTree uint64, idxLeaf uint32, pkRoot []byte) bool {
	var a adrs
	a.setLayer(0)
	a.setTree(idxTree)
	xsz := (ps.wlen + ps.hp) * ps.N
	node := ps.xmssPKFromSig(idxLeaf, sig[:xsz], m, pkSeed, &a)
	mask := uint64(1)<<uint(ps.hp) - 1
	for j := 1; j < ps.D; j++ {
		idxLeaf = uint32(idxTree & mask)
		idxTree >>= uint(ps.hp)
		a.setLayer(uint32(j))
		a.setTree(idxTree)
		node = ps.xmssPKFromSig(idxLeaf, sig[j*xsz:(j+1)*xsz], node, pkSeed, &a)
	}
	return utils.ConstantTimeEqual(node, pkRoot)
}

// ---------------------------------------------------------------------------
// FORS (§8)
// ---------------------------------------------------------------------------

func (ps *params) forsSKGen(skSeed, pkSeed []byte, a *adrs, idx uint32) []byte {
	skAdrs := *a
	skAdrs.setType(adrsFORSPRF)
	skAdrs.setKeyPair(a.keyPair())
	skAdrs.setTreeIndex(idx)
	return ps.prf(pkSeed, skSeed, &skAdrs)
}

func (ps *params) forsNode(skSeed []byte, i, z uint32, pkSeed []byte, a *adrs) []byte {
	if z == 0 {
		sk := ps.forsSKGen(skSeed, pkSeed, a, i)
		a.setTreeHeight(0)
		a.setTreeIndex(i)
		return ps.f(pkSeed, a, sk)
	}
	l := ps.forsNode(skSeed, 2*i, z-1, pkSeed, a)
	r := ps.forsNode(skSeed, 2*i+1, z-1, pkSeed, a)
	a.setTreeHeight(z)
	a.setTreeIndex(i)
	return ps.h2(pkSeed, a, l, r)
}

func (ps *params) forsSign(md, skSeed, pkSeed []byte, a *adrs) []byte {
	indices := base2b(md, ps.A, ps.K)
	sig := make([]byte, 0, ps.K*(ps.A+1)*ps.N)
	for i := 0; i < ps.K; i++ {
		sig = append(sig, ps.forsSKGen(skSeed, pkSeed, a, uint32(i)<<uint(ps.A)+indices[i])...)
		for j := 0; j < ps.A; j++ {
			s := (indices[i] >> uint(j)) ^ 1
			sig = append(sig, ps.forsNode(skSeed, uint32(i)<<uint(ps.A-j)+s, uint32(j), pkSeed, a)...)
		}
	}
	return sig
}

func (ps *params) forsPKFromSig(sig, md, pkSeed []byte, a *adrs) []byte {
	indices := base2b(md, ps.A, ps.K)
	roots := make([]byte, 0, ps.K*ps.N)
	blk := (ps.A + 1) * ps.N
	for i := 0; i < ps.K; i++ {
		sk := sig[i*blk : i*blk+ps.N]
		auth := sig[i*blk+ps.N : (i+1)*blk]
		a.setTreeHeight(0)
		a.setTreeIndex(uint32(i)<<uint(ps.A) + indices[i])
		node := ps.f(pkSeed, a, sk)
		for j := 0; j < ps.A; j++ {
			a.setTreeHeight(uint32(j + 1))
			aj := auth[j*ps.N : (j+1)*ps.N]
			if (indices[i]>>uint(j))&1 == 0 {
				a.setTreeIndex(a.treeIndex() / 2)
				node = ps.h2(pkSeed, a, node, aj)
			} else {
				a.setTreeIndex((a.treeIndex() - 1) / 2)
				node = ps.h2(pkSeed, a, aj, node)
			}
		}
		roots = append(roots, node...)
	}
	pkAdrs := *a
	pkAdrs.setType(adrsFORSRoots)
	pkAdrs.setKeyPair(a.keyPair())
	return ps.tl(pkSeed, &pkAdrs, roots)
}

// ---------------------------------------------------------------------------
// SLH-DSA (§9, §10)
// ---------------------------------------------------------------------------

// KeyGen derives a key pair from a secret seed of at least 32 bytes.
func KeyGen(p kmosaic.HashSignParams, seed []byte) (*kmosaic.HashSignKeyPair, error) {
	if len(seed) < 32 {
		return nil, errors.New("seed must be at least 32 bytes")
	}
	ps, err := newParams(p)
	if err != nil {
		return nil, err
	}
	expanded := utils.Shake256WithDomain(DomainKeyGen, seed, 3*ps.N)
	skSeed := append([]byte{}, expanded[:ps.N]...)
	skPRF := append([]byte{}, expanded[ps.N:2*ps.N]...)
	pkSeed := append([]byte{}, expanded[2*ps.N:]...)
	utils.Zeroize(expanded)

	var a adrs
	a.setLayer(uint32(ps.D - 1))
	root := ps.xmssNode(skSeed, 0, uint32(ps.hp), pkSeed, &a)

	return &kmosaic.HashSignKeyPair{
		PublicKey: kmosaic.HashSignPublicKey{Seed: pkSeed, Root: root},
		SecretKey: kmosaic.HashSignSecretKey{Seed: skSeed, PRF: skPRF, PKSeed: append([]byte{}, pkSeed...), PKRoot: append([]byte{}, root...)},
	}, nil
}

// splitDigest parses the message digest into md, idx_tree and idx_leaf.
func (ps *params) splitDigest(digest []byte) (md []byte, idxTree uint64, idxLeaf uint32) {
	mdLen := (ps.K*ps.A + 7) / 8
	treeLen := (ps.H - ps.hp + 7) / 8
	leafLen := (ps.hp + 7) / 8
	md = digest[:mdLen]
	for _, b := range digest[mdLen : mdLen+treeLen] {
		idxTree = idxTree<<8 | uint64(b)
	}
	if ps.H-ps.hp < 64 {
		idxTree &= uint64(1)<<uint(ps.H-ps.hp) - 1
	}
	for _, b := range digest[mdLen+treeLen : mdLen+treeLen+leafLen] {
		idxLeaf = idxLeaf<<8 | uint32(b)
	}
	idxLeaf &= uint32(1)<<uint(ps.hp) - 1
	return
}

// Sign produces a signature on message. Signing is randomized (hedged): a
// fresh random value is mixed into the FORS index derivation.
func Sign(sk *kmosaic.HashSignSecretKey, p kmosaic.HashSignParams, message []byte) (*kmosaic.HashSignature, error) {
	ps, err := newParams(p)
	if err != nil {
		return nil, err
	}
	if len(sk.Seed) != ps.N || len(sk.PRF) != ps.N || len(sk.PKSeed) != ps.N || len(sk.PKRoot) != ps.N {
		return nil, errors.New("slhdsa: malformed secret key")
	}
	optRand, err := utils.SecureRandomBytes(ps.N)
	if err != nil {
		return nil, err
	}
	r := ps.prfMsg(sk.PRF, optRand, message)
	digest := ps.hMsg(r, sk.PKSeed, sk.PKRoot, message)
	md, idxTree, idxLeaf := ps.splitDigest(digest)

	var a adrs
	a.setTree(idxTree)
	a.setType(adrsFORSTree)
	a.setKeyPair(idxLeaf)
	forsSig := ps.forsSign(md, sk.Seed, sk.PKSeed, &a)
	forsPK := ps.forsPKFromSig(forsSig, md, sk.PKSeed, &a)
	htSig := ps.htSign(forsPK, sk.Seed, sk.PKSeed, idxTree, idxLeaf)

	out := make([]byte, 0, ps.N+len(forsSig)+len(htSig))
	out = append(out, r...)
	out = append(out, forsSig...)
	out = append(out, htSig...)
	return &kmosaic.HashSignature{Data: out}, nil
}

// Verify reports whether sig is a valid signature on message under pk.
func Verify(pk *kmosaic.HashSignPublicKey, p kmosaic.HashSignParams, message []byte, sig *kmosaic.HashSignature) bool {
	ps, err := newParams(p)
	if err != nil || pk == nil || sig == nil {
		return false
	}
	if len(pk.Seed) != ps.N || len(pk.Root) != ps.N || len(sig.Data) != SignatureSize(p) {
		return false
	}
	r := sig.Data[:ps.N]
	forsLen := ps.K * (ps.A + 1) * ps.N
	forsSig := sig.Data[ps.N : ps.N+forsLen]
	htSig := sig.Data[ps.N+forsLen:]

	digest := ps.hMsg(r, pk.Seed, pk.Root, message)
	md, idxTree, idxLeaf := ps.splitDigest(digest)

	var a adrs
	a.setTree(idxTree)
	a.setType(adrsFORSTree)
	a.setKeyPair(idxLeaf)
	forsPK := ps.forsPKFromSig(forsSig, md, pk.Seed, &a)
	return ps.htVerify(forsPK, htSig, pk.Seed, idxTree, idxLeaf, pk.Root)
}

// SerializePublicKey serializes a public key as [seed:N][root:N].
func SerializePublicKey(pk *kmosaic.HashSignPublicKey) []byte {
	return append(append([]byte{}, pk.Seed...), pk.Root...)
}

// DeserializePublicKey parses a public key.
func DeserializePublicKey(data []byte, p kmosaic.HashSignParams) (*kmosaic.HashSignPublicKey, error) {
	if len(data) != 2*p.N {
		return nil, errors.New("invalid SLH-DSA public key: wrong length")
	}
	return &kmosaic.HashSignPublicKey{Seed: append([]byte{}, data[:p.N]...), Root: append([]byte{}, data[p.N:]...)}, nil
}

// SerializeSecretKey serializes a secret key as [sk.seed][sk.prf][pk.seed][pk.root].
func SerializeSecretKey(sk *kmosaic.HashSignSecretKey) []byte {
	out := make([]byte, 0, 4*len(sk.Seed))
	out = append(out, sk.Seed...)
	out = append(out, sk.PRF...)
	out = append(out, sk.PKSeed...)
	out = append(out, sk.PKRoot...)
	return out
}

// DeserializeSecretKey parses a secret key.
func DeserializeSecretKey(data []byte, p kmosaic.HashSignParams) (*kmosaic.HashSignSecretKey, error) {
	if len(data) != 4*p.N {
		return nil, errors.New("invalid SLH-DSA secret key: wrong length")
	}
	n := p.N
	return &kmosaic.HashSignSecretKey{
		Seed:   append([]byte{}, data[:n]...),
		PRF:    append([]byte{}, data[n:2*n]...),
		PKSeed: append([]byte{}, data[2*n:3*n]...),
		PKRoot: append([]byte{}, data[3*n:]...),
	}, nil
}
