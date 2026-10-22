package slhdsa

// Reference implementation: a verbatim copy of the v3 slhdsa.go with its
// identifiers renamed and the x/crypto SHAKE256 replaced by the identical
// crypto/sha3 one. It is used only to check that the optimized code produces
// byte-identical keys and signatures; FIPS 205 conformance itself is
// enforced by acvp_test.go against NIST ACVP vectors.

import (
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"sync"

	kmosaic "github.com/BackendStack21/k-mosaic-go/v4"
	"github.com/BackendStack21/k-mosaic-go/v4/utils"
)

var refShakePool = sync.Pool{New: func() interface{} { return sha3.NewSHAKE256() }}

func refShake(out []byte, parts ...[]byte) {
	h := refShakePool.Get().(*sha3.SHAKE)
	h.Reset()
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	_, _ = h.Read(out)
	refShakePool.Put(h)
}

// refParams bundles the parameter set with derived quantities.
type refParams struct {
	kmosaic.HashSignParams
	hp   int // h / d: height of each XMSS tree
	w    int // Winternitz parameter
	len1 int
	len2 int
	wlen int // len1 + len2
}

func refNewParams(p kmosaic.HashSignParams) (*refParams, error) {
	if p.N <= 0 || p.D <= 0 || p.H <= 0 || p.H%p.D != 0 || p.LgW != 4 || p.A <= 0 || p.K <= 0 {
		return nil, errors.New("slhdsa: invalid parameters")
	}
	ps := &refParams{HashSignParams: p, hp: p.H / p.D, w: 1 << p.LgW}
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

// ---------------------------------------------------------------------------
// Addresses (FIPS 205 §4.2)
// ---------------------------------------------------------------------------

type refAdrs [32]byte

func (a *refAdrs) setLayer(l uint32) { binary.BigEndian.PutUint32(a[0:4], l) }
func (a *refAdrs) setTree(t uint64) {
	binary.BigEndian.PutUint32(a[4:8], 0)
	binary.BigEndian.PutUint64(a[8:16], t)
}
func (a *refAdrs) setType(t uint32) {
	binary.BigEndian.PutUint32(a[16:20], t)
	copy(a[20:32], make([]byte, 12))
}
func (a *refAdrs) setKeyPair(i uint32)    { binary.BigEndian.PutUint32(a[20:24], i) }
func (a *refAdrs) setChain(i uint32)      { binary.BigEndian.PutUint32(a[24:28], i) }
func (a *refAdrs) setHash(i uint32)       { binary.BigEndian.PutUint32(a[28:32], i) }
func (a *refAdrs) setTreeHeight(i uint32) { binary.BigEndian.PutUint32(a[24:28], i) }
func (a *refAdrs) setTreeIndex(i uint32)  { binary.BigEndian.PutUint32(a[28:32], i) }
func (a *refAdrs) keyPair() uint32        { return binary.BigEndian.Uint32(a[20:24]) }
func (a *refAdrs) treeIndex() uint32      { return binary.BigEndian.Uint32(a[28:32]) }

// ---------------------------------------------------------------------------
// Tweakable hash functions (SHAKE256 instantiation, §11.1)
// ---------------------------------------------------------------------------

func (ps *refParams) prf(pkSeed, skSeed []byte, a *refAdrs) []byte {
	out := make([]byte, ps.N)
	refShake(out, pkSeed, a[:], skSeed)
	return out
}

func (ps *refParams) f(pkSeed []byte, a *refAdrs, m []byte) []byte {
	out := make([]byte, ps.N)
	refShake(out, pkSeed, a[:], m)
	return out
}

func (ps *refParams) h2(pkSeed []byte, a *refAdrs, m1, m2 []byte) []byte {
	out := make([]byte, ps.N)
	refShake(out, pkSeed, a[:], m1, m2)
	return out
}

func (ps *refParams) tl(pkSeed []byte, a *refAdrs, m []byte) []byte {
	out := make([]byte, ps.N)
	refShake(out, pkSeed, a[:], m)
	return out
}

func (ps *refParams) prfMsg(skPRF, optRand, msg []byte) []byte {
	out := make([]byte, ps.N)
	refShake(out, skPRF, optRand, msg)
	return out
}

func (ps *refParams) hMsg(r, pkSeed, pkRoot, msg []byte) []byte {
	out := make([]byte, ps.M)
	refShake(out, r, pkSeed, pkRoot, msg)
	return out
}

// ---------------------------------------------------------------------------
// base_2b (§4.4)
// ---------------------------------------------------------------------------

func refBase2b(x []byte, b int, outLen int) []uint32 {
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

func (ps *refParams) chain(x []byte, i, s int, pkSeed []byte, a *refAdrs) []byte {
	tmp := append([]byte{}, x...)
	for j := i; j < i+s; j++ {
		a.setHash(uint32(j))
		tmp = ps.f(pkSeed, a, tmp)
	}
	return tmp
}

func (ps *refParams) wotsPKGen(skSeed, pkSeed []byte, a *refAdrs) []byte {
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
func (ps *refParams) wotsDigits(m []byte) []uint32 {
	msg := refBase2b(m, ps.LgW, ps.len1)
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
	return append(msg, refBase2b(cb, ps.LgW, ps.len2)...)
}

func (ps *refParams) wotsSign(m, skSeed, pkSeed []byte, a *refAdrs) []byte {
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

func (ps *refParams) wotsPKFromSig(sig, m, pkSeed []byte, a *refAdrs) []byte {
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

func (ps *refParams) xmssNode(skSeed []byte, i, z uint32, pkSeed []byte, a *refAdrs) []byte {
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

func (ps *refParams) xmssSign(m, skSeed []byte, idx uint32, pkSeed []byte, a *refAdrs) []byte {
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

func (ps *refParams) xmssPKFromSig(idx uint32, sig, m, pkSeed []byte, a *refAdrs) []byte {
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

func (ps *refParams) htSign(m, skSeed, pkSeed []byte, idxTree uint64, idxLeaf uint32) []byte {
	var a refAdrs
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

func (ps *refParams) htVerify(m, sig, pkSeed []byte, idxTree uint64, idxLeaf uint32, pkRoot []byte) bool {
	var a refAdrs
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

func (ps *refParams) forsSKGen(skSeed, pkSeed []byte, a *refAdrs, idx uint32) []byte {
	skAdrs := *a
	skAdrs.setType(adrsFORSPRF)
	skAdrs.setKeyPair(a.keyPair())
	skAdrs.setTreeIndex(idx)
	return ps.prf(pkSeed, skSeed, &skAdrs)
}

func (ps *refParams) forsNode(skSeed []byte, i, z uint32, pkSeed []byte, a *refAdrs) []byte {
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

func (ps *refParams) forsSign(md, skSeed, pkSeed []byte, a *refAdrs) []byte {
	indices := refBase2b(md, ps.A, ps.K)
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

func (ps *refParams) forsPKFromSig(sig, md, pkSeed []byte, a *refAdrs) []byte {
	indices := refBase2b(md, ps.A, ps.K)
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

// splitDigest parses the message digest into md, idx_tree and idx_leaf.
func (ps *refParams) splitDigest(digest []byte) (md []byte, idxTree uint64, idxLeaf uint32) {
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

// refSignInternal is slh_sign_internal of the v3 code with a caller-chosen optRand.
func refSignInternal(sk *kmosaic.HashSignSecretKey, ps *refParams, message, optRand []byte) []byte {
	r := ps.prfMsg(sk.PRF, optRand, message)
	digest := ps.hMsg(r, sk.PKSeed, sk.PKRoot, message)
	md, idxTree, idxLeaf := ps.splitDigest(digest)

	var a refAdrs
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
	return out
}

// refVerifyInternal is slh_verify_internal of the v3 code.
func refVerifyInternal(pk *kmosaic.HashSignPublicKey, ps *refParams, message, sig []byte) bool {
	if len(sig) != ps.N+ps.K*(ps.A+1)*ps.N+ps.D*(ps.wlen+ps.hp)*ps.N {
		return false
	}
	r := sig[:ps.N]
	forsLen := ps.K * (ps.A + 1) * ps.N
	forsSig := sig[ps.N : ps.N+forsLen]
	htSig := sig[ps.N+forsLen:]
	digest := ps.hMsg(r, pk.Seed, pk.Root, message)
	md, idxTree, idxLeaf := ps.splitDigest(digest)
	var a refAdrs
	a.setTree(idxTree)
	a.setType(adrsFORSTree)
	a.setKeyPair(idxLeaf)
	forsPK := ps.forsPKFromSig(forsSig, md, pk.Seed, &a)
	return ps.htVerify(forsPK, htSig, pk.Seed, idxTree, idxLeaf, pk.Root)
}

// refRoot is the v3 key-generation root computation for the given seeds.
func refRoot(ps *refParams, skSeed, pkSeed []byte) []byte {
	var a refAdrs
	a.setLayer(uint32(ps.D - 1))
	return ps.xmssNode(skSeed, 0, uint32(ps.hp), pkSeed, &a)
}
