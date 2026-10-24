// Package slhdsa implements the hash-based component of the kMOSAIC
// signature: the stateless hash-based signature SLH-DSA (FIPS 205, the
// standardized SPHINCS+) with SHAKE256, "simple" tweakable hashes.
//
// Its security rests only on properties of SHAKE256 (preimage and
// second-preimage resistance, PRF security of the keyed uses and
// target-subset resilience of the FORS layer), making it independent of
// every algebraic assumption in the library. The implementation is checked
// bit-exactly against NIST ACVP vectors in acvp_test.go.
//
// Sign and Verify use the FIPS 205 "pure" external interface (Algorithms 22
// and 24) with the context string "kmosaic-v4": the message actually signed
// by slh_sign_internal is M' = 0x00 || len(ctx) || ctx || M. A standard
// SLH-DSA-SHAKE-128f/256f verifier given that context accepts the signatures.
//
// Signing computes the d hypertree layers and the k FORS trees concurrently
// on up to runtime.GOMAXPROCS(0) goroutines; the output is identical to the
// sequential FIPS 205 algorithm. Verification is single-threaded and does
// not allocate in steady state.
package slhdsa

import (
	"crypto/sha3"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"

	kmosaic "github.com/BackendStack21/k-mosaic-go/v2"
	"github.com/BackendStack21/k-mosaic-go/v2/utils"
)

const (
	// DomainKeyGen separates the expansion of the key-generation seed.
	DomainKeyGen = "kmosaic-slhdsa-keygen-v4"

	// signContext is the FIPS 205 context string of the pure interface.
	signContext = "kmosaic-v4"

	adrsWOTSHash  = 0
	adrsWOTSPK    = 1
	adrsTree      = 2
	adrsFORSTree  = 3
	adrsFORSRoots = 4
	adrsWOTSPRF   = 5
	adrsFORSPRF   = 6

	maxN = 32
)

// purePrefix is 0x00 || len(ctx) || ctx (FIPS 205 Algorithm 22, line 8).
var purePrefix = append([]byte{0x00, byte(len(signContext))}, signContext...)

// params bundles the parameter set with derived quantities.
type params struct {
	kmosaic.HashSignParams
	hp     int // h / d: height of each XMSS tree
	w      int // Winternitz parameter
	len1   int
	len2   int
	wlen   int // len1 + len2
	leaves int // 2^hp: leaves of an XMSS tree
	fleafs int // 2^a: leaves of a FORS tree

	forsSigLen int // k(a+1)n
	xmssSigLen int // (wlen+hp)n
	sigLen     int
}

func newParams(p kmosaic.HashSignParams) (params, error) {
	if (p.N != 16 && p.N != 24 && p.N != 32) || p.D <= 0 || p.D > 64 || p.H <= 0 || p.H%p.D != 0 ||
		p.LgW != 4 || p.A <= 0 || p.A > 16 || p.K <= 0 || p.K > 64 {
		return params{}, errors.New("slhdsa: invalid parameters")
	}
	ps := params{HashSignParams: p, hp: p.H / p.D, w: 1 << p.LgW}
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
	if ps.hp > 16 || p.H-ps.hp > 64 {
		return params{}, errors.New("slhdsa: tree indices too large")
	}
	expectedM := (p.K*p.A+7)/8 + (p.H-ps.hp+7)/8 + (ps.hp+7)/8
	if p.M != expectedM {
		return params{}, errors.New("slhdsa: m does not match the other parameters")
	}
	ps.leaves = 1 << ps.hp
	ps.fleafs = 1 << p.A
	ps.forsSigLen = p.K * (p.A + 1) * p.N
	ps.xmssSigLen = (ps.wlen + ps.hp) * p.N
	ps.sigLen = p.N + ps.forsSigLen + p.D*ps.xmssSigLen
	return ps, nil
}

// SignatureSize returns the signature length in bytes (0 for invalid params).
func SignatureSize(p kmosaic.HashSignParams) int {
	ps, err := newParams(p)
	if err != nil {
		return 0
	}
	return ps.sigLen
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
	clear(a[20:32])
}
func (a *adrs) setKeyPair(i uint32)    { binary.BigEndian.PutUint32(a[20:24], i) }
func (a *adrs) setChain(i uint32)      { binary.BigEndian.PutUint32(a[24:28], i) }
func (a *adrs) setTreeHeight(i uint32) { binary.BigEndian.PutUint32(a[24:28], i) }
func (a *adrs) setTreeIndex(i uint32)  { binary.BigEndian.PutUint32(a[28:32], i) }

// ---------------------------------------------------------------------------
// Worker-local hashing state (SHAKE256 instantiation, §11.1)
// ---------------------------------------------------------------------------

// worker holds one SHAKE256 state and all scratch buffers needed by one
// goroutine. Workers are recycled through a pool once per operation (not per
// hash call), so steady-state hashing does not allocate.
type worker struct {
	h      *sha3.SHAKE
	skSeed []byte
	// buf is PK.seed || ADRS || X, the input of F and PRF, kept contiguous so
	// each chain step is a single Write and a single Read.
	buf    [2*maxN + 32]byte
	node   [maxN]byte
	wots   []byte   // wlen*n: WOTS+ chain ends
	nodes  []byte   // max(2^a, 2^hp)*n: tree levels, computed in place
	roots  []byte   // k*n: FORS roots (verification)
	dig    []byte   // m: message digest
	digits []uint32 // max(wlen, k)
}

var workerPool = sync.Pool{New: func() any { return &worker{h: sha3.NewSHAKE256()} }}

func growBytes(b []byte, n int) []byte {
	if cap(b) < n {
		return make([]byte, n)
	}
	return b[:n]
}

func getWorker(ps *params, pkSeed, skSeed []byte) *worker {
	w := workerPool.Get().(*worker)
	n := ps.N
	w.wots = growBytes(w.wots, ps.wlen*n)
	w.nodes = growBytes(w.nodes, max(ps.fleafs, ps.leaves)*n)
	w.roots = growBytes(w.roots, ps.K*n)
	w.dig = growBytes(w.dig, ps.M)
	if nd := max(ps.wlen, ps.K); cap(w.digits) < nd {
		w.digits = make([]uint32, nd)
	}
	copy(w.buf[:n], pkSeed)
	w.skSeed = skSeed
	return w
}

// putWorker wipes all secret-dependent state and returns w to the pool.
func putWorker(w *worker) {
	w.skSeed = nil
	clear(w.buf[:])
	clear(w.node[:])
	clear(w.wots)
	clear(w.nodes)
	w.h.Reset()
	workerPool.Put(w)
}

// thash computes SHAKE256(PK.seed || ADRS || m1 || m2) into out; it covers
// F, H and T_l. out may alias m1 or m2.
func (w *worker) thash(out []byte, n int, a *adrs, m1, m2 []byte) {
	h := w.h
	h.Reset()
	_, _ = h.Write(w.buf[:n])
	_, _ = h.Write(a[:])
	_, _ = h.Write(m1)
	if m2 != nil {
		_, _ = h.Write(m2)
	}
	_, _ = h.Read(out)
}

// prf computes PRF(PK.seed, SK.seed, ADRS) into out.
func (w *worker) prf(out []byte, n int, a *adrs) {
	buf := w.buf[:2*n+32]
	copy(buf[n:n+32], a[:])
	copy(buf[n+32:], w.skSeed)
	h := w.h
	h.Reset()
	_, _ = h.Write(buf)
	_, _ = h.Read(out)
}

// chain applies F steps times to x in place, with hash addresses start,
// start+1, ... (FIPS 205 Algorithm 5). If store is non-nil, the value after
// k steps is written to store[k*n:(k+1)*n] for k = 0..steps.
func (w *worker) chain(x []byte, n int, a *adrs, start, steps int, store []byte) {
	buf := w.buf[:2*n+32]
	copy(buf[n:n+32], a[:])
	val := buf[n+32:]
	copy(val, x)
	if store != nil {
		copy(store[:n], val)
	}
	h := w.h
	for j := 0; j < steps; j++ {
		binary.BigEndian.PutUint32(buf[n+28:n+32], uint32(start+j))
		h.Reset()
		_, _ = h.Write(buf)
		_, _ = h.Read(val)
		if store != nil {
			copy(store[(j+1)*n:(j+2)*n], val)
		}
	}
	copy(x, val)
}

// ---------------------------------------------------------------------------
// base_2b (§4.4)
// ---------------------------------------------------------------------------

func base2bInto(out []uint32, x []byte, b int) {
	in := 0
	bits := 0
	var total uint64
	for i := range out {
		for bits < b {
			total = total<<8 | uint64(x[in])
			in++
			bits += 8
		}
		bits -= b
		out[i] = uint32(total>>uint(bits)) & ((1 << uint(b)) - 1)
	}
}

func base2b(x []byte, b int, outLen int) []uint32 {
	out := make([]uint32, outLen)
	base2bInto(out, x, b)
	return out
}

// ---------------------------------------------------------------------------
// WOTS+ (§5)
// ---------------------------------------------------------------------------

// wotsDigits writes the len1 message digits and len2 checksum digits of m to
// out[:wlen].
func (ps *params) wotsDigits(m []byte, out []uint32) {
	msg := out[:ps.len1]
	base2bInto(msg, m, ps.LgW)
	csum := 0
	for _, d := range msg {
		csum += ps.w - 1 - int(d)
	}
	csum <<= uint((8 - (ps.len2*ps.LgW)%8) % 8)
	csumBytes := (ps.len2*ps.LgW + 7) / 8
	var cb [8]byte
	for i := csumBytes - 1; i >= 0; i-- {
		cb[i] = byte(csum)
		csum >>= 8
	}
	base2bInto(out[ps.len1:ps.wlen], cb[:csumBytes], ps.LgW)
}

// wotsPKGen computes the WOTS+ public key of key pair kp in the XMSS tree
// addressed by a (layer and tree set) into out (FIPS 205 Algorithm 6). If
// chains is non-nil (wlen*w*n bytes) every intermediate chain value is
// stored there so that a signature on any message can later be read off
// without further hashing: chains[(i*w+k)*n:] = chain(sk_i, 0, k).
func (w *worker) wotsPKGen(ps *params, a *adrs, kp uint32, out, chains []byte) {
	n := ps.N
	sk, ch, pk := *a, *a, *a
	sk.setType(adrsWOTSPRF)
	sk.setKeyPair(kp)
	ch.setType(adrsWOTSHash)
	ch.setKeyPair(kp)
	pk.setType(adrsWOTSPK)
	pk.setKeyPair(kp)
	tmp := w.wots[:ps.wlen*n]
	stride := ps.w * n
	for i := 0; i < ps.wlen; i++ {
		x := tmp[i*n : (i+1)*n]
		sk.setChain(uint32(i))
		w.prf(x, n, &sk)
		ch.setChain(uint32(i))
		var st []byte
		if chains != nil {
			st = chains[i*stride : (i+1)*stride]
		}
		w.chain(x, n, &ch, 0, ps.w-1, st)
	}
	w.thash(out, n, &pk, tmp, nil)
}

// wotsSigFromChains writes the WOTS+ signature on m (n bytes) to sig, reading
// the chain values recorded by wotsPKGen. The result equals FIPS 205
// Algorithm 7.
func (ps *params) wotsSigFromChains(chains, m, sig []byte, digits []uint32) {
	n := ps.N
	ps.wotsDigits(m, digits)
	for i := 0; i < ps.wlen; i++ {
		off := (i*ps.w + int(digits[i])) * n
		copy(sig[i*n:(i+1)*n], chains[off:off+n])
	}
}

// wotsPKFromSig computes a WOTS+ public key from a signature (Algorithm 8).
// out may alias m.
func (w *worker) wotsPKFromSig(ps *params, a *adrs, kp uint32, sig, m, out []byte) {
	n := ps.N
	digits := w.digits[:ps.wlen]
	ps.wotsDigits(m, digits)
	ch, pk := *a, *a
	ch.setType(adrsWOTSHash)
	ch.setKeyPair(kp)
	pk.setType(adrsWOTSPK)
	pk.setKeyPair(kp)
	tmp := w.wots[:ps.wlen*n]
	for i := 0; i < ps.wlen; i++ {
		x := tmp[i*n : (i+1)*n]
		copy(x, sig[i*n:(i+1)*n])
		ch.setChain(uint32(i))
		d := int(digits[i])
		w.chain(x, n, &ch, d, ps.w-1-d, nil)
	}
	w.thash(out, n, &pk, tmp, nil)
}

// ---------------------------------------------------------------------------
// XMSS (§6)
// ---------------------------------------------------------------------------

// xmssTree computes, in place over nodes (which holds the 2^hp leaves), the
// XMSS tree addressed by a. It writes the authentication path of leaf idx
// to auth (if non-nil) and the root to root.
func (w *worker) xmssTree(ps *params, a *adrs, nodes []byte, idx uint32, auth, root []byte) {
	n := ps.N
	t := *a
	t.setType(adrsTree)
	cnt := ps.leaves
	for z := 0; z < ps.hp; z++ {
		if auth != nil {
			s := int((idx >> uint(z)) ^ 1)
			copy(auth[z*n:(z+1)*n], nodes[s*n:(s+1)*n])
		}
		t.setTreeHeight(uint32(z + 1))
		for i := 0; i < cnt/2; i++ {
			t.setTreeIndex(uint32(i))
			w.thash(nodes[i*n:(i+1)*n], n, &t, nodes[2*i*n:(2*i+1)*n], nodes[(2*i+1)*n:(2*i+2)*n])
		}
		cnt /= 2
	}
	copy(root, nodes[:n])
}

// xmssPKFromSig computes an XMSS root from a signature (Algorithm 11). out
// may alias m.
func (w *worker) xmssPKFromSig(ps *params, a *adrs, idx uint32, sig, m, out []byte) {
	n := ps.N
	w.wotsPKFromSig(ps, a, idx, sig[:ps.wlen*n], m, out)
	auth := sig[ps.wlen*n:]
	t := *a
	t.setType(adrsTree)
	ti := idx
	for k := 0; k < ps.hp; k++ {
		t.setTreeHeight(uint32(k + 1))
		ak := auth[k*n : (k+1)*n]
		ti >>= 1
		t.setTreeIndex(ti)
		if (idx>>uint(k))&1 == 0 {
			w.thash(out, n, &t, out, ak)
		} else {
			w.thash(out, n, &t, ak, out)
		}
	}
}

// ---------------------------------------------------------------------------
// FORS (§8)
// ---------------------------------------------------------------------------

// forsTree computes FORS tree t (key pair kp of the tree addressed by a) and
// writes the secret value of leaf idx followed by its authentication path to
// sig ((a+1)*n bytes) and the tree root to root (Algorithms 15 and 16).
func (w *worker) forsTree(ps *params, a *adrs, kp uint32, t int, idx uint32, sig, root []byte) {
	n := ps.N
	sk, f := *a, *a
	sk.setType(adrsFORSPRF)
	sk.setKeyPair(kp)
	f.setType(adrsFORSTree)
	f.setKeyPair(kp)
	nodes := w.nodes[:ps.fleafs*n]
	base := uint32(t) << uint(ps.A)
	for i := 0; i < ps.fleafs; i++ {
		x := nodes[i*n : (i+1)*n]
		sk.setTreeIndex(base + uint32(i))
		w.prf(x, n, &sk)
		if uint32(i) == idx {
			copy(sig[:n], x)
		}
		f.setTreeIndex(base + uint32(i))
		w.thash(x, n, &f, x, nil)
	}
	cnt := ps.fleafs
	for z := 0; z < ps.A; z++ {
		s := int((idx >> uint(z)) ^ 1)
		copy(sig[(z+1)*n:(z+2)*n], nodes[s*n:(s+1)*n])
		f.setTreeHeight(uint32(z + 1))
		zbase := uint32(t) << uint(ps.A-z-1)
		for i := 0; i < cnt/2; i++ {
			f.setTreeIndex(zbase + uint32(i))
			w.thash(nodes[i*n:(i+1)*n], n, &f, nodes[2*i*n:(2*i+1)*n], nodes[(2*i+1)*n:(2*i+2)*n])
		}
		cnt /= 2
	}
	copy(root, nodes[:n])
}

// forsPKFromSig computes the FORS public key from a signature (Algorithm
// 17) into out.
func (w *worker) forsPKFromSig(ps *params, a *adrs, kp uint32, sig, md, out []byte) {
	n := ps.N
	indices := w.digits[:ps.K]
	base2bInto(indices, md, ps.A)
	f, pk := *a, *a
	f.setType(adrsFORSTree)
	f.setKeyPair(kp)
	pk.setType(adrsFORSRoots)
	pk.setKeyPair(kp)
	roots := w.roots[:ps.K*n]
	node := w.node[:n]
	blk := (ps.A + 1) * n
	for i := 0; i < ps.K; i++ {
		s := sig[i*blk : (i+1)*blk]
		ti := uint32(i)<<uint(ps.A) + indices[i]
		f.setTreeHeight(0)
		f.setTreeIndex(ti)
		w.thash(node, n, &f, s[:n], nil)
		for j := 0; j < ps.A; j++ {
			aj := s[(j+1)*n : (j+2)*n]
			f.setTreeHeight(uint32(j + 1))
			ti >>= 1
			f.setTreeIndex(ti)
			if (indices[i]>>uint(j))&1 == 0 {
				w.thash(node, n, &f, node, aj)
			} else {
				w.thash(node, n, &f, aj, node)
			}
		}
		copy(roots[i*n:(i+1)*n], node)
	}
	w.thash(out, n, &pk, roots, nil)
}

// ---------------------------------------------------------------------------
// Parallel execution
// ---------------------------------------------------------------------------

// defaultWorkers is the size of the bounded worker pool used by one call.
func defaultWorkers() int { return runtime.GOMAXPROCS(0) }

// run executes job(w, 0..nJobs-1) on at most nw goroutines (the caller's
// included), each with its own worker state. Jobs are handed out in index
// order through an atomic counter.
func (ps *params) run(nJobs, nw int, pkSeed, skSeed []byte, job func(w *worker, j int)) {
	nw = min(nw, nJobs)
	if nw <= 1 {
		w := getWorker(ps, pkSeed, skSeed)
		for j := 0; j < nJobs; j++ {
			job(w, j)
		}
		putWorker(w)
		return
	}
	var next atomic.Int64
	body := func() {
		w := getWorker(ps, pkSeed, skSeed)
		for {
			j := int(next.Add(1) - 1)
			if j >= nJobs {
				break
			}
			job(w, j)
		}
		putWorker(w)
	}
	var wg sync.WaitGroup
	wg.Add(nw - 1)
	for i := 1; i < nw; i++ {
		go func() {
			defer wg.Done()
			body()
		}()
	}
	body()
	wg.Wait()
}

// ---------------------------------------------------------------------------
// SLH-DSA (§9, §10)
// ---------------------------------------------------------------------------

// keyGenRoot computes PK.root, the root of the single top-layer XMSS tree
// (Algorithm 18, line 3), using up to nw goroutines.
func (ps *params) keyGenRoot(skSeed, pkSeed []byte, nw int) []byte {
	n := ps.N
	var a adrs
	a.setLayer(uint32(ps.D - 1))
	leaves := make([]byte, ps.leaves*n)
	ps.run(ps.leaves, nw, pkSeed, skSeed, func(w *worker, i int) {
		w.wotsPKGen(ps, &a, uint32(i), leaves[i*n:(i+1)*n], nil)
	})
	root := make([]byte, n)
	w := getWorker(ps, pkSeed, skSeed)
	w.xmssTree(ps, &a, leaves, 0, nil, root)
	putWorker(w)
	return root
}

// KeyGen derives a key pair from a secret seed of at least 32 bytes.
func KeyGen(p kmosaic.HashSignParams, seed []byte) (*kmosaic.HashSignKeyPair, error) {
	if len(seed) < 32 {
		return nil, errors.New("seed must be at least 32 bytes")
	}
	ps, err := newParams(p)
	if err != nil {
		return nil, err
	}
	n := ps.N
	expanded := utils.Shake256WithDomain(DomainKeyGen, seed, 3*n)
	skSeed := append([]byte{}, expanded[:n]...)
	skPRF := append([]byte{}, expanded[n:2*n]...)
	pkSeed := append([]byte{}, expanded[2*n:]...)
	clear(expanded)

	root := ps.keyGenRoot(skSeed, pkSeed, defaultWorkers())
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

// hashMsg absorbs pre || msg (M' = pre || msg) after the given fields and
// squeezes out (PRF_msg and H_msg of §11.1).
func (w *worker) hashMsg(out, f1, f2, f3, pre, msg []byte) {
	h := w.h
	h.Reset()
	_, _ = h.Write(f1)
	_, _ = h.Write(f2)
	if f3 != nil {
		_, _ = h.Write(f3)
	}
	_, _ = h.Write(pre)
	_, _ = h.Write(msg)
	_, _ = h.Read(out)
}

func checkSecretKey(sk *kmosaic.HashSignSecretKey, n int) error {
	if sk == nil || len(sk.Seed) != n || len(sk.PRF) != n || len(sk.PKSeed) != n || len(sk.PKRoot) != n {
		return errors.New("slhdsa: malformed secret key")
	}
	return nil
}

// signCore is slh_sign_internal (Algorithm 19) on M' = pre || msg with the
// given opt_rand, using up to nw goroutines.
//
// All hashing is done in one parallel phase: every WOTS+ leaf of the d
// hypertree layers on the signing path (the layer trees depend only on
// idx_tree and idx_leaf, not on the message being signed by the layer) and
// all k FORS trees. While computing the leaf that signs at each layer the
// worker records every intermediate chain value, so the layer's WOTS+
// signature is read off once the root of the layer below is known. The last
// worker to finish a layer's leaves builds that layer's tree, yielding its
// authentication path and root.
func (ps *params) signCore(sk *kmosaic.HashSignSecretKey, pre, msg, optRand []byte, nw int) ([]byte, error) {
	n := ps.N
	if err := checkSecretKey(sk, n); err != nil {
		return nil, err
	}
	if len(optRand) != n {
		return nil, errors.New("slhdsa: opt_rand must be n bytes")
	}
	sig := make([]byte, ps.sigLen)

	w0 := getWorker(ps, sk.PKSeed, sk.Seed)
	defer putWorker(w0)
	r := sig[:n]
	w0.hashMsg(r, sk.PRF, optRand, nil, pre, msg)
	digest := w0.dig[:ps.M]
	w0.hashMsg(digest, r, sk.PKSeed, sk.PKRoot, pre, msg)
	md, idxTree, idxLeaf := ps.splitDigest(digest)

	D, L, K := ps.D, ps.leaves, ps.K
	trees := make([]uint64, D)
	leafs := make([]uint32, D)
	mask := uint64(L) - 1
	trees[0], leafs[0] = idxTree, idxLeaf
	for j := 1; j < D; j++ {
		leafs[j] = uint32(trees[j-1] & mask)
		trees[j] = trees[j-1] >> uint(ps.hp)
	}
	forsIdx := make([]uint32, K)
	base2bInto(forsIdx, md, ps.A)

	chainLen := ps.wlen * ps.w * n
	arena := make([]byte, D*L*n+D*chainLen+D*n+K*n)
	leaves := arena[:D*L*n]
	chains := arena[D*L*n : D*L*n+D*chainLen]
	layerRoots := arena[D*L*n+D*chainLen : D*L*n+D*chainLen+D*n]
	forsRoots := arena[D*L*n+D*chainLen+D*n:]
	defer clear(chains)
	layerDone := make([]atomic.Int32, D)

	forsSig := sig[n : n+ps.forsSigLen]
	htSig := sig[n+ps.forsSigLen:]
	blk := (ps.A + 1) * n

	// Hand out the more expensive kind of job first to shorten the tail.
	nLeafJobs := D * L
	forsFirst := 3*ps.fleafs > ps.wlen*ps.w+1
	ps.run(nLeafJobs+K, nw, sk.PKSeed, sk.Seed, func(w *worker, job int) {
		if forsFirst {
			job = (job + nLeafJobs) % (nLeafJobs + K)
		}
		if job >= nLeafJobs {
			t := job - nLeafJobs
			var a adrs
			a.setTree(idxTree)
			w.forsTree(ps, &a, idxLeaf, t, forsIdx[t], forsSig[t*blk:(t+1)*blk], forsRoots[t*n:(t+1)*n])
			return
		}
		j, i := job/L, job%L
		var a adrs
		a.setLayer(uint32(j))
		a.setTree(trees[j])
		lv := leaves[j*L*n : (j+1)*L*n]
		var st []byte
		if uint32(i) == leafs[j] {
			st = chains[j*chainLen : (j+1)*chainLen]
		}
		w.wotsPKGen(ps, &a, uint32(i), lv[i*n:(i+1)*n], st)
		if int(layerDone[j].Add(1)) == L {
			xs := htSig[j*ps.xmssSigLen : (j+1)*ps.xmssSigLen]
			w.xmssTree(ps, &a, lv, leafs[j], xs[ps.wlen*n:], layerRoots[j*n:(j+1)*n])
		}
	})

	if subtle.ConstantTimeCompare(layerRoots[(D-1)*n:], sk.PKRoot) != 1 {
		return nil, errors.New("slhdsa: secret key inconsistent with its public root")
	}

	var a adrs
	a.setTree(idxTree)
	a.setType(adrsFORSRoots)
	a.setKeyPair(idxLeaf)
	m := w0.node[:n]
	w0.thash(m, n, &a, forsRoots, nil)
	for j := 0; j < D; j++ {
		if j > 0 {
			m = layerRoots[(j-1)*n : j*n]
		}
		ps.wotsSigFromChains(chains[j*chainLen:(j+1)*chainLen], m, htSig[j*ps.xmssSigLen:], w0.digits)
	}
	return sig, nil
}

// signInternal is slh_sign_internal (FIPS 205 Algorithm 19) on msg.
func signInternal(sk *kmosaic.HashSignSecretKey, ps *params, msg, optRand []byte) ([]byte, error) {
	return ps.signCore(sk, nil, msg, optRand, defaultWorkers())
}

// signWithRand is the pure slh_sign (Algorithm 22) with context
// "kmosaic-v4" and the given opt_rand.
func signWithRand(sk *kmosaic.HashSignSecretKey, p kmosaic.HashSignParams, msg, optRand []byte) (*kmosaic.HashSignature, error) {
	ps, err := newParams(p)
	if err != nil {
		return nil, err
	}
	sig, err := ps.signCore(sk, purePrefix, msg, optRand, defaultWorkers())
	if err != nil {
		return nil, err
	}
	return &kmosaic.HashSignature{Data: sig}, nil
}

// Sign produces a signature on message (FIPS 205 pure SLH-DSA with context
// "kmosaic-v4"). Signing is hedged: a fresh random opt_rand is mixed into
// the randomizer R.
func Sign(sk *kmosaic.HashSignSecretKey, p kmosaic.HashSignParams, message []byte) (*kmosaic.HashSignature, error) {
	ps, err := newParams(p)
	if err != nil {
		return nil, err
	}
	if err := checkSecretKey(sk, ps.N); err != nil {
		return nil, err
	}
	optRand, err := utils.SecureRandomBytes(ps.N)
	if err != nil {
		return nil, err
	}
	sig, err := ps.signCore(sk, purePrefix, message, optRand, defaultWorkers())
	if err != nil {
		return nil, err
	}
	return &kmosaic.HashSignature{Data: sig}, nil
}

// verifyCore is slh_verify_internal (Algorithm 20) on M' = pre || msg.
func (ps *params) verifyCore(pk *kmosaic.HashSignPublicKey, pre, msg, sig []byte) bool {
	n := ps.N
	if pk == nil || len(pk.Seed) != n || len(pk.Root) != n || len(sig) != ps.sigLen {
		return false
	}
	w := getWorker(ps, pk.Seed, nil)
	defer putWorker(w)
	r := sig[:n]
	forsSig := sig[n : n+ps.forsSigLen]
	htSig := sig[n+ps.forsSigLen:]

	digest := w.dig[:ps.M]
	w.hashMsg(digest, r, pk.Seed, pk.Root, pre, msg)
	md, idxTree, idxLeaf := ps.splitDigest(digest)

	var a adrs
	a.setTree(idxTree)
	var node [maxN]byte
	m := node[:n]
	w.forsPKFromSig(ps, &a, idxLeaf, forsSig, md, m)
	mask := uint64(ps.leaves) - 1
	for j := 0; j < ps.D; j++ {
		if j > 0 {
			idxLeaf = uint32(idxTree & mask)
			idxTree >>= uint(ps.hp)
		}
		a.setLayer(uint32(j))
		a.setTree(idxTree)
		w.xmssPKFromSig(ps, &a, idxLeaf, htSig[j*ps.xmssSigLen:(j+1)*ps.xmssSigLen], m, m)
	}
	return subtle.ConstantTimeCompare(m, pk.Root) == 1
}

// verifyInternal is slh_verify_internal (FIPS 205 Algorithm 20) on msg.
func verifyInternal(pk *kmosaic.HashSignPublicKey, ps *params, msg, sig []byte) bool {
	return ps.verifyCore(pk, nil, msg, sig)
}

// Verify reports whether sig is a valid signature on message under pk (FIPS
// 205 pure SLH-DSA with context "kmosaic-v4").
func Verify(pk *kmosaic.HashSignPublicKey, p kmosaic.HashSignParams, message []byte, sig *kmosaic.HashSignature) bool {
	ps, err := newParams(p)
	if err != nil || pk == nil || sig == nil {
		return false
	}
	return ps.verifyCore(pk, purePrefix, message, sig.Data)
}

// SerializePublicKey serializes a public key as [seed:N][root:N].
func SerializePublicKey(pk *kmosaic.HashSignPublicKey) []byte {
	return append(append([]byte{}, pk.Seed...), pk.Root...)
}

// DeserializePublicKey parses a public key.
func DeserializePublicKey(data []byte, p kmosaic.HashSignParams) (*kmosaic.HashSignPublicKey, error) {
	ps, err := newParams(p)
	if err != nil {
		return nil, err
	}
	n := ps.N
	if len(data) != 2*n {
		return nil, errors.New("invalid SLH-DSA public key: wrong length")
	}
	return &kmosaic.HashSignPublicKey{Seed: append([]byte{}, data[:n]...), Root: append([]byte{}, data[n:]...)}, nil
}

// SerializeSecretKey serializes a secret key as [sk.seed][sk.prf][pk.seed][pk.root].
func SerializeSecretKey(sk *kmosaic.HashSignSecretKey) []byte {
	out := make([]byte, 0, len(sk.Seed)+len(sk.PRF)+len(sk.PKSeed)+len(sk.PKRoot))
	out = append(out, sk.Seed...)
	out = append(out, sk.PRF...)
	out = append(out, sk.PKSeed...)
	out = append(out, sk.PKRoot...)
	return out
}

// DeserializeSecretKey parses a secret key.
func DeserializeSecretKey(data []byte, p kmosaic.HashSignParams) (*kmosaic.HashSignSecretKey, error) {
	ps, err := newParams(p)
	if err != nil {
		return nil, err
	}
	n := ps.N
	if len(data) != 4*n {
		return nil, errors.New("invalid SLH-DSA secret key: wrong length")
	}
	return &kmosaic.HashSignSecretKey{
		Seed:   append([]byte{}, data[:n]...),
		PRF:    append([]byte{}, data[n:2*n]...),
		PKSeed: append([]byte{}, data[2*n:3*n]...),
		PKRoot: append([]byte{}, data[3*n:]...),
	}, nil
}
