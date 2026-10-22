package latsig

import (
	"errors"
	"math/rand"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

func TestGenerateKeyPairFromSeed_Errors(t *testing.T) {
	params := core.Lattice128Params
	if _, err := GenerateKeyPairFromSeed(params, make([]byte, 10)); err == nil {
		t.Error("expected error for short seed")
	}
	// Any 32-byte seed is accepted as given; the composite derives it from
	// a hash, and a statistical check would inspect a secret with
	// data-dependent control flow.
	if _, err := GenerateKeyPairFromSeed(params, make([]byte, 32)); err != nil {
		t.Errorf("all-zero seed rejected: %v", err)
	}
	seed, _ := utils.SecureRandomBytes(32)
	bad := params
	bad.Tau = 50
	bad.Beta = bad.Tau * bad.Eta
	if _, err := GenerateKeyPairFromSeed(bad, seed); err == nil {
		t.Error("expected error for parameters that match no security level")
	}
	if _, err := GenerateKeyPair("MOS-512"); err == nil {
		t.Error("expected error for unknown level")
	}
}

func TestVerify_WrongShape(t *testing.T) {
	kp := testKeys(t, kmosaic.MOS128)
	p := kp.PublicKey.Params
	msg := []byte("shape")
	sig, err := Sign(&kp.SecretKey, &kp.PublicKey, msg)
	if err != nil {
		t.Fatal(err)
	}
	tooMany := make([]uint16, p.Omega+1)
	for i := range tooMany {
		tooMany[i] = uint16(i)
	}
	cases := map[string]*kmosaic.LatticeSignature{
		"short challenge":  {Challenge: make([]byte, 10), Z: sig.Z, Hint: sig.Hint},
		"short response":   {Challenge: sig.Challenge, Z: sig.Z[1:], Hint: sig.Hint},
		"too many hints":   {Challenge: sig.Challenge, Z: sig.Z, Hint: tooMany},
		"unsorted hints":   {Challenge: sig.Challenge, Z: sig.Z, Hint: []uint16{5, 3}},
		"duplicate hints":  {Challenge: sig.Challenge, Z: sig.Z, Hint: []uint16{3, 3}},
		"hint index >= M":  {Challenge: sig.Challenge, Z: sig.Z, Hint: []uint16{uint16(p.M)}},
		"nil":              nil,
		"empty":            {},
		"response at γ1-β": nil,
	}
	edge := cloneSig(sig)
	edge.Z[0] = int32(p.Gamma1 - p.Beta)
	cases["response at γ1-β"] = edge
	for name, s := range cases {
		if Verify(&kp.PublicKey, msg, s) {
			t.Errorf("%s: signature with wrong shape verified", name)
		}
	}
	if Verify(nil, msg, sig) {
		t.Error("nil public key must not verify")
	}
	pk := kp.PublicKey
	pk.T1 = pk.T1[1:]
	if Verify(&pk, msg, sig) {
		t.Error("public key with wrong T1 shape verified")
	}
	pk = kp.PublicKey
	pk.Params.Omega++
	if Verify(&pk, msg, sig) {
		t.Error("public key with unknown parameters verified")
	}
}

func TestSign_BadKeys(t *testing.T) {
	kp := testKeys(t, kmosaic.MOS128)
	msg := []byte("test")
	if _, err := Sign(nil, nil, msg); err == nil {
		t.Error("expected error for nil secret key")
	}
	sk := kp.SecretKey
	sk.S1 = sk.S1[:len(sk.S1)-1]
	if _, err := Sign(&sk, nil, msg); err == nil {
		t.Error("expected error for malformed S1")
	}
	sk = kp.SecretKey
	sk.T0 = nil
	if _, err := Sign(&sk, nil, msg); err == nil {
		t.Error("expected error for missing T0")
	}
	sk = kp.SecretKey
	sk.Params.Omega++
	if _, err := Sign(&sk, nil, msg); err == nil {
		t.Error("expected error for unknown parameters")
	}
	// Entry ranges are enforced when a key is parsed or serialized.
	sk = kp.SecretKey
	sk.S1 = append([]int8{}, sk.S1...)
	sk.S1[0] = int8(sk.Params.Eta + 1)
	if SerializeSecretKey(&sk) != nil {
		t.Error("SerializeSecretKey accepted an out-of-range S1 entry")
	}
	sk = kp.SecretKey
	sk.T0 = append([]int32{}, sk.T0...)
	sk.T0[0] = -t0Half
	if SerializeSecretKey(&sk) != nil {
		t.Error("SerializeSecretKey accepted an out-of-range T0 entry")
	}
	// A public key of another level is refused.
	other := testKeys(t, kmosaic.MOS256)
	if _, err := Sign(&kp.SecretKey, &other.PublicKey, msg); err == nil {
		t.Error("Sign accepted a public key of another level")
	}
}

func TestSign_WithoutCachedMatrix(t *testing.T) {
	kp := testKeys(t, kmosaic.MOS128)
	sk := kp.SecretKey
	sk.A = nil // force re-expansion from rho
	sig, err := Sign(&sk, nil, []byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	pk := kp.PublicKey
	pk.A = nil
	pk.Tr = nil
	if !Verify(&pk, []byte("test"), sig) {
		t.Error("signature should verify when A and tr are recomputed")
	}
}

func TestGenerateKeyPair_RandError(t *testing.T) {
	old := utils.RandReader
	utils.RandReader = &errorReader{}
	defer func() { utils.RandReader = old }()
	if _, err := GenerateKeyPair(kmosaic.MOS128); err == nil {
		t.Error("expected error from rand failure")
	}
}

func TestSign_RandError(t *testing.T) {
	kp := testKeys(t, kmosaic.MOS128)
	old := utils.RandReader
	utils.RandReader = &errorReader{}
	defer func() { utils.RandReader = old }()
	if _, err := Sign(&kp.SecretKey, &kp.PublicKey, []byte("test")); err == nil {
		t.Error("expected error from rand failure")
	}
}

// refDecompose is the textbook FIPS 204 Decompose with division.
func refDecompose(r int32) (int32, int32) {
	r0 := r % alpha
	if r0 > gamma2 {
		r0 -= alpha
	}
	if r-r0 == qMod-1 {
		return 0, r0 - 1
	}
	return (r - r0) / alpha, r0
}

func TestDecomposeExhaustive(t *testing.T) {
	for r := int32(0); r < qMod; r++ {
		r1, r0 := decompose(r)
		e1, e0 := refDecompose(r)
		if r1 != e1 || r0 != e0 {
			t.Fatalf("decompose(%d) = (%d,%d), want (%d,%d)", r, r1, r0, e1, e0)
		}
		if r1 < 0 || r1 > 15 {
			t.Fatalf("decompose(%d): r1 = %d out of range", r, r1)
		}
	}
}

func TestPower2RoundExhaustive(t *testing.T) {
	for r := int32(0); r < qMod; r++ {
		r1, r0 := power2Round(r)
		if r1<<dropBits+r0 != r || r0 <= -t0Half || r0 > t0Half || r1 < 0 || r1 >= t1Limit {
			t.Fatalf("power2Round(%d) = (%d,%d)", r, r1, r0)
		}
	}
}

func TestReductions(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	check := func(x int64) {
		want := x % qMod
		if want < 0 {
			want += qMod
		}
		if got := reduce64(x); int64(got) != want {
			t.Fatalf("reduce64(%d) = %d, want %d", x, got, want)
		}
		if x >= -(1<<31-1<<22-1) && x <= 1<<31-1<<22-1 {
			if got := freeze(int32(x)); int64(got) != want {
				t.Fatalf("freeze(%d) = %d, want %d", x, got, want)
			}
		}
	}
	for _, x := range []int64{0, 1, -1, qMod - 1, qMod, -qMod, 1<<62 - 1, -(1<<62 - 1), 1 << 53, -(1 << 53), 1<<31 - 1<<22 - 1, -(1<<31 - 1<<22 - 1)} {
		check(x)
	}
	for i := 0; i < 1_000_000; i++ {
		x := rng.Int63() >> uint(rng.Intn(62))
		if rng.Intn(2) == 0 {
			x = -x
		}
		check(x)
	}
	for _, x := range []int32{0, 5, -5, -1 << 31, 1<<31 - 1} {
		a := x
		if a < 0 {
			a = -a
		}
		if absU(x) != uint32(a) && x != -1<<31 {
			t.Errorf("absU(%d) = %d", x, absU(x))
		}
	}
	if absU(-1<<31) != 1<<31 || normU([]int32{3, -1 << 31, 7}) != 1<<31 || normU([]int32{3, -9, 7}) != 9 {
		t.Error("absU/normU wrong at the extremes")
	}
}

// TestMakeUseHint checks the FIPS 204 hint lemma: for r ∈ Z_q and ||z|| <= γ2,
// UseHint(MakeHint(z, r), r) = HighBits(r + z).
func TestMakeUseHint(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	set := 0
	for i := 0; i < 2_000_000; i++ {
		r := int32(rng.Intn(qMod))
		z := int32(rng.Intn(2*gamma2+1)) - gamma2
		if i < 1000 { // edges of the range and of the wrap-around
			r = int32(qMod - 1 - i%40)
			if i%2 == 0 {
				r = int32(i % 40)
			}
		}
		h := makeHint(z, r)
		set += int(h)
		if got, want := useHint(h, r), highBits(freeze(r+z)); got != want {
			t.Fatalf("UseHint(MakeHint(%d, %d)) = %d, want %d", z, r, got, want)
		}
	}
	if set == 0 {
		t.Fatal("no hint was ever set")
	}
}

// TestUseHintRecoversW1 replays signing attempts and checks that the
// verifier's UseHint(h, A·z - T1·c·2^d) equals the signer's HighBits(A·y)
// exactly, entry by entry.
func TestUseHintRecoversW1(t *testing.T) {
	for _, level := range levels {
		kp := testKeys(t, level)
		sk, pk := &kp.SecretKey, &kp.PublicKey
		p := sk.Params
		mu := shake(TrSize, sk.Tr, []byte("w1"))
		rhoPrime := shake(TrSize, []byte("fixed rho prime"))
		s := newSignScratch(p.N, p.M)
		accepted, hints := 0, 0
		for kappa := 0; accepted < 6 && kappa < 200; kappa++ {
			expandMaskLane(rhoPrime, uint16(kappa), p.N, s.ys, 0)
			matVec4(sk.A, s.ys, p.M, p.N, &s.w)
			sig := s.attempt(sk, mu, 0)
			if sig == nil {
				continue
			}
			accepted++
			hints += len(sig.Hint)
			_, c := sampleInBall(sig.Challenge, p.Tau)
			got := recoverW1(pk, sig, &c)
			for i := range got {
				if got[i] != s.w1[i] || s.w1[i] != highBits(s.w[0][i]) {
					t.Fatalf("%s: w1'[%d] = %d, signer w1 = %d", level, i, got[i], s.w1[i])
				}
			}
			if !Verify(pk, []byte("w1"), sig) {
				t.Fatalf("%s: replayed signature does not verify", level)
			}
		}
		if accepted == 0 || hints == 0 {
			t.Fatalf("%s: %d accepted attempts with %d hints; hints not exercised", level, accepted, hints)
		}
		t.Logf("%s: %d signatures, mean %.1f hints", level, accepted, float64(hints)/float64(accepted))
	}
}

func TestSamplers(t *testing.T) {
	dense, sparse := sampleInBall([]byte("challenge seed"), 49)
	nz := 0
	for _, v := range dense {
		if v != 0 {
			nz++
			if v != 1 && v != -1 {
				t.Errorf("challenge entry %d not in {-1,0,1}", v)
			}
		}
	}
	if nz != 49 || sparse.n != 49 {
		t.Errorf("challenge weight %d/%d, want 49", nz, sparse.n)
	}
	for k := 0; k < sparse.n; k++ {
		if int32(dense[sparse.pos[k]]) != sparse.sgn[k] {
			t.Error("sparse challenge disagrees with dense form")
		}
	}

	for _, eta := range []int{2, 4} {
		counts := make(map[int8]int)
		for _, v := range sampleEta([]byte("seed"), 0, 20000, eta) {
			if int(v) > eta || int(v) < -eta {
				t.Fatalf("eta=%d: sample %d out of range", eta, v)
			}
			counts[v]++
		}
		if len(counts) != 2*eta+1 {
			t.Errorf("eta=%d: only %d distinct values", eta, len(counts))
		}
	}

	ys := make([]int32, signLane*5000)
	expandMaskLane(make([]byte, 64), 0, 5000, ys, 2)
	for k := 0; k < 5000; k++ {
		y := ys[signLane*k+2]
		if y <= -gamma1 || y > gamma1 {
			t.Fatalf("mask entry %d out of range", y)
		}
		if ys[signLane*k] != 0 {
			t.Fatal("mask written to the wrong lane")
		}
	}

	for _, a := range expandA(make([]byte, 32), 3, 300) {
		if a >= qMod || a < 0 {
			t.Fatalf("matrix entry %d out of range", a)
		}
	}
}

// TestMatrixKernels compares the optimized products with naive arithmetic.
func TestMatrixKernels(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	const m, n = 40, 36
	A := expandA([]byte("kernels"), m, n)
	ys := make([]int32, signLane*n)
	for i := range ys {
		ys[i] = int32(rng.Intn(2*gamma1)) - gamma1 + 1
	}
	var w [signLane][]int32
	for j := range w {
		w[j] = make([]int32, m)
	}
	matVec4(A, ys, m, n, &w)
	sub := make([]int32, m)
	for i := range sub {
		sub[i] = int32(rng.Intn(64 * 1024))
	}
	for j := 0; j < signLane; j++ {
		y := make([]int32, n)
		for k := range y {
			y[k] = ys[signLane*k+j]
		}
		single := make([]int32, m)
		matVec(A, y, sub, m, n, single)
		for i := 0; i < m; i++ {
			var sum int64
			for k := 0; k < n; k++ {
				sum += int64(A[i*n+k]) * int64(y[k])
			}
			want := ((sum % qMod) + qMod) % qMod
			if int64(w[j][i]) != want {
				t.Fatalf("matVec4 lane %d row %d", j, i)
			}
			want2 := (((sum - int64(sub[i])<<dropBits) % qMod) + qMod) % qMod
			if int64(single[i]) != want2 {
				t.Fatalf("matVec row %d", i)
			}
		}
	}

	S1 := sampleEta([]byte("s1"), 0, n*chalLen, 4)
	S2 := sampleEta([]byte("s2"), 0, m*chalLen, 4)
	T := computeT(A, S1, S2, m, n)
	for i := 0; i < m; i++ {
		for j := 0; j < chalLen; j++ {
			var sum int64
			for k := 0; k < n; k++ {
				sum += int64(A[i*n+k]) * int64(S1[k*chalLen+j])
			}
			want := (((sum + int64(S2[i*chalLen+j])) % qMod) + qMod) % qMod
			if int64(T[i*chalLen+j]) != want {
				t.Fatalf("computeT (%d,%d)", i, j)
			}
		}
	}

	dense, c := sampleInBall([]byte("kernels"), 60)
	out8 := make([]int32, m)
	mulSparse8(S2, &c, m, out8)
	out32 := make([]int32, m)
	mulSparse32(T, &c, m, out32)
	for i := 0; i < m; i++ {
		var s8, s32 int32
		for j := 0; j < chalLen; j++ {
			s8 += int32(S2[i*chalLen+j]) * int32(dense[j])
			s32 += T[i*chalLen+j] * int32(dense[j])
		}
		if out8[i] != s8 || out32[i] != s32 {
			t.Fatalf("sparse product row %d", i)
		}
	}
}

type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("simulated rand error")
}
