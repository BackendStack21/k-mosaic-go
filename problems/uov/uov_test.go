package uov

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math"
	"testing"
	"time"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
)

// The parameter sets are spelled out here so that this package's tests do not
// depend on other packages.
var (
	paramsIp = kmosaic.MQParams{N: 112, M: 44} // uov-Ip
	paramsV  = kmosaic.MQParams{N: 244, M: 96} // uov-V
)

var paramSets = []struct {
	name string
	p    kmosaic.MQParams
}{{"uov-Ip", paramsIp}, {"uov-V", paramsV}}

func randBytes(t testing.TB, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// slowMul multiplies in GF(2^8) bit by bit, independent of the tables.
func slowMul(a, b byte) byte {
	var r byte
	for i := 0; i < 8; i++ {
		if b&1 == 1 {
			r ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1B
		}
		b >>= 1
	}
	return r
}

func TestGF(t *testing.T) {
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			if gfMul(byte(a), byte(b)) != slowMul(byte(a), byte(b)) {
				t.Fatalf("gfMul(%d,%d) = %d want %d", a, b, gfMul(byte(a), byte(b)), slowMul(byte(a), byte(b)))
			}
		}
		if a != 0 && gfMul(byte(a), gfInv(byte(a))) != 1 {
			t.Fatalf("inverse of %d wrong", a)
		}
	}
}

func TestPackedArithmetic(t *testing.T) {
	for _, n := range []int{1, 7, 8, 13, 44, 96, 97} {
		src := randBytes(t, n)
		w := words(n)
		row := make([]uint64, w)
		packBytes(row, src)
		back := make([]byte, n)
		unpackBytes(back, row)
		if !bytes.Equal(back, src) {
			t.Fatalf("pack/unpack mismatch for n=%d", n)
		}
		for k := 0; k < w; k++ {
			x := row[k]
			y := xtime64(x)
			for j := 0; j < 8; j++ {
				if byte(y>>(8*j)) != slowMul(byte(x>>(8*j)), 2) {
					t.Fatal("xtime64 wrong")
				}
			}
		}
		tab := make([]uint64, 32*w)
		buildNibbleTable(tab, row)
		for a := 0; a < 256; a++ {
			dst := make([]uint64, w)
			mulRowInto(dst, tab, byte(a))
			got := make([]byte, 8*w)
			unpackBytes(got, dst)
			for j := 0; j < 8*w; j++ {
				want := byte(0)
				if j < n {
					want = slowMul(byte(a), src[j])
				}
				if got[j] != want {
					t.Fatalf("nibble table: n=%d a=%d j=%d got %d want %d", n, a, j, got[j], want)
				}
			}
		}
		// Bit planes and buckets.
		planes := make([]uint64, 8*w)
		vals := randBytes(t, 8*w*8)
		packBytes(planes, vals)
		dst := make([]uint64, w)
		hornerPlanes(dst, planes)
		got := make([]byte, 8*w)
		unpackBytes(got, dst)
		for j := range got {
			var want byte
			for p := 0; p < 8; p++ {
				want ^= slowMul(byte(1<<p), vals[p*8*w+j])
			}
			if got[j] != want {
				t.Fatal("hornerPlanes wrong")
			}
		}
		acc := make([]uint64, 256*w)
		accb := randBytes(t, 256*8*w)
		packBytes(acc, accb)
		combineBuckets(dst, acc)
		unpackBytes(got, dst)
		for j := range got {
			var want byte
			for b := 0; b < 256; b++ {
				want ^= slowMul(byte(b), accb[b*8*w+j])
			}
			if got[j] != want {
				t.Fatal("combineBuckets wrong")
			}
		}
	}
}

func TestTriIndex(t *testing.T) {
	d := 7
	idx := 0
	for r := 0; r < d; r++ {
		for c := r; c < d; c++ {
			if triIndex(d, r, c) != idx {
				t.Fatalf("triIndex(%d,%d)=%d want %d", r, c, triIndex(d, r, c), idx)
			}
			idx++
		}
	}
	if idx != triSize(d) {
		t.Fatal("triSize mismatch")
	}
}

// solveBytes runs the packed solver on a byte matrix L and right-hand side y.
func solveBytes(L, y []byte, m int) ([]byte, bool) {
	wa := words(m + 1)
	A := make([]uint64, m*wa)
	row := make([]byte, 8*wa)
	for r := 0; r < m; r++ {
		clear(row)
		copy(row, L[r*m:(r+1)*m])
		row[m] = y[r]
		packBytes(A[r*wa:(r+1)*wa], row)
	}
	if solve(A, m, wa, make([]uint64, 8*wa)) != 0 {
		return nil, false
	}
	x := make([]byte, m)
	for r := 0; r < m; r++ {
		x[r] = byte(A[r*wa+m/8] >> (8 * (m % 8)))
	}
	return x, true
}

func TestSolve(t *testing.T) {
	m := 5
	L := []byte{1, 2, 3, 4, 5, 0, 1, 7, 9, 2, 3, 0, 1, 4, 4, 9, 9, 0, 1, 5, 6, 7, 8, 9, 1}
	x := []byte{3, 1, 4, 1, 5}
	y := make([]byte, m)
	for r := 0; r < m; r++ {
		for c := 0; c < m; c++ {
			y[r] ^= gfMul(L[r*m+c], x[c])
		}
	}
	got, ok := solveBytes(L, y, m)
	if !ok || !bytes.Equal(got, x) {
		t.Fatalf("solve returned %v ok=%v", got, ok)
	}
	if _, ok := solveBytes(make([]byte, m*m), y, m); ok {
		t.Fatal("singular system reported solvable")
	}
	// Random systems of the real sizes, including m a multiple of 8.
	for _, m := range []int{8, 44, 96} {
		solved := 0
		for trial := 0; trial < 5; trial++ {
			L := randBytes(t, m*m)
			x := randBytes(t, m)
			y := make([]byte, m)
			for r := 0; r < m; r++ {
				for c := 0; c < m; c++ {
					y[r] ^= gfMul(L[r*m+c], x[c])
				}
			}
			got, ok := solveBytes(L, y, m)
			if ok {
				solved++
				if !bytes.Equal(got, x) {
					t.Fatalf("m=%d: wrong solution", m)
				}
			}
		}
		if solved == 0 {
			t.Fatalf("m=%d: no random system solved", m)
		}
	}
}

func TestOilSpaceVanishes(t *testing.T) {
	for _, ps := range paramSets {
		p := ps.p
		kp, err := KeyGen(p, randBytes(t, 32))
		if err != nil {
			t.Fatal(err)
		}
		v, m := p.N-p.M, p.M
		basic := kmosaic.MQPublicKey{Seed: kp.PublicKey.Seed, P1: kp.PublicKey.P1, P2: kp.PublicKey.P2, P3: kp.PublicKey.P3}
		// Every public form must vanish on (O x, x) for random x.
		for trial := 0; trial < 10; trial++ {
			x := randBytes(t, m)
			s := make([]byte, p.N)
			for r := 0; r < v; r++ {
				var acc byte
				for j := 0; j < m; j++ {
					acc ^= gfMul(kp.SecretKey.O[r*m+j], x[j])
				}
				s[r] = acc
			}
			copy(s[v:], x)
			for _, pk := range []*kmosaic.MQPublicKey{&kp.PublicKey, &basic} {
				for i, val := range Evaluate(pk, p, s) {
					if val != 0 {
						t.Fatalf("%s: form %d does not vanish on the oil space", ps.name, i)
					}
				}
			}
		}
	}
}

func TestPreparedEvaluateMatchesBasic(t *testing.T) {
	for _, ps := range paramSets {
		p := ps.p
		d, _ := checkParams(p)
		kp, err := KeyGen(p, randBytes(t, 32))
		if err != nil {
			t.Fatal(err)
		}
		pk := &kp.PublicKey
		if len(pk.Prepared) != d.pkPreparedLen() {
			t.Fatal("KeyGen did not populate the public Prepared layout")
		}
		pk2, err := DeserializePublicKey(SerializePublicKey(pk), p)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pk2.Prepared, pk.Prepared) || !bytes.Equal(pk2.P1, pk.P1) || !bytes.Equal(pk2.P2, pk.P2) {
			t.Fatal("deserialized public key differs from KeyGen's")
		}
		inputs := [][]byte{make([]byte, p.N)}
		sparse := make([]byte, p.N)
		sparse[0], sparse[p.N-1], sparse[p.N/2] = 1, 0xFF, 0x53
		inputs = append(inputs, sparse)
		for trial := 0; trial < 20; trial++ {
			inputs = append(inputs, randBytes(t, p.N))
		}
		for _, s := range inputs {
			fast := evaluatePrepared(d, pk.Prepared, s)
			slow := evaluateBasic(d, pk.P1, pk.P2, pk.P3, s)
			if !bytes.Equal(fast, slow) {
				t.Fatalf("%s: prepared evaluation differs from block evaluation", ps.name)
			}
		}
		// The secret signing layout evaluates vᵀ P1 v consistently with P1,
		// both with the constant-time evaluation used by signing and with
		// the bucket evaluation used by verification.
		for _, vin := range [][]byte{randBytes(t, d.v), make([]byte, d.v), bytes.Repeat([]byte{0xFF}, d.v)} {
			full := make([]byte, p.N)
			copy(full, vin) // oil part zero: only the P1 blocks contribute
			want := evaluateBasic(d, pk.P1, pk.P2, pk.P3, full)
			p1Prep := kp.SecretKey.Prepared[:d.t1*d.stride]
			got := make([]uint64, d.w)
			evalBuckets(got, make([]uint64, 256*d.w), p1Prep, vin)
			gotB := make([]byte, d.m)
			unpackBytes(gotB, got)
			if !bytes.Equal(gotB, want) {
				t.Fatalf("%s: bucket evaluation of the signing layout is wrong", ps.name)
			}
			evalP1CT(got, make([]uint64, 8*d.w), make([]uint64, d.w), p1Prep, vin)
			unpackBytes(gotB, got)
			if !bytes.Equal(gotB, want) {
				t.Fatalf("%s: constant-time evaluation of the signing layout is wrong", ps.name)
			}
		}
	}
}

// naivePrepared builds the interleaved public layout entry by entry.
func naivePrepared(d dims, P1, P2, P3 []byte) []byte {
	prep := make([]byte, d.pkPreparedLen())
	for i := 0; i < d.m; i++ {
		for r := 0; r < d.n; r++ {
			for c := r; c < d.n; c++ {
				var a byte
				switch {
				case c < d.v:
					a = P1[i*d.t1+triIndex(d.v, r, c)]
				case r < d.v:
					a = P2[i*d.v*d.m+r*d.m+c-d.v]
				default:
					a = P3[i*d.t3+triIndex(d.m, r-d.v, c-d.v)]
				}
				prep[triIndex(d.n, r, c)*d.stride+i] = a
			}
		}
	}
	return prep
}

func TestPreparedLayout(t *testing.T) {
	for _, p := range []kmosaic.MQParams{paramsV, paramsIp, {N: 23, M: 7}, {N: 41, M: 16}} {
		d, err := checkParams(p)
		if err != nil {
			t.Fatal(err)
		}
		P1, P2 := expandPublic(randBytes(t, PKSeedSize), d)
		P3 := randBytes(t, d.p3Len())
		if !bytes.Equal(naivePrepared(d, P1, P2, P3), buildPKPrepared(d, P1, P2, P3)) {
			t.Fatalf("%+v: public Prepared layout wrong", p)
		}
		S := randBytes(t, d.p2Len())
		sk := buildSKPrepared(d, P1, S)
		for i := 0; i < d.m; i++ {
			for k := 0; k < d.t1; k++ {
				if sk[k*d.stride+i] != P1[i*d.t1+k] {
					t.Fatalf("%+v: secret Prepared P1 layout wrong", p)
				}
			}
		}
		for k := 0; k < d.m*d.v; k++ {
			row := sk[(d.t1+k)*d.stride : (d.t1+k+1)*d.stride]
			if !bytes.Equal(row[:d.m], S[k*d.m:(k+1)*d.m]) || !bytes.Equal(row[d.m:], make([]byte, d.stride-d.m)) {
				t.Fatalf("%+v: secret Prepared S layout wrong", p)
			}
		}
	}
}

// TestOddParams runs the whole scheme on small parameter sets whose M is not
// a multiple of 8 (or is one, so that the augmented system needs an extra
// word), exercising the padding paths.
func TestOddParams(t *testing.T) {
	for _, p := range []kmosaic.MQParams{{N: 23, M: 7}, {N: 20, M: 8}, {N: 41, M: 16}, {N: 40, M: 13}} {
		d, _ := checkParams(p)
		kp, err := KeyGen(p, randBytes(t, 32))
		if err != nil {
			t.Fatal(err)
		}
		for trial := 0; trial < 10; trial++ {
			msg := randBytes(t, 20)
			sig, err := Sign(&kp.SecretKey, p, msg)
			if err != nil {
				t.Fatal(err)
			}
			if !Verify(&kp.PublicKey, p, msg, sig) {
				t.Fatalf("%+v: valid signature rejected", p)
			}
			s := randBytes(t, p.N)
			if !bytes.Equal(evaluatePrepared(d, kp.PublicKey.Prepared, s), evaluateBasic(d, kp.PublicKey.P1, kp.PublicKey.P2, kp.PublicKey.P3, s)) {
				t.Fatalf("%+v: prepared evaluation differs", p)
			}
		}
		pk2, err := DeserializePublicKey(SerializePublicKey(&kp.PublicKey), p)
		if err != nil || !bytes.Equal(pk2.Prepared, kp.PublicKey.Prepared) {
			t.Fatalf("%+v: public key round trip failed", p)
		}
		sk2, err := DeserializeSecretKey(SerializeSecretKey(&kp.SecretKey), p)
		if err != nil || !bytes.Equal(sk2.Prepared, kp.SecretKey.Prepared) || !bytes.Equal(sk2.S, kp.SecretKey.S) {
			t.Fatalf("%+v: secret key round trip failed", p)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	for _, ps := range paramSets {
		p := ps.p
		t.Run(ps.name, func(t *testing.T) {
			seed := randBytes(t, 32)
			st := time.Now()
			kp, err := KeyGen(p, seed)
			if err != nil {
				t.Fatal(err)
			}
			tk := time.Since(st)
			msg := []byte("multivariate message")
			st = time.Now()
			sig, err := Sign(&kp.SecretKey, p, msg)
			if err != nil {
				t.Fatal(err)
			}
			ts := time.Since(st)
			st = time.Now()
			if !Verify(&kp.PublicKey, p, msg, sig) {
				t.Fatal("valid signature rejected")
			}
			tv := time.Since(st)
			t.Logf("keygen=%v sign=%v verify=%v pk=%d sig=%d", tk, ts, tv, len(SerializePublicKey(&kp.PublicKey)), len(SerializeSignature(sig)))

			if Verify(&kp.PublicKey, p, []byte("other"), sig) {
				t.Fatal("wrong message accepted")
			}
			for _, pos := range []int{0, p.N - p.M - 1, p.N - p.M, p.N - 1} {
				bad := &kmosaic.MQSignature{S: append([]byte{}, sig.S...), Salt: append([]byte{}, sig.Salt...)}
				bad.S[pos] ^= 1
				if Verify(&kp.PublicKey, p, msg, bad) {
					t.Fatalf("tampered signature (byte %d) accepted", pos)
				}
			}
			bad := &kmosaic.MQSignature{S: append([]byte{}, sig.S...), Salt: append([]byte{}, sig.Salt...)}
			bad.Salt[0] ^= 1
			if Verify(&kp.PublicKey, p, msg, bad) {
				t.Fatal("tampered salt accepted")
			}
			if Verify(&kp.PublicKey, p, msg, &kmosaic.MQSignature{S: sig.S[1:], Salt: sig.Salt}) {
				t.Fatal("short signature accepted")
			}

			// A public key without the Prepared layout verifies the same way.
			plain := kmosaic.MQPublicKey{Seed: kp.PublicKey.Seed, P1: kp.PublicKey.P1, P2: kp.PublicKey.P2, P3: kp.PublicKey.P3}
			if !Verify(&plain, p, msg, sig) || Verify(&plain, p, msg, bad) {
				t.Fatal("plain-layout verification disagrees")
			}
			// Verify must not trust malformed expanded blocks.
			for _, mut := range []func(pk *kmosaic.MQPublicKey){
				func(pk *kmosaic.MQPublicKey) { pk.P1 = pk.P1[:len(pk.P1)-1] },
				func(pk *kmosaic.MQPublicKey) { pk.P2 = nil },
				func(pk *kmosaic.MQPublicKey) { pk.P3 = append(pk.P3, 0) },
			} {
				broken := kp.PublicKey
				mut(&broken)
				if Verify(&broken, p, msg, sig) {
					t.Fatal("public key with malformed blocks accepted")
				}
			}

			// Serialization
			pk2, err := DeserializePublicKey(SerializePublicKey(&kp.PublicKey), p)
			if err != nil {
				t.Fatal(err)
			}
			sig2, err := DeserializeSignature(SerializeSignature(sig), p)
			if err != nil {
				t.Fatal(err)
			}
			if !Verify(pk2, p, msg, sig2) {
				t.Fatal("round-tripped signature rejected")
			}
			skBytes := SerializeSecretKey(&kp.SecretKey)
			if !bytes.Equal(skBytes, seed) {
				t.Fatal("secret key does not serialize to its seed")
			}
			sk2, err := DeserializeSecretKey(skBytes, p)
			if err != nil {
				t.Fatal(err)
			}
			sig3, err := Sign(sk2, p, msg)
			if err != nil {
				t.Fatal(err)
			}
			if !Verify(&kp.PublicKey, p, msg, sig3) {
				t.Fatal("signature from deserialized secret key rejected")
			}
			if _, err := DeserializePublicKey([]byte{1, 2}, p); err == nil {
				t.Fatal("accepted short pk")
			}
			if _, err := DeserializeSignature([]byte{1, 2}, p); err == nil {
				t.Fatal("accepted short signature")
			}
			if _, err := DeserializeSignature(append(SerializeSignature(sig), 0), p); err == nil {
				t.Fatal("accepted long signature")
			}
			if _, err := DeserializeSecretKey(append(skBytes, 0), p); err == nil {
				t.Fatal("accepted long secret key")
			}
		})
	}
}

func TestKeysDoNotShareMemory(t *testing.T) {
	kp, err := KeyGen(paramsIp, randBytes(t, 32))
	if err != nil {
		t.Fatal(err)
	}
	pk, sk := &kp.PublicKey, &kp.SecretKey
	pk.Seed[0] ^= 1
	pk.P1[0] ^= 1
	if sk.PKSeed[0] == pk.Seed[0] || sk.P1[0] == pk.P1[0] {
		t.Fatal("public and secret keys share the seed or P1 slices")
	}
}

func TestSeedMustBe32Bytes(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := KeyGen(paramsIp, make([]byte, n)); err == nil {
			t.Fatalf("KeyGen accepted a %d-byte seed", n)
		}
		if _, err := DeserializeSecretKey(make([]byte, n), paramsIp); err == nil {
			t.Fatalf("DeserializeSecretKey accepted a %d-byte seed", n)
		}
	}
	seed := randBytes(t, 32)
	kp, err := KeyGen(paramsIp, seed)
	if err != nil {
		t.Fatal(err)
	}
	sk2, err := DeserializeSecretKey(SerializeSecretKey(&kp.SecretKey), paramsIp)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sk2.O, kp.SecretKey.O) || !bytes.Equal(sk2.S, kp.SecretKey.S) {
		t.Fatal("secret key round trip changed the key")
	}
	bad := kp.SecretKey
	bad.Seed = append(append([]byte{}, seed...), 0)
	if _, err := Sign(&bad, paramsIp, []byte("m")); err == nil {
		t.Fatal("Sign accepted a secret key with a 33-byte seed")
	}
	if SerializeSecretKey(&bad) != nil {
		t.Fatal("SerializeSecretKey serialized a malformed seed")
	}
}

func TestParamsValidation(t *testing.T) {
	kp, err := KeyGen(paramsIp, randBytes(t, 32))
	if err != nil {
		t.Fatal(err)
	}
	pkBytes := SerializePublicKey(&kp.PublicKey)
	sig, err := Sign(&kp.SecretKey, paramsIp, []byte("m"))
	if err != nil {
		t.Fatal(err)
	}
	sigBytes := SerializeSignature(sig)
	bogus := []kmosaic.MQParams{
		{N: 0, M: 0}, {N: -5, M: 2}, {N: 10, M: -1}, {N: 88, M: 44}, {N: 112, M: 0},
		{N: 1 << 20, M: 44}, {N: math.MaxInt / 2, M: math.MaxInt / 8}, {N: MaxN + 1, M: 44},
	}
	for _, p := range bogus {
		if _, err := KeyGen(p, make([]byte, 32)); err == nil {
			t.Fatalf("KeyGen accepted %+v", p)
		}
		if _, err := DeserializePublicKey(pkBytes, p); err == nil {
			t.Fatalf("DeserializePublicKey accepted %+v", p)
		}
		if _, err := DeserializeSecretKey(make([]byte, 32), p); err == nil {
			t.Fatalf("DeserializeSecretKey accepted %+v", p)
		}
		if _, err := DeserializeSignature(sigBytes, p); err == nil {
			t.Fatalf("DeserializeSignature accepted %+v", p)
		}
		if _, err := Sign(&kp.SecretKey, p, []byte("m")); err == nil {
			t.Fatalf("Sign accepted %+v", p)
		}
		if Verify(&kp.PublicKey, p, []byte("m"), sig) {
			t.Fatalf("Verify accepted %+v", p)
		}
		if Evaluate(&kp.PublicKey, p, sig.S) != nil {
			t.Fatalf("Evaluate accepted %+v", p)
		}
	}
	// Mismatched but valid parameters must fail on length, not panic.
	if _, err := DeserializePublicKey(pkBytes, paramsV); err == nil {
		t.Fatal("uov-Ip public key accepted as uov-V")
	}
	if _, err := DeserializeSignature(sigBytes, paramsV); err == nil {
		t.Fatal("uov-Ip signature accepted as uov-V")
	}
	if Verify(&kp.PublicKey, paramsV, []byte("m"), sig) {
		t.Fatal("uov-Ip signature verified under uov-V")
	}
	if _, err := Sign(&kp.SecretKey, paramsV, []byte("m")); err == nil {
		t.Fatal("uov-Ip secret key used with uov-V")
	}
	if Verify(nil, paramsIp, []byte("m"), sig) || Verify(&kp.PublicKey, paramsIp, []byte("m"), nil) {
		t.Fatal("nil key or signature accepted")
	}
	if _, err := Sign(nil, paramsIp, []byte("m")); err == nil {
		t.Fatal("Sign accepted a nil key")
	}
}

// TestDeterministicSigning checks, with fixed salt randomness, that the
// secret-key fast path (DeserializeSecretKey), KeyGen's key and a key without
// the signing layout all produce identical, valid signatures.
func TestDeterministicSigning(t *testing.T) {
	for _, ps := range paramSets {
		p := ps.p
		kp, err := KeyGen(p, randBytes(t, 32))
		if err != nil {
			t.Fatal(err)
		}
		sk2, err := DeserializeSecretKey(SerializeSecretKey(&kp.SecretKey), p)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(sk2.Prepared, kp.SecretKey.Prepared) || !bytes.Equal(sk2.P1, kp.SecretKey.P1) ||
			!bytes.Equal(sk2.PKSeed, kp.SecretKey.PKSeed) {
			t.Fatalf("%s: fast-path secret key differs from KeyGen's", ps.name)
		}
		noPrep := kp.SecretKey
		noPrep.Prepared = nil

		rnd := make([]byte, RandSize) // a "failed" RNG returning zeros
		for i, msg := range [][]byte{[]byte("first"), []byte("second"), {}} {
			var sigs []*kmosaic.MQSignature
			for _, sk := range []*kmosaic.MQSecretKey{&kp.SecretKey, sk2, &noPrep} {
				sig, err := signWithRand(sk, p, msg, rnd)
				if err != nil {
					t.Fatal(err)
				}
				sigs = append(sigs, sig)
			}
			for j, sig := range sigs {
				if !Verify(&kp.PublicKey, p, msg, sig) {
					t.Fatalf("%s msg %d key %d: signature rejected", ps.name, i, j)
				}
				if !bytes.Equal(SerializeSignature(sig), SerializeSignature(sigs[0])) {
					t.Fatalf("%s msg %d: key %d produced a different signature", ps.name, i, j)
				}
				if Verify(&kp.PublicKey, p, append(msg, 'x'), sig) {
					t.Fatalf("%s: signature verified for another message", ps.name)
				}
			}
		}
		// Hedged salts: with a broken RNG, different messages still get
		// different salts; fresh randomness gives fresh salts.
		a, _ := signWithRand(&kp.SecretKey, p, []byte("a"), rnd)
		b, _ := signWithRand(&kp.SecretKey, p, []byte("b"), rnd)
		if bytes.Equal(a.Salt, b.Salt) {
			t.Fatal("salt does not depend on the message")
		}
		c, _ := Sign(&kp.SecretKey, p, []byte("a"))
		e, _ := Sign(&kp.SecretKey, p, []byte("a"))
		if bytes.Equal(c.Salt, e.Salt) || bytes.Equal(c.Salt, a.Salt) {
			t.Fatal("salt does not depend on the randomness")
		}
	}
}

func TestManySignatures(t *testing.T) {
	kp, err := KeyGen(paramsIp, randBytes(t, 32))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		msg := []byte(fmt.Sprintf("message %d", i))
		sig, err := Sign(&kp.SecretKey, paramsIp, msg)
		if err != nil {
			t.Fatal(err)
		}
		if !Verify(&kp.PublicKey, paramsIp, msg, sig) {
			t.Fatalf("signature %d rejected", i)
		}
	}
}

func BenchmarkUOV(b *testing.B) {
	for _, ps := range paramSets {
		p := ps.p
		seed := randBytes(b, 32)
		kp, err := KeyGen(p, seed)
		if err != nil {
			b.Fatal(err)
		}
		msg := []byte("benchmark message")
		sig, err := Sign(&kp.SecretKey, p, msg)
		if err != nil {
			b.Fatal(err)
		}
		pkBytes := SerializePublicKey(&kp.PublicKey)
		b.Run("KeyGen/"+ps.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := KeyGen(p, seed); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("Sign/"+ps.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := Sign(&kp.SecretKey, p, msg); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("Verify/"+ps.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if !Verify(&kp.PublicKey, p, msg, sig) {
					b.Fatal("rejected")
				}
			}
		})
		b.Run("DeserializeSecretKey/"+ps.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := DeserializeSecretKey(seed, p); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("DeserializePublicKey/"+ps.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := DeserializePublicKey(pkBytes, p); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
