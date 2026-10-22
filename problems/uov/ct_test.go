package uov

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	mrand "math/rand"
	"testing"
	"time"

	kmosaic "github.com/BackendStack21/k-mosaic-go/v4"
	"github.com/BackendStack21/k-mosaic-go/v4/utils"
)

// ---------------------------------------------------------------------------
// Constant-time field arithmetic against the tables (themselves checked
// against the bit-serial slowMul in TestGF).

func TestGFMulCTExhaustive(t *testing.T) {
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			if got, want := gfMulCT(byte(a), byte(b)), gfMul(byte(a), byte(b)); got != want {
				t.Fatalf("gfMulCT(%d,%d) = %d want %d", a, b, got, want)
			}
		}
	}
}

func TestGFInvCTExhaustive(t *testing.T) {
	for a := 0; a < 256; a++ {
		if got, want := gfInvCT(byte(a)), gfInv(byte(a)); got != want {
			t.Fatalf("gfInvCT(%d) = %d want %d", a, got, want)
		}
		if a != 0 && gfMul(byte(a), gfInvCT(byte(a))) != 1 {
			t.Fatalf("gfInvCT(%d) is not an inverse", a)
		}
	}
}

func TestIsZeroMask(t *testing.T) {
	for b := 0; b < 256; b++ {
		want := uint64(0)
		if b == 0 {
			want = ^uint64(0)
		}
		if isZeroMask(byte(b)) != want {
			t.Fatalf("isZeroMask(%d) wrong", b)
		}
	}
}

func TestPackedCTArithmetic(t *testing.T) {
	rng := mrand.New(mrand.NewSource(1))
	// gfMulU64 for every scalar on random words, element by element.
	for c := 0; c < 256; c++ {
		for trial := 0; trial < 8; trial++ {
			x := rng.Uint64()
			y := gfMulU64(x, byte(c))
			for j := 0; j < 8; j++ {
				if byte(y>>(8*j)) != gfMul(byte(c), byte(x>>(8*j))) {
					t.Fatalf("gfMulU64 wrong for c=%d", c)
				}
			}
		}
	}
	// mulAddVec on random vectors of every length up to 70 (tails included),
	// with a guard byte after the active part of dst.
	for n := 0; n <= 70; n++ {
		for trial := 0; trial < 20; trial++ {
			src := make([]byte, n)
			dst := make([]byte, n+1)
			rng.Read(src)
			rng.Read(dst)
			c := byte(rng.Intn(256))
			switch trial {
			case 0:
				c = 0
			case 1:
				c = 1
			}
			want := append([]byte{}, dst...)
			for i := range src {
				want[i] ^= gfMul(c, src[i])
			}
			mulAddVec(dst, src, c)
			if !bytes.Equal(dst, want) {
				t.Fatalf("mulAddVec wrong for n=%d c=%d", n, c)
			}
		}
	}
	// mulAddVec64, mulAddPow and accumPlanes+hornerPlanes on packed rows.
	for _, n := range []int{1, 7, 8, 13, 44, 96, 97} {
		w := words(n)
		srcB := make([]byte, 8*w)
		rng.Read(srcB[:n])
		src := make([]uint64, w)
		packBytes(src, srcB)
		pow := make([]uint64, 8*w)
		buildPowTable(pow, src)
		for c := 0; c < 256; c++ {
			d0 := make([]uint64, w)
			for k := range d0 {
				d0[k] = rng.Uint64()
			}
			want := make([]byte, 8*w)
			unpackBytes(want, d0)
			for j := range want {
				want[j] ^= gfMul(byte(c), srcB[j])
			}
			for name, f := range map[string]func(dst []uint64){
				"mulAddVec64": func(dst []uint64) { mulAddVec64(dst, src, byte(c)) },
				"mulAddPow":   func(dst []uint64) { mulAddPow(dst, pow, byte(c)) },
				"accumPlanes": func(dst []uint64) {
					planes := make([]uint64, 8*w)
					accumPlanes(planes, srcB, byte(c))
					u := make([]uint64, w)
					hornerPlanes(u, planes)
					for k := range dst {
						dst[k] ^= u[k]
					}
				},
			} {
				dst := append([]uint64{}, d0...)
				f(dst)
				got := make([]byte, 8*w)
				unpackBytes(got, dst)
				if !bytes.Equal(got, want) {
					t.Fatalf("%s wrong for n=%d c=%d", name, n, c)
				}
			}
		}
	}
}

func TestOuterAddPow(t *testing.T) {
	rng := mrand.New(mrand.NewSource(2))
	for _, m := range []int{1, 7, 8, 13, 44, 96} {
		w := words(m)
		rowB, qB := make([]byte, 8*w), make([]byte, 8*w)
		rng.Read(rowB[:m])
		rng.Read(qB[:m])
		row, q := make([]uint64, w), make([]uint64, w)
		packBytes(row, rowB)
		packBytes(q, qB)
		pow := make([]uint64, 8*w)
		buildPowTable(pow, row)
		dst := make([]uint64, m*w)
		for k := range dst {
			dst[k] = rng.Uint64()
		}
		want := append([]uint64{}, dst...)
		for b := 0; b < m; b++ {
			for k := 0; k < w; k++ {
				for j := 0; j < 8; j++ {
					e := gfMul(qB[b], rowB[8*k+j])
					want[b*w+k] ^= uint64(e) << (8 * j)
				}
			}
		}
		outerAddPow(dst, pow, q)
		for k := range dst {
			if dst[k] != want[k] {
				t.Fatalf("outerAddPow wrong for m=%d", m)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Constant-time solver on adversarial systems.

func mulMatVec(L, x []byte, m int) []byte {
	y := make([]byte, m)
	for r := 0; r < m; r++ {
		for c := 0; c < m; c++ {
			y[r] ^= gfMul(L[r*m+c], x[c])
		}
	}
	return y
}

func TestSolveCTAdversarial(t *testing.T) {
	rng := mrand.New(mrand.NewSource(3))
	for _, m := range []int{1, 2, 5, 8, 9, 44, 96} {
		x := make([]byte, m)
		rng.Read(x)
		// Anti-identity: the pivot of every column is the last candidate.
		anti := make([]byte, m*m)
		for i := 0; i < m; i++ {
			anti[i*m+m-1-i] = byte(1 + rng.Intn(255))
		}
		// Upper rows with zeros in the leading columns (a staircase from the
		// bottom), random elsewhere: many zero pivot candidates.
		stair := make([]byte, m*m)
		for r := 0; r < m; r++ {
			for c := m - 1 - r; c < m; c++ {
				stair[r*m+c] = byte(rng.Intn(256))
			}
			stair[r*m+m-1-r] |= 1
		}
		for name, L := range map[string][]byte{"anti": anti, "stair": stair} {
			got, ok := solveBytes(L, mulMatVec(L, x, m), m)
			if !ok || !bytes.Equal(got, x) {
				t.Fatalf("m=%d %s: wrong solution or flagged singular", m, name)
			}
		}
		if m < 3 {
			continue
		}
		// Rank deficient but nowhere zero-heavy: last row = row0 + 3·row1.
		def := make([]byte, m*m)
		rng.Read(def)
		for c := 0; c < m; c++ {
			def[(m-1)*m+c] = def[c] ^ gfMul(3, def[m+c])
		}
		if _, ok := solveBytes(def, make([]byte, m), m); ok {
			t.Fatalf("m=%d: rank-deficient system not flagged", m)
		}
		// A zero column in the middle.
		zc := make([]byte, m*m)
		rng.Read(zc)
		for r := 0; r < m; r++ {
			zc[r*m+m/2] = 0
		}
		if _, ok := solveBytes(zc, make([]byte, m), m); ok {
			t.Fatalf("m=%d: system with a zero column not flagged", m)
		}
	}
}

// ---------------------------------------------------------------------------
// Pinned outputs. These digests were computed with the table-based code
// before signing and the P3 computation were made constant-time; the maths
// is unchanged, so keys are bit-identical. Signatures are also unchanged: the
// solution of a non-singular system is unique whatever the row operations,
// and the singular attempts that are retried are the same.

var pinned = []struct {
	set            string
	seedByte       byte
	pk, sk, s, sig string
}{
	{"uov-Ip", 0x00,
		"db63143686d59a318c336a222604ba6eed7d53e4a248896f28b8bca6ec970bc1",
		"9e6291970cb44dd94008c79bcaf9d86f18b4b49ba5b2a04781db7199ed3b9e4e",
		"7cc38acecf9f03ce4827e81c1d1f486b4d2f79ee7dc80eb4c3c6715f7ef4e64a",
		"9ab566856f9e37ad42b6985655d222b4f683910d14cd509535ed7bac8d858aaf"},
	{"uov-Ip", 0x01,
		"92031c2508d8ebfb60f0baf91ab184813e536ffc574881974f8c33e3280a75a4",
		"0bcdd0df6a2e10784e1241541e91ccb897541af713e327f9555231d141c99644",
		"be2579cc64b71f00706b99cbc7669af5cb4aca2cb0a79a248f5d2698beb2a0a0",
		"7fc357cefd5376e8b88b4b242fdb9bbc040d7fc219205d16fe80828f330d2ada"},
	{"uov-V", 0x00,
		"812015864bb09aa4270ef86df6bb7c0606e71efe9cde00b5881d3c17ee460518",
		"9e6291970cb44dd94008c79bcaf9d86f18b4b49ba5b2a04781db7199ed3b9e4e",
		"4d3f04b2a44e3d4bebd321a39a8af702dd0488c171c4d6f1e6a5245f0302ee21",
		"5f0d7138241f5e819ed792dfb187e355203d90e4e634e813158315aa538f3a51"},
	{"uov-V", 0x01,
		"004a585c021b9853b799485e1391a4bcbd44f82c80f6046c9c3d5f009c691ac4",
		"0bcdd0df6a2e10784e1241541e91ccb897541af713e327f9555231d141c99644",
		"37b382a5298b920e39a54ef76c1484b24830de38ab142b6bc18a6f93f9d5e0f4",
		"e7aa728b07893dc509a71ba1092a06826dee3919cc548d82163c76fba5534b35"},
}

func TestPinnedKeysAndSignatures(t *testing.T) {
	params := map[string]kmosaic.MQParams{"uov-Ip": paramsIp, "uov-V": paramsV}
	digest := func(b []byte) string { d := sha3.Sum256(b); return hex.EncodeToString(d[:]) }
	for _, pc := range pinned {
		p := params[pc.set]
		seed := bytes.Repeat([]byte{pc.seedByte}, SeedSize)
		kp, err := KeyGen(p, seed)
		if err != nil {
			t.Fatal(err)
		}
		if got := digest(SerializePublicKey(&kp.PublicKey)); got != pc.pk {
			t.Errorf("%s seed %#x: public key digest %s want %s", pc.set, pc.seedByte, got, pc.pk)
		}
		if got := digest(SerializeSecretKey(&kp.SecretKey)); got != pc.sk {
			t.Errorf("%s seed %#x: secret key digest %s want %s", pc.set, pc.seedByte, got, pc.sk)
		}
		if got := digest(kp.SecretKey.S); got != pc.s {
			t.Errorf("%s seed %#x: S digest %s want %s", pc.set, pc.seedByte, got, pc.s)
		}
		sk2, err := DeserializeSecretKey(seed, p)
		if err != nil || digest(sk2.S) != pc.s {
			t.Errorf("%s seed %#x: deserialized S differs", pc.set, pc.seedByte)
		}
		sig, err := signWithRand(&kp.SecretKey, p, []byte("pinned message"), make([]byte, RandSize))
		if err != nil {
			t.Fatal(err)
		}
		if got := digest(SerializeSignature(sig)); got != pc.sig {
			t.Errorf("%s seed %#x: signature digest %s want %s", pc.set, pc.seedByte, got, pc.sig)
		}
	}
}

// ---------------------------------------------------------------------------
// Timing and allocations.

// timingCase is one signing attempt with chosen key and vinegar.
// timingCase is one input to the shared signer: every case runs through the
// same signer struct, the same scratch buffers and the same output buffer,
// with only the data (signing layout, vinegar, target) swapped in, so that
// the measurement cannot be skewed by the memory layout of per-case
// allocations (which produced a persistent 50% offset for one case on a
// 32-bit CI runner).
type timingCase struct {
	name string
	sg   *signer
	prep []byte // signing layout to install in sg before each batch
	vin  []byte
	t    []byte
	s    []byte
}

func (c *timingCase) install() {
	d := c.sg.d
	c.sg.p1Prep = c.prep[:d.t1*d.stride]
	c.sg.sPacked = c.prep[d.t1*d.stride:]
}

func measureAttempts(cases []timingCase, rounds, perBatch int) []time.Duration {
	best := make([]time.Duration, len(cases))
	for r := 0; r < rounds; r++ {
		for j := range cases {
			c := &cases[j]
			c.install()
			start := time.Now()
			for i := 0; i < perBatch; i++ {
				c.sg.attempt(c.s, c.vin, c.t)
			}
			if d := time.Since(start) / time.Duration(perBatch); best[j] == 0 || d < best[j] {
				best[j] = d
			}
		}
	}
	return best
}

// TestSignTimingFlat checks that a signing attempt takes the same time for
// vinegars and keys that drove the old code down very different paths:
// a zero vinegar (zero linear system: the old solver gave up at the first
// column, and every bucket index was 0), a key whose system is the
// anti-identity (every pivot found at the last candidate after a full
// search and a swap), a constant vinegar, and random vinegars. The check is
// loose (minimum over interleaved rounds, re-measured before failing) so as
// not to flake on a busy machine; the numbers are logged.
func TestSignTimingFlat(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test skipped in -short mode")
	}
	for _, ps := range paramSets {
		t.Run(ps.name, func(t *testing.T) {
			p := ps.p
			d, _ := checkParams(p)
			rng := mrand.New(mrand.NewSource(11))
			seed := make([]byte, SeedSize)
			rng.Read(seed)
			kp, err := KeyGen(p, seed)
			if err != nil {
				t.Fatal(err)
			}
			sk := &kp.SecretKey
			// Crafted key: row 0 of every S_i is a unit vector so that, for
			// the vinegar e_0, L is the anti-identity.
			S := append([]byte{}, sk.S...)
			for i := 0; i < d.m; i++ {
				row := S[i*d.v*d.m : i*d.v*d.m+d.m]
				clear(row)
				row[d.m-1-i] = 1
			}
			antiPrep := buildSKPrepared(d, sk.P1, S)
			e0 := make([]byte, d.v)
			e0[0] = 1
			shared := newSigner(d, sk.Prepared, sk.O)
			out := make([]byte, d.n)
			newCase := func(name string, prep, vin []byte) timingCase {
				tt := make([]byte, d.m)
				rng.Read(tt)
				return timingCase{name, shared, prep, vin, tt, out}
			}
			randVin := func() []byte { b := make([]byte, d.v); rng.Read(b); return b }
			cases := []timingCase{
				newCase("zero vinegar (singular)", sk.Prepared, make([]byte, d.v)),
				newCase("anti-identity system", antiPrep, e0),
				newCase("constant 0xFF vinegar", sk.Prepared, bytes.Repeat([]byte{0xFF}, d.v)),
				newCase("random vinegar 1", sk.Prepared, randVin()),
				newCase("random vinegar 2", sk.Prepared, randVin()),
			}
			cases[0].install()
			if cases[0].sg.attempt(cases[0].s, cases[0].vin, cases[0].t) != 1 {
				t.Fatal("zero vinegar not flagged singular")
			}
			cases[1].install()
			if cases[1].sg.attempt(cases[1].s, cases[1].vin, cases[1].t) != 0 {
				t.Fatal("anti-identity system flagged singular")
			}
			rounds, perBatch := 30, 4
			if ps.name == "uov-V" {
				rounds, perBatch = 15, 2
			}
			measureAttempts(cases, 2, perBatch) // warm-up
			var ratio float64
			for attempt := 0; attempt < 3; attempt++ {
				times := measureAttempts(cases, rounds, perBatch)
				lo, hi := times[0], times[0]
				for i, dd := range times {
					t.Logf("%-26s %v", cases[i].name, dd)
					lo, hi = min(lo, dd), max(hi, dd)
				}
				ratio = float64(hi) / float64(lo)
				t.Logf("max/min = %.3f", ratio)
				if ratio <= 1.2 {
					return
				}
			}
			t.Errorf("signing time depends on the vinegar/system: max/min = %.3f", ratio)
		})
	}
}

// TestSignAllocsIndependentOfMessage checks that the number of allocations
// of Sign does not depend on the message (contents or length) and that a
// signing attempt allocates nothing.
func TestSignAllocsIndependentOfMessage(t *testing.T) {
	kp, err := KeyGen(paramsIp, randBytes(t, SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	sk := &kp.SecretKey
	msgs := [][]byte{{}, []byte("a"), bytes.Repeat([]byte{0}, 1000), randBytes(t, 10000)}
	var ref float64
	for i, msg := range msgs {
		n := testing.AllocsPerRun(20, func() {
			if _, err := Sign(sk, paramsIp, msg); err != nil {
				t.Fatal(err)
			}
		})
		t.Logf("message of %d bytes: %.1f allocations per Sign", len(msg), n)
		if i == 0 {
			ref = n
		} else if n != ref {
			t.Fatalf("Sign allocates %.1f times for a %d-byte message, %.1f for an empty one", n, len(msg), ref)
		}
	}
	d, _ := checkParams(paramsIp)
	sg := newSigner(d, sk.Prepared, sk.O)
	s, vin, tt := make([]byte, d.n), randBytes(t, d.v), randBytes(t, d.m)
	if n := testing.AllocsPerRun(10, func() { sg.attempt(s, vin, tt) }); n != 0 {
		t.Fatalf("a signing attempt allocates %.1f times", n)
	}
}

// TestSolveTimingFlat compares the solver alone on systems that took very
// different paths in the old branching elimination (which took about 2µs on
// the zero matrix and 200µs on a random one for M = 96): zero, anti-identity,
// staircase, rank-deficient and random matrices.
func TestSolveTimingFlat(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test skipped in -short mode")
	}
	const m = 96
	wa := words(m + 1)
	rng := mrand.New(mrand.NewSource(17))
	pack := func(L []byte) []uint64 {
		A := make([]uint64, m*wa)
		row := make([]byte, 8*wa)
		for r := 0; r < m; r++ {
			clear(row)
			copy(row, L[r*m:(r+1)*m])
			row[m] = byte(rng.Intn(256))
			packBytes(A[r*wa:(r+1)*wa], row)
		}
		return A
	}
	anti, stair, rnd := make([]byte, m*m), make([]byte, m*m), make([]byte, m*m)
	rng.Read(rnd)
	for r := 0; r < m; r++ {
		anti[r*m+m-1-r] = 1
		for c := m - 1 - r; c < m; c++ {
			stair[r*m+c] = byte(rng.Intn(256)) | 1
		}
	}
	def := append([]byte{}, rnd...)
	copy(def[(m-1)*m:], def[:m])
	names := []string{"zero", "anti-identity", "staircase", "rank-deficient", "random"}
	mats := [][]uint64{pack(make([]byte, m*m)), pack(anti), pack(stair), pack(def), pack(rnd)}
	work := make([]uint64, m*wa)
	pow := make([]uint64, 8*wa)
	measure := func(rounds, perBatch int) []time.Duration {
		best := make([]time.Duration, len(mats))
		for r := 0; r < rounds; r++ {
			for j, A := range mats {
				start := time.Now()
				for i := 0; i < perBatch; i++ {
					copy(work, A)
					solve(work, m, wa, pow)
				}
				if d := time.Since(start) / time.Duration(perBatch); best[j] == 0 || d < best[j] {
					best[j] = d
				}
			}
		}
		return best
	}
	measure(2, 5)
	var ratio float64
	for attempt := 0; attempt < 3; attempt++ {
		times := measure(40, 5)
		lo, hi := times[0], times[0]
		for i, d := range times {
			t.Logf("solve %-15s %v", names[i], d)
			lo, hi = min(lo, d), max(hi, d)
		}
		ratio = float64(hi) / float64(lo)
		t.Logf("max/min = %.3f", ratio)
		if ratio <= 1.2 {
			return
		}
	}
	t.Errorf("solve time depends on the matrix: max/min = %.3f", ratio)
}

// TestSignUsesInjectedRNG checks that Sign draws its salt randomness from
// utils.RandReader, so the library's RNG injection covers UOV.
func TestSignUsesInjectedRNG(t *testing.T) {
	kp, err := KeyGen(paramsIp, randBytes(t, SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	rnd := bytes.Repeat([]byte{0xA5}, RandSize)
	saved := utils.RandReader
	defer func() { utils.RandReader = saved }()
	utils.RandReader = bytes.NewReader(rnd)
	sig, err := Sign(&kp.SecretKey, paramsIp, []byte("m"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := signWithRand(&kp.SecretKey, paramsIp, []byte("m"), rnd)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(SerializeSignature(sig), SerializeSignature(want)) {
		t.Fatal("Sign did not use utils.RandReader")
	}
	utils.RandReader = bytes.NewReader(nil) // failing source
	if _, err := Sign(&kp.SecretKey, paramsIp, []byte("m")); err == nil {
		t.Fatal("Sign ignored a failing random source")
	}
}
