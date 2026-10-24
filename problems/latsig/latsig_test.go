package latsig

import (
	"bytes"
	"sync"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go/v2"
	"github.com/BackendStack21/k-mosaic-go/v2/core"
	"github.com/BackendStack21/k-mosaic-go/v2/utils"
)

var levels = []kmosaic.SecurityLevel{kmosaic.MOS128, kmosaic.MOS256}

var (
	keyCacheMu sync.Mutex
	keyCache   = map[kmosaic.SecurityLevel]*kmosaic.LatticeSignKeyPair{}
)

// testKeys returns a key pair for level shared by all tests (callers must not
// modify it; take copies of slices before mutating).
func testKeys(t testing.TB, level kmosaic.SecurityLevel) *kmosaic.LatticeSignKeyPair {
	t.Helper()
	keyCacheMu.Lock()
	defer keyCacheMu.Unlock()
	if kp, ok := keyCache[level]; ok {
		return kp
	}
	kp, err := GenerateKeyPair(level)
	if err != nil {
		t.Fatalf("GenerateKeyPair(%s): %v", level, err)
	}
	keyCache[level] = kp
	return kp
}

func cloneSig(sig *kmosaic.LatticeSignature) *kmosaic.LatticeSignature {
	return &kmosaic.LatticeSignature{
		Challenge: append([]byte{}, sig.Challenge...),
		Z:         append([]int32{}, sig.Z...),
		Hint:      append([]uint16{}, sig.Hint...),
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	for _, level := range levels {
		t.Run(string(level), func(t *testing.T) {
			kp := testKeys(t, level)
			p := kp.PublicKey.Params
			for i := 0; i < 5; i++ {
				msg := []byte{byte(i), 'm', 's', 'g'}
				sig, err := Sign(&kp.SecretKey, &kp.PublicKey, msg)
				if err != nil {
					t.Fatal(err)
				}
				if !Verify(&kp.PublicKey, msg, sig) {
					t.Fatal("valid signature rejected")
				}
				if len(sig.Challenge) != p.CTildeSize || len(sig.Z) != p.N {
					t.Fatalf("signature shape: |c̃|=%d |z|=%d", len(sig.Challenge), len(sig.Z))
				}
				if int(normU(sig.Z)) >= p.Gamma1-p.Beta {
					t.Fatalf("response norm %d not below γ1-β", normU(sig.Z))
				}
				if !checkHints(sig.Hint, p) {
					t.Fatalf("hint list invalid: %v", sig.Hint)
				}
			}
		})
	}
}

func TestSerializedSizes(t *testing.T) {
	want := map[kmosaic.SecurityLevel][3]int{
		kmosaic.MOS128: {491563, 999563, 3309},
		kmosaic.MOS256: {655403, 1220747, 4627},
	}
	for _, level := range levels {
		kp := testKeys(t, level)
		p := kp.PublicKey.Params
		sig, err := Sign(&kp.SecretKey, &kp.PublicKey, []byte("size"))
		if err != nil {
			t.Fatal(err)
		}
		got := [3]int{
			len(SerializePublicKey(&kp.PublicKey)),
			len(SerializeSecretKey(&kp.SecretKey)),
			len(SerializeSignature(sig, p)),
		}
		if got != want[level] {
			t.Errorf("%s: sizes (pk, sk, sig) = %v, want %v", level, got, want[level])
		}
		if got[0] != publicKeySize(p) || got[1] != secretKeySize(p) || got[2] != signatureSize(p) {
			t.Errorf("%s: size helpers disagree with encoders", level)
		}
	}
}

func TestKeyGenDeterministicAndHedgedSigning(t *testing.T) {
	seed, _ := utils.SecureRandomBytes(32)
	params := core.Lattice128Params
	kp1, err := GenerateKeyPairFromSeed(params, seed)
	if err != nil {
		t.Fatal(err)
	}
	kp2, err := GenerateKeyPairFromSeed(params, seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(SerializePublicKey(&kp1.PublicKey), SerializePublicKey(&kp2.PublicKey)) {
		t.Error("public key not deterministic")
	}
	if !bytes.Equal(SerializeSecretKey(&kp1.SecretKey), SerializeSecretKey(&kp2.SecretKey)) {
		t.Error("secret key not deterministic")
	}
	if !bytes.Equal(kp1.PublicKey.Tr, kp1.SecretKey.Tr) || len(kp1.PublicKey.Tr) != TrSize {
		t.Error("tr not cached consistently in both keys")
	}
	if !bytes.Equal(kp1.PublicKey.Tr, shake(TrSize, SerializePublicKey(&kp1.PublicKey))) {
		t.Error("cached tr differs from H(pk)")
	}

	msg := []byte("m")
	s1, _ := Sign(&kp1.SecretKey, &kp1.PublicKey, msg)
	s2, _ := Sign(&kp1.SecretKey, &kp1.PublicKey, msg)
	if !Verify(&kp1.PublicKey, msg, s1) || !Verify(&kp1.PublicKey, msg, s2) {
		t.Error("hedged signatures failed to verify")
	}
	if bytes.Equal(SerializeSignature(s1, params), SerializeSignature(s2, params)) {
		t.Error("two hedged signatures were identical")
	}
}

// TestPowerTwoRoundKeys checks that T1·2^d + T0 = A·S1 + S2 mod q and the
// ranges of T1 and T0.
func TestPowerTwoRoundKeys(t *testing.T) {
	kp := testKeys(t, kmosaic.MOS128)
	p := kp.PublicKey.Params
	sk := &kp.SecretKey
	// Check a sample of rows against a direct computation.
	for _, i := range []int{0, 1, p.M / 2, p.M - 1} {
		for j := 0; j < chalLen; j++ {
			var sum int64
			for k := 0; k < p.N; k++ {
				sum += int64(sk.A[i*p.N+k]) * int64(sk.S1[k*chalLen+j])
			}
			want := (sum + int64(sk.S2[i*chalLen+j])) % qMod
			if want < 0 {
				want += qMod
			}
			t1, t0 := kp.PublicKey.T1[i*chalLen+j], sk.T0[i*chalLen+j]
			if t1 < 0 || t1 >= t1Limit || t0 <= -t0Half || t0 > t0Half {
				t.Fatalf("T1/T0 out of range: %d %d", t1, t0)
			}
			if int64(t1)<<dropBits+int64(t0) != want {
				t.Fatalf("T1·2^d + T0 != T at (%d,%d)", i, j)
			}
		}
	}
}

// TestBatchSigningMatchesSequential checks that processing four masks per
// pass over A yields exactly the signature of one-at-a-time signing.
func TestBatchSigningMatchesSequential(t *testing.T) {
	for _, level := range levels {
		kp := testKeys(t, level)
		for i := 0; i < 4; i++ {
			rnd := []byte{byte(i), 1, 2, 3}
			msg := []byte{byte(i)}
			seq, na, err := signInternal(&kp.SecretKey, msg, rnd, 1)
			if err != nil {
				t.Fatal(err)
			}
			bat, nb, err := signInternal(&kp.SecretKey, msg, rnd, signLane)
			if err != nil {
				t.Fatal(err)
			}
			p := kp.PublicKey.Params
			if na != nb || !bytes.Equal(SerializeSignature(seq, p), SerializeSignature(bat, p)) {
				t.Fatalf("%s: batched signature differs from sequential (attempts %d vs %d)", level, na, nb)
			}
			if !Verify(&kp.PublicKey, msg, bat) {
				t.Fatalf("%s: batched signature does not verify", level)
			}
		}
	}
}

// TestAcceptanceRate checks that the expected number of attempts is in line
// with ML-DSA (about 5.1 for the 65 shape and 3.9 for the 87 shape).
func TestAcceptanceRate(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	for _, level := range levels {
		kp := testKeys(t, level)
		const runs = 40
		total := 0
		for i := 0; i < runs; i++ {
			_, n, err := signInternal(&kp.SecretKey, []byte("rate"), []byte{byte(i), byte(i >> 8)}, signLane)
			if err != nil {
				t.Fatal(err)
			}
			total += n
		}
		mean := float64(total) / runs
		t.Logf("%s: mean attempts %.2f", level, mean)
		if mean < 1.5 || mean > 12 {
			t.Errorf("%s: mean attempts %.2f outside the plausible range", level, mean)
		}
	}
}

func TestVerifyTrCaching(t *testing.T) {
	kp := testKeys(t, kmosaic.MOS128)
	msg := []byte("tr")
	sig, err := Sign(&kp.SecretKey, &kp.PublicKey, msg)
	if err != nil {
		t.Fatal(err)
	}
	pk := kp.PublicKey
	pk.Tr = nil // recomputed from the key
	if !Verify(&pk, msg, sig) {
		t.Error("verification without cached tr failed")
	}
	if _, err := Sign(&kp.SecretKey, &pk, msg); err != nil {
		t.Errorf("Sign with uncached pk.Tr failed: %v", err)
	}
	pk.Tr = make([]byte, TrSize) // a wrong cached tr changes μ
	if Verify(&pk, msg, sig) {
		t.Error("verification with a wrong cached tr succeeded")
	}
	if _, err := Sign(&kp.SecretKey, &pk, msg); err == nil {
		t.Error("Sign accepted a public key whose tr does not match")
	}
}

func benchKeys(b *testing.B, f func(b *testing.B, kp *kmosaic.LatticeSignKeyPair)) {
	for _, level := range levels {
		kp := testKeys(b, level)
		b.Run(string(level), func(b *testing.B) { f(b, kp) })
	}
}

func BenchmarkKeyGen(b *testing.B) {
	for _, level := range levels {
		b.Run(string(level), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := GenerateKeyPair(level); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkSign(b *testing.B) {
	benchKeys(b, func(b *testing.B, kp *kmosaic.LatticeSignKeyPair) {
		for i := 0; i < b.N; i++ {
			if _, err := Sign(&kp.SecretKey, &kp.PublicKey, []byte("bench")); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkVerify(b *testing.B) {
	benchKeys(b, func(b *testing.B, kp *kmosaic.LatticeSignKeyPair) {
		sig, _ := Sign(&kp.SecretKey, &kp.PublicKey, []byte("bench"))
		for i := 0; i < b.N; i++ {
			if !Verify(&kp.PublicKey, []byte("bench"), sig) {
				b.Fatal("verify failed")
			}
		}
	})
}

func BenchmarkDeserializePublicKey(b *testing.B) {
	benchKeys(b, func(b *testing.B, kp *kmosaic.LatticeSignKeyPair) {
		data := SerializePublicKey(&kp.PublicKey)
		for i := 0; i < b.N; i++ {
			if _, err := DeserializePublicKey(data); err != nil {
				b.Fatal(err)
			}
		}
	})
}
