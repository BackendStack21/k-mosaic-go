package qcsd

import (
	"bytes"
	"math/rand"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

func TestGF256(t *testing.T) {
	for a := 1; a < 256; a++ {
		if gfMul(byte(a), gfInv(byte(a))) != 1 {
			t.Fatalf("inverse of %d wrong", a)
		}
	}
	// distributivity spot check
	for i := 0; i < 1000; i++ {
		a, b, c := byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256))
		if gfMul(a, b^c) != gfMul(a, b)^gfMul(a, c) {
			t.Fatal("distributivity failed")
		}
	}
}

func TestReedSolomon(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for _, tc := range []struct{ n1, delta int }{{46, 15}, {56, 16}, {90, 29}} {
		k := tc.n1 - 2*tc.delta
		for trial := 0; trial < 200; trial++ {
			msg := make([]byte, k)
			rng.Read(msg)
			cw := rsEncode(msg, tc.n1, tc.delta)
			if !bytes.Equal(cw[2*tc.delta:], msg) {
				t.Fatal("encoding is not systematic")
			}
			// Every codeword must have zero syndromes.
			for j := 1; j <= 2*tc.delta; j++ {
				if polyEval(cw, gfPow(j)) != 0 {
					t.Fatalf("syndrome %d non-zero on a fresh codeword", j)
				}
			}
			nerr := rng.Intn(tc.delta + 1)
			noisy := append([]byte{}, cw...)
			perm := rng.Perm(tc.n1)
			for _, pos := range perm[:nerr] {
				noisy[pos] ^= byte(1 + rng.Intn(255))
			}
			dec, err := rsDecode(noisy, tc.n1, tc.delta)
			if err != nil {
				t.Fatalf("[%d,%d] trial %d with %d errors: %v", tc.n1, k, trial, nerr, err)
			}
			if !bytes.Equal(dec, msg) {
				t.Fatalf("[%d,%d] trial %d with %d errors: wrong message", tc.n1, k, trial, nerr)
			}
		}
		// delta+1 errors must not be silently mis-decoded into a different message
		// often; mostly they are detected. Just make sure nothing panics.
		msg := make([]byte, k)
		cw := rsEncode(msg, tc.n1, tc.delta)
		for i := 0; i <= tc.delta; i++ {
			cw[i] ^= 1
		}
		_, _ = rsDecode(cw, tc.n1, tc.delta)
	}
}

func TestReedMuller(t *testing.T) {
	for _, mult := range []int{3, 5} {
		for b := 0; b < 256; b++ {
			v := make([]uint64, words(128*mult))
			rmEncodeByte(v, 0, byte(b), mult)
			if got := rmDecodeByte(v, 0, mult); got != byte(b) {
				t.Fatalf("mult %d: byte %d decoded as %d", mult, b, got)
			}
			// RM(1,7) repeated mult times corrects any pattern of fewer than
			// 32*mult errors. Flip 31*mult random bits.
			rng := rand.New(rand.NewSource(int64(b)))
			for _, p := range rng.Perm(128 * mult)[:31*mult] {
				v[p>>6] ^= 1 << (uint(p) & 63)
			}
			if got := rmDecodeByte(v, 0, mult); got != byte(b) {
				t.Fatalf("mult %d: byte %d with errors decoded as %d", mult, b, got)
			}
		}
	}
}

func naiveRotate(src []uint64, s, n int) []uint64 {
	dst := make([]uint64, len(src))
	for i := 0; i < n; i++ {
		if getBit(src, i) {
			setBit(dst, (i+s)%n)
		}
	}
	return dst
}

func TestRotateAndMul(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for _, n := range []int{64, 65, 127, 1000, 17669, 57637} {
		src := make([]uint64, words(n))
		for i := range src {
			src[i] = rng.Uint64()
		}
		maskTop(src, n)
		for _, s := range []int{0, 1, 63, 64, 65, n - 1, n / 2, 3000 % n} {
			if !equal(rotate(src, s, n), naiveRotate(src, s, n)) {
				t.Fatalf("rotate mismatch n=%d s=%d", n, s)
			}
		}
	}
	// Commutativity of the ring multiplication: h·y computed via sparse y
	// must equal y·h computed via sparse h (both sparse).
	n := 17669
	a := sampleFixedWeight([]byte("a"), n, 50)
	b := sampleFixedWeight([]byte("b"), n, 60)
	if !equal(mulSparse(a, positions(b, n), n), mulSparse(b, positions(a, n), n)) {
		t.Fatal("ring multiplication not commutative")
	}
	if weight(a) != 50 || weight(b) != 60 {
		t.Fatal("fixed-weight sampling returned the wrong weight")
	}
}

func equal(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestRoundTrip(t *testing.T) {
	p := core.CodeHQC256
	seed, _ := utils.SecureRandomBytes(32)
	kp, err := KeyGen(p, seed)
	if err != nil {
		t.Fatal(err)
	}
	if weight(kp.SecretKey.X) != p.W || weight(kp.SecretKey.Y) != p.W {
		t.Fatal("secret weights wrong")
	}
	trials := 200
	if testing.Short() {
		trials = 20
	}
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < trials; i++ {
		msg := make([]byte, p.K)
		rng.Read(msg)
		rnd, _ := utils.SecureRandomBytes(32)
		ct, err := Encrypt(kp.PublicKey, msg, p, rnd)
		if err != nil {
			t.Fatal(err)
		}
		dec := Decrypt(ct, kp.SecretKey, p)
		if !bytes.Equal(dec, msg) {
			t.Fatalf("trial %d: decryption failed", i)
		}
	}

	// Deterministic in the randomness
	msg := make([]byte, p.K)
	rnd, _ := utils.SecureRandomBytes(32)
	c1, _ := Encrypt(kp.PublicKey, msg, p, rnd)
	c2, _ := Encrypt(kp.PublicKey, msg, p, rnd)
	if !equal(c1.U, c2.U) || !equal(c1.V, c2.V) {
		t.Fatal("encryption not deterministic in randomness")
	}

	// Wrong message size
	if _, err := Encrypt(kp.PublicKey, make([]byte, p.K-1), p, rnd); err == nil {
		t.Fatal("accepted wrong message size")
	}
	// Wrong-shape ciphertext
	if Decrypt(&kmosaic.CodeCiphertext{U: c1.U[:3], V: c1.V}, kp.SecretKey, p) != nil {
		t.Fatal("decrypted malformed ciphertext")
	}
}

func TestSerialization(t *testing.T) {
	p := core.CodeHQC256
	seed, _ := utils.SecureRandomBytes(32)
	kp, _ := KeyGen(p, seed)
	msg := make([]byte, p.K)
	rand.New(rand.NewSource(43)).Read(msg)
	rnd, _ := utils.SecureRandomBytes(32)
	ct, _ := Encrypt(kp.PublicKey, msg, p, rnd)

	pkb := SerializePublicKey(kp.PublicKey, p)
	pk2, err := DeserializePublicKey(pkb, p)
	if err != nil {
		t.Fatal(err)
	}
	if !equal(pk2.H, kp.PublicKey.H) || !bytes.Equal(SerializePublicKey(*pk2, p), pkb) {
		t.Fatal("public key round trip failed")
	}
	skb := SerializeSecretKey(kp.SecretKey, p)
	sk2, err := DeserializeSecretKey(skb, p)
	if err != nil {
		t.Fatal(err)
	}
	ctb := SerializeCiphertext(ct, p)
	ct2, err := DeserializeCiphertext(ctb, p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(Decrypt(ct2, *sk2, p), msg) {
		t.Fatal("round-tripped objects do not decrypt")
	}
	t.Logf("pk=%d sk=%d ct=%d bytes", len(pkb), len(skb), len(ctb))

	// Malformed inputs
	if _, err := DeserializePublicKey(pkb[:len(pkb)-1], p); err == nil {
		t.Fatal("accepted truncated pk")
	}
	bad := append([]byte{}, pkb...)
	bad[len(bad)-1] |= 0x80 // padding bit of a 57637-bit vector
	if _, err := DeserializePublicKey(bad, p); err == nil {
		t.Fatal("accepted non-zero padding")
	}
	badSK := append([]byte{}, skb...)
	badSK[0] ^= 0xFF
	if _, err := DeserializeSecretKey(badSK, p); err == nil {
		t.Fatal("accepted secret key with wrong weight")
	}
	if _, err := DeserializeCiphertext(ctb[:10], p); err == nil {
		t.Fatal("accepted truncated ciphertext")
	}
}
