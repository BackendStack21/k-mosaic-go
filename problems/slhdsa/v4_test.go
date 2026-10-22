package slhdsa

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"fmt"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

var paramSets = []struct {
	name string
	p    kmosaic.HashSignParams
	// Known answers produced by the v3 implementation (before the v4
	// rewrite) for katKey and signInternal("kat message", opt_rand = 0x5a..).
	root, sigSHA3 string
}{
	{"128f", core.Hash128Params, "2f94dbe8bfcb4e0044943fbe8154ed85",
		"91739465af48a05a236eb84a21222fdab5f1177b787317cdf226ae4c5e46f34e"},
	{"256f", core.Hash256Params, "0997d0d43907577b2ab4356d71a8ada7601276dd973dfbfa27b2df362b8263c8",
		"aaa40891c7285b9792edfa4d1cb471f4f9babb9bf1aac1af877ee212f9f71ef1"},
}

// katKey builds a key pair from fixed seeds using the new key generation.
func katKey(t testing.TB, ps *params) (*kmosaic.HashSignSecretKey, *kmosaic.HashSignPublicKey) {
	n := ps.N
	sks, prf, pks := make([]byte, n), make([]byte, n), make([]byte, n)
	for i := 0; i < n; i++ {
		sks[i], prf[i], pks[i] = byte(i), byte(0x40+i), byte(0x80+i)
	}
	root := ps.keyGenRoot(sks, pks, defaultWorkers())
	return &kmosaic.HashSignSecretKey{Seed: sks, PRF: prf, PKSeed: pks, PKRoot: root},
		&kmosaic.HashSignPublicKey{Seed: pks, Root: root}
}

func TestKnownAnswers(t *testing.T) {
	for _, tc := range paramSets {
		t.Run(tc.name, func(t *testing.T) {
			ps, _ := newParams(tc.p)
			sk, pk := katKey(t, &ps)
			if hex.EncodeToString(pk.Root) != tc.root {
				t.Fatalf("root %x, want %s", pk.Root, tc.root)
			}
			sig, err := signInternal(sk, &ps, []byte("kat message"), bytes.Repeat([]byte{0x5a}, ps.N))
			if err != nil {
				t.Fatal(err)
			}
			if h := sha3.Sum256(sig); hex.EncodeToString(h[:]) != tc.sigSHA3 {
				t.Fatalf("signature hash %x, want %s", h, tc.sigSHA3)
			}
		})
	}
}

// TestMatchesReference checks that the optimized key generation and
// slh_sign_internal are byte-identical to the v3 implementation (reference
// in ref_v3_test.go), for every worker count, and that the two verifiers
// accept each other's signatures.
func TestMatchesReference(t *testing.T) {
	msgs := [][]byte{{}, []byte("abc"), bytes.Repeat([]byte{0xA5}, 1000)}
	for _, tc := range paramSets {
		t.Run(tc.name, func(t *testing.T) {
			ps, _ := newParams(tc.p)
			rp, _ := refNewParams(tc.p)
			seed, _ := utils.SecureRandomBytes(32)
			kp, err := KeyGen(tc.p, seed)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(refRoot(rp, kp.SecretKey.Seed, kp.PublicKey.Seed), kp.PublicKey.Root) {
				t.Fatal("KeyGen root differs from reference")
			}
			for _, nw := range []int{1, 2, 3, 7} {
				if !bytes.Equal(ps.keyGenRoot(kp.SecretKey.Seed, kp.PublicKey.Seed, nw), kp.PublicKey.Root) {
					t.Fatalf("keyGenRoot with %d workers differs", nw)
				}
			}
			for mi, msg := range msgs {
				optRand, _ := utils.SecureRandomBytes(ps.N)
				want := refSignInternal(&kp.SecretKey, rp, msg, optRand)
				got, err := signInternal(&kp.SecretKey, &ps, msg, optRand)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("msg %d: signature differs from reference", mi)
				}
				for _, nw := range []int{1, 2, 5} {
					seq, err := ps.signCore(&kp.SecretKey, nil, msg, optRand, nw)
					if err != nil || !bytes.Equal(seq, want) {
						t.Fatalf("msg %d: signature with %d workers differs", mi, nw)
					}
				}
				if !verifyInternal(&kp.PublicKey, &ps, msg, want) {
					t.Fatalf("msg %d: reference signature rejected", mi)
				}
				if !refVerifyInternal(&kp.PublicKey, rp, msg, got) {
					t.Fatalf("msg %d: reference verifier rejected signature", mi)
				}
			}
		})
	}
}

// TestPureInterface checks the FIPS 205 pure interface with context
// "kmosaic-v4": M' = 0x00 || len(ctx) || ctx || M.
func TestPureInterface(t *testing.T) {
	for _, tc := range paramSets {
		t.Run(tc.name, func(t *testing.T) {
			ps, _ := newParams(tc.p)
			rp, _ := refNewParams(tc.p)
			seed, _ := utils.SecureRandomBytes(32)
			kp, _ := KeyGen(tc.p, seed)
			msg := []byte("pure interface message")
			mPrime := append([]byte{0x00, byte(len("kmosaic-v4"))}, "kmosaic-v4"...)
			mPrime = append(mPrime, msg...)
			optRand, _ := utils.SecureRandomBytes(ps.N)

			sig, err := signWithRand(&kp.SecretKey, tc.p, msg, optRand)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(sig.Data, refSignInternal(&kp.SecretKey, rp, mPrime, optRand)) {
				t.Fatal("pure signature is not slh_sign_internal(M')")
			}
			if !Verify(&kp.PublicKey, tc.p, msg, sig) || !refVerifyInternal(&kp.PublicKey, rp, mPrime, sig.Data) {
				t.Fatal("pure signature rejected")
			}
			if verifyInternal(&kp.PublicKey, &ps, msg, sig.Data) {
				t.Fatal("pure signature accepted as internal signature on M")
			}
			raw, _ := signInternal(&kp.SecretKey, &ps, msg, optRand)
			if Verify(&kp.PublicKey, tc.p, msg, &kmosaic.HashSignature{Data: raw}) {
				t.Fatal("context-free signature accepted by Verify")
			}

			// Sign is hedged and uses the same interface.
			s1, _ := Sign(&kp.SecretKey, tc.p, msg)
			s2, _ := Sign(&kp.SecretKey, tc.p, msg)
			if bytes.Equal(s1.Data, s2.Data) {
				t.Fatal("Sign is not randomized")
			}
			if !refVerifyInternal(&kp.PublicKey, rp, mPrime, s1.Data) {
				t.Fatal("reference verifier rejected Sign output with context")
			}
		})
	}
}

func TestInvalidInputs(t *testing.T) {
	p := core.Hash128Params
	bad := p
	bad.N = 17
	if _, err := DeserializePublicKey(make([]byte, 34), bad); err == nil {
		t.Fatal("public key accepted with invalid params")
	}
	if _, err := DeserializeSecretKey(make([]byte, 68), bad); err == nil {
		t.Fatal("secret key accepted with invalid params")
	}
	if _, err := DeserializePublicKey(make([]byte, 2*p.N+1), p); err == nil {
		t.Fatal("public key of wrong length accepted")
	}
	if _, err := DeserializeSecretKey(make([]byte, 4*p.N-1), p); err == nil {
		t.Fatal("secret key of wrong length accepted")
	}
	if SignatureSize(bad) != 0 {
		t.Fatal("SignatureSize of invalid params not 0")
	}
	for _, q := range []kmosaic.HashSignParams{{}, {N: 16, H: 66, D: 22, A: 6, K: 33, LgW: 4, M: 35}, {N: 16, H: 66, D: 0, A: 6, K: 33, LgW: 4, M: 34}} {
		if _, err := newParams(q); err == nil {
			t.Fatalf("newParams accepted %+v", q)
		}
	}

	seed, _ := utils.SecureRandomBytes(32)
	kp, _ := KeyGen(p, seed)
	if _, err := Sign(nil, p, []byte("m")); err == nil {
		t.Fatal("nil secret key accepted")
	}
	if _, err := Sign(&kp.SecretKey, bad, []byte("m")); err == nil {
		t.Fatal("invalid params accepted by Sign")
	}
	inconsistent := kp.SecretKey
	inconsistent.PKRoot = append([]byte{}, kp.SecretKey.PKRoot...)
	inconsistent.PKRoot[0] ^= 1
	if _, err := Sign(&inconsistent, p, []byte("m")); err == nil {
		t.Fatal("secret key with wrong PK.root accepted")
	}
	sig, _ := Sign(&kp.SecretKey, p, []byte("m"))
	if Verify(nil, p, []byte("m"), sig) || Verify(&kp.PublicKey, p, []byte("m"), nil) || Verify(&kp.PublicKey, bad, []byte("m"), sig) {
		t.Fatal("Verify accepted nil or invalid input")
	}
	if _, err := KeyGen(p, seed[:31]); err == nil {
		t.Fatal("short seed accepted")
	}
}

func TestVerifyDoesNotAllocate(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("allocation counts are not meaningful in short or race mode")
	}
	for _, tc := range paramSets {
		seed, _ := utils.SecureRandomBytes(32)
		kp, _ := KeyGen(tc.p, seed)
		msg := []byte("allocation")
		sig, _ := Sign(&kp.SecretKey, tc.p, msg)
		Verify(&kp.PublicKey, tc.p, msg, sig)
		if a := testing.AllocsPerRun(20, func() {
			if !Verify(&kp.PublicKey, tc.p, msg, sig) {
				t.Fatal("rejected")
			}
		}); a != 0 {
			t.Errorf("%s: Verify allocates %.1f times", tc.name, a)
		}
	}
}

func BenchmarkSLHDSA(b *testing.B) {
	for _, tc := range paramSets {
		seed := bytes.Repeat([]byte{1}, 32)
		kp, _ := KeyGen(tc.p, seed)
		msg := []byte("benchmark message")
		sig, _ := Sign(&kp.SecretKey, tc.p, msg)
		b.Run(fmt.Sprintf("KeyGen-%s", tc.name), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := KeyGen(tc.p, seed); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("Sign-%s", tc.name), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := Sign(&kp.SecretKey, tc.p, msg); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("SignSequential-%s", tc.name), func(b *testing.B) {
			ps, _ := newParams(tc.p)
			opt := make([]byte, ps.N)
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := ps.signCore(&kp.SecretKey, purePrefix, msg, opt, 1); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("Verify-%s", tc.name), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if !Verify(&kp.PublicKey, tc.p, msg, sig) {
					b.Fatal("rejected")
				}
			}
		})
	}
}
