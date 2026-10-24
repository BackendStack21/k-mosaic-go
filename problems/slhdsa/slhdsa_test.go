package slhdsa

import (
	"bytes"
	"testing"
	"time"

	kmosaic "github.com/BackendStack21/k-mosaic-go/v2"
	"github.com/BackendStack21/k-mosaic-go/v2/core"
	"github.com/BackendStack21/k-mosaic-go/v2/utils"
)

func TestBase2b(t *testing.T) {
	got := base2b([]byte{0xAB, 0xCD}, 4, 4)
	want := []uint32{0xA, 0xB, 0xC, 0xD}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("base2b nibble %d = %x want %x", i, got[i], want[i])
		}
	}
	got = base2b([]byte{0xFF, 0x00, 0x0F}, 6, 4)
	want = []uint32{0x3F, 0x30, 0x00, 0x0F}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("base2b 6-bit %d = %x want %x", i, got[i], want[i])
		}
	}
}

func TestDerivedParams(t *testing.T) {
	ps, err := newParams(core.Hash128Params)
	if err != nil {
		t.Fatal(err)
	}
	if ps.len1 != 32 || ps.len2 != 3 || ps.hp != 3 {
		t.Fatalf("128f derived params wrong: %+v", ps)
	}
	if SignatureSize(core.Hash128Params) != 17088 {
		t.Fatalf("128f signature size %d, want 17088", SignatureSize(core.Hash128Params))
	}
	ps, _ = newParams(core.Hash256Params)
	if ps.len1 != 64 || ps.len2 != 3 || ps.hp != 4 {
		t.Fatalf("256f derived params wrong: %+v", ps)
	}
	if SignatureSize(core.Hash256Params) != 49856 {
		t.Fatalf("256f signature size %d, want 49856", SignatureSize(core.Hash256Params))
	}
}

func TestWOTS(t *testing.T) {
	ps, _ := newParams(core.Hash128Params)
	skSeed, _ := utils.SecureRandomBytes(ps.N)
	pkSeed, _ := utils.SecureRandomBytes(ps.N)
	w := getWorker(&ps, pkSeed, skSeed)
	defer putWorker(w)
	var a adrs
	a.setLayer(3)
	a.setTree(77)
	pk := make([]byte, ps.N)
	chains := make([]byte, ps.wlen*ps.w*ps.N)
	w.wotsPKGen(&ps, &a, 5, pk, chains)
	msg, _ := utils.SecureRandomBytes(ps.N)
	sig := make([]byte, ps.wlen*ps.N)
	ps.wotsSigFromChains(chains, msg, sig, make([]uint32, ps.wlen))
	got := make([]byte, ps.N)
	w.wotsPKFromSig(&ps, &a, 5, sig, msg, got)
	if !bytes.Equal(got, pk) {
		t.Fatal("WOTS+ pkFromSig mismatch")
	}
	// Agrees with the reference WOTS+ (FIPS 205 Algorithms 6 and 7).
	rp, _ := refNewParams(core.Hash128Params)
	var ra refAdrs
	copy(ra[:], a[:])
	ra.setType(adrsWOTSHash)
	ra.setKeyPair(5)
	if !bytes.Equal(rp.wotsPKGen(skSeed, pkSeed, &ra), pk) {
		t.Fatal("WOTS+ public key differs from reference")
	}
	if !bytes.Equal(rp.wotsSign(msg, skSeed, pkSeed, &ra), sig) {
		t.Fatal("WOTS+ signature differs from reference")
	}
	msg[0] ^= 1
	w.wotsPKFromSig(&ps, &a, 5, sig, msg, got)
	if bytes.Equal(got, pk) {
		t.Fatal("WOTS+ accepted wrong message")
	}
}

func TestXMSS(t *testing.T) {
	ps, _ := newParams(core.Hash128Params)
	skSeed, _ := utils.SecureRandomBytes(ps.N)
	pkSeed, _ := utils.SecureRandomBytes(ps.N)
	w := getWorker(&ps, pkSeed, skSeed)
	defer putWorker(w)
	var a adrs
	a.setLayer(1)
	a.setTree(9)
	n := ps.N
	msg, _ := utils.SecureRandomBytes(n)
	for idx := uint32(0); idx < uint32(ps.leaves); idx++ {
		leaves := make([]byte, ps.leaves*n)
		chains := make([]byte, ps.wlen*ps.w*n)
		for i := 0; i < ps.leaves; i++ {
			var st []byte
			if uint32(i) == idx {
				st = chains
			}
			w.wotsPKGen(&ps, &a, uint32(i), leaves[i*n:(i+1)*n], st)
		}
		sig := make([]byte, ps.xmssSigLen)
		root := make([]byte, n)
		w.xmssTree(&ps, &a, leaves, idx, sig[ps.wlen*n:], root)
		ps.wotsSigFromChains(chains, msg, sig, make([]uint32, ps.wlen))
		got := make([]byte, n)
		w.xmssPKFromSig(&ps, &a, idx, sig, msg, got)
		if !bytes.Equal(got, root) {
			t.Fatalf("XMSS root mismatch for leaf %d", idx)
		}
		rp, _ := refNewParams(core.Hash128Params)
		var ra refAdrs
		copy(ra[:], a[:])
		if !bytes.Equal(rp.xmssSign(msg, skSeed, idx, pkSeed, &ra), sig) {
			t.Fatalf("XMSS signature differs from reference for leaf %d", idx)
		}
		copy(ra[:], a[:])
		if !bytes.Equal(rp.xmssNode(skSeed, 0, uint32(ps.hp), pkSeed, &ra), root) {
			t.Fatal("XMSS root differs from reference")
		}
	}
}

func TestRoundTrip(t *testing.T) {
	for name, p := range map[string]kmosaic.HashSignParams{"128f": core.Hash128Params, "256f": core.Hash256Params} {
		t.Run(name, func(t *testing.T) {
			seed, _ := utils.SecureRandomBytes(32)
			st := time.Now()
			kp, err := KeyGen(p, seed)
			if err != nil {
				t.Fatal(err)
			}
			tk := time.Since(st)
			msg := []byte("hash-based message")
			st = time.Now()
			sig, err := Sign(&kp.SecretKey, p, msg)
			if err != nil {
				t.Fatal(err)
			}
			ts := time.Since(st)
			if len(sig.Data) != SignatureSize(p) {
				t.Fatalf("signature size %d want %d", len(sig.Data), SignatureSize(p))
			}
			st = time.Now()
			if !Verify(&kp.PublicKey, p, msg, sig) {
				t.Fatal("valid signature rejected")
			}
			tv := time.Since(st)
			t.Logf("keygen=%v sign=%v verify=%v sig=%d", tk, ts, tv, len(sig.Data))

			if Verify(&kp.PublicKey, p, []byte("other"), sig) {
				t.Fatal("wrong message accepted")
			}
			for _, pos := range []int{0, p.N + 3, len(sig.Data) / 2, len(sig.Data) - 1} {
				bad := &kmosaic.HashSignature{Data: append([]byte{}, sig.Data...)}
				bad.Data[pos] ^= 1
				if Verify(&kp.PublicKey, p, msg, bad) {
					t.Fatalf("tampered signature (byte %d) accepted", pos)
				}
			}
			if Verify(&kp.PublicKey, p, msg, &kmosaic.HashSignature{Data: sig.Data[:len(sig.Data)-1]}) {
				t.Fatal("truncated signature accepted")
			}

			pk2, err := DeserializePublicKey(SerializePublicKey(&kp.PublicKey), p)
			if err != nil {
				t.Fatal(err)
			}
			sk2, err := DeserializeSecretKey(SerializeSecretKey(&kp.SecretKey), p)
			if err != nil {
				t.Fatal(err)
			}
			sig2, _ := Sign(sk2, p, msg)
			if !Verify(pk2, p, msg, sig2) {
				t.Fatal("round-tripped keys failed")
			}

			// Deterministic key generation
			kp2, _ := KeyGen(p, seed)
			if !bytes.Equal(kp2.PublicKey.Root, kp.PublicKey.Root) {
				t.Fatal("key generation not deterministic")
			}
		})
	}
}
