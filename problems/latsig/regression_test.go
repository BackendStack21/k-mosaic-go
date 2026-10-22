package latsig

import (
	"slices"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

// TestForgeryWithoutSecretKeyFails reproduces the attack that broke the
// original kMOSAIC signature: with the old scheme Verify only recomputed the
// challenge hash from public data, so any (commitment, H(commitment, msg, pk),
// junk) triple verified. The lattice scheme must reject every such attempt,
// including ones that abuse the hint vector.
func TestForgeryWithoutSecretKeyFails(t *testing.T) {
	kp := testKeys(t, kmosaic.MOS128)
	pk := &kp.PublicKey
	p := pk.Params
	msg := []byte("I owe the attacker one million dollars")

	// Attempt 1: zero challenge with a zero response and no hints.
	forged := &kmosaic.LatticeSignature{Challenge: make([]byte, p.CTildeSize), Z: make([]int32, p.N)}
	if Verify(pk, msg, forged) {
		t.Fatal("zero signature verified")
	}

	// Attempt 2: pick z first and hash HighBits(A·z), the strategy that
	// worked against the old scheme (it ignores the -T1·c·2^d term).
	z := make([]int32, p.N)
	for i := range z {
		z[i] = int32(i%7) - 3
	}
	mu := shake(TrSize, pk.Tr, msg)
	w := make([]int32, p.M)
	matVec(pk.A, z, nil, p.M, p.N, w)
	w1 := make([]int32, p.M)
	for i, v := range w {
		w1[i] = highBits(v)
	}
	w1p := make([]byte, p.M/2)
	packW1(w1, w1p)
	guess := shake(p.CTildeSize, mu, w1p)
	if Verify(pk, msg, &kmosaic.LatticeSignature{Challenge: guess, Z: z}) {
		t.Fatal("challenge-first forgery verified")
	}

	// Attempt 3: random challenges, and random hint vectors of maximal weight.
	for i := 0; i < 8; i++ {
		c, _ := utils.SecureRandomBytes(p.CTildeSize)
		hint := make([]uint16, 0, p.Omega)
		for j := 0; j < p.Omega; j++ {
			hint = append(hint, uint16(j*(p.M/p.Omega)+i))
		}
		if Verify(pk, msg, &kmosaic.LatticeSignature{Challenge: c, Z: z}) ||
			Verify(pk, msg, &kmosaic.LatticeSignature{Challenge: c, Z: z, Hint: hint}) {
			t.Fatal("random signature verified")
		}
	}
}

// TestSignatureMalleability checks that every component of a valid signature
// is bound: changing the challenge, any response entry, or the hint set
// invalidates it, as does moving it to another key or message.
func TestSignatureMalleability(t *testing.T) {
	kp := testKeys(t, kmosaic.MOS128)
	pk := &kp.PublicKey
	msg := []byte("message")
	sig, err := Sign(&kp.SecretKey, pk, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(pk, msg, sig) {
		t.Fatal("valid signature rejected")
	}
	if Verify(pk, []byte("wrong"), sig) {
		t.Error("signature verified for another message")
	}

	bad := cloneSig(sig)
	bad.Challenge[0] ^= 1
	if Verify(pk, msg, bad) {
		t.Error("modified challenge verified")
	}
	for _, idx := range []int{0, len(sig.Z) / 2, len(sig.Z) - 1} {
		bad = cloneSig(sig)
		bad.Z[idx]++
		if Verify(pk, msg, bad) {
			t.Errorf("modified response at %d verified", idx)
		}
	}

	if len(sig.Hint) == 0 {
		t.Log("signature has no hints; skipping hint mutations")
	} else {
		bad = cloneSig(sig)
		bad.Hint = bad.Hint[1:]
		if Verify(pk, msg, bad) {
			t.Error("signature with a dropped hint verified")
		}
	}
	// Adding a hint flips HighBits at that index, so it must invalidate the
	// signature (for any index not already set).
	for _, idx := range []uint16{0, uint16(pk.Params.M / 2), uint16(pk.Params.M - 1)} {
		if slices.Contains(sig.Hint, idx) || len(sig.Hint) >= pk.Params.Omega {
			continue
		}
		bad = cloneSig(sig)
		bad.Hint = append(bad.Hint, idx)
		slices.Sort(bad.Hint)
		if Verify(pk, msg, bad) {
			t.Errorf("signature with an extra hint at %d verified", idx)
		}
	}

	other, err := GenerateKeyPair(kmosaic.MOS128)
	if err != nil {
		t.Fatal(err)
	}
	if Verify(&other.PublicKey, msg, sig) {
		t.Error("signature verified under a different public key")
	}
	if _, err := Sign(&kp.SecretKey, &other.PublicKey, msg); err == nil {
		t.Error("Sign accepted a public key that does not match the secret key")
	}
}
