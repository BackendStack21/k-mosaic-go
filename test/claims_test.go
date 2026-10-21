package test

import (
	"bytes"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/kem"
	"github.com/BackendStack21/k-mosaic-go/problems/qcsd"
	"github.com/BackendStack21/k-mosaic-go/problems/slss"
	"github.com/BackendStack21/k-mosaic-go/sign"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

// These tests encode the attacks described in SECURITY_ASSESSMENT.md. Each
// one succeeded against the original implementation; they are kept so that
// the corresponding weakness cannot silently return.

// TestClaim_SLSSClusteringAttackFails runs the ciphertext-only bit recovery
// that broke the original SLSS encryption (every v_i shared one inner
// product, so the bits were the two clusters of v) and checks that it now
// performs no better than guessing.
func TestClaim_SLSSClusteringAttackFails(t *testing.T) {
	for _, level := range []kmosaic.SecurityLevel{kmosaic.MOS_128, kmosaic.MOS_256} {
		kp, _ := kem.GenerateKeyPair(level)
		pk := &kp.PublicKey
		q := pk.Params.SLSS.Q

		eph := make([]byte, 32)
		for i := range eph {
			eph[i] = byte(i*13 + 7)
		}
		res, _ := kem.EncapsulateDeterministic(pk, eph)
		// The attacker's target: the SLSS share, which we know here only
		// because we hold the secret key.
		share := slss.Decrypt(&res.Ciphertext.C1, kp.SecretKey.SLSS, pk.Params.SLSS)

		v := res.Ciphertext.C1.V
		correct := 0
		for j := range v {
			d := int(v[j]) - int(v[0])
			d = ((d % q) + q) % q
			bit := byte(0)
			if d > q/4 && d < 3*q/4 {
				bit = 1
			}
			if bit == (share[j/8]>>(j%8))&1 {
				correct++
			}
		}
		if correct > 3*len(v)/4 || correct < len(v)/4 {
			t.Fatalf("%s: clustering attack recovered %d/%d bits", level, correct, len(v))
		}
	}
}

// TestClaim_ComponentsRequireSecretKeys checks that neither KEM component
// decrypts with the wrong secret key. In the original design two of three
// components decrypted with an empty key.
func TestClaim_ComponentsRequireSecretKeys(t *testing.T) {
	kp, _ := kem.GenerateKeyPair(kmosaic.MOS_128)
	other, _ := kem.GenerateKeyPair(kmosaic.MOS_128)
	pk := &kp.PublicKey
	share := make([]byte, 32)
	for i := range share {
		share[i] = byte(i)
	}
	rnd, _ := utils.SecureRandomBytes(32)

	c1, _ := slss.Encrypt(pk.SLSS, share, pk.Params.SLSS, rnd)
	if bytes.Equal(slss.Decrypt(c1, other.SecretKey.SLSS, pk.Params.SLSS), share) {
		t.Fatal("SLSS ciphertext decrypted with an unrelated secret key")
	}
	c2, _ := qcsd.Encrypt(pk.Code, share, pk.Params.Code, rnd)
	if got := qcsd.Decrypt(c2, other.SecretKey.Code, pk.Params.Code); got != nil && bytes.Equal(got, share) {
		t.Fatal("code ciphertext decrypted with an unrelated secret key")
	}
	if got := qcsd.Decrypt(c2, kmosaic.CodeSecretKey{X: make([]uint64, len(kp.SecretKey.Code.X)), Y: make([]uint64, len(kp.SecretKey.Code.Y))}, pk.Params.Code); got != nil && bytes.Equal(got, share) {
		t.Fatal("code ciphertext decrypted with an empty secret key")
	}
}

// TestClaim_SignatureForgeryFails runs the universal forgery that worked
// against the original scheme in its closest analogue: a signature made of
// arbitrary component data, and a signature whose components are each valid
// but come from a different key pair.
func TestClaim_SignatureForgeryFails(t *testing.T) {
	kp, _ := sign.GenerateKeyPair(kmosaic.MOS_128)
	other, _ := sign.GenerateKeyPair(kmosaic.MOS_128)
	pk := &kp.PublicKey
	msg := []byte("I owe the attacker one million dollars")

	junk, _ := sign.Sign(&other.SecretKey, &other.PublicKey, msg)
	if sign.Verify(pk, msg, junk) {
		t.Fatal("signature from another key pair accepted")
	}

	real, _ := sign.Sign(&kp.SecretKey, pk, msg)
	// Replace one component at a time with the other key's component.
	mixed := *real
	mixed.Lattice = junk.Lattice
	if sign.Verify(pk, msg, &mixed) {
		t.Fatal("mixed lattice component accepted")
	}
	mixed = *real
	mixed.MQ = junk.MQ
	if sign.Verify(pk, msg, &mixed) {
		t.Fatal("mixed MQ component accepted")
	}
	mixed = *real
	mixed.Hash = junk.Hash
	if sign.Verify(pk, msg, &mixed) {
		t.Fatal("mixed hash component accepted")
	}
	if !sign.Verify(pk, msg, real) {
		t.Fatal("genuine signature rejected")
	}
}
