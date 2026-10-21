package test

import (
	"bytes"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/entanglement"
	"github.com/BackendStack21/k-mosaic-go/kem"
	"github.com/BackendStack21/k-mosaic-go/problems/egrw"
	"github.com/BackendStack21/k-mosaic-go/problems/tdd"
	"github.com/BackendStack21/k-mosaic-go/sign"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

// These tests encode the attacks described in SECURITY_ASSESSMENT.md. Each one
// succeeded against the original implementation; they are kept so that the
// corresponding weakness cannot silently return.

// TestClaim_KEMCiphertextOnlyAttackFails runs the ciphertext-only recovery of
// the shared secret (TDD and EGRW shares are public; SLSS bits were readable
// as two clusters of v) and checks that it no longer works.
func TestClaim_KEMCiphertextOnlyAttackFails(t *testing.T) {
	for _, level := range []kmosaic.SecurityLevel{kmosaic.MOS_128, kmosaic.MOS_256} {
		kp, _ := kem.GenerateKeyPair(level)
		pk := &kp.PublicKey
		res, _ := kem.Encapsulate(pk)
		ct := &res.Ciphertext
		q := pk.Params.SLSS.Q

		// Shares 2 and 3 are still recoverable without the secret key (documented).
		share2 := tdd.Decrypt(&ct.C2, kmosaic.TDDSecretKey{}, pk.TDD, pk.Params.TDD)
		share3 := egrw.Decrypt(&ct.C3, kmosaic.EGRWSecretKey{}, pk.EGRW, pk.Params.EGRW)

		v := ct.C1.V
		bits := make([]byte, len(v))
		for i := range v {
			d := int(v[i]) - int(v[0])
			d = ((d % q) + q) % q
			if d > q/4 && d < 3*q/4 {
				bits[i] = 1
			}
		}
		candidates := [][]byte{make([]byte, len(v)/8), make([]byte, len(v)/8)}
		for i, b := range bits {
			candidates[0][i/8] |= b << (i % 8)
			candidates[1][i/8] |= (b ^ 1) << (i % 8)
		}
		for _, share1 := range candidates {
			eph, err := entanglement.SecretReconstruct([][]byte{share1, share2, share3})
			if err != nil {
				continue
			}
			re, err := kem.EncapsulateDeterministic(pk, eph)
			if err != nil {
				continue
			}
			if bytes.Equal(re.SharedSecret, res.SharedSecret) {
				t.Fatalf("%s: shared secret recovered from public key and ciphertext alone", level)
			}
		}
	}
}

// TestClaim_SignatureForgeryFails runs the universal forgery that worked
// against the original scheme (any commitment, recomputed challenge, junk
// response) in its closest analogue for the lattice scheme.
func TestClaim_SignatureForgeryFails(t *testing.T) {
	kp, _ := sign.GenerateKeyPair(kmosaic.MOS_128)
	pk := &kp.PublicKey
	p := pk.Params
	msg := []byte("I owe the attacker one million dollars")

	for i := 0; i < 4; i++ {
		c, _ := utils.SecureRandomBytes(p.CTildeSize)
		z := make([]int32, p.N)
		for j := range z {
			z[j] = int32(j*(i+1)%11) - 5
		}
		if sign.Verify(pk, msg, &kmosaic.MOSAICSignature{Challenge: c, Z: z}) {
			t.Fatal("forged signature accepted")
		}
	}
}

// TestClaim_EGRWPathIsRecoverable documents (rather than fixes) that the EGRW
// "secret" walk is not secret: SL(2, Z_1021) has about 10^9 elements and a
// breadth-first search finds a walk from VStart to VEnd in milliseconds.
// This is why EGRW contributes nothing to the security of the KEM.
func TestClaim_EGRWPathIsRecoverable(t *testing.T) {
	params := kmosaic.EGRWParams{P: 1021, K: 128}
	seed, _ := utils.SecureRandomBytes(32)
	kp, _ := egrw.KeyGen(params, seed)
	p := params.P
	gens := egrw.GetGenerators(p)

	type node struct {
		v   kmosaic.SL2Element
		par int
		gen int
	}
	start := kp.PublicKey.VStart
	nodes := []node{{v: start, par: -1}}
	seen := map[kmosaic.SL2Element]int{start: 0}
	found := -1
	for i := 0; i < len(nodes) && found < 0 && len(nodes) < 20_000_000; i++ {
		for g := 0; g < 4; g++ {
			nv := egrw.SL2Multiply(nodes[i].v, gens[g], p)
			if _, ok := seen[nv]; ok {
				continue
			}
			seen[nv] = len(nodes)
			nodes = append(nodes, node{v: nv, par: i, gen: g})
			if nv == kp.PublicKey.VEnd {
				found = len(nodes) - 1
				break
			}
		}
	}
	if found < 0 {
		t.Fatal("search budget exhausted (unexpected for p=1021)")
	}
	var walk []int
	for i := found; nodes[i].par >= 0; i = nodes[i].par {
		walk = append([]int{nodes[i].gen}, walk...)
	}
	if egrw.ApplyWalk(start, walk, p) != kp.PublicKey.VEnd {
		t.Fatal("recovered walk does not reach VEnd")
	}
	t.Logf("EGRW: equivalent walk of length %d found after visiting %d vertices", len(walk), len(nodes))
}

// TestClaim_TDDAndEGRWDecryptWithoutSecretKey documents that the TDD and EGRW
// component ciphertexts are decryptable with an empty secret key.
func TestClaim_TDDAndEGRWDecryptWithoutSecretKey(t *testing.T) {
	kp, _ := kem.GenerateKeyPair(kmosaic.MOS_128)
	pk := &kp.PublicKey
	share := make([]byte, 32)
	for i := range share {
		share[i] = byte(i)
	}
	rnd, _ := utils.SecureRandomBytes(32)

	c2, _ := tdd.Encrypt(pk.TDD, share, pk.Params.TDD, rnd)
	if !bytes.Equal(tdd.Decrypt(c2, kmosaic.TDDSecretKey{}, pk.TDD, pk.Params.TDD), share) {
		t.Log("TDD ciphertext no longer decrypts without the secret key")
	} else {
		t.Log("TDD ciphertext decrypts with an empty secret key (known, documented)")
	}
	c3, _ := egrw.Encrypt(pk.EGRW, share, pk.Params.EGRW, rnd)
	if !bytes.Equal(egrw.Decrypt(c3, kmosaic.EGRWSecretKey{}, pk.EGRW, pk.Params.EGRW), share) {
		t.Log("EGRW ciphertext no longer decrypts without the secret key")
	} else {
		t.Log("EGRW ciphertext decrypts with an empty secret key (known, documented)")
	}
}
