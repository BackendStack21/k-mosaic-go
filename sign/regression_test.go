package sign

import (
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

// TestForgeryWithoutSecretKeyFails reproduces the attack that broke the
// original kMOSAIC signature: with the old scheme Verify only recomputed the
// challenge hash from public data, so any (commitment, H(commitment, msg, pk),
// junk) triple verified. The lattice scheme must reject every such attempt.
func TestForgeryWithoutSecretKeyFails(t *testing.T) {
	kp, err := GenerateKeyPair(kmosaic.MOS_128)
	if err != nil {
		t.Fatal(err)
	}
	pk := &kp.PublicKey
	p := pk.Params
	msg := []byte("I owe the attacker one million dollars")

	// Attempt 1: random challenge with a zero response.
	forged := &kmosaic.MOSAICSignature{Challenge: make([]byte, p.CTildeSize), Z: make([]int32, p.N)}
	if Verify(pk, msg, forged) {
		t.Fatal("zero signature verified")
	}

	// Attempt 2: pick z first, compute the challenge the verifier would derive
	// for it (the strategy that worked against the old scheme), and present it.
	z := make([]int32, p.N)
	for i := range z {
		z[i] = int32(i%7) - 3
	}
	tr := shake(TrSize, SerializePublicKey(pk))
	mu := shake(TrSize, tr, msg)
	w := matVec(pk.A, z, p.M, p.N, p.Q)
	guess := shake(p.CTildeSize, mu, packW1(highBits(w, p.Q, p.Gamma2)))
	forged = &kmosaic.MOSAICSignature{Challenge: guess, Z: z}
	if Verify(pk, msg, forged) {
		t.Fatal("challenge-first forgery verified")
	}

	// Attempt 3: random signatures.
	for i := 0; i < 8; i++ {
		c, _ := utils.SecureRandomBytes(p.CTildeSize)
		if Verify(pk, msg, &kmosaic.MOSAICSignature{Challenge: c, Z: z}) {
			t.Fatal("random signature verified")
		}
	}
}
