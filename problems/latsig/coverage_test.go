package latsig

import (
	"errors"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

func TestGenerateKeyPair_Coverage(t *testing.T) {
	keys, err := GenerateKeyPair(kmosaic.MOS128)
	if err != nil {
		t.Fatal(err)
	}
	if keys == nil {
		t.Error("keys should not be nil")
	}
}

func TestGenerateKeyPairFromSeed_Coverage(t *testing.T) {
	params, _ := core.GetLatticeSignParams(kmosaic.MOS128)
	seed, _ := utils.SecureRandomBytes(32)
	keys, err := GenerateKeyPairFromSeed(params, seed)
	if err != nil {
		t.Fatal(err)
	}
	if keys == nil {
		t.Error("keys should not be nil")
	}
}

func TestGenerateKeyPairFromSeed_ShortSeed(t *testing.T) {
	params, _ := core.GetLatticeSignParams(kmosaic.MOS128)
	if _, err := GenerateKeyPairFromSeed(params, make([]byte, 10)); err == nil {
		t.Error("expected error for short seed")
	}
}

func TestGenerateKeyPairFromSeed_UnknownParams(t *testing.T) {
	params, _ := core.GetLatticeSignParams(kmosaic.MOS128)
	params.Tau = 50
	params.Beta = params.Tau * params.Eta
	seed, _ := utils.SecureRandomBytes(32)
	if _, err := GenerateKeyPairFromSeed(params, seed); err == nil {
		t.Error("expected error for parameters that match no security level")
	}
}

func TestVerify_Invalid(t *testing.T) {
	keys, _ := GenerateKeyPair(kmosaic.MOS128)
	msg := []byte("hello world")

	sig, _ := Sign(&keys.SecretKey, &keys.PublicKey, msg)
	sig.Challenge[0] ^= 0xFF
	if Verify(&keys.PublicKey, msg, sig) {
		t.Error("modified signature should be invalid")
	}
}

func TestVerify_WrongMessage(t *testing.T) {
	keys, _ := GenerateKeyPair(kmosaic.MOS128)
	msg := []byte("hello world")

	sig, _ := Sign(&keys.SecretKey, &keys.PublicKey, msg)
	if Verify(&keys.PublicKey, []byte("wrong message"), sig) {
		t.Error("signature for wrong message should be invalid")
	}
}

func TestVerify_WrongShape(t *testing.T) {
	keys, _ := GenerateKeyPair(kmosaic.MOS128)
	p := keys.PublicKey.Params

	cases := map[string]*kmosaic.LatticeSignature{
		"short challenge": {Challenge: make([]byte, 10), Z: make([]int32, p.N)},
		"short response":  {Challenge: make([]byte, p.CTildeSize), Z: make([]int32, p.N-1)},
		"nil":             nil,
	}
	for name, sig := range cases {
		if Verify(&keys.PublicKey, []byte("test"), sig) {
			t.Errorf("%s: signature with wrong shape should be invalid", name)
		}
	}
	if Verify(nil, []byte("test"), &kmosaic.LatticeSignature{}) {
		t.Error("nil public key must not verify")
	}
}

func TestSign_BadSecretKey(t *testing.T) {
	keys, _ := GenerateKeyPair(kmosaic.MOS128)
	sk := keys.SecretKey
	sk.S1 = sk.S1[:len(sk.S1)-1]
	if _, err := Sign(&sk, nil, []byte("test")); err == nil {
		t.Error("expected error for malformed secret key")
	}

	sk = keys.SecretKey
	sk.S1 = append([]int8{}, sk.S1...)
	sk.S1[0] = int8(sk.Params.Eta + 1)
	if _, err := Sign(&sk, nil, []byte("test")); err == nil {
		t.Error("expected error for out-of-range secret entry")
	}
}

func TestSign_WithoutPublicKeyAndWithoutCachedMatrix(t *testing.T) {
	keys, _ := GenerateKeyPair(kmosaic.MOS128)
	sk := keys.SecretKey
	sk.A = nil // force re-expansion from rho
	sig, err := Sign(&sk, nil, []byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	pk := keys.PublicKey
	pk.A = nil
	if !Verify(&pk, []byte("test"), sig) {
		t.Error("signature should verify when A is re-expanded on both sides")
	}
}

func TestGenerateKeyPair_RandError(t *testing.T) {
	old := utils.RandReader
	utils.RandReader = &errorReader{}
	defer func() { utils.RandReader = old }()

	if _, err := GenerateKeyPair(kmosaic.MOS128); err == nil {
		t.Error("expected error from rand failure")
	}
}

func TestSign_RandError(t *testing.T) {
	keys, _ := GenerateKeyPair(kmosaic.MOS128)

	old := utils.RandReader
	utils.RandReader = &errorReader{}
	defer func() { utils.RandReader = old }()

	if _, err := Sign(&keys.SecretKey, &keys.PublicKey, []byte("test")); err == nil {
		t.Error("expected error from rand failure")
	}
}

func TestLatticeHelpers(t *testing.T) {
	q := core.LatticeSignQ
	gamma2 := (q - 1) / 32
	alpha := int32(2 * gamma2)

	// decompose reconstructs r and keeps r0 in (-gamma2, gamma2].
	for _, r := range []int32{0, 1, int32(gamma2), int32(gamma2) + 1, alpha, alpha + 5, int32(q - 1), int32(q - 2), int32(q / 2)} {
		r1, r0 := decompose(r, q, gamma2)
		if r0 <= -int32(gamma2) || r0 > int32(gamma2) {
			t.Errorf("decompose(%d): r0=%d out of range", r, r0)
		}
		if modQ(int64(r1)*int64(alpha)+int64(r0), q) != r {
			t.Errorf("decompose(%d): %d*alpha + %d does not reconstruct", r, r1, r0)
		}
	}

	// sampleInBall yields exactly tau non-zero ±1 entries.
	c := sampleInBall([]byte("challenge seed"), 49, 256)
	nz := 0
	for _, v := range c {
		if v != 0 {
			nz++
			if v != 1 && v != -1 {
				t.Errorf("challenge entry %d not in {-1,0,1}", v)
			}
		}
	}
	if nz != 49 {
		t.Errorf("challenge weight %d, want 49", nz)
	}

	// sampleEta stays within [-eta, eta] for both supported eta values.
	for _, eta := range []int{2, 4} {
		for _, v := range sampleEta([]byte("seed"), 0, 10000, eta) {
			if int(v) > eta || int(v) < -eta {
				t.Errorf("eta=%d: sample %d out of range", eta, v)
			}
		}
	}

	// expandMask stays within (-gamma1, gamma1].
	for _, y := range expandMask(make([]byte, 64), 0, 5000, 1<<19) {
		if y <= -(1<<19) || y > 1<<19 {
			t.Errorf("mask entry %d out of range", y)
		}
	}

	// expandA entries are below q.
	for _, a := range expandA(make([]byte, 32), 3, 300, q) {
		if int(a) >= q || a < 0 {
			t.Errorf("matrix entry %d out of range", a)
		}
	}
}

type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("simulated rand error")
}
