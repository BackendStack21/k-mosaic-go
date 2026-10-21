package uov

import (
	"bytes"
	"testing"
	"time"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

// slowMul multiplies in GF(2^8) bit by bit, independent of the tables.
func slowMul(a, b byte) byte {
	var r byte
	for i := 0; i < 8; i++ {
		if b&1 == 1 {
			r ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1B
		}
		b >>= 1
	}
	return r
}

func TestGF(t *testing.T) {
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			if gfMul(byte(a), byte(b)) != slowMul(byte(a), byte(b)) {
				t.Fatalf("gfMul(%d,%d) = %d want %d", a, b, gfMul(byte(a), byte(b)), slowMul(byte(a), byte(b)))
			}
		}
		if a != 0 && gfMul(byte(a), gfInv(byte(a))) != 1 {
			t.Fatalf("inverse of %d wrong", a)
		}
	}
}

func TestTriIndex(t *testing.T) {
	d := 7
	idx := 0
	for r := 0; r < d; r++ {
		for c := r; c < d; c++ {
			if triIndex(d, r, c) != idx {
				t.Fatalf("triIndex(%d,%d)=%d want %d", r, c, triIndex(d, r, c), idx)
			}
			idx++
		}
	}
	if idx != triSize(d) {
		t.Fatal("triSize mismatch")
	}
}

func TestSolve(t *testing.T) {
	m := 5
	L := []byte{1, 2, 3, 4, 5, 0, 1, 7, 9, 2, 3, 0, 1, 4, 4, 9, 9, 0, 1, 5, 6, 7, 8, 9, 1}
	x := []byte{3, 1, 4, 1, 5}
	y := make([]byte, m)
	for r := 0; r < m; r++ {
		for c := 0; c < m; c++ {
			y[r] ^= gfMul(L[r*m+c], x[c])
		}
	}
	got, ok := solve(L, y, m)
	if !ok || !bytes.Equal(got, x) {
		t.Fatalf("solve returned %v ok=%v", got, ok)
	}
	if _, ok := solve(make([]byte, m*m), y, m); ok {
		t.Fatal("singular system reported solvable")
	}
}

func TestOilSpaceVanishes(t *testing.T) {
	p := core.MQ128Params
	seed, _ := utils.SecureRandomBytes(32)
	kp, err := KeyGen(p, seed)
	if err != nil {
		t.Fatal(err)
	}
	v, m := p.N-p.M, p.M
	// Every public form must vanish on (O x, x) for random x.
	for trial := 0; trial < 20; trial++ {
		x, _ := utils.SecureRandomBytes(m)
		s := make([]byte, p.N)
		for r := 0; r < v; r++ {
			var acc byte
			for j := 0; j < m; j++ {
				acc ^= gfMul(kp.SecretKey.O[r*m+j], x[j])
			}
			s[r] = acc
		}
		copy(s[v:], x)
		for i, val := range Evaluate(&kp.PublicKey, p, s) {
			if val != 0 {
				t.Fatalf("form %d does not vanish on the oil space", i)
			}
		}
	}
}

func TestRoundTrip(t *testing.T) {
	for name, p := range map[string]kmosaic.MQParams{"uov-Ip": core.MQ128Params, "uov-V": core.MQ256Params} {
		t.Run(name, func(t *testing.T) {
			seed, _ := utils.SecureRandomBytes(32)
			st := time.Now()
			kp, err := KeyGen(p, seed)
			if err != nil {
				t.Fatal(err)
			}
			tk := time.Since(st)
			msg := []byte("multivariate message")
			st = time.Now()
			sig, err := Sign(&kp.SecretKey, p, msg)
			if err != nil {
				t.Fatal(err)
			}
			ts := time.Since(st)
			st = time.Now()
			if !Verify(&kp.PublicKey, p, msg, sig) {
				t.Fatal("valid signature rejected")
			}
			tv := time.Since(st)
			t.Logf("keygen=%v sign=%v verify=%v pk=%d sig=%d", tk, ts, tv, len(SerializePublicKey(&kp.PublicKey)), len(SerializeSignature(sig)))

			if Verify(&kp.PublicKey, p, []byte("other"), sig) {
				t.Fatal("wrong message accepted")
			}
			bad := &kmosaic.MQSignature{S: append([]byte{}, sig.S...), Salt: append([]byte{}, sig.Salt...)}
			bad.S[0] ^= 1
			if Verify(&kp.PublicKey, p, msg, bad) {
				t.Fatal("tampered signature accepted")
			}
			bad = &kmosaic.MQSignature{S: append([]byte{}, sig.S...), Salt: append([]byte{}, sig.Salt...)}
			bad.Salt[0] ^= 1
			if Verify(&kp.PublicKey, p, msg, bad) {
				t.Fatal("tampered salt accepted")
			}

			// Serialization
			pk2, err := DeserializePublicKey(SerializePublicKey(&kp.PublicKey), p)
			if err != nil {
				t.Fatal(err)
			}
			sig2, err := DeserializeSignature(SerializeSignature(sig), p)
			if err != nil {
				t.Fatal(err)
			}
			if !Verify(pk2, p, msg, sig2) {
				t.Fatal("round-tripped signature rejected")
			}
			sk2, err := DeserializeSecretKey(SerializeSecretKey(&kp.SecretKey), p)
			if err != nil {
				t.Fatal(err)
			}
			sig3, _ := Sign(sk2, p, msg)
			if !Verify(&kp.PublicKey, p, msg, sig3) {
				t.Fatal("signature from deserialized secret key rejected")
			}
			if _, err := DeserializePublicKey([]byte{1, 2}, p); err == nil {
				t.Fatal("accepted short pk")
			}
			if _, err := DeserializeSignature([]byte{1, 2}, p); err == nil {
				t.Fatal("accepted short signature")
			}
		})
	}
}
