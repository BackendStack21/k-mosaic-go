package slhdsa

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go/v4"
	"github.com/BackendStack21/k-mosaic-go/v4/core"
)

// The vectors in testdata/acvp_shake_f.json.gz are a subset of NIST's ACVP
// sample vectors for SLH-DSA (ACVP-Server, revision FIPS205, downloaded on
// 2026-10-22): key generation, signature
// generation (deterministic and hedged, internal and external "pure"
// interface) and signature verification (valid, modified message, modified
// R, modified FORS part, modified hypertree part) for SLH-DSA-SHAKE-128f and
// SLH-DSA-SHAKE-256f. They enforce bit-exact FIPS 205 conformance of this
// implementation in CI. The composite library signs with the external "pure"
// interface and the fixed context string "kmosaic-v4".
type acvpVectors struct {
	KeyGen []struct {
		ParameterSet          string
		TcID                  int `json:"tcId"`
		SkSeed, SkPrf, PkSeed string
		Pk                    string
	}
	SigGen []struct {
		ParameterSet         string
		TcID                 int `json:"tcId"`
		Deterministic        bool
		SignatureInterface   string
		Sk, Message, Context string
		AdditionalRandomness string
		Signature            string
	}
	SigVer []struct {
		ParameterSet         string
		TcID                 int `json:"tcId"`
		SignatureInterface   string
		Pk, Message, Context string
		Signature            string
		TestPassed           bool
		Reason               string
	}
}

func loadACVP(t *testing.T) *acvpVectors {
	f, err := os.Open("testdata/acvp_shake_f.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var v acvpVectors
	if err := json.NewDecoder(gz).Decode(&v); err != nil {
		t.Fatal(err)
	}
	return &v
}

func acvpParams(t *testing.T, set string) *params {
	var p kmosaic.HashSignParams
	switch set {
	case "SLH-DSA-SHAKE-128f":
		p = core.Hash128Params
	case "SLH-DSA-SHAKE-256f":
		p = core.Hash256Params
	default:
		t.Fatalf("unexpected parameter set %q", set)
	}
	ps, err := newParams(p)
	if err != nil {
		t.Fatal(err)
	}
	return &ps
}

func unhex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// acvpPrefix is the FIPS 205 Algorithm 22 prefix 0x00 || len(ctx) || ctx for
// the external "pure" interface, or nil for the internal interface.
func acvpPrefix(iface string, ctx []byte) []byte {
	if iface == "internal" {
		return nil
	}
	return append([]byte{0x00, byte(len(ctx))}, ctx...)
}

func TestACVP_KeyGen(t *testing.T) {
	v := loadACVP(t)
	for _, tc := range v.KeyGen {
		ps := acvpParams(t, tc.ParameterSet)
		pkSeed := unhex(t, tc.PkSeed)
		root := ps.keyGenRoot(unhex(t, tc.SkSeed), pkSeed, defaultWorkers())
		if got := append(append([]byte{}, pkSeed...), root...); !bytes.Equal(got, unhex(t, tc.Pk)) {
			t.Errorf("%s tcId %d: public key mismatch", tc.ParameterSet, tc.TcID)
		}
	}
}

func TestACVP_SigGen(t *testing.T) {
	v := loadACVP(t)
	for _, tc := range v.SigGen {
		ps := acvpParams(t, tc.ParameterSet)
		n := ps.N
		skb := unhex(t, tc.Sk)
		sk := &kmosaic.HashSignSecretKey{Seed: skb[:n], PRF: skb[n : 2*n], PKSeed: skb[2*n : 3*n], PKRoot: skb[3*n:]}
		optRand := sk.PKSeed // deterministic variant: opt_rand = PK.seed (FIPS 205 Algorithm 19, line 2)
		if !tc.Deterministic {
			optRand = unhex(t, tc.AdditionalRandomness)
		}
		pre := acvpPrefix(tc.SignatureInterface, unhex(t, tc.Context))
		for _, workers := range []int{1, 4} {
			sig, err := ps.signCore(sk, pre, unhex(t, tc.Message), optRand, workers)
			if err != nil {
				t.Fatalf("%s tcId %d: %v", tc.ParameterSet, tc.TcID, err)
			}
			if !bytes.Equal(sig, unhex(t, tc.Signature)) {
				t.Errorf("%s tcId %d (%s, deterministic=%v, workers=%d): signature mismatch",
					tc.ParameterSet, tc.TcID, tc.SignatureInterface, tc.Deterministic, workers)
			}
		}
	}
}

func TestACVP_SigVer(t *testing.T) {
	v := loadACVP(t)
	for _, tc := range v.SigVer {
		ps := acvpParams(t, tc.ParameterSet)
		n := ps.N
		pkb := unhex(t, tc.Pk)
		pk := &kmosaic.HashSignPublicKey{Seed: pkb[:n], Root: pkb[n:]}
		pre := acvpPrefix(tc.SignatureInterface, unhex(t, tc.Context))
		got := ps.verifyCore(pk, pre, unhex(t, tc.Message), unhex(t, tc.Signature))
		if got != tc.TestPassed {
			t.Errorf("%s tcId %d (%s): verify = %v, want %v", tc.ParameterSet, tc.TcID, tc.Reason, got, tc.TestPassed)
		}
	}
}
