package latsig

import (
	"bytes"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
)

// FuzzDeserializePublicKey checks that parsing never panics and that every
// accepted encoding is canonical (re-serializes to the same bytes).
func FuzzDeserializePublicKey(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff}) // max uint32 length prefix
	f.Add([]byte{7, 0, 0, 0, 'M', 'O', 'S', '-', '1', '2', '8'})
	f.Add(make([]byte, 100))

	f.Fuzz(func(t *testing.T, data []byte) {
		pk, err := DeserializePublicKey(data)
		if err == nil && !bytes.Equal(SerializePublicKey(pk), data) {
			t.Fatal("accepted a non-canonical public key encoding")
		}
	})
}

// FuzzDeserializeSecretKey checks that parsing never panics and that every
// accepted encoding is canonical.
func FuzzDeserializeSecretKey(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff}) // max uint32 length prefix
	f.Add([]byte{7, 0, 0, 0, 'M', 'O', 'S', '-', '2', '5', '6'})
	f.Add(make([]byte, 100))

	f.Fuzz(func(t *testing.T, data []byte) {
		sk, err := DeserializeSecretKey(data)
		if err == nil && !bytes.Equal(SerializeSecretKey(sk), data) {
			t.Fatal("accepted a non-canonical secret key encoding")
		}
	})
}

// FuzzDeserializeSignature checks that parsing never panics and that every
// accepted encoding is canonical, at both levels.
func FuzzDeserializeSignature(f *testing.F) {
	for _, params := range []kmosaic.LatticeSignParams{core.Lattice128Params, core.Lattice256Params} {
		f.Add(SerializeSignature(&kmosaic.LatticeSignature{
			Challenge: make([]byte, params.CTildeSize),
			Z:         make([]int32, params.N),
			Hint:      []uint16{1, 2, 300, uint16(params.M - 1)},
		}, params))
	}
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add(make([]byte, 100))

	f.Fuzz(func(t *testing.T, data []byte) {
		for _, params := range []kmosaic.LatticeSignParams{core.Lattice128Params, core.Lattice256Params} {
			sig, err := DeserializeSignature(data, params)
			if err != nil {
				continue
			}
			if !bytes.Equal(SerializeSignature(sig, params), data) {
				t.Fatal("accepted a non-canonical signature encoding")
			}
			if !checkHints(sig.Hint, params) || normU(sig.Z) >= uint32(params.Gamma1-params.Beta) {
				t.Fatal("parsed an out-of-range signature")
			}
		}
	})
}
