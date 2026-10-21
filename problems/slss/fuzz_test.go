package slss

import (
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
)

// FuzzDeserializePublicKey tests public key deserialization with random inputs
func FuzzDeserializePublicKey(f *testing.F) {
	params, _ := core.GetParams(kmosaic.MOS_128)
	small := params.SLSS
	small.N, small.M, small.W, small.L = 8, 8, 2, 8

	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add(make([]byte, 36))
	f.Add(make([]byte, 36+2*64))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic, may return error
		_, _ = DeserializePublicKey(data, small)
	})
}
