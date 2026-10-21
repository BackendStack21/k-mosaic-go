package sign

import (
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
)

func FuzzDeserializePublicKey(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0})
	f.Add(make([]byte, 100))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DeserializePublicKey(data)
	})
}

func FuzzDeserializeSecretKey(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0})
	f.Add(make([]byte, 100))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DeserializeSecretKey(data)
	})
}

func FuzzDeserializeSignature(f *testing.F) {
	params, _ := core.GetSignParams(kmosaic.MOS_128)
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0})
	f.Add(make([]byte, 100))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DeserializeSignature(data, params)
	})
}
