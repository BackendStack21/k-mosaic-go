package sign

import (
	"testing"
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
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0})
	f.Add(make([]byte, 100))
	f.Add([]byte{'k', 'M', 'O', 'S', 4, 7, 1, 0, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = DeserializeSignature(data)
	})
}
