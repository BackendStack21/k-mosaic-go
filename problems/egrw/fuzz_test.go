package egrw

import (
	"testing"
)

// FuzzDeserializePublicKey tests EGRW public key deserialization with random inputs
func FuzzDeserializePublicKey(f *testing.F) {
	// Add seed corpus
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add(make([]byte, 16))
	f.Add(make([]byte, 32)) // Expected size
	f.Add(make([]byte, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic, may return error
		_, _ = DeserializePublicKey(data)
	})
}

// FuzzBytesToSL2 tests SL2 matrix deserialization with random inputs
func FuzzBytesToSL2(f *testing.F) {
	// Add seed corpus
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add(make([]byte, 8))
	f.Add(make([]byte, 16)) // Expected size
	f.Add(make([]byte, 32))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic
		_ = BytesToSL2(data)
	})
}
