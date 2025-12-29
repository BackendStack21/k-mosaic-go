package sign

import (
	"testing"
)

// FuzzDeserializePublicKey tests public key deserialization with random inputs
func FuzzDeserializePublicKey(f *testing.F) {
	// Add seed corpus
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff}) // Max uint32
	f.Add(make([]byte, 16))
	f.Add(make([]byte, 100))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic, may return error
		_, _ = DeserializePublicKey(data)
	})
}

// FuzzDeserializeSecretKey tests secret key deserialization with random inputs
func FuzzDeserializeSecretKey(f *testing.F) {
	// Add seed corpus
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff}) // Max uint32
	f.Add(make([]byte, 16))
	f.Add(make([]byte, 100))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic, may return error
		_, _ = DeserializeSecretKey(data)
	})
}

// FuzzDeserializeSignature tests signature deserialization with random inputs
func FuzzDeserializeSignature(f *testing.F) {
	// Add seed corpus
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) // Minimum valid length
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})             // Max uint32
	f.Add(make([]byte, 16))
	f.Add(make([]byte, 100))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic, may return error
		_, _ = DeserializeSignature(data)
	})
}
