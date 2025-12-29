package entanglement

import (
	"testing"
)

// FuzzDeserializeNIZKProof tests NIZK proof deserialization with random inputs
func FuzzDeserializeNIZKProof(f *testing.F) {
	// Add seed corpus
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add(make([]byte, 16))
	f.Add(make([]byte, 32)) // Expected size
	f.Add(make([]byte, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic
		_ = DeserializeNIZKProof(data)
	})
}
