package latsig

import (
	"bytes"
	"encoding/binary"
	"slices"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go/v4"
	"github.com/BackendStack21/k-mosaic-go/v4/core"
)

// TestReadLength32BitSafe checks the length-prefix helper with prefixes that
// would turn negative if converted to a 32-bit int before the bounds check.
func TestReadLength32BitSafe(t *testing.T) {
	for _, prefix := range []uint32{0xFFFFFFFF, 0x80000000, 0x7FFFFFFF, 5} {
		data := binary.LittleEndian.AppendUint32(nil, prefix)
		data = append(data, 1, 2, 3, 4)
		if _, _, err := readLength(data, 0); err == nil {
			t.Errorf("prefix %#x accepted with 4 bytes remaining", prefix)
		}
	}
	data := binary.LittleEndian.AppendUint32(nil, 4)
	data = append(data, 1, 2, 3, 4)
	if n, next, err := readLength(data, 0); err != nil || n != 4 || next != 8 {
		t.Errorf("exact-length field: n=%d next=%d err=%v", n, next, err)
	}
	for _, off := range []int{-1, 5, 9} {
		if _, _, err := readLength(data, off); err == nil {
			t.Errorf("offset %d accepted", off)
		}
	}
	// The same prefixes through every key parser: an error, never a panic.
	for _, prefix := range []uint32{0xFFFFFFFF, 0x80000000, maxLevelLen + 1} {
		data := binary.LittleEndian.AppendUint32(nil, prefix)
		data = append(data, make([]byte, 64)...)
		if _, err := DeserializePublicKey(data); err == nil {
			t.Errorf("public key with level prefix %#x accepted", prefix)
		}
		if _, err := DeserializeSecretKey(data); err == nil {
			t.Errorf("secret key with level prefix %#x accepted", prefix)
		}
	}
}

func withLevel(level string, rest int) []byte {
	data := binary.LittleEndian.AppendUint32(nil, uint32(len(level)))
	data = append(data, level...)
	return append(data, make([]byte, rest)...)
}

func TestDeserializePublicKey_Rejections(t *testing.T) {
	kp := testKeys(t, kmosaic.MOS128)
	data := SerializePublicKey(&kp.PublicKey)

	pk, err := DeserializePublicKey(data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(SerializePublicKey(pk), data) || !slices.Equal(pk.A, kp.PublicKey.A) || !bytes.Equal(pk.Tr, kp.PublicKey.Tr) {
		t.Fatal("public key round trip lost information")
	}

	for _, cut := range []int{0, 3, 4 + len(kmosaic.MOS128), 4 + len(kmosaic.MOS128) + SeedSize, len(data) / 2, len(data) - 1} {
		if _, err := DeserializePublicKey(data[:cut]); err == nil {
			t.Errorf("public key truncated to %d bytes accepted", cut)
		}
	}
	if _, err := DeserializePublicKey(append(slices.Clone(data), 0)); err == nil {
		t.Error("public key with trailing data accepted")
	}
	if _, err := DeserializePublicKey(withLevel("MOS-512", len(data))); err == nil {
		t.Error("unknown level accepted")
	}
	// A MOS-128 body under the MOS-256 label has the wrong length.
	relabeled := append(withLevel(string(kmosaic.MOS256), 0), data[4+len(kmosaic.MOS128):]...)
	if _, err := DeserializePublicKey(relabeled); err == nil {
		t.Error("public key with mismatched level accepted")
	}
}

func TestSerializePublicKey_Invalid(t *testing.T) {
	kp := testKeys(t, kmosaic.MOS128)
	pk := kp.PublicKey
	pk.T1 = slices.Clone(pk.T1)
	pk.T1[7] = t1Limit
	if SerializePublicKey(&pk) != nil {
		t.Error("T1 entry >= 2^10 serialized")
	}
	pk.T1[7] = -1
	if SerializePublicKey(&pk) != nil {
		t.Error("negative T1 entry serialized")
	}
	pk = kp.PublicKey
	pk.Params.Omega = 1
	if SerializePublicKey(&pk) != nil {
		t.Error("unknown parameters serialized")
	}
	if SerializePublicKey(nil) != nil || SerializeSecretKey(nil) != nil {
		t.Error("nil key serialized")
	}
}

func TestDeserializeSecretKey_Rejections(t *testing.T) {
	for _, level := range levels {
		t.Run(string(level), func(t *testing.T) {
			kp := testKeys(t, level)
			p := kp.SecretKey.Params
			data := SerializeSecretKey(&kp.SecretKey)
			sk, err := DeserializeSecretKey(data)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(SerializeSecretKey(sk), data) ||
				!slices.Equal(sk.S1, kp.SecretKey.S1) || !slices.Equal(sk.S2, kp.SecretKey.S2) ||
				!slices.Equal(sk.T0, kp.SecretKey.T0) || !slices.Equal(sk.A, kp.SecretKey.A) {
				t.Fatal("secret key round trip lost information")
			}
			msg := []byte("parsed key")
			sig, err := Sign(sk, &kp.PublicKey, msg)
			if err != nil || !Verify(&kp.PublicKey, msg, sig) {
				t.Fatalf("parsed secret key does not sign: %v", err)
			}

			for _, cut := range []int{3, 4 + len(level) + SeedSize, len(data) / 2, len(data) - 1} {
				if _, err := DeserializeSecretKey(data[:cut]); err == nil {
					t.Errorf("secret key truncated to %d bytes accepted", cut)
				}
			}
			if _, err := DeserializeSecretKey(append(slices.Clone(data), 0)); err == nil {
				t.Error("secret key with trailing data accepted")
			}

			// Out-of-range packed secret entries in S1 and S2 (all ones is
			// 7 for 3-bit and 15 for 4-bit fields, both above 2·eta).
			start := 4 + len(level) + 2*SeedSize + TrSize
			s1Len := p.N * chalLen * int(etaBits(p.Eta)) / 8
			for _, off := range []int{start, start + s1Len/2, start + s1Len, start + s1Len + 100} {
				bad := slices.Clone(data)
				bad[off] = 0xFF
				if _, err := DeserializeSecretKey(bad); err == nil {
					t.Errorf("out-of-range secret entry at byte %d accepted", off)
				}
			}
			// Smallest invalid value 2·eta+1 in the first entry.
			bad := slices.Clone(data)
			mask := byte(1)<<etaBits(p.Eta) - 1
			bad[start] = bad[start]&^mask | byte(2*p.Eta+1)
			if _, err := DeserializeSecretKey(bad); err == nil {
				t.Error("secret entry 2·eta+1 accepted")
			}
		})
	}
}

func TestSerializeDeserializeSignature(t *testing.T) {
	for _, level := range levels {
		t.Run(string(level), func(t *testing.T) {
			kp := testKeys(t, level)
			p := kp.PublicKey.Params
			msg := []byte("signature encoding")
			sig, err := Sign(&kp.SecretKey, &kp.PublicKey, msg)
			if err != nil {
				t.Fatal(err)
			}
			data := SerializeSignature(sig, p)
			got, err := DeserializeSignature(data, p)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(SerializeSignature(got, p), data) || !slices.Equal(got.Hint, sig.Hint) || !slices.Equal(got.Z, sig.Z) {
				t.Fatal("signature round trip lost information")
			}
			if !Verify(&kp.PublicKey, msg, got) {
				t.Fatal("parsed signature does not verify")
			}
			other := core.Lattice128Params
			if level == kmosaic.MOS128 {
				other = core.Lattice256Params
			}
			if _, err := DeserializeSignature(data, other); err == nil {
				t.Error("signature parsed under the other level")
			}
			if SerializeSignature(sig, other) != nil {
				t.Error("signature serialized under the other level")
			}
		})
	}
}

// TestDeserializeSignature_Canonical builds signatures with chosen hints and
// checks every rule of FIPS 204 HintBitUnpack plus the response bound.
func TestDeserializeSignature_Canonical(t *testing.T) {
	p := core.Lattice128Params
	omega, blocks := p.Omega, p.M/chalLen
	base := &kmosaic.LatticeSignature{
		Challenge: make([]byte, p.CTildeSize),
		Z:         make([]int32, p.N),
		Hint:      []uint16{3, 9, 256, 300, 1535},
	}
	data := SerializeSignature(base, p)
	if len(data) != signatureSize(p) {
		t.Fatalf("size %d", len(data))
	}
	got, err := DeserializeSignature(data, p)
	if err != nil || !slices.Equal(got.Hint, base.Hint) {
		t.Fatalf("hint round trip: %v %v", got, err)
	}
	hintOff := len(data) - omega - blocks
	counts := data[hintOff+omega:]
	if !bytes.Equal(counts, []byte{2, 4, 4, 4, 4, 5}) || !bytes.Equal(data[hintOff:hintOff+5], []byte{3, 9, 0, 44, 255}) {
		t.Fatalf("unexpected hint layout %v %v", data[hintOff:hintOff+5], counts)
	}

	mutate := func(name string, f func(b []byte)) {
		b := slices.Clone(data)
		f(b)
		if _, err := DeserializeSignature(b, p); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	mutate("decreasing counts", func(b []byte) { b[hintOff+omega+1] = 1 })
	mutate("count above omega", func(b []byte) { b[hintOff+omega+blocks-1] = byte(omega + 1) })
	mutate("equal indices in a block", func(b []byte) { b[hintOff+1] = 3 })
	mutate("decreasing indices in a block", func(b []byte) { b[hintOff+1] = 2 })
	mutate("non-zero padding", func(b []byte) { b[hintOff+omega-1] = 1 })
	mutate("response = γ1", func(b []byte) { b[p.CTildeSize] = 0; b[p.CTildeSize+1] = 0; b[p.CTildeSize+2] &^= 0x0F })
	if _, err := DeserializeSignature(data[:len(data)-1], p); err == nil {
		t.Error("truncated signature accepted")
	}
	if _, err := DeserializeSignature(append(slices.Clone(data), 0), p); err == nil {
		t.Error("signature with trailing data accepted")
	}
	bad := p
	bad.Omega = 54
	if _, err := DeserializeSignature(data, bad); err == nil {
		t.Error("unknown parameters accepted")
	}

	// Responses at the bound are rejected; just inside it they are accepted.
	edge := cloneSig(base)
	edge.Z[5] = int32(p.Gamma1 - p.Beta - 1)
	edge.Z[6] = -int32(p.Gamma1 - p.Beta - 1)
	if _, err := DeserializeSignature(SerializeSignature(edge, p), p); err != nil {
		t.Errorf("response inside the bound rejected: %v", err)
	}
	edge.Z[5] = int32(p.Gamma1 - p.Beta)
	if _, err := DeserializeSignature(SerializeSignature(edge, p), p); err == nil {
		t.Error("response at γ1-β accepted")
	}

	// The encoder refuses malformed signatures.
	for name, s := range map[string]*kmosaic.LatticeSignature{
		"unsorted hints": {Challenge: base.Challenge, Z: base.Z, Hint: []uint16{9, 3}},
		"hint >= M":      {Challenge: base.Challenge, Z: base.Z, Hint: []uint16{uint16(p.M)}},
		"short z":        {Challenge: base.Challenge, Z: base.Z[1:]},
		"z beyond γ1":    {Challenge: base.Challenge, Z: append([]int32{-gamma1}, base.Z[1:]...)},
		"nil":            nil,
	} {
		if SerializeSignature(s, p) != nil {
			t.Errorf("%s serialized", name)
		}
	}
}
