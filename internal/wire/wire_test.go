package wire

import (
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go/v4"
)

func TestHeaderRoundTrip(t *testing.T) {
	h, err := Header(TypeKEMCiphertext, kmosaic.MOS256)
	if err != nil {
		t.Fatal(err)
	}
	level, body, err := ParseHeader(append(h, 1, 2, 3), TypeKEMCiphertext)
	if err != nil || level != kmosaic.MOS256 || len(body) != 3 {
		t.Fatalf("round trip failed: %v %v %d", err, level, len(body))
	}
	if _, _, err := ParseHeader(h, TypeSignature); err == nil {
		t.Fatal("wrong type accepted")
	}
	bad := append([]byte{}, h...)
	bad[4] = 3
	if _, _, err := ParseHeader(bad, TypeKEMCiphertext); err == nil {
		t.Fatal("wrong version accepted")
	}
	bad = append([]byte{}, h...)
	bad[6] = 9
	if _, _, err := ParseHeader(bad, TypeKEMCiphertext); err == nil {
		t.Fatal("unknown level accepted")
	}
	if _, _, err := ParseHeader(h[:5], TypeKEMCiphertext); err == nil {
		t.Fatal("short header accepted")
	}
}

func TestReaderHugeLength(t *testing.T) {
	// A 0xFFFFFFFF prefix must be rejected on every platform, never sliced.
	r := NewReader([]byte{0xff, 0xff, 0xff, 0xff, 1, 2, 3})
	if _, err := r.LV(1 << 30); err == nil {
		t.Fatal("huge length accepted")
	}
	r = NewReader([]byte{0x00, 0x00, 0x00, 0x80, 1, 2, 3})
	if _, err := r.LV(1 << 30); err == nil {
		t.Fatal("2^31 length accepted")
	}
	r = NewReader(AppendLV(nil, []byte{9, 9}))
	v, err := r.LV(10)
	if err != nil || len(v) != 2 || r.Done() != nil {
		t.Fatal("valid field rejected")
	}
	r = NewReader(append(AppendLV(nil, []byte{9}), 0))
	if _, err := r.LV(10); err != nil {
		t.Fatal(err)
	}
	if r.Done() == nil {
		t.Fatal("trailing byte accepted")
	}
}
