package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// TestDecodeStringHexAndBase64 pins the decoding rule directly.
func TestDecodeStringHexAndBase64(t *testing.T) {
	raw := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02}

	hexStr := hex.EncodeToString(raw) // 12 chars: valid base64 syntax as well
	got, err := decodeString(hexStr)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("hex decode: got %x err %v, want %x", got, err, raw)
	}

	b64 := base64.StdEncoding.EncodeToString(raw)
	got, err = decodeString(b64)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("base64 decode: got %x err %v, want %x", got, err, raw)
	}

	if _, err := decodeString("not*valid"); err == nil {
		t.Fatal("expected error for undecodable string")
	}
}
