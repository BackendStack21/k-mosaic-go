package utils

import (
	"testing"
)

func TestSafeMultiply(t *testing.T) {
	// Normal cases
	result, err := SafeMultiply(10, 20)
	if err != nil || result != 200 {
		t.Errorf("SafeMultiply(10, 20) = %d, %v; want 200, nil", result, err)
	}

	// Zero cases
	result, err = SafeMultiply(0, 100)
	if err != nil || result != 0 {
		t.Errorf("SafeMultiply(0, 100) = %d, %v; want 0, nil", result, err)
	}

	// Negative input should error
	_, err = SafeMultiply(-1, 10)
	if err == nil {
		t.Error("SafeMultiply(-1, 10) should return error")
	}

	// Large values that would overflow on 64-bit (need values > sqrt(MaxInt))
	_, err = SafeMultiply(1<<32, 1<<32)
	if err == nil {
		t.Error("SafeMultiply with overflow should return error")
	}
}

func TestSafeMultiply3(t *testing.T) {
	result, err := SafeMultiply3(10, 10, 10)
	if err != nil || result != 1000 {
		t.Errorf("SafeMultiply3(10, 10, 10) = %d, %v; want 1000, nil", result, err)
	}

	// Overflow case - needs to overflow on 64-bit
	_, err = SafeMultiply3(1<<22, 1<<22, 1<<22)
	if err == nil {
		t.Error("SafeMultiply3 with overflow should return error")
	}
}

func TestSafeMakeInt32Slice(t *testing.T) {
	// Valid allocation
	slice, err := SafeMakeInt32Slice(100, MaxVectorLength)
	if err != nil || len(slice) != 100 {
		t.Errorf("SafeMakeInt32Slice(100) failed: %v", err)
	}

	// Exceeds limit
	_, err = SafeMakeInt32Slice(MaxVectorLength+1, MaxVectorLength)
	if err == nil {
		t.Error("SafeMakeInt32Slice exceeding limit should error")
	}

	// Negative count
	_, err = SafeMakeInt32Slice(-1, MaxVectorLength)
	if err == nil {
		t.Error("SafeMakeInt32Slice with negative count should error")
	}
}

func TestCheckLength(t *testing.T) {
	if err := CheckLength(100, 1000); err != nil {
		t.Errorf("CheckLength(100, 1000) should pass: %v", err)
	}

	if err := CheckLength(1001, 1000); err == nil {
		t.Error("CheckLength(1001, 1000) should fail")
	}

	if err := CheckLength(-1, 1000); err == nil {
		t.Error("CheckLength(-1, 1000) should fail")
	}
}

func TestSafeReadLength(t *testing.T) {
	// Valid data
	data := []byte{0x10, 0x00, 0x00, 0x00} // 16 in little-endian
	length, offset, err := SafeReadLength(data, 0, 100)
	if err != nil || length != 16 || offset != 4 {
		t.Errorf("SafeReadLength failed: length=%d, offset=%d, err=%v", length, offset, err)
	}

	// Truncated data
	_, _, err = SafeReadLength([]byte{0x10, 0x00}, 0, 100)
	if err == nil {
		t.Error("SafeReadLength with truncated data should error")
	}

	// Exceeds max
	data = []byte{0xFF, 0xFF, 0xFF, 0x7F} // large value
	_, _, err = SafeReadLength(data, 0, 100)
	if err == nil {
		t.Error("SafeReadLength exceeding max should error")
	}
}

func TestValidateSliceAccess(t *testing.T) {
	data := make([]byte, 100)

	if err := ValidateSliceAccess(data, 0, 50); err != nil {
		t.Errorf("ValidateSliceAccess(0, 50) should pass: %v", err)
	}

	if err := ValidateSliceAccess(data, 90, 20); err == nil {
		t.Error("ValidateSliceAccess(90, 20) should fail (out of bounds)")
	}

	if err := ValidateSliceAccess(data, -1, 10); err == nil {
		t.Error("ValidateSliceAccess with negative offset should fail")
	}
}
