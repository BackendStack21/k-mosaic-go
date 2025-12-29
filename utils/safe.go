// Package utils provides utility functions for kMOSAIC.
// This file contains safe arithmetic and allocation helpers to prevent
// integer overflow and denial-of-service via large allocations.

package utils

import (
	"errors"
	"math"
)

// Maximum allowed lengths for various data types to prevent DoS via large allocations.
const (
	// MaxVectorLength is the maximum allowed length for vectors (e.g., SLSS secret, TDD factors).
	MaxVectorLength = 1 << 20 // 1M elements

	// MaxMatrixElements is the maximum allowed number of elements in a matrix.
	MaxMatrixElements = 1 << 24 // 16M elements

	// MaxTensorElements is the maximum allowed number of elements in a tensor.
	MaxTensorElements = 1 << 26 // 64M elements

	// MaxFactorCount is the maximum allowed number of factors (e.g., TDD rank).
	MaxFactorCount = 1000

	// MaxMessageSize is the maximum allowed message size in bytes.
	MaxMessageSize = 1 << 20 // 1MB

	// MaxPayloadLength is the maximum allowed payload length for serialized data.
	MaxPayloadLength = 1 << 28 // 256MB

	// MaxWalkLength is the maximum allowed walk length for EGRW.
	MaxWalkLength = 1 << 16 // 64K steps
)

var (
	// ErrOverflow indicates an integer overflow occurred.
	ErrOverflow = errors.New("integer overflow")

	// ErrExceedsLimit indicates a value exceeds the allowed limit.
	ErrExceedsLimit = errors.New("value exceeds allowed limit")

	// ErrInvalidLength indicates an invalid length value.
	ErrInvalidLength = errors.New("invalid length")
)

// SafeMultiply multiplies two non-negative integers and returns an error if overflow occurs.
func SafeMultiply(a, b int) (int, error) {
	if a < 0 || b < 0 {
		return 0, ErrInvalidLength
	}
	if a == 0 || b == 0 {
		return 0, nil
	}
	// Check for overflow before multiplying
	if a > math.MaxInt/b {
		return 0, ErrOverflow
	}
	return a * b, nil
}

// SafeMultiply3 multiplies three non-negative integers and returns an error if overflow occurs.
func SafeMultiply3(a, b, c int) (int, error) {
	ab, err := SafeMultiply(a, b)
	if err != nil {
		return 0, err
	}
	return SafeMultiply(ab, c)
}

// SafeMakeInt32Slice creates an int32 slice with bounds checking.
// Returns error if count is negative, exceeds maxAllowed, or would cause overflow.
func SafeMakeInt32Slice(count, maxAllowed int) ([]int32, error) {
	if count < 0 {
		return nil, ErrInvalidLength
	}
	if count > maxAllowed {
		return nil, ErrExceedsLimit
	}
	return make([]int32, count), nil
}

// SafeMakeByteSlice creates a byte slice with bounds checking.
func SafeMakeByteSlice(count, maxAllowed int) ([]byte, error) {
	if count < 0 {
		return nil, ErrInvalidLength
	}
	if count > maxAllowed {
		return nil, ErrExceedsLimit
	}
	return make([]byte, count), nil
}

// SafeMakeIntSlice creates an int slice with bounds checking.
func SafeMakeIntSlice(count, maxAllowed int) ([]int, error) {
	if count < 0 {
		return nil, ErrInvalidLength
	}
	if count > maxAllowed {
		return nil, ErrExceedsLimit
	}
	return make([]int, count), nil
}

// CheckLength validates that length is within [0, maxAllowed].
func CheckLength(length, maxAllowed int) error {
	if length < 0 {
		return ErrInvalidLength
	}
	if length > maxAllowed {
		return ErrExceedsLimit
	}
	return nil
}

// CheckPositive validates that value is > 0.
func CheckPositive(value int, name string) error {
	if value <= 0 {
		return errors.New(name + " must be positive")
	}
	return nil
}

// SafeReadLength reads a uint32 length from data at offset, validates it, and returns the value.
// Returns error if not enough bytes available or length exceeds maxAllowed.
func SafeReadLength(data []byte, offset, maxAllowed int) (length int, newOffset int, err error) {
	if offset < 0 || offset+4 > len(data) {
		return 0, offset, errors.New("truncated length field")
	}
	// Read as uint32 first
	raw := uint32(data[offset]) | uint32(data[offset+1])<<8 | uint32(data[offset+2])<<16 | uint32(data[offset+3])<<24
	// Check against max allowed (also handles potential negative after int cast on 32-bit)
	if raw > uint32(maxAllowed) || (maxAllowed > math.MaxInt32 && int(raw) < 0) {
		return 0, offset, ErrExceedsLimit
	}
	return int(raw), offset + 4, nil
}

// ValidateSliceAccess checks that accessing data[offset:offset+size] is safe.
func ValidateSliceAccess(data []byte, offset, size int) error {
	if offset < 0 || size < 0 {
		return ErrInvalidLength
	}
	if offset+size < offset { // overflow check
		return ErrOverflow
	}
	if offset+size > len(data) {
		return errors.New("slice access out of bounds")
	}
	return nil
}
