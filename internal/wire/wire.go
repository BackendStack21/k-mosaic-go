// Package wire implements the self-describing byte format shared by every
// serialized kMOSAIC object:
//
//	[magic "kMOS":4][version:1][type:1][level:1][reserved 0:1] followed by the body.
//
// Length-prefixed fields use 32-bit little-endian prefixes and are read with
// bounds checks that are safe on 32-bit platforms (lengths are compared as
// 64-bit values before any conversion to int).
package wire

import (
	"encoding/binary"
	"errors"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
)

// Version is the current format version.
const Version = 4

// HeaderSize is the size of the common header.
const HeaderSize = 8

// Object types.
const (
	TypeKEMPublicKey  = 1
	TypeKEMSecretKey  = 2
	TypeKEMCiphertext = 3
	TypeEncryptedMsg  = 4
	TypeSignPublicKey = 5
	TypeSignSecretKey = 6
	TypeSignature     = 7
)

var magic = [4]byte{'k', 'M', 'O', 'S'}

var (
	ErrHeader  = errors.New("wire: bad header")
	ErrTooLong = errors.New("wire: field exceeds remaining data")
	ErrTrailer = errors.New("wire: trailing data")
)

// LevelByte maps a security level to its header byte.
func LevelByte(level kmosaic.SecurityLevel) (byte, error) {
	switch level {
	case kmosaic.MOS128:
		return 1, nil
	case kmosaic.MOS256:
		return 2, nil
	default:
		return 0, errors.New("wire: unknown security level")
	}
}

// LevelFromByte maps a header byte to its security level.
func LevelFromByte(b byte) (kmosaic.SecurityLevel, error) {
	switch b {
	case 1:
		return kmosaic.MOS128, nil
	case 2:
		return kmosaic.MOS256, nil
	default:
		return "", errors.New("wire: unknown security level byte")
	}
}

// Header builds the common header for an object of the given type and level.
func Header(typ byte, level kmosaic.SecurityLevel) ([]byte, error) {
	lb, err := LevelByte(level)
	if err != nil {
		return nil, err
	}
	h := make([]byte, HeaderSize)
	copy(h, magic[:])
	h[4] = Version
	h[5] = typ
	h[6] = lb
	return h, nil
}

// ParseHeader validates the header of data for the given type and returns the
// security level and the body.
func ParseHeader(data []byte, typ byte) (kmosaic.SecurityLevel, []byte, error) {
	if len(data) < HeaderSize {
		return "", nil, ErrHeader
	}
	if [4]byte{data[0], data[1], data[2], data[3]} != magic || data[4] != Version || data[5] != typ || data[7] != 0 {
		return "", nil, ErrHeader
	}
	level, err := LevelFromByte(data[6])
	if err != nil {
		return "", nil, err
	}
	return level, data[HeaderSize:], nil
}

// AppendLV appends a 32-bit little-endian length prefix and the value.
func AppendLV(dst []byte, v []byte) []byte {
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(v)))
	dst = append(dst, lenBuf[:]...)
	return append(dst, v...)
}

// Reader walks a byte slice of length-prefixed fields.
type Reader struct {
	data []byte
	off  int
}

// NewReader returns a reader positioned at the start of data.
func NewReader(data []byte) *Reader { return &Reader{data: data} }

// LV reads one length-prefixed field. maxLen bounds the accepted length.
func (r *Reader) LV(maxLen int) ([]byte, error) {
	if maxLen < 0 || r.off > len(r.data)-4 {
		return nil, ErrTooLong
	}
	n := uint64(binary.LittleEndian.Uint32(r.data[r.off:]))
	if n > uint64(maxLen) || n > uint64(len(r.data)-r.off-4) {
		// The reader is left in place so that a failed read never looks
		// like a consumed field.
		return nil, ErrTooLong
	}
	start := r.off + 4
	r.off = start + int(n)
	return r.data[start:r.off], nil
}

// Fixed reads exactly n bytes.
func (r *Reader) Fixed(n int) ([]byte, error) {
	if n < 0 || n > len(r.data)-r.off {
		return nil, ErrTooLong
	}
	v := r.data[r.off : r.off+n]
	r.off += n
	return v, nil
}

// Rest returns the remaining bytes and consumes them.
func (r *Reader) Rest() []byte {
	v := r.data[r.off:]
	r.off = len(r.data)
	return v
}

// Done returns an error unless every byte was consumed.
func (r *Reader) Done() error {
	if r == nil || r.off != len(r.data) {
		return ErrTrailer
	}
	return nil
}
