package kmosaic

import "errors"

// Sentinel errors returned by the composite KEM and signature packages.
// Component-specific detail is wrapped around them with fmt.Errorf("%w: ...").
var (
	// ErrInvalidKey is returned when a serialized key cannot be parsed or fails validation.
	ErrInvalidKey = errors.New("kmosaic: invalid key")
	// ErrInvalidCiphertext is returned when a serialized ciphertext cannot be parsed.
	ErrInvalidCiphertext = errors.New("kmosaic: invalid ciphertext")
	// ErrInvalidSignature is returned when a serialized signature cannot be parsed.
	ErrInvalidSignature = errors.New("kmosaic: invalid signature")
	// ErrKeyMismatch is returned when a secret key is used with a public key it does not belong to.
	ErrKeyMismatch = errors.New("kmosaic: public key does not match secret key")
	// ErrAuthentication is returned when AEAD decryption fails.
	ErrAuthentication = errors.New("kmosaic: authentication failed")
	// ErrInvalidParams is returned when a parameter set fails validation.
	ErrInvalidParams = errors.New("kmosaic: invalid parameters")
	// ErrMessageTooLarge is returned when a plaintext exceeds the AEAD limit.
	ErrMessageTooLarge = errors.New("kmosaic: message too large")
)
