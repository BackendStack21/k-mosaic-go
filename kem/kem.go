// Package kem implements the kMOSAIC Key Encapsulation Mechanism.
//
// Encapsulation splits a 32-byte ephemeral secret into two XOR shares and
// encrypts one with the SLSS component (unstructured LWE with sparse ternary
// secrets) and one with the code component (quasi-cyclic syndrome decoding,
// the HQC construction). Recovering the ephemeral secret requires both
// shares, so the scheme is IND-CPA as long as either component is, and the
// Fujisaki-Okamoto transform (derandomization on the public key, re-encryption
// check, implicit rejection, no early exits) lifts it to IND-CCA in the
// random-oracle model.
//
// Every serialized object starts with the self-describing header of
// internal/wire, so deserialization needs no parameters.
package kem

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"sync"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/entanglement"
	"github.com/BackendStack21/k-mosaic-go/internal/wire"
	"github.com/BackendStack21/k-mosaic-go/problems/qcsd"
	"github.com/BackendStack21/k-mosaic-go/problems/slss"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

const (
	DomainSLSS         = "kmosaic-kem-slss-v4"
	DomainCode         = "kmosaic-kem-code-v4"
	DomainSharedSecret = "kmosaic-kem-ss-v4"
	DomainEncKey       = "kmosaic-enc-key-v4"
	DomainNonce        = "kmosaic-nonce-v4"
	DomainRejectKey    = "kmosaic-kem-reject-key-v4"
	DomainReject       = "kmosaic-kem-reject-v4"

	// SeedSize is the exact size of a key-generation seed.
	SeedSize = 32
	// SharedSecretSize is the size of the shared secret and of the ephemeral secret.
	SharedSecretSize = 32

	shareSize = 32
	numShares = 2

	// MaxComponentSize bounds any length prefix read during deserialization.
	MaxComponentSize = 16 * 1024 * 1024
)

// GenerateKeyPair generates a kMOSAIC key pair for the given security level.
func GenerateKeyPair(level kmosaic.SecurityLevel) (*kmosaic.MOSAICKeyPair, error) {
	params, err := core.GetParams(level)
	if err != nil {
		return nil, err
	}
	seed, err := utils.SecureRandomBytes(SeedSize)
	if err != nil {
		return nil, err
	}
	defer utils.Zeroize(seed)
	return GenerateKeyPairFromSeed(params, seed)
}

// GenerateKeyPairFromSeed deterministically generates a key pair from a
// 32-byte seed.
func GenerateKeyPairFromSeed(params kmosaic.MOSAICParams, seed []byte) (*kmosaic.MOSAICKeyPair, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("%w: seed must be exactly %d bytes", kmosaic.ErrInvalidKey, SeedSize)
	}
	if err := core.ValidateParams(params); err != nil {
		return nil, fmt.Errorf("%w: %v", kmosaic.ErrInvalidParams, err)
	}
	if _, err := core.GetParams(params.Level); err != nil {
		return nil, fmt.Errorf("%w: %v", kmosaic.ErrInvalidParams, err)
	}
	if slss.MessageSize(params.SLSS) != shareSize || qcsd.MessageSize(params.Code) != shareSize {
		return nil, fmt.Errorf("%w: components must encrypt 32-byte shares", kmosaic.ErrInvalidParams)
	}

	slssSeed := utils.HashWithDomain(DomainSLSS, seed)
	codeSeed := utils.HashWithDomain(DomainCode, seed)
	defer func() {
		utils.Zeroize(slssSeed)
		utils.Zeroize(codeSeed)
	}()

	var wg sync.WaitGroup
	var slssKP *kmosaic.SLSSKeyPair
	var codeKP *kmosaic.CodeKeyPair
	var slssErr, codeErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		slssKP, slssErr = slss.KeyGen(params.SLSS, slssSeed)
	}()
	go func() {
		defer wg.Done()
		codeKP, codeErr = qcsd.KeyGen(params.Code, codeSeed)
	}()
	wg.Wait()
	if slssErr != nil {
		return nil, slssErr
	}
	if codeErr != nil {
		return nil, codeErr
	}

	publicKey := kmosaic.MOSAICPublicKey{
		SLSS:   slssKP.PublicKey,
		Code:   codeKP.PublicKey,
		Params: params,
	}
	publicKey.Binding = entanglement.ComputeBinding(
		slss.SerializePublicKey(publicKey.SLSS),
		qcsd.SerializePublicKey(publicKey.Code, params.Code),
	)
	publicKey.Hash = utils.SHA3256(SerializePublicKey(&publicKey))

	secretKey := kmosaic.MOSAICSecretKey{
		SLSS:          slssKP.SecretKey,
		Code:          codeKP.SecretKey,
		Seed:          append([]byte{}, seed...),
		PublicKeyHash: append([]byte{}, publicKey.Hash...),
	}
	return &kmosaic.MOSAICKeyPair{PublicKey: publicKey, SecretKey: secretKey}, nil
}

// PublicKeyHash returns the cached hash of pk, computing it if necessary.
func PublicKeyHash(pk *kmosaic.MOSAICPublicKey) []byte {
	if len(pk.Hash) == 32 {
		return pk.Hash
	}
	return utils.SHA3256(SerializePublicKey(pk))
}

// Encapsulate generates a shared secret and ciphertext under pk.
func Encapsulate(pk *kmosaic.MOSAICPublicKey) (*kmosaic.EncapsulationResult, error) {
	ephemeralSecret, err := utils.SecureRandomBytes(SharedSecretSize)
	if err != nil {
		return nil, err
	}
	defer utils.Zeroize(ephemeralSecret)
	return EncapsulateDeterministic(pk, ephemeralSecret)
}

// EncapsulateDeterministic encapsulates a caller-chosen 32-byte ephemeral
// secret. It exists for known-answer tests and for the re-encryption step of
// decapsulation; callers must never reuse an ephemeral secret.
func EncapsulateDeterministic(pk *kmosaic.MOSAICPublicKey, ephemeralSecret []byte) (*kmosaic.EncapsulationResult, error) {
	if pk == nil {
		return nil, fmt.Errorf("%w: nil public key", kmosaic.ErrInvalidKey)
	}
	if len(ephemeralSecret) != SharedSecretSize {
		return nil, errors.New("ephemeral secret must be 32 bytes")
	}
	params := pk.Params
	if slss.MessageSize(params.SLSS) != shareSize || qcsd.MessageSize(params.Code) != shareSize {
		return nil, fmt.Errorf("%w: components must encrypt 32-byte shares", kmosaic.ErrInvalidParams)
	}

	// Derandomize on the secret and the public key hash (FO transform).
	randomness := utils.HashConcat(ephemeralSecret, PublicKeyHash(pk))
	defer utils.Zeroize(randomness)

	shares, err := entanglement.SecretShareDeterministic(ephemeralSecret, numShares, randomness)
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, s := range shares {
			utils.Zeroize(s)
		}
	}()

	rand1 := utils.HashWithDomain(DomainSLSS+"-rand", randomness)
	rand2 := utils.HashWithDomain(DomainCode+"-rand", randomness)
	defer func() {
		utils.Zeroize(rand1)
		utils.Zeroize(rand2)
	}()

	var wg sync.WaitGroup
	var c1 *kmosaic.SLSSCiphertext
	var c2 *kmosaic.CodeCiphertext
	var err1, err2 error
	wg.Add(2)
	go func() {
		defer wg.Done()
		c1, err1 = slss.Encrypt(pk.SLSS, shares[0], params.SLSS, rand1)
	}()
	go func() {
		defer wg.Done()
		c2, err2 = qcsd.Encrypt(pk.Code, shares[1], params.Code, rand2)
	}()
	wg.Wait()
	if err1 != nil {
		return nil, err1
	}
	if err2 != nil {
		return nil, err2
	}

	ciphertext := kmosaic.MOSAICCiphertext{C1: *c1, C2: *c2}
	ctBytes := SerializeCiphertext(&ciphertext, params)
	sharedSecret := deriveSharedSecret(ephemeralSecret, ctBytes)
	return &kmosaic.EncapsulationResult{SharedSecret: sharedSecret, Ciphertext: ciphertext}, nil
}

func deriveSharedSecret(ephemeralSecret, ctBytes []byte) []byte {
	return utils.Shake256(
		utils.HashWithDomain(DomainSharedSecret, utils.HashConcat(ephemeralSecret, utils.SHA3256(ctBytes))),
		SharedSecretSize,
	)
}

// Decapsulate recovers the shared secret from a ciphertext. The public key
// must be the one matching sk (checked against the hash stored in sk).
// Invalid ciphertexts yield a pseudorandom rejection value (implicit
// rejection); the amount of work does not depend on where validation fails.
func Decapsulate(sk *kmosaic.MOSAICSecretKey, pk *kmosaic.MOSAICPublicKey, ct *kmosaic.MOSAICCiphertext) ([]byte, error) {
	if sk == nil || pk == nil || ct == nil {
		return nil, fmt.Errorf("%w: nil argument", kmosaic.ErrInvalidKey)
	}
	if len(sk.Seed) != SeedSize || len(sk.PublicKeyHash) != 32 {
		return nil, fmt.Errorf("%w: malformed secret key", kmosaic.ErrInvalidKey)
	}
	if !utils.ConstantTimeEqual(PublicKeyHash(pk), sk.PublicKeyHash) {
		return nil, kmosaic.ErrKeyMismatch
	}
	params := pk.Params

	if !ciphertextShapeValid(ct, params) {
		// The shape of a ciphertext is public information; rejecting here
		// reveals nothing about the key.
		return implicitReject(sk, SerializeCiphertext(ct, params)), nil
	}
	ctBytes := SerializeCiphertext(ct, params)

	var wg sync.WaitGroup
	var m1, m2 []byte
	var ok2 int
	wg.Add(2)
	go func() {
		defer wg.Done()
		m1 = slss.Decrypt(&ct.C1, sk.SLSS, params.SLSS)
	}()
	go func() {
		defer wg.Done()
		m2, ok2 = qcsd.Decrypt(&ct.C2, sk.Code, params.Code)
	}()
	wg.Wait()
	defer func() {
		utils.Zeroize(m1)
		utils.Zeroize(m2)
	}()
	if len(m1) != shareSize || len(m2) != shareSize {
		// Only reachable through a key/parameter mismatch that shape
		// validation already excludes; treated as a rejection.
		return implicitReject(sk, ctBytes), nil
	}

	ephemeralSecret := make([]byte, shareSize)
	for i := range ephemeralSecret {
		ephemeralSecret[i] = m1[i] ^ m2[i]
	}
	defer utils.Zeroize(ephemeralSecret)

	// Re-encrypt and compare without early exit; a code decoding failure is
	// folded into the same constant-time selection.
	valid := ok2
	reEnc, err := EncapsulateDeterministic(pk, ephemeralSecret)
	if err != nil {
		return nil, err
	}
	if !utils.ConstantTimeEqual(ctBytes, SerializeCiphertext(&reEnc.Ciphertext, params)) {
		valid = 0
	}
	rejectSecret := implicitReject(sk, ctBytes)
	result := utils.ConstantTimeSelect(valid, reEnc.SharedSecret, rejectSecret)
	utils.Zeroize(rejectSecret)
	utils.Zeroize(reEnc.SharedSecret)
	return result, nil
}

// ciphertextShapeValid reports whether every component of ct has the
// dimensions that encapsulation under params produces.
func ciphertextShapeValid(ct *kmosaic.MOSAICCiphertext, params kmosaic.MOSAICParams) bool {
	if len(ct.C1.U) != params.SLSS.N || len(ct.C1.V) != params.SLSS.L {
		return false
	}
	if len(ct.C2.U) != (params.Code.N+63)/64 || len(ct.C2.V) != (qcsd.CodeLength(params.Code)+63)/64 {
		return false
	}
	return true
}

// implicitReject returns the rejection value for a ciphertext: a PRF of the
// ciphertext under a key derived from the secret seed.
func implicitReject(sk *kmosaic.MOSAICSecretKey, ctBytes []byte) []byte {
	rejectKey := utils.HashWithDomain(DomainRejectKey, sk.Seed)
	defer utils.Zeroize(rejectKey)
	return utils.Shake256(
		utils.HashWithDomain(DomainReject, utils.HashConcat(rejectKey, utils.SHA3256(ctBytes))),
		SharedSecretSize,
	)
}

// Encrypt encrypts a message (possibly empty) using the KEM and AES-256-GCM.
func Encrypt(pk *kmosaic.MOSAICPublicKey, plaintext []byte) (*kmosaic.EncryptedMessage, error) {
	result, err := Encapsulate(pk)
	if err != nil {
		return nil, err
	}
	defer utils.Zeroize(result.SharedSecret)

	aead, nonce, err := aeadFor(result.SharedSecret)
	if err != nil {
		return nil, err
	}
	encrypted := aead.Seal(nil, nonce, plaintext, nil)
	return &kmosaic.EncryptedMessage{Ciphertext: result.Ciphertext, Encrypted: encrypted}, nil
}

// Decrypt decrypts an encrypted message.
func Decrypt(sk *kmosaic.MOSAICSecretKey, pk *kmosaic.MOSAICPublicKey, em *kmosaic.EncryptedMessage) ([]byte, error) {
	if em == nil {
		return nil, fmt.Errorf("%w: nil message", kmosaic.ErrInvalidCiphertext)
	}
	sharedSecret, err := Decapsulate(sk, pk, &em.Ciphertext)
	if err != nil {
		return nil, err
	}
	defer utils.Zeroize(sharedSecret)

	aead, nonce, err := aeadFor(sharedSecret)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, em.Encrypted, nil)
	if err != nil {
		return nil, kmosaic.ErrAuthentication
	}
	return plaintext, nil
}

// aeadFor derives the AES-256-GCM key and nonce from a shared secret. Each
// encapsulation yields a fresh shared secret, so the nonce is never reused.
func aeadFor(sharedSecret []byte) (cipher.AEAD, []byte, error) {
	encKey := utils.Shake256(utils.HashWithDomain(DomainEncKey, sharedSecret), 32)
	defer utils.Zeroize(encKey)
	nonce := utils.Shake256(utils.HashWithDomain(DomainNonce, sharedSecret), 12)
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	return aead, nonce, nil
}

// -----------------------------------------------------------------------------
// Serialization
// -----------------------------------------------------------------------------

// SerializePublicKey serializes a public key:
// header || [slss_len:4][slss] || [code_len:4][code] || binding:32.
func SerializePublicKey(pk *kmosaic.MOSAICPublicKey) []byte {
	hdr, err := wire.Header(wire.TypeKEMPublicKey, pk.Params.Level)
	if err != nil {
		return nil
	}
	out := hdr
	out = wire.AppendLV(out, slss.SerializePublicKey(pk.SLSS))
	out = wire.AppendLV(out, qcsd.SerializePublicKey(pk.Code, pk.Params.Code))
	return append(out, pk.Binding...)
}

// DeserializePublicKey parses a public key, validates its binding and caches its hash.
func DeserializePublicKey(data []byte) (*kmosaic.MOSAICPublicKey, error) {
	level, body, err := wire.ParseHeader(data, wire.TypeKEMPublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", kmosaic.ErrInvalidKey, err)
	}
	params, _ := core.GetParams(level)
	r := wire.NewReader(body)
	slssBytes, err := r.LV(MaxComponentSize)
	if err != nil {
		return nil, fmt.Errorf("%w: SLSS component: %v", kmosaic.ErrInvalidKey, err)
	}
	codeBytes, err := r.LV(MaxComponentSize)
	if err != nil {
		return nil, fmt.Errorf("%w: code component: %v", kmosaic.ErrInvalidKey, err)
	}
	binding, err := r.Fixed(32)
	if err != nil || r.Done() != nil {
		return nil, fmt.Errorf("%w: binding has wrong length", kmosaic.ErrInvalidKey)
	}
	if !utils.ConstantTimeEqual(binding, entanglement.ComputeBinding(slssBytes, codeBytes)) {
		return nil, fmt.Errorf("%w: binding mismatch", kmosaic.ErrInvalidKey)
	}

	var wg sync.WaitGroup
	var slssPK *kmosaic.SLSSPublicKey
	var codePK *kmosaic.CodePublicKey
	var errS, errC error
	wg.Add(2)
	go func() {
		defer wg.Done()
		slssPK, errS = slss.DeserializePublicKey(slssBytes, params.SLSS)
	}()
	go func() {
		defer wg.Done()
		codePK, errC = qcsd.DeserializePublicKey(codeBytes, params.Code)
	}()
	wg.Wait()
	if errS != nil {
		return nil, fmt.Errorf("%w: %v", kmosaic.ErrInvalidKey, errS)
	}
	if errC != nil {
		return nil, fmt.Errorf("%w: %v", kmosaic.ErrInvalidKey, errC)
	}
	pk := &kmosaic.MOSAICPublicKey{SLSS: *slssPK, Code: *codePK, Binding: append([]byte{}, binding...), Params: params}
	pk.Hash = utils.SHA3256(data)
	return pk, nil
}

// SerializeSecretKey serializes a secret key:
// header || [slss_len:4][slss] || [code_len:4][code] || seed:32 || pkhash:32.
func SerializeSecretKey(sk *kmosaic.MOSAICSecretKey, params kmosaic.MOSAICParams) []byte {
	hdr, err := wire.Header(wire.TypeKEMSecretKey, params.Level)
	if err != nil {
		return nil
	}
	out := hdr
	out = wire.AppendLV(out, slss.SerializeSecretKey(sk.SLSS, params.SLSS))
	out = wire.AppendLV(out, qcsd.SerializeSecretKey(sk.Code, params.Code))
	out = append(out, sk.Seed...)
	return append(out, sk.PublicKeyHash...)
}

// DeserializeSecretKey parses a secret key.
func DeserializeSecretKey(data []byte) (*kmosaic.MOSAICSecretKey, error) {
	level, body, err := wire.ParseHeader(data, wire.TypeKEMSecretKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", kmosaic.ErrInvalidKey, err)
	}
	params, _ := core.GetParams(level)
	r := wire.NewReader(body)
	slssBytes, err := r.LV(MaxComponentSize)
	if err != nil {
		return nil, fmt.Errorf("%w: SLSS component: %v", kmosaic.ErrInvalidKey, err)
	}
	codeBytes, err := r.LV(MaxComponentSize)
	if err != nil {
		return nil, fmt.Errorf("%w: code component: %v", kmosaic.ErrInvalidKey, err)
	}
	seed, err := r.Fixed(SeedSize)
	if err != nil {
		return nil, fmt.Errorf("%w: seed truncated", kmosaic.ErrInvalidKey)
	}
	hash, err := r.Fixed(32)
	if err != nil || r.Done() != nil {
		return nil, fmt.Errorf("%w: public key hash has wrong length", kmosaic.ErrInvalidKey)
	}
	slssSK, err := slss.DeserializeSecretKey(slssBytes, params.SLSS)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", kmosaic.ErrInvalidKey, err)
	}
	codeSK, err := qcsd.DeserializeSecretKey(codeBytes, params.Code)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", kmosaic.ErrInvalidKey, err)
	}
	return &kmosaic.MOSAICSecretKey{
		SLSS:          *slssSK,
		Code:          *codeSK,
		Seed:          append([]byte{}, seed...),
		PublicKeyHash: append([]byte{}, hash...),
	}, nil
}

// SerializeCiphertext serializes a ciphertext: header || [c1_len:4][c1] || [c2_len:4][c2].
func SerializeCiphertext(ct *kmosaic.MOSAICCiphertext, params kmosaic.MOSAICParams) []byte {
	hdr, err := wire.Header(wire.TypeKEMCiphertext, params.Level)
	if err != nil {
		return nil
	}
	out := hdr
	out = wire.AppendLV(out, slss.SerializeCiphertext(&ct.C1, params.SLSS))
	return wire.AppendLV(out, qcsd.SerializeCiphertext(&ct.C2, params.Code))
}

// DeserializeCiphertext parses a ciphertext. The parameters are taken from
// the header; the result is returned together with them.
func DeserializeCiphertext(data []byte) (*kmosaic.MOSAICCiphertext, kmosaic.MOSAICParams, error) {
	level, body, err := wire.ParseHeader(data, wire.TypeKEMCiphertext)
	if err != nil {
		return nil, kmosaic.MOSAICParams{}, fmt.Errorf("%w: %v", kmosaic.ErrInvalidCiphertext, err)
	}
	params, _ := core.GetParams(level)
	r := wire.NewReader(body)
	c1Bytes, err := r.LV(MaxComponentSize)
	if err != nil {
		return nil, params, fmt.Errorf("%w: C1: %v", kmosaic.ErrInvalidCiphertext, err)
	}
	c2Bytes, err := r.LV(MaxComponentSize)
	if err != nil || r.Done() != nil {
		return nil, params, fmt.Errorf("%w: C2 truncated or trailing data", kmosaic.ErrInvalidCiphertext)
	}
	c1, err := slss.DeserializeCiphertext(c1Bytes, params.SLSS)
	if err != nil {
		return nil, params, fmt.Errorf("%w: %v", kmosaic.ErrInvalidCiphertext, err)
	}
	c2, err := qcsd.DeserializeCiphertext(c2Bytes, params.Code)
	if err != nil {
		return nil, params, fmt.Errorf("%w: %v", kmosaic.ErrInvalidCiphertext, err)
	}
	return &kmosaic.MOSAICCiphertext{C1: *c1, C2: *c2}, params, nil
}

// SerializeEncryptedMessage serializes an encrypted message:
// header || [ct_len:4][ciphertext] || payload.
func SerializeEncryptedMessage(em *kmosaic.EncryptedMessage, params kmosaic.MOSAICParams) []byte {
	hdr, err := wire.Header(wire.TypeEncryptedMsg, params.Level)
	if err != nil {
		return nil
	}
	out := hdr
	out = wire.AppendLV(out, SerializeCiphertext(&em.Ciphertext, params))
	return append(out, em.Encrypted...)
}

// DeserializeEncryptedMessage parses an encrypted message.
func DeserializeEncryptedMessage(data []byte) (*kmosaic.EncryptedMessage, kmosaic.MOSAICParams, error) {
	level, body, err := wire.ParseHeader(data, wire.TypeEncryptedMsg)
	if err != nil {
		return nil, kmosaic.MOSAICParams{}, fmt.Errorf("%w: %v", kmosaic.ErrInvalidCiphertext, err)
	}
	params, _ := core.GetParams(level)
	r := wire.NewReader(body)
	ctBytes, err := r.LV(MaxComponentSize)
	if err != nil {
		return nil, params, fmt.Errorf("%w: ciphertext: %v", kmosaic.ErrInvalidCiphertext, err)
	}
	ct, ctParams, err := DeserializeCiphertext(ctBytes)
	if err != nil {
		return nil, params, err
	}
	if ctParams.Level != level {
		return nil, params, fmt.Errorf("%w: level mismatch", kmosaic.ErrInvalidCiphertext)
	}
	return &kmosaic.EncryptedMessage{Ciphertext: *ct, Encrypted: append([]byte{}, r.Rest()...)}, params, nil
}
