// Package kem implements the kMOSAIC Key Encapsulation Mechanism.
//
// Encapsulation splits a 32-byte ephemeral secret into two XOR shares and
// encrypts one with the SLSS component (unstructured LWE with sparse ternary
// secrets) and one with the code component (quasi-cyclic syndrome decoding,
// the HQC construction). Recovering the ephemeral secret requires both
// shares, so the scheme is IND-CPA as long as either component is, and the
// Fujisaki-Okamoto transform (derandomization, re-encryption check, implicit
// rejection) lifts it to IND-CCA in the random-oracle model.
package kem

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/entanglement"
	"github.com/BackendStack21/k-mosaic-go/problems/qcsd"
	"github.com/BackendStack21/k-mosaic-go/problems/slss"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

const (
	DomainSLSS           = "kmosaic-kem-slss-v3"
	DomainCode           = "kmosaic-kem-code-v3"
	DomainSharedSecret   = "kmosaic-kem-ss-v3"
	DomainEncKey         = "kmosaic-enc-key-v3"
	DomainNonce          = "kmosaic-nonce-v3"
	DomainImplicitReject = "kmosaic-kem-reject-v3"

	// shareSize is the length in bytes of the ephemeral secret and of each
	// secret share encrypted by the component schemes.
	shareSize = 32
	numShares = 2

	// MaxComponentSize bounds any length prefix read during deserialization.
	MaxComponentSize = 64 * 1024 * 1024
)

// GenerateKeyPair generates a kMOSAIC key pair.
func GenerateKeyPair(level kmosaic.SecurityLevel) (*kmosaic.MOSAICKeyPair, error) {
	params, err := core.GetParams(level)
	if err != nil {
		return nil, err
	}
	if err := core.ValidateParams(params); err != nil {
		return nil, err
	}

	seed, err := utils.SecureRandomBytes(32)
	if err != nil {
		return nil, err
	}

	kp, err := GenerateKeyPairFromSeed(params, seed)
	utils.Zeroize(seed)
	return kp, err
}

// GenerateKeyPairFromSeed generates a deterministic key pair from seed.
func GenerateKeyPairFromSeed(params kmosaic.MOSAICParams, seed []byte) (*kmosaic.MOSAICKeyPair, error) {
	if len(seed) < 32 {
		return nil, errors.New("seed must be at least 32 bytes")
	}
	if err := utils.ValidateSeedEntropy(seed); err != nil {
		return nil, err
	}
	if err := core.ValidateParams(params); err != nil {
		return nil, err
	}
	if slss.MessageSize(params.SLSS) != shareSize || qcsd.MessageSize(params.Code) != shareSize {
		return nil, errors.New("component parameters do not encrypt 32-byte shares")
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

	binding := entanglement.ComputeBinding(
		slss.SerializePublicKey(slssKP.PublicKey),
		qcsd.SerializePublicKey(codeKP.PublicKey, params.Code),
	)

	publicKey := kmosaic.MOSAICPublicKey{
		SLSS:    slssKP.PublicKey,
		Code:    codeKP.PublicKey,
		Binding: binding,
		Params:  params,
	}
	publicKeyHash := utils.SHA3256(SerializePublicKey(&publicKey))

	secretKey := kmosaic.MOSAICSecretKey{
		SLSS:          slssKP.SecretKey,
		Code:          codeKP.SecretKey,
		Seed:          append([]byte{}, seed...),
		PublicKeyHash: publicKeyHash,
	}
	return &kmosaic.MOSAICKeyPair{PublicKey: publicKey, SecretKey: secretKey}, nil
}

// Encapsulate generates a shared secret and ciphertext.
func Encapsulate(pk *kmosaic.MOSAICPublicKey) (*kmosaic.EncapsulationResult, error) {
	ephemeralSecret, err := utils.SecureRandomBytes(shareSize)
	if err != nil {
		return nil, err
	}
	result, err := EncapsulateDeterministic(pk, ephemeralSecret)
	utils.Zeroize(ephemeralSecret)
	return result, err
}

// EncapsulateDeterministic performs deterministic encapsulation of a fixed
// 32-byte ephemeral secret.
func EncapsulateDeterministic(pk *kmosaic.MOSAICPublicKey, ephemeralSecret []byte) (*kmosaic.EncapsulationResult, error) {
	if len(ephemeralSecret) != shareSize {
		return nil, errors.New("ephemeral secret must be 32 bytes")
	}
	params := pk.Params
	if slss.MessageSize(params.SLSS) != shareSize || qcsd.MessageSize(params.Code) != shareSize {
		return nil, errors.New("component parameters do not encrypt 32-byte shares")
	}

	// Derandomize on the secret and the key binding (FO transform).
	randomness := utils.HashConcat(ephemeralSecret, pk.Binding)
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

	ciphertextHashes := [][]byte{
		utils.SHA3256(serializeSLSSCiphertext(c1)),
		utils.SHA3256(qcsd.SerializeCiphertext(c2, params.Code)),
	}
	proof := entanglement.GenerateNIZKProof(
		ephemeralSecret,
		shares,
		ciphertextHashes,
		utils.HashWithDomain(DomainSLSS+"-nizk", randomness),
	)

	ciphertext := kmosaic.MOSAICCiphertext{C1: *c1, C2: *c2, Proof: proof}

	ctHash := utils.SHA3256(SerializeCiphertext(&ciphertext, params))
	sharedSecret := utils.Shake256(
		utils.HashWithDomain(DomainSharedSecret, utils.HashConcat(ephemeralSecret, ctHash)),
		shareSize,
	)
	return &kmosaic.EncapsulationResult{SharedSecret: sharedSecret, Ciphertext: ciphertext}, nil
}

// Decapsulate recovers the shared secret from a ciphertext. Invalid
// ciphertexts yield a pseudorandom rejection value (implicit rejection).
func Decapsulate(sk *kmosaic.MOSAICSecretKey, pk *kmosaic.MOSAICPublicKey, ct *kmosaic.MOSAICCiphertext) ([]byte, error) {
	params := pk.Params

	if !ciphertextShapeValid(ct, params) {
		return implicitReject(sk, ct, params), nil
	}

	var wg sync.WaitGroup
	var m1, m2 []byte
	wg.Add(2)
	go func() {
		defer wg.Done()
		m1 = slss.Decrypt(&ct.C1, sk.SLSS, params.SLSS)
	}()
	go func() {
		defer wg.Done()
		m2 = qcsd.Decrypt(&ct.C2, sk.Code, params.Code)
	}()
	wg.Wait()
	defer func() {
		utils.Zeroize(m1)
		utils.Zeroize(m2)
	}()
	if m1 == nil || m2 == nil {
		return implicitReject(sk, ct, params), nil
	}

	ephemeralSecret, err := entanglement.SecretReconstruct([][]byte{m1, m2})
	if err != nil {
		return implicitReject(sk, ct, params), nil
	}
	defer utils.Zeroize(ephemeralSecret)

	// Re-encrypt (Fujisaki-Okamoto) and compare without early exit.
	reEnc, err := EncapsulateDeterministic(pk, ephemeralSecret)
	if err != nil {
		return implicitReject(sk, ct, params), nil
	}
	validDecapsulation := 1
	if !utils.ConstantTimeEqual(SerializeCiphertext(ct, params), SerializeCiphertext(&reEnc.Ciphertext, params)) {
		validDecapsulation = 0
	}
	ciphertextHashes := [][]byte{
		utils.SHA3256(serializeSLSSCiphertext(&ct.C1)),
		utils.SHA3256(qcsd.SerializeCiphertext(&ct.C2, params.Code)),
	}
	if !entanglement.VerifyNIZKProof(ct.Proof, ciphertextHashes, ephemeralSecret) {
		validDecapsulation = 0
	}

	rejectSecret := implicitReject(sk, ct, params)
	result := utils.ConstantTimeSelect(validDecapsulation, reEnc.SharedSecret, rejectSecret)
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

// implicitReject returns a deterministic but unpredictable rejection value.
func implicitReject(sk *kmosaic.MOSAICSecretKey, ct *kmosaic.MOSAICCiphertext, params kmosaic.MOSAICParams) []byte {
	return utils.Shake256(
		utils.HashWithDomain(DomainImplicitReject, utils.HashConcat(sk.Seed, SerializeCiphertext(ct, params))),
		shareSize,
	)
}

// Encrypt encrypts a message using KEM + AES-256-GCM.
func Encrypt(pk *kmosaic.MOSAICPublicKey, plaintext []byte) (*kmosaic.EncryptedMessage, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("plaintext cannot be empty")
	}

	result, err := Encapsulate(pk)
	if err != nil {
		return nil, err
	}

	encKey := utils.Shake256(utils.HashWithDomain(DomainEncKey, result.SharedSecret), 32)
	nonce := utils.Shake256(utils.HashWithDomain(DomainNonce, result.SharedSecret), 12)
	defer utils.Zeroize(encKey)
	utils.Zeroize(result.SharedSecret)

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	encrypted := aead.Seal(nil, nonce, plaintext, nil)

	return &kmosaic.EncryptedMessage{Ciphertext: result.Ciphertext, Encrypted: encrypted, Nonce: nonce}, nil
}

// Decrypt decrypts an encrypted message.
func Decrypt(sk *kmosaic.MOSAICSecretKey, pk *kmosaic.MOSAICPublicKey, em *kmosaic.EncryptedMessage) ([]byte, error) {
	sharedSecret, err := Decapsulate(sk, pk, &em.Ciphertext)
	if err != nil {
		return nil, err
	}
	defer utils.Zeroize(sharedSecret)

	encKey := utils.Shake256(utils.HashWithDomain(DomainEncKey, sharedSecret), 32)
	nonce := utils.Shake256(utils.HashWithDomain(DomainNonce, sharedSecret), 12)
	defer utils.Zeroize(encKey)

	if len(em.Encrypted) < 1 {
		return nil, errors.New("ciphertext too short")
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, em.Encrypted, nil)
	if err != nil {
		return nil, errors.New("authentication failed")
	}
	return plaintext, nil
}

// -----------------------------------------------------------------------------
// Serialization
// -----------------------------------------------------------------------------

func appendLV(dst []byte, v []byte) []byte {
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(v)))
	dst = append(dst, lenBuf...)
	return append(dst, v...)
}

func readLV(data []byte, offset int, what string) ([]byte, int, error) {
	if offset+4 > len(data) {
		return nil, offset, fmt.Errorf("invalid %s: missing length", what)
	}
	n := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if n > MaxComponentSize || offset+n > len(data) {
		return nil, offset, fmt.Errorf("invalid %s: truncated", what)
	}
	return data[offset : offset+n], offset + n, nil
}

// SerializePublicKey serializes a public key.
// Format: [level_len:4][level][slss_len:4][slss][code_len:4][code][binding:32]
func SerializePublicKey(pk *kmosaic.MOSAICPublicKey) []byte {
	var result []byte
	result = appendLV(result, []byte(pk.Params.Level))
	result = appendLV(result, slss.SerializePublicKey(pk.SLSS))
	result = appendLV(result, qcsd.SerializePublicKey(pk.Code, pk.Params.Code))
	return append(result, pk.Binding...)
}

// DeserializePublicKey parses a public key and validates its binding.
func DeserializePublicKey(data []byte) (*kmosaic.MOSAICPublicKey, error) {
	levelBytes, offset, err := readLV(data, 0, "public key level")
	if err != nil {
		return nil, err
	}
	params, err := core.GetParams(kmosaic.SecurityLevel(levelBytes))
	if err != nil {
		return nil, fmt.Errorf("invalid public key: unknown security level %q", string(levelBytes))
	}
	slssBytes, offset, err := readLV(data, offset, "public key SLSS component")
	if err != nil {
		return nil, err
	}
	codeBytes, offset, err := readLV(data, offset, "public key code component")
	if err != nil {
		return nil, err
	}
	if len(data) != offset+32 {
		return nil, errors.New("invalid public key: binding has wrong length")
	}
	binding := append([]byte{}, data[offset:]...)

	if !utils.ConstantTimeEqual(binding, entanglement.ComputeBinding(slssBytes, codeBytes)) {
		return nil, errors.New("invalid public key: binding mismatch")
	}

	slssPK, err := slss.DeserializePublicKey(slssBytes, params.SLSS)
	if err != nil {
		return nil, err
	}
	codePK, err := qcsd.DeserializePublicKey(codeBytes, params.Code)
	if err != nil {
		return nil, err
	}
	return &kmosaic.MOSAICPublicKey{SLSS: *slssPK, Code: *codePK, Binding: binding, Params: params}, nil
}

// SerializeSecretKey serializes a secret key.
// Format: [level_len:4][level][s_len:4][S bytes][code_len:4][code sk][seed_len:4][seed][hash_len:4][hash]
func SerializeSecretKey(sk *kmosaic.MOSAICSecretKey, params kmosaic.MOSAICParams) []byte {
	var result []byte
	result = appendLV(result, []byte(params.Level))
	sBytes := make([]byte, len(sk.SLSS.S))
	for i, v := range sk.SLSS.S {
		sBytes[i] = byte(v)
	}
	result = appendLV(result, sBytes)
	result = appendLV(result, qcsd.SerializeSecretKey(sk.Code, params.Code))
	result = appendLV(result, sk.Seed)
	result = appendLV(result, sk.PublicKeyHash)
	return result
}

// DeserializeSecretKey parses a secret key.
func DeserializeSecretKey(data []byte) (*kmosaic.MOSAICSecretKey, error) {
	levelBytes, offset, err := readLV(data, 0, "secret key level")
	if err != nil {
		return nil, err
	}
	params, err := core.GetParams(kmosaic.SecurityLevel(levelBytes))
	if err != nil {
		return nil, fmt.Errorf("invalid secret key: unknown security level %q", string(levelBytes))
	}
	sBytes, offset, err := readLV(data, offset, "secret key SLSS component")
	if err != nil {
		return nil, err
	}
	if len(sBytes) != params.SLSS.L*params.SLSS.N {
		return nil, errors.New("invalid secret key: SLSS dimension mismatch with params")
	}
	sk := &kmosaic.MOSAICSecretKey{}
	sk.SLSS.S = make([]int8, len(sBytes))
	for i, b := range sBytes {
		v := int8(b)
		if v < -1 || v > 1 {
			return nil, errors.New("invalid secret key: SLSS entry not ternary")
		}
		sk.SLSS.S[i] = v
	}
	codeBytes, offset, err := readLV(data, offset, "secret key code component")
	if err != nil {
		return nil, err
	}
	codeSK, err := qcsd.DeserializeSecretKey(codeBytes, params.Code)
	if err != nil {
		return nil, err
	}
	sk.Code = *codeSK
	seed, offset, err := readLV(data, offset, "secret key seed")
	if err != nil {
		return nil, err
	}
	sk.Seed = append([]byte{}, seed...)
	hash, offset, err := readLV(data, offset, "secret key public key hash")
	if err != nil {
		return nil, err
	}
	sk.PublicKeyHash = append([]byte{}, hash...)
	if offset != len(data) {
		return nil, errors.New("invalid secret key: trailing data")
	}
	return sk, nil
}

// SerializeCiphertext serializes a ciphertext.
// Format: [c1_len:4][c1][c2_len:4][c2][proof]
func SerializeCiphertext(ct *kmosaic.MOSAICCiphertext, params kmosaic.MOSAICParams) []byte {
	var result []byte
	result = appendLV(result, serializeSLSSCiphertext(&ct.C1))
	result = appendLV(result, qcsd.SerializeCiphertext(&ct.C2, params.Code))
	return append(result, ct.Proof...)
}

// DeserializeCiphertext parses a ciphertext for the given parameters.
func DeserializeCiphertext(data []byte, params kmosaic.MOSAICParams) (*kmosaic.MOSAICCiphertext, error) {
	c1Bytes, offset, err := readLV(data, 0, "ciphertext C1")
	if err != nil {
		return nil, err
	}
	c2Bytes, offset, err := readLV(data, offset, "ciphertext C2")
	if err != nil {
		return nil, err
	}
	c1, err := deserializeSLSSCiphertext(c1Bytes)
	if err != nil {
		return nil, err
	}
	c2, err := qcsd.DeserializeCiphertext(c2Bytes, params.Code)
	if err != nil {
		return nil, err
	}
	return &kmosaic.MOSAICCiphertext{C1: *c1, C2: *c2, Proof: append([]byte{}, data[offset:]...)}, nil
}

func serializeSLSSCiphertext(ct *kmosaic.SLSSCiphertext) []byte {
	result := make([]byte, 8+4*len(ct.U)+4*len(ct.V))
	binary.LittleEndian.PutUint32(result[0:], uint32(4*len(ct.U)))
	offset := 4
	for i, v := range ct.U {
		binary.LittleEndian.PutUint32(result[offset+i*4:], uint32(v))
	}
	offset += 4 * len(ct.U)
	binary.LittleEndian.PutUint32(result[offset:], uint32(4*len(ct.V)))
	offset += 4
	for i, v := range ct.V {
		binary.LittleEndian.PutUint32(result[offset+i*4:], uint32(v))
	}
	return result
}

func deserializeSLSSCiphertext(data []byte) (*kmosaic.SLSSCiphertext, error) {
	uBytes, offset, err := readLV(data, 0, "SLSS ciphertext U")
	if err != nil {
		return nil, err
	}
	vBytes, offset, err := readLV(data, offset, "SLSS ciphertext V")
	if err != nil {
		return nil, err
	}
	if len(uBytes)%4 != 0 || len(vBytes)%4 != 0 {
		return nil, errors.New("invalid SLSS ciphertext: length not a multiple of 4")
	}
	if offset != len(data) {
		return nil, errors.New("invalid SLSS ciphertext: trailing data")
	}
	ct := &kmosaic.SLSSCiphertext{U: make([]int32, len(uBytes)/4), V: make([]int32, len(vBytes)/4)}
	for i := range ct.U {
		ct.U[i] = int32(binary.LittleEndian.Uint32(uBytes[4*i:]))
	}
	for i := range ct.V {
		ct.V[i] = int32(binary.LittleEndian.Uint32(vBytes[4*i:]))
	}
	return ct, nil
}

// SerializeEncryptedMessage serializes an encrypted message.
// Format: [kemCt_len:4][kemCt][aes_encrypted_data]
func SerializeEncryptedMessage(em *kmosaic.EncryptedMessage, params kmosaic.MOSAICParams) []byte {
	var result []byte
	result = appendLV(result, SerializeCiphertext(&em.Ciphertext, params))
	return append(result, em.Encrypted...)
}

// DeserializeEncryptedMessage parses an encrypted message. The nonce is not
// stored; it is derived from the shared secret during decryption.
func DeserializeEncryptedMessage(data []byte, params kmosaic.MOSAICParams) (*kmosaic.EncryptedMessage, error) {
	ctBytes, offset, err := readLV(data, 0, "encrypted message ciphertext")
	if err != nil {
		return nil, err
	}
	ct, err := DeserializeCiphertext(ctBytes, params)
	if err != nil {
		return nil, err
	}
	return &kmosaic.EncryptedMessage{Ciphertext: *ct, Encrypted: append([]byte{}, data[offset:]...)}, nil
}
