// Package kem implements the Key Encapsulation Mechanism for kMOSAIC.
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
	"github.com/BackendStack21/k-mosaic-go/problems/egrw"
	"github.com/BackendStack21/k-mosaic-go/problems/slss"
	"github.com/BackendStack21/k-mosaic-go/problems/tdd"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

const (
	DomainSLSS           = "kmosaic-kem-slss-v1"
	DomainTDD            = "kmosaic-kem-tdd-v1"
	DomainEGRW           = "kmosaic-kem-egrw-v1"
	DomainSharedSecret   = "kmosaic-kem-ss-v1"
	DomainEncKey         = "kmosaic-enc-key-v1"
	DomainNonce          = "kmosaic-nonce-v1"
	DomainImplicitReject = "kmosaic-kem-reject-v1"
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

	// Derive component seeds
	slssSeed := utils.HashWithDomain(DomainSLSS, seed)
	tddSeed := utils.HashWithDomain(DomainTDD, seed)
	egrwSeed := utils.HashWithDomain(DomainEGRW, seed)
	defer func() {
		utils.Zeroize(slssSeed)
		utils.Zeroize(tddSeed)
		utils.Zeroize(egrwSeed)
	}()

	// Generate component keys in parallel
	var wg sync.WaitGroup
	var slssKP *kmosaic.SLSSKeyPair
	var tddKP *kmosaic.TDDKeyPair
	var egrwKP *kmosaic.EGRWKeyPair
	var slssErr, tddErr, egrwErr error

	wg.Add(3)
	go func() {
		defer wg.Done()
		slssKP, slssErr = slss.KeyGen(params.SLSS, slssSeed)
	}()
	go func() {
		defer wg.Done()
		tddKP, tddErr = tdd.KeyGen(params.TDD, tddSeed)
	}()
	go func() {
		defer wg.Done()
		egrwKP, egrwErr = egrw.KeyGen(params.EGRW, egrwSeed)
	}()
	wg.Wait()

	if slssErr != nil {
		return nil, slssErr
	}
	if tddErr != nil {
		return nil, tddErr
	}
	if egrwErr != nil {
		return nil, egrwErr
	}

	// Compute binding
	slssBytes := slss.SerializePublicKey(slssKP.PublicKey)
	tddBytes := tdd.SerializePublicKey(tddKP.PublicKey)
	egrwBytes := egrw.SerializePublicKey(egrwKP.PublicKey)
	binding := entanglement.ComputeBinding(slssBytes, tddBytes, egrwBytes)

	publicKey := kmosaic.MOSAICPublicKey{
		SLSS:    slssKP.PublicKey,
		TDD:     tddKP.PublicKey,
		EGRW:    egrwKP.PublicKey,
		Binding: binding,
		Params:  params,
	}

	publicKeyHash := utils.SHA3256(SerializePublicKey(&publicKey))

	secretKey := kmosaic.MOSAICSecretKey{
		SLSS:          slssKP.SecretKey,
		TDD:           tddKP.SecretKey,
		EGRW:          egrwKP.SecretKey,
		Seed:          append([]byte{}, seed...),
		PublicKeyHash: publicKeyHash,
	}

	return &kmosaic.MOSAICKeyPair{
		PublicKey: publicKey,
		SecretKey: secretKey,
	}, nil
}

// Encapsulate generates a shared secret and ciphertext.
func Encapsulate(pk *kmosaic.MOSAICPublicKey) (*kmosaic.EncapsulationResult, error) {
	ephemeralSecret, err := utils.SecureRandomBytes(32)
	if err != nil {
		return nil, err
	}
	result, err := EncapsulateDeterministic(pk, ephemeralSecret)
	utils.Zeroize(ephemeralSecret)
	return result, err
}

// EncapsulateDeterministic performs deterministic encapsulation.
func EncapsulateDeterministic(pk *kmosaic.MOSAICPublicKey, ephemeralSecret []byte) (*kmosaic.EncapsulationResult, error) {
	if len(ephemeralSecret) != 32 {
		return nil, errors.New("ephemeral secret must be 32 bytes")
	}

	params := pk.Params

	// Derive randomness
	randomness := utils.HashConcat(ephemeralSecret, pk.Binding)

	// Split secret into 3 shares
	shares, err := entanglement.SecretShareDeterministic(ephemeralSecret, 3, randomness)
	if err != nil {
		return nil, err
	}

	// Encrypt shares in parallel
	var wg sync.WaitGroup
	var c1 *kmosaic.SLSSCiphertext
	var c2 *kmosaic.TDDCiphertext
	var c3 *kmosaic.EGRWCiphertext
	var err1, err2, err3 error

	rand1 := utils.HashWithDomain(DomainSLSS+"-rand", randomness)
	rand2 := utils.HashWithDomain(DomainTDD+"-rand", randomness)
	rand3 := utils.HashWithDomain(DomainEGRW+"-rand", randomness)

	wg.Add(3)
	go func() {
		defer wg.Done()
		c1, err1 = slss.Encrypt(pk.SLSS, shares[0], params.SLSS, rand1)
	}()
	go func() {
		defer wg.Done()
		c2, err2 = tdd.Encrypt(pk.TDD, shares[1], params.TDD, rand2)
	}()
	go func() {
		defer wg.Done()
		c3, err3 = egrw.Encrypt(pk.EGRW, shares[2], params.EGRW, rand3)
	}()
	wg.Wait()

	if err1 != nil {
		return nil, err1
	}
	if err2 != nil {
		return nil, err2
	}
	if err3 != nil {
		return nil, err3
	}

	// Generate NIZK proof (must happen BEFORE zeroizing shares and randomness)
	ciphertextHashes := [][]byte{
		utils.SHA3256(serializeSLSSCiphertext(c1)),
		utils.SHA3256(serializeTDDCiphertext(c2)),
		utils.SHA3256(serializeEGRWCiphertext(c3)),
	}
	proof := entanglement.GenerateNIZKProof(
		ephemeralSecret,
		shares,
		ciphertextHashes,
		utils.HashWithDomain(DomainSLSS+"-nizk", randomness),
	)

	// Zeroize shares and randomness after NIZK proof generation
	for _, share := range shares {
		utils.Zeroize(share)
	}
	utils.Zeroize(randomness)

	ciphertext := kmosaic.MOSAICCiphertext{
		C1:    *c1,
		C2:    *c2,
		C3:    *c3,
		Proof: proof,
	}

	// Derive shared secret
	ctHash := utils.SHA3256(SerializeCiphertext(&ciphertext))
	sharedSecret := utils.Shake256(
		utils.HashWithDomain(DomainSharedSecret, utils.HashConcat(ephemeralSecret, ctHash)),
		32,
	)

	return &kmosaic.EncapsulationResult{
		SharedSecret: sharedSecret,
		Ciphertext:   ciphertext,
	}, nil
}

// Decapsulate recovers the shared secret from a ciphertext.
func Decapsulate(sk *kmosaic.MOSAICSecretKey, pk *kmosaic.MOSAICPublicKey, ct *kmosaic.MOSAICCiphertext) ([]byte, error) {
	params := pk.Params

	// Decrypt shares in parallel
	var wg sync.WaitGroup
	var m1, m2, m3 []byte
	defer func() {
		utils.Zeroize(m1)
		utils.Zeroize(m2)
		utils.Zeroize(m3)
	}()

	wg.Add(3)
	go func() {
		defer wg.Done()
		m1 = slss.Decrypt(&ct.C1, sk.SLSS, params.SLSS)
	}()
	go func() {
		defer wg.Done()
		m2 = tdd.Decrypt(&ct.C2, sk.TDD, pk.TDD, params.TDD)
	}()
	go func() {
		defer wg.Done()
		m3 = egrw.Decrypt(&ct.C3, sk.EGRW, pk.EGRW, params.EGRW)
	}()
	wg.Wait()

	// Reconstruct secret
	shares := [][]byte{m1, m2, m3}
	ephemeralSecret, err := entanglement.SecretReconstruct(shares)
	if err != nil {
		return implicitReject(sk, ct), nil
	}
	defer utils.Zeroize(ephemeralSecret)

	// Re-encrypt to verify (Fujisaki-Okamoto)
	reEncResult, err := EncapsulateDeterministic(pk, ephemeralSecret)
	if err != nil {
		return implicitReject(sk, ct), nil
	}

	// Compare ciphertexts in constant time; do NOT return early to avoid timing leaks
	originalCT := SerializeCiphertext(ct)
	reEncCT := SerializeCiphertext(&reEncResult.Ciphertext)
	validDecapsulation := 1
	if !utils.ConstantTimeEqual(originalCT, reEncCT) {
		validDecapsulation = 0
	}

	// Verify NIZK proof using recovered ephemeral secret (post-reconstruction)
	ciphertextHashes := [][]byte{
		utils.SHA3256(serializeSLSSCiphertext(&ct.C1)),
		utils.SHA3256(serializeTDDCiphertext(&ct.C2)),
		utils.SHA3256(serializeEGRWCiphertext(&ct.C3)),
	}
	if !entanglement.VerifyNIZKProof(ct.Proof, ciphertextHashes, ephemeralSecret) {
		validDecapsulation = 0
	}

	// Constant-time select between correct shared secret and implicit reject
	correctSecret := reEncResult.SharedSecret
	rejectSecret := implicitReject(sk, ct)
	result := utils.ConstantTimeSelect(validDecapsulation, correctSecret, rejectSecret)

	// Zeroize temporary secrets
	utils.Zeroize(rejectSecret)
	utils.Zeroize(correctSecret)

	return result, nil
}

// implicitReject returns a deterministic but unpredictable rejection value.
func implicitReject(sk *kmosaic.MOSAICSecretKey, ct *kmosaic.MOSAICCiphertext) []byte {
	return utils.Shake256(
		utils.HashWithDomain(DomainImplicitReject, utils.HashConcat(sk.Seed, SerializeCiphertext(ct))),
		32,
	)
}

// Encrypt encrypts a message using KEM+DEM.
func Encrypt(pk *kmosaic.MOSAICPublicKey, plaintext []byte) (*kmosaic.EncryptedMessage, error) {
	result, err := Encapsulate(pk)
	if err != nil {
		return nil, err
	}

	// Derive encryption key and nonce
	encKey := utils.Shake256(utils.HashWithDomain(DomainEncKey, result.SharedSecret), 32)
	nonce := utils.Shake256(utils.HashWithDomain(DomainNonce, result.SharedSecret), 12)
	defer utils.Zeroize(encKey)

	// AEAD encryption using AES-256-GCM
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	encrypted := aead.Seal(nil, nonce, plaintext, nil)

	return &kmosaic.EncryptedMessage{
		Ciphertext: result.Ciphertext,
		Encrypted:  encrypted,
		Nonce:      nonce,
	}, nil
}

// Decrypt decrypts an encrypted message.
func Decrypt(sk *kmosaic.MOSAICSecretKey, pk *kmosaic.MOSAICPublicKey, em *kmosaic.EncryptedMessage) ([]byte, error) {
	sharedSecret, err := Decapsulate(sk, pk, &em.Ciphertext)
	if err != nil {
		return nil, err
	}

	// Derive encryption key and nonce
	encKey := utils.Shake256(utils.HashWithDomain(DomainEncKey, sharedSecret), 32)
	nonce := utils.Shake256(utils.HashWithDomain(DomainNonce, sharedSecret), 12)
	defer utils.Zeroize(encKey)

	// AEAD decryption using AES-256-GCM
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

// SerializePublicKey serializes a public key.
// Format: [level_len:4][level_string][slss_len:4][slss_data][tdd_len:4][tdd_data][egrw_len:4][egrw_data][binding:32]
func SerializePublicKey(pk *kmosaic.MOSAICPublicKey) []byte {
	slssBytes := slss.SerializePublicKey(pk.SLSS)
	tddBytes := tdd.SerializePublicKey(pk.TDD)
	egrwBytes := egrw.SerializePublicKey(pk.EGRW)

	// Serialize security level as string
	levelStr := string(pk.Params.Level)
	levelBytes := []byte(levelStr)

	result := make([]byte, 0, 16+len(levelBytes)+len(slssBytes)+len(tddBytes)+len(egrwBytes)+32)

	// Length prefixes buffer
	lenBuf := make([]byte, 4)

	// Security level string
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(levelBytes)))
	result = append(result, lenBuf...)
	result = append(result, levelBytes...)

	// SLSS component
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(slssBytes)))
	result = append(result, lenBuf...)
	result = append(result, slssBytes...)

	// TDD component
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(tddBytes)))
	result = append(result, lenBuf...)
	result = append(result, tddBytes...)

	// EGRW component
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(egrwBytes)))
	result = append(result, lenBuf...)
	result = append(result, egrwBytes...)

	// Binding (fixed 32 bytes, no length prefix)
	result = append(result, pk.Binding...)

	return result
}

// SerializeCiphertext serializes a ciphertext.
// Format: [c1_len:4][c1_data][c2_len:4][c2_data][c3_len:4][c3_data][proof_data]
// Note: proof has no length prefix - it extends to end of buffer
func SerializeCiphertext(ct *kmosaic.MOSAICCiphertext) []byte {
	c1Bytes := serializeSLSSCiphertext(&ct.C1)
	c2Bytes := serializeTDDCiphertext(&ct.C2)
	c3Bytes := serializeEGRWCiphertext(&ct.C3)

	result := make([]byte, 0, 12+len(c1Bytes)+len(c2Bytes)+len(c3Bytes)+len(ct.Proof))

	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(c1Bytes)))
	result = append(result, lenBuf...)
	result = append(result, c1Bytes...)

	binary.LittleEndian.PutUint32(lenBuf, uint32(len(c2Bytes)))
	result = append(result, lenBuf...)
	result = append(result, c2Bytes...)

	binary.LittleEndian.PutUint32(lenBuf, uint32(len(c3Bytes)))
	result = append(result, lenBuf...)
	result = append(result, c3Bytes...)

	// Proof has no length prefix - just append to end (matching Node implementation)
	result = append(result, ct.Proof...)

	return result
}

func serializeSLSSCiphertext(ct *kmosaic.SLSSCiphertext) []byte {
	uBytes := len(ct.U) * 4
	vBytes := len(ct.V) * 4
	result := make([]byte, 8+uBytes+vBytes)
	// Write byte lengths (not element counts)
	binary.LittleEndian.PutUint32(result[0:], uint32(uBytes))
	offset := 4
	for i, v := range ct.U {
		binary.LittleEndian.PutUint32(result[offset+i*4:], uint32(v))
	}
	offset += uBytes
	binary.LittleEndian.PutUint32(result[offset:], uint32(vBytes))
	offset += 4
	for i, v := range ct.V {
		binary.LittleEndian.PutUint32(result[offset+i*4:], uint32(v))
	}
	return result
}

func serializeTDDCiphertext(ct *kmosaic.TDDCiphertext) []byte {
	dataBytes := len(ct.Data) * 4
	result := make([]byte, 4+dataBytes)
	// Write byte length (not element count)
	binary.LittleEndian.PutUint32(result[0:], uint32(dataBytes))
	for i, v := range ct.Data {
		binary.LittleEndian.PutUint32(result[4+i*4:], uint32(v))
	}
	return result
}

func serializeEGRWCiphertext(ct *kmosaic.EGRWCiphertext) []byte {
	vertexBytes := egrw.SL2ToBytes(ct.Vertex)
	result := make([]byte, len(vertexBytes)+len(ct.Commitment))
	copy(result, vertexBytes)
	copy(result[len(vertexBytes):], ct.Commitment)
	return result
}

// SerializeSecretKey serializes a secret key.
func SerializeSecretKey(sk *kmosaic.MOSAICSecretKey) []byte {
	result := make([]byte, 0)
	lenBuf := make([]byte, 4)

	// SLSS secret key (sparse vector)
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(sk.SLSS.S)))
	result = append(result, lenBuf...)
	for _, v := range sk.SLSS.S {
		result = append(result, byte(v))
	}

	// TDD secret key (factors)
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(sk.TDD.Factors.A)))
	result = append(result, lenBuf...)
	for _, vec := range sk.TDD.Factors.A {
		binary.LittleEndian.PutUint32(lenBuf, uint32(len(vec)))
		result = append(result, lenBuf...)
		for _, v := range vec {
			buf := make([]byte, 4)
			binary.LittleEndian.PutUint32(buf, uint32(v))
			result = append(result, buf...)
		}
	}
	for _, vec := range sk.TDD.Factors.B {
		binary.LittleEndian.PutUint32(lenBuf, uint32(len(vec)))
		result = append(result, lenBuf...)
		for _, v := range vec {
			buf := make([]byte, 4)
			binary.LittleEndian.PutUint32(buf, uint32(v))
			result = append(result, buf...)
		}
	}
	for _, vec := range sk.TDD.Factors.C {
		binary.LittleEndian.PutUint32(lenBuf, uint32(len(vec)))
		result = append(result, lenBuf...)
		for _, v := range vec {
			buf := make([]byte, 4)
			binary.LittleEndian.PutUint32(buf, uint32(v))
			result = append(result, buf...)
		}
	}

	// EGRW secret key (walk)
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(sk.EGRW.Walk)))
	result = append(result, lenBuf...)
	for _, v := range sk.EGRW.Walk {
		result = append(result, byte(v))
	}

	// Seed
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(sk.Seed)))
	result = append(result, lenBuf...)
	result = append(result, sk.Seed...)

	// PublicKeyHash
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(sk.PublicKeyHash)))
	result = append(result, lenBuf...)
	result = append(result, sk.PublicKeyHash...)

	return result
}

// DeserializePublicKey deserializes bytes to a public key.
// Format: [level_len:4][level_string][slss_len:4][slss_data][tdd_len:4][tdd_data][egrw_len:4][egrw_data][binding:32]
func DeserializePublicKey(data []byte) (*kmosaic.MOSAICPublicKey, error) {
	if len(data) < 16 {
		return nil, errors.New("invalid public key data: too short")
	}

	offset := 0
	pk := &kmosaic.MOSAICPublicKey{}

	// Read security level string
	levelLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if offset+levelLen > len(data) {
		return nil, errors.New("invalid public key: level string truncated")
	}
	levelStr := string(data[offset : offset+levelLen])
	offset += levelLen

	// Get params from level string
	level := kmosaic.SecurityLevel(levelStr)
	params, err := core.GetParams(level)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: unknown security level %q: %w", levelStr, err)
	}
	pk.Params = params

	// Read SLSS public key
	slssLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if offset+slssLen > len(data) {
		return nil, errors.New("invalid public key: SLSS data truncated")
	}
	slssPK, err := slss.DeserializePublicKey(data[offset : offset+slssLen])
	if err != nil {
		return nil, err
	}
	pk.SLSS = *slssPK
	offset += slssLen

	// Read TDD public key
	tddLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if offset+tddLen > len(data) {
		return nil, errors.New("invalid public key: TDD data truncated")
	}
	tddPK, err := tdd.DeserializePublicKey(data[offset : offset+tddLen])
	if err != nil {
		return nil, err
	}
	pk.TDD = *tddPK
	offset += tddLen

	// Read EGRW public key
	egrwLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if offset+egrwLen > len(data) {
		return nil, errors.New("invalid public key: EGRW data truncated")
	}
	egrwPK, err := egrw.DeserializePublicKey(data[offset : offset+egrwLen])
	if err != nil {
		return nil, err
	}
	pk.EGRW = *egrwPK
	offset += egrwLen

	// Read binding (fixed 32 bytes, no length prefix)
	if offset+32 > len(data) {
		return nil, errors.New("invalid public key: binding truncated")
	}
	pk.Binding = make([]byte, 32)
	copy(pk.Binding, data[offset:offset+32])

	// Validate binding to prevent component substitution attacks
	slssBytes := slss.SerializePublicKey(pk.SLSS)
	tddBytes := tdd.SerializePublicKey(pk.TDD)
	egrwBytes := egrw.SerializePublicKey(pk.EGRW)
	expectedBinding := entanglement.ComputeBinding(slssBytes, tddBytes, egrwBytes)
	if !utils.ConstantTimeEqual(pk.Binding, expectedBinding) {
		return nil, errors.New("invalid public key: binding mismatch")
	}

	// Validate consistency with params
	expectedSLSSALen := params.SLSS.M * params.SLSS.N
	if len(pk.SLSS.A) != expectedSLSSALen {
		return nil, errors.New("invalid public key: SLSS.A length mismatch with params")
	}
	if len(pk.SLSS.T) != params.SLSS.M {
		return nil, errors.New("invalid public key: SLSS.T length mismatch with params")
	}
	expectedTDDTLen := params.TDD.N * params.TDD.N * params.TDD.N
	if len(pk.TDD.T) != expectedTDDTLen {
		return nil, errors.New("invalid public key: TDD.T length mismatch with params")
	}

	return pk, nil
}

// DeserializeSecretKey deserializes bytes to a secret key.
func DeserializeSecretKey(data []byte) (*kmosaic.MOSAICSecretKey, error) {
	if len(data) < 4 {
		return nil, errors.New("invalid secret key data: too short")
	}

	offset := 0
	sk := &kmosaic.MOSAICSecretKey{}

	// Read SLSS secret key
	if offset+4 > len(data) {
		return nil, errors.New("invalid secret key: truncated SLSS length")
	}
	slssLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if offset+slssLen > len(data) {
		return nil, errors.New("invalid secret key: SLSS data truncated")
	}
	sk.SLSS.S = make([]int8, slssLen)
	for i := 0; i < slssLen; i++ {
		sk.SLSS.S[i] = int8(data[offset+i])
	}
	offset += slssLen

	// Read TDD factors
	if offset+4 > len(data) {
		return nil, errors.New("invalid secret key: missing TDD factor count")
	}
	factorCount := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if factorCount < 0 || factorCount > 1000000 {
		return nil, errors.New("invalid secret key: unreasonable factor count")
	}
	sk.TDD.Factors.A = make([][]int32, factorCount)
	sk.TDD.Factors.B = make([][]int32, factorCount)
	sk.TDD.Factors.C = make([][]int32, factorCount)

	for i := 0; i < factorCount; i++ {
		if offset+4 > len(data) {
			return nil, errors.New("invalid secret key: TDD factor A length truncated")
		}
		vecLen := int(binary.LittleEndian.Uint32(data[offset:]))
		offset += 4
		if vecLen < 0 || vecLen > (len(data)-offset)/4 {
			return nil, errors.New("invalid secret key: TDD factor A truncated")
		}
		sk.TDD.Factors.A[i] = make([]int32, vecLen)
		for j := 0; j < vecLen; j++ {
			sk.TDD.Factors.A[i][j] = int32(binary.LittleEndian.Uint32(data[offset:]))
			offset += 4
		}
	}
	for i := 0; i < factorCount; i++ {
		if offset+4 > len(data) {
			return nil, errors.New("invalid secret key: TDD factor B length truncated")
		}
		vecLen := int(binary.LittleEndian.Uint32(data[offset:]))
		offset += 4
		if vecLen < 0 || vecLen > (len(data)-offset)/4 {
			return nil, errors.New("invalid secret key: TDD factor B truncated")
		}
		sk.TDD.Factors.B[i] = make([]int32, vecLen)
		for j := 0; j < vecLen; j++ {
			sk.TDD.Factors.B[i][j] = int32(binary.LittleEndian.Uint32(data[offset:]))
			offset += 4
		}
	}
	for i := 0; i < factorCount; i++ {
		if offset+4 > len(data) {
			return nil, errors.New("invalid secret key: TDD factor C length truncated")
		}
		vecLen := int(binary.LittleEndian.Uint32(data[offset:]))
		offset += 4
		if vecLen < 0 || vecLen > (len(data)-offset)/4 {
			return nil, errors.New("invalid secret key: TDD factor C truncated")
		}
		sk.TDD.Factors.C[i] = make([]int32, vecLen)
		for j := 0; j < vecLen; j++ {
			sk.TDD.Factors.C[i][j] = int32(binary.LittleEndian.Uint32(data[offset:]))
			offset += 4
		}
	}

	// Read EGRW walk
	if offset+4 > len(data) {
		return nil, errors.New("invalid secret key: missing EGRW walk length")
	}
	walkLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if walkLen < 0 || walkLen > (len(data)-offset) {
		return nil, errors.New("invalid secret key: EGRW walk truncated")
	}
	sk.EGRW.Walk = make([]int, walkLen)
	for i := 0; i < walkLen; i++ {
		sk.EGRW.Walk[i] = int(data[offset+i])
	}
	offset += walkLen

	// Read Seed
	if offset+4 > len(data) {
		return nil, errors.New("invalid secret key: missing seed length")
	}
	seedLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if seedLen < 0 || seedLen > (len(data)-offset) {
		return nil, errors.New("invalid secret key: seed truncated")
	}
	sk.Seed = make([]byte, seedLen)
	copy(sk.Seed, data[offset:offset+seedLen])
	offset += seedLen

	// Read PublicKeyHash
	if offset+4 > len(data) {
		return nil, errors.New("invalid secret key: missing public key hash length")
	}
	hashLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if hashLen < 0 || hashLen > (len(data)-offset) {
		return nil, errors.New("invalid secret key: public key hash truncated")
	}
	sk.PublicKeyHash = make([]byte, hashLen)
	copy(sk.PublicKeyHash, data[offset:offset+hashLen])

	return sk, nil
}

// DeserializeCiphertext deserializes bytes to a ciphertext.
// Format: [c1_len:4][c1_data][c2_len:4][c2_data][c3_len:4][c3_data][proof_data]
// Note: proof has no length prefix - it's everything remaining in buffer
func DeserializeCiphertext(data []byte) (*kmosaic.MOSAICCiphertext, error) {
	if len(data) < 12 {
		return nil, errors.New("invalid ciphertext data: too short")
	}

	offset := 0
	ct := &kmosaic.MOSAICCiphertext{}

	// Read C1 (SLSS ciphertext)
	c1Len := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if offset+c1Len > len(data) {
		return nil, errors.New("invalid ciphertext: C1 truncated")
	}
	c1, err := deserializeSLSSCiphertext(data[offset : offset+c1Len])
	if err != nil {
		return nil, err
	}
	ct.C1 = *c1
	offset += c1Len

	// Read C2 (TDD ciphertext)
	c2Len := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if offset+c2Len > len(data) {
		return nil, errors.New("invalid ciphertext: C2 truncated")
	}
	c2, err := deserializeTDDCiphertext(data[offset : offset+c2Len])
	if err != nil {
		return nil, err
	}
	ct.C2 = *c2
	offset += c2Len

	// Read C3 (EGRW ciphertext)
	c3Len := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if offset+c3Len > len(data) {
		return nil, errors.New("invalid ciphertext: C3 truncated")
	}
	c3, err := deserializeEGRWCiphertext(data[offset : offset+c3Len])
	if err != nil {
		return nil, err
	}
	ct.C3 = *c3
	offset += c3Len

	// Read proof - everything remaining in buffer
	ct.Proof = make([]byte, len(data)-offset)
	copy(ct.Proof, data[offset:])

	return ct, nil
}

func deserializeSLSSCiphertext(data []byte) (*kmosaic.SLSSCiphertext, error) {
	if len(data) < 8 {
		return nil, errors.New("invalid SLSS ciphertext")
	}
	ct := &kmosaic.SLSSCiphertext{}
	offset := 0

	// Read byte length (not element count)
	uBytes := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if uBytes%4 != 0 {
		return nil, errors.New("invalid SLSS ciphertext: U length not multiple of 4")
	}
	uLen := uBytes / 4
	if offset+uBytes > len(data) {
		return nil, errors.New("invalid SLSS ciphertext: U truncated")
	}
	ct.U = make([]int32, uLen)
	for i := 0; i < uLen; i++ {
		ct.U[i] = int32(binary.LittleEndian.Uint32(data[offset:]))
		offset += 4
	}

	if offset+4 > len(data) {
		return nil, errors.New("invalid SLSS ciphertext: missing V length")
	}
	// Read byte length (not element count)
	vBytes := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if vBytes%4 != 0 {
		return nil, errors.New("invalid SLSS ciphertext: V length not multiple of 4")
	}
	vLen := vBytes / 4
	if offset+vBytes > len(data) {
		return nil, errors.New("invalid SLSS ciphertext: V truncated")
	}
	ct.V = make([]int32, vLen)
	for i := 0; i < vLen; i++ {
		ct.V[i] = int32(binary.LittleEndian.Uint32(data[offset:]))
		offset += 4
	}

	return ct, nil
}

func deserializeTDDCiphertext(data []byte) (*kmosaic.TDDCiphertext, error) {
	if len(data) < 4 {
		return nil, errors.New("invalid TDD ciphertext")
	}
	ct := &kmosaic.TDDCiphertext{}
	// Read byte length (not element count)
	dataBytes := int(binary.LittleEndian.Uint32(data[0:]))
	if dataBytes%4 != 0 {
		return nil, errors.New("invalid TDD ciphertext: data length not multiple of 4")
	}
	dataLen := dataBytes / 4
	if 4+dataBytes > len(data) {
		return nil, errors.New("invalid TDD ciphertext: data truncated")
	}
	ct.Data = make([]int32, dataLen)
	for i := 0; i < dataLen; i++ {
		ct.Data[i] = int32(binary.LittleEndian.Uint32(data[4+i*4:]))
	}
	return ct, nil
}

func deserializeEGRWCiphertext(data []byte) (*kmosaic.EGRWCiphertext, error) {
	if len(data) < 16 {
		return nil, errors.New("invalid EGRW ciphertext")
	}
	ct := &kmosaic.EGRWCiphertext{}
	ct.Vertex = egrw.BytesToSL2(data[:16])
	ct.Commitment = make([]byte, len(data)-16)
	copy(ct.Commitment, data[16:])
	return ct, nil
}

// SerializeEncryptedMessage serializes an encrypted message.
// Format: [kemCt_len:4][kemCt_data][aes_encrypted_data]
// Note: nonce is not stored - it's derived from shared secret during decryption
func SerializeEncryptedMessage(em *kmosaic.EncryptedMessage) []byte {
	ctBytes := SerializeCiphertext(&em.Ciphertext)

	result := make([]byte, 0, 4+len(ctBytes)+len(em.Encrypted))
	lenBuf := make([]byte, 4)

	// KEM Ciphertext length and data
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(ctBytes)))
	result = append(result, lenBuf...)
	result = append(result, ctBytes...)

	// AES-GCM encrypted payload (includes auth tag)
	// No length prefix - everything remaining is encrypted data
	result = append(result, em.Encrypted...)

	return result
}

// DeserializeEncryptedMessage deserializes bytes to an encrypted message.
// Format: [kemCt_len:4][kemCt_data][aes_encrypted_data]
// Note: nonce is not stored - it will be derived from shared secret during decryption
func DeserializeEncryptedMessage(data []byte) (*kmosaic.EncryptedMessage, error) {
	if len(data) < 4 {
		return nil, errors.New("invalid encrypted message: too short")
	}

	em := &kmosaic.EncryptedMessage{}
	offset := 0

	// Read KEM ciphertext
	ctLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if offset+ctLen > len(data) {
		return nil, errors.New("invalid encrypted message: ciphertext truncated")
	}
	ct, err := DeserializeCiphertext(data[offset : offset+ctLen])
	if err != nil {
		return nil, err
	}
	em.Ciphertext = *ct
	offset += ctLen

	// Read AES-GCM encrypted payload - everything remaining
	em.Encrypted = make([]byte, len(data)-offset)
	copy(em.Encrypted, data[offset:])

	// Nonce will be derived from shared secret during decryption (not stored)
	em.Nonce = nil

	return em, nil
}
