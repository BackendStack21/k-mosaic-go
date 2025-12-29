// Package kem implements the Key Encapsulation Mechanism for kMOSAIC.
package kem

import (
	"encoding/binary"
	"errors"
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

	// Zeroize shares and randomness after use
	for _, share := range shares {
		utils.Zeroize(share)
	}
	utils.Zeroize(randomness)

	if err1 != nil {
		return nil, err1
	}
	if err2 != nil {
		return nil, err2
	}
	if err3 != nil {
		return nil, err3
	}

	// Generate NIZK proof
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

	// Verify NIZK proof
	ciphertextHashes := [][]byte{
		utils.SHA3256(serializeSLSSCiphertext(&ct.C1)),
		utils.SHA3256(serializeTDDCiphertext(&ct.C2)),
		utils.SHA3256(serializeEGRWCiphertext(&ct.C3)),
	}
	if !entanglement.VerifyNIZKProof(ct.Proof, ciphertextHashes, pk.Binding) {
		return implicitReject(sk, ct), nil
	}

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

	// Compare ciphertexts
	originalCT := SerializeCiphertext(ct)
	reEncCT := SerializeCiphertext(&reEncResult.Ciphertext)
	if !utils.ConstantTimeEqual(originalCT, reEncCT) {
		return implicitReject(sk, ct), nil
	}

	return reEncResult.SharedSecret, nil
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

	// Simple XOR encryption (in production, use AES-GCM)
	keystream := utils.Shake256(utils.HashConcat(encKey, nonce), len(plaintext)+16)
	defer utils.Zeroize(keystream)
	encrypted := make([]byte, len(plaintext)+16)
	for i := 0; i < len(plaintext); i++ {
		encrypted[i] = plaintext[i] ^ keystream[i]
	}
	// Add authentication tag
	tag := utils.SHA3256(utils.HashConcat(encKey, plaintext))
	copy(encrypted[len(plaintext):], tag[:16])

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

	// Derive encryption key
	encKey := utils.Shake256(utils.HashWithDomain(DomainEncKey, sharedSecret), 32)
	defer utils.Zeroize(encKey)

	// Decrypt
	if len(em.Encrypted) < 16 {
		return nil, errors.New("ciphertext too short")
	}
	keystream := utils.Shake256(utils.HashConcat(encKey, em.Nonce), len(em.Encrypted))
	defer utils.Zeroize(keystream)
	plaintextLen := len(em.Encrypted) - 16
	plaintext := make([]byte, plaintextLen)
	for i := 0; i < plaintextLen; i++ {
		plaintext[i] = em.Encrypted[i] ^ keystream[i]
	}

	// Verify tag
	expectedTag := utils.SHA3256(utils.HashConcat(encKey, plaintext))
	if !utils.ConstantTimeEqual(em.Encrypted[plaintextLen:], expectedTag[:16]) {
		return nil, errors.New("authentication failed")
	}

	return plaintext, nil
}

// SerializePublicKey serializes a public key.
func SerializePublicKey(pk *kmosaic.MOSAICPublicKey) []byte {
	slssBytes := slss.SerializePublicKey(pk.SLSS)
	tddBytes := tdd.SerializePublicKey(pk.TDD)
	egrwBytes := egrw.SerializePublicKey(pk.EGRW)

	// Serialize params (security level as string)
	levelBytes := []byte(pk.Params.Level)

	result := make([]byte, 0, 16+len(slssBytes)+len(tddBytes)+len(egrwBytes)+len(pk.Binding)+len(levelBytes))

	// Length prefixes
	lenBuf := make([]byte, 4)

	// Security level
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(levelBytes)))
	result = append(result, lenBuf...)
	result = append(result, levelBytes...)

	binary.LittleEndian.PutUint32(lenBuf, uint32(len(slssBytes)))
	result = append(result, lenBuf...)
	result = append(result, slssBytes...)

	binary.LittleEndian.PutUint32(lenBuf, uint32(len(tddBytes)))
	result = append(result, lenBuf...)
	result = append(result, tddBytes...)

	binary.LittleEndian.PutUint32(lenBuf, uint32(len(egrwBytes)))
	result = append(result, lenBuf...)
	result = append(result, egrwBytes...)

	result = append(result, pk.Binding...)

	return result
}

// SerializeCiphertext serializes a ciphertext.
func SerializeCiphertext(ct *kmosaic.MOSAICCiphertext) []byte {
	c1Bytes := serializeSLSSCiphertext(&ct.C1)
	c2Bytes := serializeTDDCiphertext(&ct.C2)
	c3Bytes := serializeEGRWCiphertext(&ct.C3)

	result := make([]byte, 0, 16+len(c1Bytes)+len(c2Bytes)+len(c3Bytes)+len(ct.Proof))

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

	binary.LittleEndian.PutUint32(lenBuf, uint32(len(ct.Proof)))
	result = append(result, lenBuf...)
	result = append(result, ct.Proof...)

	return result
}

func serializeSLSSCiphertext(ct *kmosaic.SLSSCiphertext) []byte {
	result := make([]byte, 8+len(ct.U)*4+len(ct.V)*4)
	binary.LittleEndian.PutUint32(result[0:], uint32(len(ct.U)))
	offset := 4
	for i, v := range ct.U {
		binary.LittleEndian.PutUint32(result[offset+i*4:], uint32(v))
	}
	offset += len(ct.U) * 4
	binary.LittleEndian.PutUint32(result[offset:], uint32(len(ct.V)))
	offset += 4
	for i, v := range ct.V {
		binary.LittleEndian.PutUint32(result[offset+i*4:], uint32(v))
	}
	return result
}

func serializeTDDCiphertext(ct *kmosaic.TDDCiphertext) []byte {
	result := make([]byte, 4+len(ct.Data)*4)
	binary.LittleEndian.PutUint32(result[0:], uint32(len(ct.Data)))
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
func DeserializePublicKey(data []byte) (*kmosaic.MOSAICPublicKey, error) {
	if len(data) < 16 {
		return nil, errors.New("invalid public key data: too short")
	}

	offset := 0
	pk := &kmosaic.MOSAICPublicKey{}

	// Read security level
	levelLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if offset+levelLen > len(data) {
		return nil, errors.New("invalid public key: security level truncated")
	}
	level := kmosaic.SecurityLevel(data[offset : offset+levelLen])
	params, err := core.GetParams(level)
	if err != nil {
		return nil, err
	}
	pk.Params = params
	offset += levelLen

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

	// Rest is binding (32 bytes)
	if offset+32 > len(data) {
		return nil, errors.New("invalid public key: binding truncated")
	}
	pk.Binding = make([]byte, 32)
	copy(pk.Binding, data[offset:offset+32])

	// Cross-field consistency checks
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
func DeserializeCiphertext(data []byte) (*kmosaic.MOSAICCiphertext, error) {
	if len(data) < 16 {
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

	// Read proof
	proofLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if offset+proofLen > len(data) {
		return nil, errors.New("invalid ciphertext: proof truncated")
	}
	ct.Proof = make([]byte, proofLen)
	copy(ct.Proof, data[offset:offset+proofLen])

	return ct, nil
}

func deserializeSLSSCiphertext(data []byte) (*kmosaic.SLSSCiphertext, error) {
	if len(data) < 8 {
		return nil, errors.New("invalid SLSS ciphertext")
	}
	ct := &kmosaic.SLSSCiphertext{}
	offset := 0

	uLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if uLen < 0 || uLen > (len(data)-offset)/4 {
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
	vLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if vLen < 0 || vLen > (len(data)-offset)/4 {
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
	dataLen := int(binary.LittleEndian.Uint32(data[0:]))
	if dataLen < 0 || dataLen > (len(data)-4)/4 {
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
func SerializeEncryptedMessage(em *kmosaic.EncryptedMessage) []byte {
	ctBytes := SerializeCiphertext(&em.Ciphertext)

	result := make([]byte, 0, 12+len(ctBytes)+len(em.Encrypted)+len(em.Nonce))
	lenBuf := make([]byte, 4)

	// Ciphertext
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(ctBytes)))
	result = append(result, lenBuf...)
	result = append(result, ctBytes...)

	// Encrypted payload
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(em.Encrypted)))
	result = append(result, lenBuf...)
	result = append(result, em.Encrypted...)

	// Nonce
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(em.Nonce)))
	result = append(result, lenBuf...)
	result = append(result, em.Nonce...)

	return result
}

// DeserializeEncryptedMessage deserializes bytes to an encrypted message.
func DeserializeEncryptedMessage(data []byte) (*kmosaic.EncryptedMessage, error) {
	if len(data) < 12 {
		return nil, errors.New("invalid encrypted message: too short")
	}

	em := &kmosaic.EncryptedMessage{}
	offset := 0

	// Read ciphertext
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

	// Read encrypted payload
	encLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if offset+encLen > len(data) {
		return nil, errors.New("invalid encrypted message: encrypted payload truncated")
	}
	em.Encrypted = make([]byte, encLen)
	copy(em.Encrypted, data[offset:offset+encLen])
	offset += encLen

	// Read nonce
	nonceLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if offset+nonceLen > len(data) {
		return nil, errors.New("invalid encrypted message: nonce truncated")
	}
	em.Nonce = make([]byte, nonceLen)
	copy(em.Nonce, data[offset:offset+nonceLen])

	return em, nil
}
