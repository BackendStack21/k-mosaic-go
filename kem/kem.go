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

	// Simple XOR encryption (in production, use AES-GCM)
	keystream := utils.Shake256(utils.HashConcat(encKey, nonce), len(plaintext)+16)
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

	// Decrypt
	if len(em.Encrypted) < 16 {
		return nil, errors.New("ciphertext too short")
	}
	keystream := utils.Shake256(utils.HashConcat(encKey, em.Nonce), len(em.Encrypted))
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

	result := make([]byte, 0, 12+len(slssBytes)+len(tddBytes)+len(egrwBytes)+len(pk.Binding))

	// Length prefixes
	lenBuf := make([]byte, 4)
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
