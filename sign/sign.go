// Package sign implements the digital signature scheme for kMOSAIC.
package sign

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
	DomainSLSS      = "kmosaic-sign-slss-v1"
	DomainTDD       = "kmosaic-sign-tdd-v1"
	DomainEGRW      = "kmosaic-sign-egrw-v1"
	DomainChallenge = "kmosaic-sign-chal-v1"
	DomainWitness   = "kmosaic-sign-wit-v1"
	DomainResponse  = "kmosaic-sign-resp-v1"
)

// GenerateKeyPair generates a signature key pair.
func GenerateKeyPair(level kmosaic.SecurityLevel) (*kmosaic.MOSAICSignKeyPair, error) {
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

// GenerateKeyPairFromSeed generates a deterministic signature key pair.
func GenerateKeyPairFromSeed(params kmosaic.MOSAICParams, seed []byte) (*kmosaic.MOSAICSignKeyPair, error) {
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

	publicKey := kmosaic.MOSAICSignPublicKey{
		SLSS:    slssKP.PublicKey,
		TDD:     tddKP.PublicKey,
		EGRW:    egrwKP.PublicKey,
		Binding: binding,
		Params:  params,
	}

	publicKeyHash := utils.SHA3256(SerializePublicKey(&publicKey))

	secretKey := kmosaic.MOSAICSignSecretKey{
		SLSS:          slssKP.SecretKey,
		TDD:           tddKP.SecretKey,
		EGRW:          egrwKP.SecretKey,
		Seed:          append([]byte{}, seed...),
		PublicKeyHash: publicKeyHash,
	}

	return &kmosaic.MOSAICSignKeyPair{
		PublicKey: publicKey,
		SecretKey: secretKey,
	}, nil
}

// Sign creates a signature for a message.
func Sign(sk *kmosaic.MOSAICSignSecretKey, pk *kmosaic.MOSAICSignPublicKey, message []byte) (*kmosaic.MOSAICSignature, error) {
	// Generate random witness
	witnessRand, err := utils.SecureRandomBytes(32)
	if err != nil {
		return nil, err
	}

	// Compute message hash
	msgHash := utils.SHA3256(utils.HashConcat(message, pk.Binding))

	// Compute commitment: H(witness || message || binding)
	commitment := utils.SHA3256(utils.HashConcat(witnessRand, msgHash, pk.Binding))

	// Compute challenge: H(commitment || message || publicKeyHash)
	challenge := utils.HashWithDomain(DomainChallenge, utils.HashConcat(commitment, msgHash, sk.PublicKeyHash))

	// Compute response: combine secret key with challenge
	response := computeResponse(sk, challenge, witnessRand)

	// Zeroize witness randomness
	utils.Zeroize(witnessRand)

	return &kmosaic.MOSAICSignature{
		Commitment: commitment,
		Challenge:  challenge,
		Response:   response,
	}, nil
}

// computeResponse creates the signature response.
func computeResponse(sk *kmosaic.MOSAICSignSecretKey, challenge, witnessRand []byte) []byte {
	// Combine secret key components with challenge and witness
	skBytes := make([]byte, 0, 1024)

	// SLSS secret key contribution
	for _, v := range sk.SLSS.S {
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, uint32(int32(v)))
		skBytes = append(skBytes, buf...)
	}

	// TDD secret key contribution
	for _, vec := range sk.TDD.Factors.A {
		for _, v := range vec {
			buf := make([]byte, 4)
			binary.LittleEndian.PutUint32(buf, uint32(v))
			skBytes = append(skBytes, buf...)
		}
	}

	// EGRW secret key contribution
	for _, w := range sk.EGRW.Walk {
		skBytes = append(skBytes, byte(w))
	}

	// Generate response as hash of combined data
	response := utils.Shake256(utils.HashWithDomain(DomainResponse,
		utils.HashConcat(skBytes, challenge, witnessRand)), 64)

	// Zeroize sensitive data
	utils.Zeroize(skBytes)

	return response
}

// Verify checks if a signature is valid for a message.
func Verify(pk *kmosaic.MOSAICSignPublicKey, message []byte, sig *kmosaic.MOSAICSignature) bool {
	// Check lengths
	if len(sig.Commitment) != 32 || len(sig.Challenge) != 32 || len(sig.Response) != 64 {
		return false
	}

	// Compute message hash
	msgHash := utils.SHA3256(utils.HashConcat(message, pk.Binding))

	// Compute public key hash
	pkHash := utils.SHA3256(SerializePublicKey(pk))

	// Recompute expected challenge
	expectedChallenge := utils.HashWithDomain(DomainChallenge,
		utils.HashConcat(sig.Commitment, msgHash, pkHash))

	// Verify challenge matches
	return utils.ConstantTimeEqual(sig.Challenge, expectedChallenge)
}

// SerializePublicKey serializes a signature public key.
func SerializePublicKey(pk *kmosaic.MOSAICSignPublicKey) []byte {
	slssBytes := slss.SerializePublicKey(pk.SLSS)
	tddBytes := tdd.SerializePublicKey(pk.TDD)
	egrwBytes := egrw.SerializePublicKey(pk.EGRW)

	// Serialize params (security level as string)
	levelBytes := []byte(pk.Params.Level)

	result := make([]byte, 0, 16+len(slssBytes)+len(tddBytes)+len(egrwBytes)+len(pk.Binding)+len(levelBytes))

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

// SerializeSignature serializes a signature.
func SerializeSignature(sig *kmosaic.MOSAICSignature) []byte {
	result := make([]byte, 0, 12+len(sig.Commitment)+len(sig.Challenge)+len(sig.Response))

	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(sig.Commitment)))
	result = append(result, lenBuf...)
	result = append(result, sig.Commitment...)

	binary.LittleEndian.PutUint32(lenBuf, uint32(len(sig.Challenge)))
	result = append(result, lenBuf...)
	result = append(result, sig.Challenge...)

	binary.LittleEndian.PutUint32(lenBuf, uint32(len(sig.Response)))
	result = append(result, lenBuf...)
	result = append(result, sig.Response...)

	return result
}

// SerializeSecretKey serializes a signature secret key.
func SerializeSecretKey(sk *kmosaic.MOSAICSignSecretKey) []byte {
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

// DeserializePublicKey deserializes bytes to a signature public key.
func DeserializePublicKey(data []byte) (*kmosaic.MOSAICSignPublicKey, error) {
	if len(data) < 16 {
		return nil, errors.New("invalid public key data: too short")
	}

	offset := 0
	pk := &kmosaic.MOSAICSignPublicKey{}

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

// DeserializeSecretKey deserializes bytes to a signature secret key.
func DeserializeSecretKey(data []byte) (*kmosaic.MOSAICSignSecretKey, error) {
	if len(data) < 4 {
		return nil, errors.New("invalid secret key data: too short")
	}

	offset := 0
	sk := &kmosaic.MOSAICSignSecretKey{}

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

	// EGRW secret key (walk)
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

// DeserializeSignature deserializes bytes to a signature.
func DeserializeSignature(data []byte) (*kmosaic.MOSAICSignature, error) {
	if len(data) < 12 {
		return nil, errors.New("invalid signature data: too short")
	}

	// Maximum signature component size (1MB each for commitment, challenge, response)
	const maxSigComponentSize = 1 << 20

	sig := &kmosaic.MOSAICSignature{}
	offset := 0

	// Read commitment
	commitLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if commitLen < 0 || commitLen > maxSigComponentSize {
		return nil, errors.New("invalid signature: commitment length exceeds limit")
	}
	if offset+commitLen > len(data) {
		return nil, errors.New("invalid signature: commitment truncated")
	}
	sig.Commitment = make([]byte, commitLen)
	copy(sig.Commitment, data[offset:offset+commitLen])
	offset += commitLen

	// Read challenge
	if offset+4 > len(data) {
		return nil, errors.New("invalid signature: missing challenge length")
	}
	chalLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if chalLen < 0 || chalLen > maxSigComponentSize {
		return nil, errors.New("invalid signature: challenge length exceeds limit")
	}
	if offset+chalLen > len(data) {
		return nil, errors.New("invalid signature: challenge truncated")
	}
	sig.Challenge = make([]byte, chalLen)
	copy(sig.Challenge, data[offset:offset+chalLen])
	offset += chalLen

	// Read response
	if offset+4 > len(data) {
		return nil, errors.New("invalid signature: missing response length")
	}
	respLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if respLen < 0 || respLen > maxSigComponentSize {
		return nil, errors.New("invalid signature: response length exceeds limit")
	}
	if offset+respLen > len(data) {
		return nil, errors.New("invalid signature: response truncated")
	}
	sig.Response = make([]byte, respLen)
	copy(sig.Response, data[offset:offset+respLen])

	return sig, nil
}
