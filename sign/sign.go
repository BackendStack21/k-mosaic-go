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

	result := make([]byte, 0, 12+len(slssBytes)+len(tddBytes)+len(egrwBytes)+len(pk.Binding))

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
