// Package sign implements the kMOSAIC composite digital signature.
//
// A composite key pair holds three independent component key pairs:
//
//   - latsig: a Fiat-Shamir-with-aborts signature over unstructured lattices
//     (ML-DSA construction, SIS/LWE assumptions),
//   - uov:    Unbalanced Oil and Vinegar over F_256 (multivariate quadratic),
//   - slhdsa: SLH-DSA / SPHINCS+ with SHAKE256 (hash-function assumptions only).
//
// Signing hashes the message together with the composite public key into a
// 64-byte digest μ and signs μ with every component. A composite signature is
// valid only if all three component signatures are valid, so forging one
// requires breaking all three problems ("AND" combiner). The binding of the
// component public keys and the inclusion of the public-key hash in μ prevent
// mixing components across key pairs.
package sign

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/entanglement"
	"github.com/BackendStack21/k-mosaic-go/problems/latsig"
	"github.com/BackendStack21/k-mosaic-go/problems/slhdsa"
	"github.com/BackendStack21/k-mosaic-go/problems/uov"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

const (
	DomainLattice = "kmosaic-sign-lattice-v3"
	DomainMQ      = "kmosaic-sign-mq-v3"
	DomainHash    = "kmosaic-sign-hash-v3"
	DomainMessage = "kmosaic-sign-msg-v3"

	// PublicKeyHashSize is the size of the composite public key hash.
	PublicKeyHashSize = 64
	// MaxComponentSize bounds any length prefix read during deserialization.
	MaxComponentSize = 64 * 1024 * 1024
)

// GenerateKeyPair generates a composite signature key pair.
func GenerateKeyPair(level kmosaic.SecurityLevel) (result *kmosaic.MOSAICSignKeyPair, err error) {
	defer func() {
		if r := recover(); r != nil {
			result = nil
			err = fmt.Errorf("signature key generation panic: %v", r)
		}
	}()

	params, err := core.GetSignParams(level)
	if err != nil {
		return nil, err
	}
	seed, err := utils.SecureRandomBytes(32)
	if err != nil {
		return nil, err
	}
	defer utils.Zeroize(seed)
	return GenerateKeyPairFromSeed(params, seed)
}

// GenerateKeyPairFromSeed deterministically generates a composite key pair.
func GenerateKeyPairFromSeed(params kmosaic.SignParams, seed []byte) (*kmosaic.MOSAICSignKeyPair, error) {
	if len(seed) < 32 {
		return nil, errors.New("seed must be at least 32 bytes")
	}
	if err := utils.ValidateSeedEntropy(seed); err != nil {
		return nil, err
	}
	if err := core.ValidateSignParams(params); err != nil {
		return nil, err
	}
	if _, err := core.GetSignParams(params.Level); err != nil {
		return nil, err
	}

	latSeed := utils.HashWithDomain(DomainLattice, seed)
	mqSeed := utils.HashWithDomain(DomainMQ, seed)
	hashSeed := utils.HashWithDomain(DomainHash, seed)
	defer func() {
		utils.Zeroize(latSeed)
		utils.Zeroize(mqSeed)
		utils.Zeroize(hashSeed)
	}()

	var wg sync.WaitGroup
	var latKP *kmosaic.LatticeSignKeyPair
	var mqKP *kmosaic.MQKeyPair
	var hashKP *kmosaic.HashSignKeyPair
	var errLat, errMQ, errHash error
	wg.Add(3)
	go func() {
		defer wg.Done()
		latKP, errLat = latsig.GenerateKeyPairFromSeed(params.Lattice, latSeed)
	}()
	go func() {
		defer wg.Done()
		mqKP, errMQ = uov.KeyGen(params.MQ, mqSeed)
	}()
	go func() {
		defer wg.Done()
		hashKP, errHash = slhdsa.KeyGen(params.Hash, hashSeed)
	}()
	wg.Wait()
	for _, err := range []error{errLat, errMQ, errHash} {
		if err != nil {
			return nil, err
		}
	}

	binding := entanglement.ComputeBinding(
		latsig.SerializePublicKey(&latKP.PublicKey),
		uov.SerializePublicKey(&mqKP.PublicKey),
		slhdsa.SerializePublicKey(&hashKP.PublicKey),
	)
	publicKey := kmosaic.MOSAICSignPublicKey{
		Params:  params,
		Lattice: latKP.PublicKey,
		MQ:      mqKP.PublicKey,
		Hash:    hashKP.PublicKey,
		Binding: binding,
	}
	secretKey := kmosaic.MOSAICSignSecretKey{
		Params:        params,
		Lattice:       latKP.SecretKey,
		MQ:            mqKP.SecretKey,
		Hash:          hashKP.SecretKey,
		Seed:          append([]byte{}, seed...),
		PublicKeyHash: publicKeyHash(&publicKey),
	}
	return &kmosaic.MOSAICSignKeyPair{PublicKey: publicKey, SecretKey: secretKey}, nil
}

func publicKeyHash(pk *kmosaic.MOSAICSignPublicKey) []byte {
	return utils.Shake256(SerializePublicKey(pk), PublicKeyHashSize)
}

// messageDigest binds the message to the composite public key.
func messageDigest(pkHash, message []byte) []byte {
	return utils.Shake256WithDomain(DomainMessage, append(append([]byte{}, pkHash...), message...), PublicKeyHashSize)
}

// Sign creates a composite signature on message. pk, if non-nil, must match sk.
func Sign(sk *kmosaic.MOSAICSignSecretKey, pk *kmosaic.MOSAICSignPublicKey, message []byte) (result *kmosaic.MOSAICSignature, err error) {
	defer func() {
		if r := recover(); r != nil {
			result = nil
			err = fmt.Errorf("signature creation panic: %v", r)
		}
	}()

	if err := core.ValidateSignParams(sk.Params); err != nil {
		return nil, err
	}
	if len(sk.PublicKeyHash) != PublicKeyHashSize {
		return nil, errors.New("invalid secret key: missing public key hash")
	}
	if pk != nil && !utils.ConstantTimeEqual(sk.PublicKeyHash, publicKeyHash(pk)) {
		return nil, errors.New("public key does not match secret key")
	}
	mu := messageDigest(sk.PublicKeyHash, message)

	var wg sync.WaitGroup
	var latSig *kmosaic.LatticeSignature
	var mqSig *kmosaic.MQSignature
	var hashSig *kmosaic.HashSignature
	var errLat, errMQ, errHash error
	wg.Add(3)
	go func() {
		defer wg.Done()
		latSig, errLat = latsig.Sign(&sk.Lattice, nil, mu)
	}()
	go func() {
		defer wg.Done()
		mqSig, errMQ = uov.Sign(&sk.MQ, sk.Params.MQ, mu)
	}()
	go func() {
		defer wg.Done()
		hashSig, errHash = slhdsa.Sign(&sk.Hash, sk.Params.Hash, mu)
	}()
	wg.Wait()
	for _, err := range []error{errLat, errMQ, errHash} {
		if err != nil {
			return nil, err
		}
	}
	return &kmosaic.MOSAICSignature{Lattice: *latSig, MQ: *mqSig, Hash: *hashSig}, nil
}

// Verify reports whether sig is a valid composite signature on message
// under pk. All three component signatures are checked; all must pass.
func Verify(pk *kmosaic.MOSAICSignPublicKey, message []byte, sig *kmosaic.MOSAICSignature) (isValid bool) {
	defer func() {
		if r := recover(); r != nil {
			isValid = false
		}
	}()
	if pk == nil || sig == nil {
		return false
	}
	if err := core.ValidateSignParams(pk.Params); err != nil {
		return false
	}
	mu := messageDigest(publicKeyHash(pk), message)

	var wg sync.WaitGroup
	var okLat, okMQ, okHash bool
	wg.Add(3)
	go func() {
		defer wg.Done()
		okLat = latsig.Verify(&pk.Lattice, mu, &sig.Lattice)
	}()
	go func() {
		defer wg.Done()
		okMQ = uov.Verify(&pk.MQ, pk.Params.MQ, mu, &sig.MQ)
	}()
	go func() {
		defer wg.Done()
		okHash = slhdsa.Verify(&pk.Hash, pk.Params.Hash, mu, &sig.Hash)
	}()
	wg.Wait()
	return okLat && okMQ && okHash
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

// SerializePublicKey serializes a composite public key.
// Format: [level_len:4][level][lat_len:4][lat][mq_len:4][mq][hash_len:4][hash][binding:32]
func SerializePublicKey(pk *kmosaic.MOSAICSignPublicKey) []byte {
	var result []byte
	result = appendLV(result, []byte(pk.Params.Level))
	result = appendLV(result, latsig.SerializePublicKey(&pk.Lattice))
	result = appendLV(result, uov.SerializePublicKey(&pk.MQ))
	result = appendLV(result, slhdsa.SerializePublicKey(&pk.Hash))
	return append(result, pk.Binding...)
}

// DeserializePublicKey parses a composite public key and validates its binding.
func DeserializePublicKey(data []byte) (*kmosaic.MOSAICSignPublicKey, error) {
	levelBytes, offset, err := readLV(data, 0, "public key level")
	if err != nil {
		return nil, err
	}
	params, err := core.GetSignParams(kmosaic.SecurityLevel(levelBytes))
	if err != nil {
		return nil, fmt.Errorf("invalid public key: unknown security level %q", string(levelBytes))
	}
	latBytes, offset, err := readLV(data, offset, "public key lattice component")
	if err != nil {
		return nil, err
	}
	mqBytes, offset, err := readLV(data, offset, "public key MQ component")
	if err != nil {
		return nil, err
	}
	hashBytes, offset, err := readLV(data, offset, "public key hash component")
	if err != nil {
		return nil, err
	}
	if len(data) != offset+32 {
		return nil, errors.New("invalid public key: binding has wrong length")
	}
	binding := append([]byte{}, data[offset:]...)
	if !utils.ConstantTimeEqual(binding, entanglement.ComputeBinding(latBytes, mqBytes, hashBytes)) {
		return nil, errors.New("invalid public key: binding mismatch")
	}

	latPK, err := latsig.DeserializePublicKey(latBytes)
	if err != nil {
		return nil, err
	}
	if latPK.Params != params.Lattice {
		return nil, errors.New("invalid public key: lattice component level mismatch")
	}
	mqPK, err := uov.DeserializePublicKey(mqBytes, params.MQ)
	if err != nil {
		return nil, err
	}
	hashPK, err := slhdsa.DeserializePublicKey(hashBytes, params.Hash)
	if err != nil {
		return nil, err
	}
	return &kmosaic.MOSAICSignPublicKey{Params: params, Lattice: *latPK, MQ: *mqPK, Hash: *hashPK, Binding: binding}, nil
}

// SerializeSecretKey serializes a composite secret key.
// Format: [level_len:4][level][lat_len:4][lat][mq_len:4][mq][hash_len:4][hash][seed_len:4][seed][pkhash:64]
func SerializeSecretKey(sk *kmosaic.MOSAICSignSecretKey) []byte {
	var result []byte
	result = appendLV(result, []byte(sk.Params.Level))
	result = appendLV(result, latsig.SerializeSecretKey(&sk.Lattice))
	result = appendLV(result, uov.SerializeSecretKey(&sk.MQ))
	result = appendLV(result, slhdsa.SerializeSecretKey(&sk.Hash))
	result = appendLV(result, sk.Seed)
	return append(result, sk.PublicKeyHash...)
}

// DeserializeSecretKey parses a composite secret key.
func DeserializeSecretKey(data []byte) (*kmosaic.MOSAICSignSecretKey, error) {
	levelBytes, offset, err := readLV(data, 0, "secret key level")
	if err != nil {
		return nil, err
	}
	params, err := core.GetSignParams(kmosaic.SecurityLevel(levelBytes))
	if err != nil {
		return nil, fmt.Errorf("invalid secret key: unknown security level %q", string(levelBytes))
	}
	latBytes, offset, err := readLV(data, offset, "secret key lattice component")
	if err != nil {
		return nil, err
	}
	mqBytes, offset, err := readLV(data, offset, "secret key MQ component")
	if err != nil {
		return nil, err
	}
	hashBytes, offset, err := readLV(data, offset, "secret key hash component")
	if err != nil {
		return nil, err
	}
	seed, offset, err := readLV(data, offset, "secret key seed")
	if err != nil {
		return nil, err
	}
	if len(data) != offset+PublicKeyHashSize {
		return nil, errors.New("invalid secret key: public key hash has wrong length")
	}
	latSK, err := latsig.DeserializeSecretKey(latBytes)
	if err != nil {
		return nil, err
	}
	if latSK.Params != params.Lattice {
		return nil, errors.New("invalid secret key: lattice component level mismatch")
	}
	mqSK, err := uov.DeserializeSecretKey(mqBytes, params.MQ)
	if err != nil {
		return nil, err
	}
	hashSK, err := slhdsa.DeserializeSecretKey(hashBytes, params.Hash)
	if err != nil {
		return nil, err
	}
	return &kmosaic.MOSAICSignSecretKey{
		Params:        params,
		Lattice:       *latSK,
		MQ:            *mqSK,
		Hash:          *hashSK,
		Seed:          append([]byte{}, seed...),
		PublicKeyHash: append([]byte{}, data[offset:]...),
	}, nil
}

// SerializeSignature serializes a composite signature.
// Format: [lat_len:4][lat][mq_len:4][mq][hash_len:4][hash]
func SerializeSignature(sig *kmosaic.MOSAICSignature) []byte {
	var result []byte
	result = appendLV(result, latsig.SerializeSignature(&sig.Lattice))
	result = appendLV(result, uov.SerializeSignature(&sig.MQ))
	result = appendLV(result, sig.Hash.Data)
	return result
}

// DeserializeSignature parses a composite signature for the given parameters.
func DeserializeSignature(data []byte, params kmosaic.SignParams) (*kmosaic.MOSAICSignature, error) {
	latBytes, offset, err := readLV(data, 0, "signature lattice component")
	if err != nil {
		return nil, err
	}
	mqBytes, offset, err := readLV(data, offset, "signature MQ component")
	if err != nil {
		return nil, err
	}
	hashBytes, offset, err := readLV(data, offset, "signature hash component")
	if err != nil {
		return nil, err
	}
	if offset != len(data) {
		return nil, errors.New("invalid signature: trailing data")
	}
	latSig, err := latsig.DeserializeSignature(latBytes)
	if err != nil {
		return nil, err
	}
	mqSig, err := uov.DeserializeSignature(mqBytes, params.MQ)
	if err != nil {
		return nil, err
	}
	if len(hashBytes) != slhdsa.SignatureSize(params.Hash) {
		return nil, errors.New("invalid signature: hash component has wrong length")
	}
	return &kmosaic.MOSAICSignature{Lattice: *latSig, MQ: *mqSig, Hash: kmosaic.HashSignature{Data: append([]byte{}, hashBytes...)}}, nil
}
