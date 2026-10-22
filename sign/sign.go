// Package sign implements the kMOSAIC composite digital signature.
//
// A composite key pair holds three independent component key pairs:
//
//   - latsig: a Fiat-Shamir-with-aborts signature over unstructured lattices
//     (ML-DSA construction, SIS/LWE assumptions),
//   - uov:    Unbalanced Oil and Vinegar over F_256 (multivariate quadratic),
//   - slhdsa: SLH-DSA / SPHINCS+ with SHAKE256 (hash-function assumptions only).
//
// Signing draws a fresh 32-byte nonce, hashes it with the composite public
// key hash and the message into a 64-byte digest μ, and signs μ with every
// component. A composite signature is valid only if all three component
// signatures are valid, so forging one requires breaking all three problems.
// The nonce ties the three components to one signature: components taken
// from two different signatures on the same message never share a digest,
// so they cannot be recombined (strong unforgeability of the composite then
// follows from the unforgeability of the components).
//
// Every serialized object starts with the self-describing header of
// internal/wire, so deserialization needs no parameters.
package sign

import (
	"fmt"
	"sync"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/core"
	"github.com/BackendStack21/k-mosaic-go/entanglement"
	"github.com/BackendStack21/k-mosaic-go/internal/wire"
	"github.com/BackendStack21/k-mosaic-go/problems/latsig"
	"github.com/BackendStack21/k-mosaic-go/problems/slhdsa"
	"github.com/BackendStack21/k-mosaic-go/problems/uov"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

const (
	DomainLattice = "kmosaic-sign-lattice-v4"
	DomainMQ      = "kmosaic-sign-mq-v4"
	DomainHash    = "kmosaic-sign-hash-v4"
	DomainMessage = "kmosaic-sign-msg-v4"

	// SeedSize is the exact size of a key-generation seed.
	SeedSize = 32
	// NonceSize is the size of the per-signature nonce.
	NonceSize = 32
	// PublicKeyHashSize is the size of the composite public key hash.
	PublicKeyHashSize = 64
	// MaxComponentSize bounds any length prefix read during deserialization.
	MaxComponentSize = 16 * 1024 * 1024
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
	seed, err := utils.SecureRandomBytes(SeedSize)
	if err != nil {
		return nil, err
	}
	defer utils.Zeroize(seed)
	return GenerateKeyPairFromSeed(params, seed)
}

// GenerateKeyPairFromSeed deterministically generates a composite key pair
// from a 32-byte seed.
func GenerateKeyPairFromSeed(params kmosaic.SignParams, seed []byte) (*kmosaic.MOSAICSignKeyPair, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("%w: seed must be exactly %d bytes", kmosaic.ErrInvalidKey, SeedSize)
	}
	if err := core.ValidateSignParams(params); err != nil {
		return nil, fmt.Errorf("%w: %v", kmosaic.ErrInvalidParams, err)
	}
	if known, err := core.GetSignParams(params.Level); err != nil || known != params {
		return nil, fmt.Errorf("%w: parameters do not match level %q", kmosaic.ErrInvalidParams, params.Level)
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

	publicKey := kmosaic.MOSAICSignPublicKey{
		Params:  params,
		Lattice: latKP.PublicKey,
		MQ:      mqKP.PublicKey,
		Hash:    hashKP.PublicKey,
	}
	publicKey.Binding = entanglement.ComputeBinding(
		latsig.SerializePublicKey(&publicKey.Lattice),
		uov.SerializePublicKey(&publicKey.MQ),
		slhdsa.SerializePublicKey(&publicKey.Hash),
	)
	publicKey.KeyHash = utils.Shake256(SerializePublicKey(&publicKey), PublicKeyHashSize)

	secretKey := kmosaic.MOSAICSignSecretKey{
		Params:        params,
		Lattice:       latKP.SecretKey,
		MQ:            mqKP.SecretKey,
		Hash:          hashKP.SecretKey,
		Seed:          append([]byte{}, seed...),
		PublicKeyHash: append([]byte{}, publicKey.KeyHash...),
	}
	return &kmosaic.MOSAICSignKeyPair{PublicKey: publicKey, SecretKey: secretKey}, nil
}

// PublicKeyHash returns the cached hash of pk, computing it if necessary.
func PublicKeyHash(pk *kmosaic.MOSAICSignPublicKey) []byte {
	if len(pk.KeyHash) == PublicKeyHashSize {
		return pk.KeyHash
	}
	return utils.Shake256(SerializePublicKey(pk), PublicKeyHashSize)
}

// messageDigest binds the message to the composite public key and the nonce.
func messageDigest(pkHash, nonce, message []byte) []byte {
	in := make([]byte, 0, len(pkHash)+len(nonce)+len(message))
	in = append(in, pkHash...)
	in = append(in, nonce...)
	in = append(in, message...)
	return utils.Shake256WithDomain(DomainMessage, in, PublicKeyHashSize)
}

// Sign creates a composite signature on message. pk, if non-nil, must match sk.
func Sign(sk *kmosaic.MOSAICSignSecretKey, pk *kmosaic.MOSAICSignPublicKey, message []byte) (result *kmosaic.MOSAICSignature, err error) {
	defer func() {
		if r := recover(); r != nil {
			result = nil
			err = fmt.Errorf("signature creation panic: %v", r)
		}
	}()

	if sk == nil {
		return nil, fmt.Errorf("%w: nil secret key", kmosaic.ErrInvalidKey)
	}
	if err := core.ValidateSignParams(sk.Params); err != nil {
		return nil, fmt.Errorf("%w: %v", kmosaic.ErrInvalidParams, err)
	}
	if len(sk.PublicKeyHash) != PublicKeyHashSize {
		return nil, fmt.Errorf("%w: missing public key hash", kmosaic.ErrInvalidKey)
	}
	if pk != nil && !utils.ConstantTimeEqual(sk.PublicKeyHash, PublicKeyHash(pk)) {
		return nil, kmosaic.ErrKeyMismatch
	}
	nonce, err := utils.SecureRandomBytes(NonceSize)
	if err != nil {
		return nil, err
	}
	mu := messageDigest(sk.PublicKeyHash, nonce, message)

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
	return &kmosaic.MOSAICSignature{Nonce: nonce, Lattice: *latSig, MQ: *mqSig, Hash: *hashSig}, nil
}

// Verify reports whether sig is a valid composite signature on message
// under pk. All three component signatures are checked; all must pass.
func Verify(pk *kmosaic.MOSAICSignPublicKey, message []byte, sig *kmosaic.MOSAICSignature) (isValid bool) {
	defer func() {
		if r := recover(); r != nil {
			isValid = false
		}
	}()
	if pk == nil || sig == nil || len(sig.Nonce) != NonceSize {
		return false
	}
	if err := core.ValidateSignParams(pk.Params); err != nil {
		return false
	}
	mu := messageDigest(PublicKeyHash(pk), sig.Nonce, message)

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

// SerializePublicKey serializes a composite public key:
// header || [lat_len:4][lat] || [mq_len:4][mq] || [hash_len:4][hash] || binding:32.
func SerializePublicKey(pk *kmosaic.MOSAICSignPublicKey) []byte {
	hdr, err := wire.Header(wire.TypeSignPublicKey, pk.Params.Level)
	if err != nil {
		return nil
	}
	out := hdr
	out = wire.AppendLV(out, latsig.SerializePublicKey(&pk.Lattice))
	out = wire.AppendLV(out, uov.SerializePublicKey(&pk.MQ))
	out = wire.AppendLV(out, slhdsa.SerializePublicKey(&pk.Hash))
	return append(out, pk.Binding...)
}

// DeserializePublicKey parses a composite public key, validates its binding
// and caches its hash.
func DeserializePublicKey(data []byte) (*kmosaic.MOSAICSignPublicKey, error) {
	level, body, err := wire.ParseHeader(data, wire.TypeSignPublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", kmosaic.ErrInvalidKey, err)
	}
	params, _ := core.GetSignParams(level)
	r := wire.NewReader(body)
	latBytes, err := r.LV(MaxComponentSize)
	if err != nil {
		return nil, fmt.Errorf("%w: lattice component: %v", kmosaic.ErrInvalidKey, err)
	}
	mqBytes, err := r.LV(MaxComponentSize)
	if err != nil {
		return nil, fmt.Errorf("%w: MQ component: %v", kmosaic.ErrInvalidKey, err)
	}
	hashBytes, err := r.LV(MaxComponentSize)
	if err != nil {
		return nil, fmt.Errorf("%w: hash component: %v", kmosaic.ErrInvalidKey, err)
	}
	binding, err := r.Fixed(32)
	if err != nil || r.Done() != nil {
		return nil, fmt.Errorf("%w: binding has wrong length", kmosaic.ErrInvalidKey)
	}
	if !utils.ConstantTimeEqual(binding, entanglement.ComputeBinding(latBytes, mqBytes, hashBytes)) {
		return nil, fmt.Errorf("%w: binding mismatch", kmosaic.ErrInvalidKey)
	}

	var wg sync.WaitGroup
	var latPK *kmosaic.LatticeSignPublicKey
	var mqPK *kmosaic.MQPublicKey
	var hashPK *kmosaic.HashSignPublicKey
	var errLat, errMQ, errHash error
	wg.Add(3)
	go func() {
		defer wg.Done()
		latPK, errLat = latsig.DeserializePublicKey(latBytes)
	}()
	go func() {
		defer wg.Done()
		mqPK, errMQ = uov.DeserializePublicKey(mqBytes, params.MQ)
	}()
	go func() {
		defer wg.Done()
		hashPK, errHash = slhdsa.DeserializePublicKey(hashBytes, params.Hash)
	}()
	wg.Wait()
	for _, err := range []error{errLat, errMQ, errHash} {
		if err != nil {
			return nil, fmt.Errorf("%w: %v", kmosaic.ErrInvalidKey, err)
		}
	}
	if latPK.Params != params.Lattice {
		return nil, fmt.Errorf("%w: lattice component level mismatch", kmosaic.ErrInvalidKey)
	}
	pk := &kmosaic.MOSAICSignPublicKey{Params: params, Lattice: *latPK, MQ: *mqPK, Hash: *hashPK, Binding: append([]byte{}, binding...)}
	pk.KeyHash = utils.Shake256(data, PublicKeyHashSize)
	return pk, nil
}

// SerializeSecretKey serializes a composite secret key:
// header || [lat_len:4][lat] || [mq_len:4][mq] || [hash_len:4][hash] || seed:32 || pkhash:64.
func SerializeSecretKey(sk *kmosaic.MOSAICSignSecretKey) []byte {
	hdr, err := wire.Header(wire.TypeSignSecretKey, sk.Params.Level)
	if err != nil {
		return nil
	}
	out := hdr
	out = wire.AppendLV(out, latsig.SerializeSecretKey(&sk.Lattice))
	out = wire.AppendLV(out, uov.SerializeSecretKey(&sk.MQ))
	out = wire.AppendLV(out, slhdsa.SerializeSecretKey(&sk.Hash))
	out = append(out, sk.Seed...)
	return append(out, sk.PublicKeyHash...)
}

// DeserializeSecretKey parses a composite secret key.
func DeserializeSecretKey(data []byte) (*kmosaic.MOSAICSignSecretKey, error) {
	level, body, err := wire.ParseHeader(data, wire.TypeSignSecretKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", kmosaic.ErrInvalidKey, err)
	}
	params, _ := core.GetSignParams(level)
	r := wire.NewReader(body)
	latBytes, err := r.LV(MaxComponentSize)
	if err != nil {
		return nil, fmt.Errorf("%w: lattice component: %v", kmosaic.ErrInvalidKey, err)
	}
	mqBytes, err := r.LV(MaxComponentSize)
	if err != nil {
		return nil, fmt.Errorf("%w: MQ component: %v", kmosaic.ErrInvalidKey, err)
	}
	hashBytes, err := r.LV(MaxComponentSize)
	if err != nil {
		return nil, fmt.Errorf("%w: hash component: %v", kmosaic.ErrInvalidKey, err)
	}
	seed, err := r.Fixed(SeedSize)
	if err != nil {
		return nil, fmt.Errorf("%w: seed truncated", kmosaic.ErrInvalidKey)
	}
	pkHash, err := r.Fixed(PublicKeyHashSize)
	if err != nil || r.Done() != nil {
		return nil, fmt.Errorf("%w: public key hash has wrong length", kmosaic.ErrInvalidKey)
	}

	var wg sync.WaitGroup
	var latSK *kmosaic.LatticeSignSecretKey
	var mqSK *kmosaic.MQSecretKey
	var hashSK *kmosaic.HashSignSecretKey
	var errLat, errMQ, errHash error
	wg.Add(3)
	go func() {
		defer wg.Done()
		latSK, errLat = latsig.DeserializeSecretKey(latBytes)
	}()
	go func() {
		defer wg.Done()
		mqSK, errMQ = uov.DeserializeSecretKey(mqBytes, params.MQ)
	}()
	go func() {
		defer wg.Done()
		hashSK, errHash = slhdsa.DeserializeSecretKey(hashBytes, params.Hash)
	}()
	wg.Wait()
	for _, err := range []error{errLat, errMQ, errHash} {
		if err != nil {
			return nil, fmt.Errorf("%w: %v", kmosaic.ErrInvalidKey, err)
		}
	}
	if latSK.Params != params.Lattice {
		return nil, fmt.Errorf("%w: lattice component level mismatch", kmosaic.ErrInvalidKey)
	}
	return &kmosaic.MOSAICSignSecretKey{
		Params:        params,
		Lattice:       *latSK,
		MQ:            *mqSK,
		Hash:          *hashSK,
		Seed:          append([]byte{}, seed...),
		PublicKeyHash: append([]byte{}, pkHash...),
	}, nil
}

// SerializeSignature serializes a composite signature:
// header || nonce:32 || [lat_len:4][lat] || [mq_len:4][mq] || [hash_len:4][hash].
func SerializeSignature(sig *kmosaic.MOSAICSignature, params kmosaic.SignParams) []byte {
	hdr, err := wire.Header(wire.TypeSignature, params.Level)
	if err != nil {
		return nil
	}
	out := append(hdr, sig.Nonce...)
	out = wire.AppendLV(out, latsig.SerializeSignature(&sig.Lattice, params.Lattice))
	out = wire.AppendLV(out, uov.SerializeSignature(&sig.MQ))
	return wire.AppendLV(out, sig.Hash.Data)
}

// DeserializeSignature parses a composite signature. The parameters are taken
// from the header and returned with the signature.
func DeserializeSignature(data []byte) (*kmosaic.MOSAICSignature, kmosaic.SignParams, error) {
	level, body, err := wire.ParseHeader(data, wire.TypeSignature)
	if err != nil {
		return nil, kmosaic.SignParams{}, fmt.Errorf("%w: %v", kmosaic.ErrInvalidSignature, err)
	}
	params, _ := core.GetSignParams(level)
	r := wire.NewReader(body)
	nonce, err := r.Fixed(NonceSize)
	if err != nil {
		return nil, params, fmt.Errorf("%w: nonce truncated", kmosaic.ErrInvalidSignature)
	}
	latBytes, err := r.LV(MaxComponentSize)
	if err != nil {
		return nil, params, fmt.Errorf("%w: lattice component: %v", kmosaic.ErrInvalidSignature, err)
	}
	mqBytes, err := r.LV(MaxComponentSize)
	if err != nil {
		return nil, params, fmt.Errorf("%w: MQ component: %v", kmosaic.ErrInvalidSignature, err)
	}
	hashBytes, err := r.LV(MaxComponentSize)
	if err != nil || r.Done() != nil {
		return nil, params, fmt.Errorf("%w: hash component truncated or trailing data", kmosaic.ErrInvalidSignature)
	}
	latSig, err := latsig.DeserializeSignature(latBytes, params.Lattice)
	if err != nil {
		return nil, params, fmt.Errorf("%w: %v", kmosaic.ErrInvalidSignature, err)
	}
	mqSig, err := uov.DeserializeSignature(mqBytes, params.MQ)
	if err != nil {
		return nil, params, fmt.Errorf("%w: %v", kmosaic.ErrInvalidSignature, err)
	}
	if len(hashBytes) != slhdsa.SignatureSize(params.Hash) {
		return nil, params, fmt.Errorf("%w: hash component has wrong length", kmosaic.ErrInvalidSignature)
	}
	return &kmosaic.MOSAICSignature{
		Nonce:   append([]byte{}, nonce...),
		Lattice: *latSig,
		MQ:      *mqSig,
		Hash:    kmosaic.HashSignature{Data: append([]byte{}, hashBytes...)},
	}, params, nil
}
