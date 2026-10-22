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
// signatures are valid, so forging one requires breaking all three problems
// (or finding a second preimage of the 64-byte SHAKE256 digest they all
// sign). The nonce ties the three components to one signature: components
// taken from two different signatures on the same message never share a
// digest, so they cannot be recombined. Strong unforgeability of the
// composite additionally requires every component to be strongly
// unforgeable, since replacing one component signature by another valid one
// for the same digest would be a new signature; this is assumed of the
// components, not tested.
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
		return nil, fmt.Errorf("%w: %v", kmosaic.ErrInvalidParams, err)
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
	if err := checkKnownParams(params); err != nil {
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
		defer recoverInto(&errLat)
		latKP, errLat = latsig.GenerateKeyPairFromSeed(params.Lattice, latSeed)
	}()
	go func() {
		defer wg.Done()
		defer recoverInto(&errMQ)
		mqKP, errMQ = uov.KeyGen(params.MQ, mqSeed)
	}()
	go func() {
		defer wg.Done()
		defer recoverInto(&errHash)
		hashKP, errHash = slhdsa.KeyGen(params.Hash, hashSeed)
	}()
	wg.Wait()
	for _, err := range []error{errLat, errMQ, errHash} {
		if err != nil {
			wipeComponents(latKP, mqKP, hashKP)
			return nil, fmt.Errorf("%w: %v", kmosaic.ErrInvalidParams, err)
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
// The cache is trusted: keys produced by GenerateKeyPair or
// DeserializePublicKey carry the correct hash, and a key struct edited by
// hand (other fields changed, KeyHash kept) is not detected. Clear
// pk.KeyHash after editing a key in memory to force recomputation.
func PublicKeyHash(pk *kmosaic.MOSAICSignPublicKey) []byte {
	if pk == nil {
		return nil
	}
	if len(pk.KeyHash) == PublicKeyHashSize {
		return pk.KeyHash
	}
	return utils.Shake256(SerializePublicKey(pk), PublicKeyHashSize)
}

// recoverInto converts a panic in a component call into an error, so that a
// component bug surfaces as a failed operation instead of crashing the
// process. The component packages validate their inputs, so this is a
// backstop, not a control path.
func recoverInto(err *error) {
	if r := recover(); r != nil {
		*err = fmt.Errorf("component panic: %v", r)
	}
}

// wipeComponents zeroizes whatever component secret keys were produced
// before an error aborted key generation.
func wipeComponents(lat *kmosaic.LatticeSignKeyPair, mq *kmosaic.MQKeyPair, hash *kmosaic.HashSignKeyPair) {
	if lat != nil {
		wipeLatticeSecret(&lat.SecretKey)
	}
	if mq != nil {
		wipeMQSecret(&mq.SecretKey)
	}
	if hash != nil {
		wipeHashSecret(&hash.SecretKey)
	}
}

func wipeLatticeSecret(sk *kmosaic.LatticeSignSecretKey) {
	utils.ZeroizeInt8(sk.S1)
	utils.ZeroizeInt8(sk.S2)
	utils.ZeroizeInt32(sk.T0)
	utils.Zeroize(sk.K)
}

func wipeMQSecret(sk *kmosaic.MQSecretKey) {
	utils.Zeroize(sk.Seed)
	utils.Zeroize(sk.O)
	utils.Zeroize(sk.S)
	utils.Zeroize(sk.Prepared)
}

func wipeHashSecret(sk *kmosaic.HashSignSecretKey) {
	utils.Zeroize(sk.Seed)
	utils.Zeroize(sk.PRF)
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
	if err := checkKnownParams(sk.Params); err != nil {
		return nil, err
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
		defer recoverInto(&errLat)
		latSig, errLat = latsig.Sign(&sk.Lattice, nil, mu)
	}()
	go func() {
		defer wg.Done()
		defer recoverInto(&errMQ)
		mqSig, errMQ = uov.Sign(&sk.MQ, sk.Params.MQ, mu)
	}()
	go func() {
		defer wg.Done()
		defer recoverInto(&errHash)
		hashSig, errHash = slhdsa.Sign(&sk.Hash, sk.Params.Hash, mu)
	}()
	wg.Wait()
	for _, err := range []error{errLat, errMQ, errHash} {
		if err != nil {
			return nil, fmt.Errorf("%w: %v", kmosaic.ErrInvalidKey, err)
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
	if checkKnownParams(pk.Params) != nil {
		return false
	}
	mu := messageDigest(PublicKeyHash(pk), sig.Nonce, message)

	var wg sync.WaitGroup
	var okLat, okMQ, okHash bool
	wg.Add(3)
	go func() {
		defer wg.Done()
		defer func() { _ = recover() }() // a panicking component verifies as false
		okLat = latsig.Verify(&pk.Lattice, mu, &sig.Lattice)
	}()
	go func() {
		defer wg.Done()
		defer func() { _ = recover() }()
		okMQ = uov.Verify(&pk.MQ, pk.Params.MQ, mu, &sig.MQ)
	}()
	go func() {
		defer wg.Done()
		defer func() { _ = recover() }()
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
// It returns nil for a nil key, a key whose parameters are not a published
// level, or a key with a mis-shaped component.
func SerializePublicKey(pk *kmosaic.MOSAICSignPublicKey) []byte {
	if pk == nil || checkKnownParams(pk.Params) != nil || len(pk.Binding) != 32 || pk.Lattice.Params != pk.Params.Lattice {
		return nil
	}
	hdr, err := wire.Header(wire.TypeSignPublicKey, pk.Params.Level)
	if err != nil {
		return nil
	}
	lat, mq, hash := latsig.SerializePublicKey(&pk.Lattice), uov.SerializePublicKey(&pk.MQ), slhdsa.SerializePublicKey(&pk.Hash)
	if lat == nil || mq == nil || hash == nil {
		return nil
	}
	out := hdr
	out = wire.AppendLV(out, lat)
	out = wire.AppendLV(out, mq)
	out = wire.AppendLV(out, hash)
	return append(out, pk.Binding...)
}

// checkKnownParams rejects any parameter set that is not exactly the
// published set for its level.
func checkKnownParams(params kmosaic.SignParams) error {
	if err := core.ValidateSignParams(params); err != nil {
		return fmt.Errorf("%w: %v", kmosaic.ErrInvalidParams, err)
	}
	if known, err := core.GetSignParams(params.Level); err != nil || known != params {
		return fmt.Errorf("%w: parameters do not match level %q", kmosaic.ErrInvalidParams, params.Level)
	}
	return nil
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
		defer recoverInto(&errLat)
		latPK, errLat = latsig.DeserializePublicKey(latBytes)
	}()
	go func() {
		defer wg.Done()
		defer recoverInto(&errMQ)
		mqPK, errMQ = uov.DeserializePublicKey(mqBytes, params.MQ)
	}()
	go func() {
		defer wg.Done()
		defer recoverInto(&errHash)
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
// It returns nil for a nil key, a key whose parameters are not a published
// level, or a key with a mis-shaped component.
func SerializeSecretKey(sk *kmosaic.MOSAICSignSecretKey) []byte {
	if sk == nil || checkKnownParams(sk.Params) != nil || len(sk.Seed) != SeedSize ||
		len(sk.PublicKeyHash) != PublicKeyHashSize || sk.Lattice.Params != sk.Params.Lattice {
		return nil
	}
	hdr, err := wire.Header(wire.TypeSignSecretKey, sk.Params.Level)
	if err != nil {
		return nil
	}
	lat, mq, hash := latsig.SerializeSecretKey(&sk.Lattice), uov.SerializeSecretKey(&sk.MQ), slhdsa.SerializeSecretKey(&sk.Hash)
	if lat == nil || mq == nil || hash == nil {
		return nil
	}
	out := hdr
	out = wire.AppendLV(out, lat)
	out = wire.AppendLV(out, mq)
	out = wire.AppendLV(out, hash)
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
		defer recoverInto(&errLat)
		latSK, errLat = latsig.DeserializeSecretKey(latBytes)
	}()
	go func() {
		defer wg.Done()
		defer recoverInto(&errMQ)
		mqSK, errMQ = uov.DeserializeSecretKey(mqBytes, params.MQ)
	}()
	go func() {
		defer wg.Done()
		defer recoverInto(&errHash)
		hashSK, errHash = slhdsa.DeserializeSecretKey(hashBytes, params.Hash)
	}()
	wg.Wait()
	wipeAll := func() {
		if latSK != nil {
			wipeLatticeSecret(latSK)
		}
		if mqSK != nil {
			wipeMQSecret(mqSK)
		}
		if hashSK != nil {
			wipeHashSecret(hashSK)
		}
	}
	for _, err := range []error{errLat, errMQ, errHash} {
		if err != nil {
			wipeAll()
			return nil, fmt.Errorf("%w: %v", kmosaic.ErrInvalidKey, err)
		}
	}
	if latSK.Params != params.Lattice {
		wipeAll()
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
// It returns nil if sig is nil or does not have the shape of a signature
// under params (so a signature serialized under the wrong level is refused
// rather than emitted with an empty component).
func SerializeSignature(sig *kmosaic.MOSAICSignature, params kmosaic.SignParams) []byte {
	if sig == nil || checkKnownParams(params) != nil || len(sig.Nonce) != NonceSize ||
		len(sig.Hash.Data) != slhdsa.SignatureSize(params.Hash) {
		return nil
	}
	hdr, err := wire.Header(wire.TypeSignature, params.Level)
	if err != nil {
		return nil
	}
	lat, mq := latsig.SerializeSignature(&sig.Lattice, params.Lattice), uov.SerializeSignature(&sig.MQ)
	if lat == nil || mq == nil || len(sig.MQ.S) != params.MQ.N {
		return nil
	}
	out := append(hdr, sig.Nonce...)
	out = wire.AppendLV(out, lat)
	out = wire.AppendLV(out, mq)
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
