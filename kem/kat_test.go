package kem

import (
	"encoding/hex"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go/v4"
	"github.com/BackendStack21/k-mosaic-go/v4/core"
	"github.com/BackendStack21/k-mosaic-go/v4/utils"
)

// TestKnownAnswers pins the composite KEM: SHA3-256 digests of the
// serialized public key, secret key and a deterministic encapsulation for a
// fixed seed and ephemeral secret, at both levels. Any change to the
// seed-to-key derivation, the samplers, the encodings or the FO transform
// changes these digests; such a change must be deliberate, stated in
// CHANGELOG.md, and update the digests in the same commit.
func TestKnownAnswers(t *testing.T) {
	want := map[kmosaic.SecurityLevel][4]string{
		kmosaic.MOS_128: {KAT128PK, KAT128SK, KAT128CT, KAT128SS},
		kmosaic.MOS_256: {KAT256PK, KAT256SK, KAT256CT, KAT256SS},
	}
	seed := make([]byte, SeedSize)
	eph := make([]byte, SharedSecretSize)
	for i := range seed {
		seed[i] = byte(i)
		eph[i] = byte(0xA0 + i)
	}
	for level, w := range want {
		params, _ := core.GetParams(level)
		kp, err := GenerateKeyPairFromSeed(params, seed)
		if err != nil {
			t.Fatal(err)
		}
		res, err := EncapsulateDeterministic(&kp.PublicKey, eph)
		if err != nil {
			t.Fatal(err)
		}
		got := [4]string{
			hex.EncodeToString(utils.SHA3256(SerializePublicKey(&kp.PublicKey))),
			hex.EncodeToString(utils.SHA3256(SerializeSecretKey(&kp.SecretKey, params))),
			hex.EncodeToString(utils.SHA3256(SerializeCiphertext(&res.Ciphertext, params))),
			hex.EncodeToString(res.SharedSecret),
		}
		if got != w {
			t.Errorf("%s: known answers changed:\n got  %q\n want %q", level, got, w)
		}
	}
}

// Digests pinned on 2026-10-22 for version 4.2.0.
const (
	KAT128PK = "4f56374e727295ec4e247eaf96b9037bf0764d2763af1a5f3602ed7b0597f299"
	KAT128SK = "12151cc5331973e1ed180854ea98200b6bebc3d499df7e5295d9e91073eb3401"
	KAT128CT = "d5af7035f4354039f30358f07d1fcd02b2c69e7c7feea8ec099637b44366fa15"
	KAT128SS = "419e1cfbbe18aecb2c41d3feac2c3060d73e0b100fe65a25119d2195161ebbdd"
	KAT256PK = "51afd3eee674c8e78b48e8b28a09ef99d094ab2fbd3770a4813f288083df0899"
	KAT256SK = "22ba09d232046c5385ddf256d67a8aa315b8cc9b3a149db9656509bd3af4e724"
	KAT256CT = "e8dd37e2b3cd6044e55158b38c6585cc40160f8e9a8aa2764242fd2f0cfef264"
	KAT256SS = "3cb886167de8b03bcb54e4972b2e040ceb052904338b5a6c8e11027d09b1f669"
)
