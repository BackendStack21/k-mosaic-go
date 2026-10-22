package sign

import (
	"encoding/hex"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go/v4"
	"github.com/BackendStack21/k-mosaic-go/v4/core"
	"github.com/BackendStack21/k-mosaic-go/v4/utils"
)

// TestKnownAnswers pins the composite signature keys: SHA3-256 digests of
// the serialized public and secret key for a fixed seed at both levels.
// Signatures themselves are randomized (nonce, hedged components) and are
// not pinned here; the components pin their deterministic paths. A change
// must be deliberate, stated in CHANGELOG.md, and update the digests in the
// same commit.
func TestKnownAnswers(t *testing.T) {
	want := map[kmosaic.SecurityLevel][2]string{
		kmosaic.MOS_128: {KAT128PK, KAT128SK},
		kmosaic.MOS_256: {KAT256PK, KAT256SK},
	}
	seed := make([]byte, SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	for level, w := range want {
		params, _ := core.GetSignParams(level)
		kp, err := GenerateKeyPairFromSeed(params, seed)
		if err != nil {
			t.Fatal(err)
		}
		got := [2]string{
			hex.EncodeToString(utils.SHA3256(SerializePublicKey(&kp.PublicKey))),
			hex.EncodeToString(utils.SHA3256(SerializeSecretKey(&kp.SecretKey))),
		}
		if got != w {
			t.Errorf("%s: known answers changed:\n got  %q\n want %q", level, got, w)
		}
	}
}

// Digests pinned on 2026-10-22 for version 4.2.0.
const (
	KAT128PK = "2ab80ca44d7e75adad0ccd872cd3b3b1fa9fa980aad9c3f1dce7b8243abbb589"
	KAT128SK = "c71389dcdd93fcbf35c28e32d3ec2647f603ad044f9aee994111af6dbfa1468b"
	KAT256PK = "3ab4cb9d3de23c034afee4434c9b0572d90fbd1e8177648edfa04ea51405dcac"
	KAT256SK = "78d45c8adcaf79f85883cfc8979de72e129802bba9d04e80a25851028ad97586"
)
