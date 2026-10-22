package slss

import (
	"bytes"
	"encoding/hex"
	"math"
	"slices"
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go/v4"
	"github.com/BackendStack21/k-mosaic-go/v4/core"
	"github.com/BackendStack21/k-mosaic-go/v4/utils"
)

var levels = []kmosaic.SecurityLevel{kmosaic.MOS_128, kmosaic.MOS_256}

func testMessage(params kmosaic.SLSSParams) []byte {
	msg := make([]byte, MessageSize(params))
	for i := range msg {
		msg[i] = byte(i*37 + 11)
	}
	return msg
}

func fixedSeed(tag byte) []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = tag ^ byte(i*7)
	}
	return s
}

func TestSLSS(t *testing.T) {
	for _, level := range levels {
		t.Run(string(level), func(t *testing.T) {
			params, _ := core.GetParams(level)

			seed, _ := utils.SecureRandomBytes(32)
			kp, err := KeyGen(params.SLSS, seed)
			if err != nil {
				t.Fatalf("KeyGen failed: %v", err)
			}
			if len(kp.PublicKey.T) != params.SLSS.L*params.SLSS.M || len(kp.SecretKey.S) != params.SLSS.L*params.SLSS.N {
				t.Fatal("key dimensions do not match params")
			}

			for trial := 0; trial < 5; trial++ {
				msg := testMessage(params.SLSS)
				msg[0] = byte(trial)
				randomness, _ := utils.SecureRandomBytes(32)
				ct, err := Encrypt(kp.PublicKey, msg, params.SLSS, randomness)
				if err != nil {
					t.Fatalf("Encrypt failed: %v", err)
				}
				for _, u := range ct.U {
					if u < 0 || u >= 1<<params.SLSS.DU {
						t.Fatalf("u coefficient %d not compressed", u)
					}
				}
				for _, v := range ct.V {
					if v < 0 || v >= 1<<params.SLSS.DV {
						t.Fatalf("v coefficient %d not compressed", v)
					}
				}
				dec := Decrypt(ct, kp.SecretKey, params.SLSS)
				if !bytes.Equal(msg, dec) {
					t.Fatalf("decryption mismatch: got %x want %x", dec, msg)
				}
			}
		})
	}
}

func TestEncrypt_RejectsWrongMessageSize(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS_128)
	seed, _ := utils.SecureRandomBytes(32)
	kp, _ := KeyGen(params.SLSS, seed)
	randomness, _ := utils.SecureRandomBytes(32)
	for _, n := range []int{0, 4, 31, 33, 64} {
		if _, err := Encrypt(kp.PublicKey, make([]byte, n), params.SLSS, randomness); err == nil {
			t.Errorf("Encrypt accepted a %d-byte message", n)
		}
	}
	msg := testMessage(params.SLSS)
	if _, err := Encrypt(kp.PublicKey, msg, params.SLSS, randomness[:31]); err == nil {
		t.Error("Encrypt accepted short randomness")
	}
	bad := kp.PublicKey
	bad.A = bad.A[:len(bad.A)-1]
	if _, err := Encrypt(bad, msg, params.SLSS, randomness); err == nil {
		t.Error("Encrypt accepted a truncated A")
	}
	bad = kp.PublicKey
	bad.T = bad.T[:len(bad.T)-1]
	if _, err := Encrypt(bad, msg, params.SLSS, randomness); err == nil {
		t.Error("Encrypt accepted a truncated T")
	}
}

// TestCiphertextDoesNotLeakMessage checks that the (decompressed) v
// component does not cluster around two values: in the original design every
// v_i shared one inner product, so the bits were readable from the
// ciphertext alone.
func TestCiphertextDoesNotLeakMessage(t *testing.T) {
	params, _ := core.GetParams(kmosaic.MOS_128)
	p := params.SLSS
	seed, _ := utils.SecureRandomBytes(32)
	kp, _ := KeyGen(p, seed)
	for trial := 0; trial < 4; trial++ {
		randomness, _ := utils.SecureRandomBytes(32)
		msg := testMessage(p)
		msg[1] = byte(trial)
		ct, _ := Encrypt(kp.PublicKey, msg, p, randomness)

		// Decode the way the old attack did: cluster v relative to v[0].
		v0 := decompress(ct.V[0], uint(p.DV))
		correct := 0
		for j := range ct.V {
			d := int(mod32(decompress(ct.V[j], uint(p.DV)) - v0))
			bit := byte(0)
			if d > q/4 && d < 3*q/4 {
				bit = 1
			}
			if bit == (msg[j/8]>>(j%8))&1 {
				correct++
			}
		}
		// Either polarity must look like a coin flip (σ = 8 bits), not a
		// decryption.
		if correct > 3*len(ct.V)/4 || correct < len(ct.V)/4 {
			t.Fatalf("clustering attack recovered %d/%d bits", correct, len(ct.V))
		}
	}
}

func TestMathOps(t *testing.T) {
	cases := []struct {
		x    int64
		want int32
	}{{-5, q - 5}, {5, 5}, {0, 0}, {q, 0}, {-q, 0}, {q - 1, q - 1}, {-q - 1, q - 1}, {1 << 40, int32((1 << 40) % q)}, {-(1 << 40), int32(q - (1<<40)%q)}}
	for _, c := range cases {
		if got := mod(c.x); got != c.want {
			t.Errorf("mod(%d) = %d, want %d", c.x, got, c.want)
		}
		if c.x >= math.MinInt32 && c.x <= math.MaxInt32 {
			if got := mod32(int32(c.x)); got != c.want {
				t.Errorf("mod32(%d) = %d, want %d", c.x, got, c.want)
			}
		}
	}
	for _, x := range []int32{math.MinInt32, math.MaxInt32, -1, 1} {
		want := int32(((int64(x) % q) + q) % q)
		if got := mod32(x); got != want {
			t.Errorf("mod32(%d) = %d, want %d", x, got, want)
		}
	}
	for x := int32(-2 * q); x <= 2*q; x++ {
		c := centerMod(x)
		if c < -(q-1)/2 || c > (q-1)/2 || mod32(c-x) != 0 {
			t.Fatalf("centerMod(%d) = %d", x, c)
		}
	}
}

// TestCompression checks the FIPS 203 bounds: decompress(compress(x)) is
// within round(q/2^(d+1)) of x (mod± q), compress∘decompress is the identity
// when 2^d < q, and decompress∘compress is the identity when 2^d > q.
func TestCompression(t *testing.T) {
	for d := uint(1); d <= 14; d++ {
		bound := int32((q + (1 << d)) >> (d + 1)) // round(q / 2^(d+1))
		for x := int32(0); x < q; x++ {
			c := compress(x, d)
			if c < 0 || c >= 1<<d {
				t.Fatalf("d=%d: compress(%d) = %d out of range", d, x, c)
			}
			y := decompress(c, d)
			if y < 0 || y >= q {
				t.Fatalf("d=%d: decompress(%d) = %d out of range", d, c, y)
			}
			if e := centerMod(y - x); e > bound || e < -bound {
				t.Fatalf("d=%d: x=%d round trip %d error %d > %d", d, x, y, e, bound)
			}
			if 1<<d > q && y != x {
				t.Fatalf("d=%d: round trip of %d not exact", d, x)
			}
		}
		if 1<<d < q {
			for c := int32(0); c < 1<<d; c++ {
				if got := compress(decompress(c, d), d); got != c {
					t.Fatalf("d=%d: compress(decompress(%d)) = %d", d, c, got)
				}
			}
		}
		// Out-of-range inputs to decompress are masked, never out of [0, q).
		for _, c := range []int32{-1, 1 << d, math.MaxInt32, math.MinInt32} {
			if y := decompress(c, d); y < 0 || y >= q {
				t.Fatalf("d=%d: decompress(%d) = %d", d, c, y)
			}
		}
	}
}

func TestSerializeDeserializePublicKey(t *testing.T) {
	for _, level := range levels {
		t.Run(string(level), func(t *testing.T) {
			params, _ := core.GetParams(level)
			seed, _ := utils.SecureRandomBytes(32)
			kp, err := KeyGen(params.SLSS, seed)
			if err != nil {
				t.Fatalf("KeyGen failed: %v", err)
			}

			serialized := SerializePublicKey(kp.PublicKey)
			if len(serialized) != PublicKeySize(params.SLSS) || len(serialized) != SeedSize+params.SLSS.L*params.SLSS.M*14/8 {
				t.Fatalf("unexpected serialized size %d", len(serialized))
			}

			deserialized, err := DeserializePublicKey(serialized, params.SLSS)
			if err != nil {
				t.Fatalf("DeserializePublicKey failed: %v", err)
			}
			if !bytes.Equal(serialized, SerializePublicKey(*deserialized)) {
				t.Error("round trip of public key failed")
			}
			if !slices.Equal(deserialized.T, kp.PublicKey.T) || !bytes.Equal(deserialized.Seed, kp.PublicKey.Seed) {
				t.Error("deserialized key differs")
			}
			if !slices.Equal(deserialized.A, kp.PublicKey.A) {
				t.Error("matrix re-expanded from seed differs")
			}

			msg := testMessage(params.SLSS)
			randomness, _ := utils.SecureRandomBytes(32)
			ct, err := Encrypt(*deserialized, msg, params.SLSS, randomness)
			if err != nil {
				t.Fatalf("Encrypt with deserialized key failed: %v", err)
			}
			if !bytes.Equal(msg, Decrypt(ct, kp.SecretKey, params.SLSS)) {
				t.Error("decryption with deserialized public key failed")
			}
		})
	}
}

func TestDeserializePublicKeyErrors(t *testing.T) {
	p := core.MOS128Params.SLSS
	size := PublicKeySize(p)

	for _, n := range []int{0, 3, SeedSize, size - 1, size + 1} {
		if _, err := DeserializePublicKey(make([]byte, n), p); err == nil {
			t.Errorf("accepted %d-byte public key", n)
		}
	}
	if _, err := DeserializePublicKey(make([]byte, size), p); err != nil {
		t.Errorf("rejected all-zero public key: %v", err)
	}

	// Entry out of range: the last 14-bit entry occupies the top 14 bits of
	// the last 7 bytes; q = 12289 ≤ 0x3fff.
	full := make([]byte, size)
	full[size-1] = 0xFF
	full[size-2] = 0xFF
	if _, err := DeserializePublicKey(full, p); err == nil {
		t.Error("accepted out-of-range entry")
	}
	// q itself is out of range; q-1 is in range.
	vals := make([]int32, p.L*p.M)
	vals[17] = q
	pk := kmosaic.SLSSPublicKey{Seed: make([]byte, SeedSize), T: vals}
	if _, err := DeserializePublicKey(SerializePublicKey(pk), p); err == nil {
		t.Error("accepted entry equal to q")
	}
	vals[17] = q - 1
	if _, err := DeserializePublicKey(SerializePublicKey(pk), p); err != nil {
		t.Errorf("rejected entry q-1: %v", err)
	}

	bad := p
	bad.Q = 3329
	if _, err := DeserializePublicKey(make([]byte, size), bad); err == nil {
		t.Error("accepted invalid params")
	}
}

func TestSerializeCiphertext(t *testing.T) {
	for _, level := range levels {
		t.Run(string(level), func(t *testing.T) {
			params, _ := core.GetParams(level)
			p := params.SLSS
			kp, _ := KeyGen(p, fixedSeed(1))
			msg := testMessage(p)
			ct, err := Encrypt(kp.PublicKey, msg, p, fixedSeed(2))
			if err != nil {
				t.Fatal(err)
			}
			data := SerializeCiphertext(ct, p)
			want := (p.N*p.DU+7)/8 + (p.L*p.DV+7)/8
			if len(data) != want || CiphertextSize(p) != want {
				t.Fatalf("ciphertext size %d, want %d", len(data), want)
			}
			back, err := DeserializeCiphertext(data, p)
			if err != nil {
				t.Fatalf("DeserializeCiphertext failed: %v", err)
			}
			if !slices.Equal(back.U, ct.U) || !slices.Equal(back.V, ct.V) {
				t.Fatal("ciphertext round trip mismatch")
			}
			if !bytes.Equal(Decrypt(back, kp.SecretKey, p), msg) {
				t.Fatal("decryption of deserialized ciphertext failed")
			}

			for _, n := range []int{0, len(data) - 1, len(data) + 1} {
				if _, err := DeserializeCiphertext(make([]byte, n), p); err == nil {
					t.Errorf("accepted %d-byte ciphertext", n)
				}
			}
			if SerializeCiphertext(&kmosaic.SLSSCiphertext{U: ct.U[1:], V: ct.V}, p) != nil ||
				SerializeCiphertext(&kmosaic.SLSSCiphertext{U: ct.U, V: ct.V[1:]}, p) != nil ||
				SerializeCiphertext(nil, p) != nil {
				t.Error("SerializeCiphertext accepted a malformed ciphertext")
			}
		})
	}
}

// TestDeserializeCiphertext_Canonical checks that non-zero padding bits are
// rejected, so that each ciphertext has exactly one encoding.
func TestDeserializeCiphertext_Canonical(t *testing.T) {
	p := core.MOS128Params.SLSS
	p.N, p.DU = 765, 11 // 765·11 = 8415 bits: 1 padding bit in U
	p.L, p.DV = 8, 5    // 40 bits: no padding in V
	if _, err := DeserializeCiphertext(make([]byte, CiphertextSize(p)), p); err != nil {
		t.Fatalf("rejected canonical all-zero ciphertext: %v", err)
	}
	uLen := (p.N*p.DU + 7) / 8
	data := make([]byte, CiphertextSize(p))
	data[uLen-1] = 0x80
	if _, err := DeserializeCiphertext(data, p); err == nil {
		t.Error("accepted non-zero padding in U")
	}
	data[uLen-1] = 0x40 // bit 10 of the last U coefficient
	ct, err := DeserializeCiphertext(data, p)
	if err != nil || ct.U[p.N-1] != 1<<(p.DU-1) {
		t.Errorf("last U coefficient misparsed: %v", err)
	}

	// Every mutation of a padding bit in a real ciphertext is rejected, and
	// every accepted encoding re-serializes to itself.
	p = core.MOS128Params.SLSS
	p.N = 769 // 769·11 = 8459 bits: 5 padding bits in U
	kp, err := KeyGen(p, fixedSeed(3))
	if err != nil {
		t.Fatal(err)
	}
	ct, _ = Encrypt(kp.PublicKey, testMessage(p), p, fixedSeed(4))
	data = SerializeCiphertext(ct, p)
	uLen = (p.N*p.DU + 7) / 8
	for bit := 3; bit < 8; bit++ {
		mut := slices.Clone(data)
		mut[uLen-1] ^= 1 << bit
		if _, err := DeserializeCiphertext(mut, p); err == nil {
			t.Errorf("accepted padding bit %d set", bit)
		}
	}
	back, err := DeserializeCiphertext(data, p)
	if err != nil || !bytes.Equal(SerializeCiphertext(back, p), data) {
		t.Fatalf("canonical ciphertext failed round trip: %v", err)
	}
	if !bytes.Equal(Decrypt(back, kp.SecretKey, p), testMessage(p)) {
		t.Fatal("decryption with unaligned N failed")
	}
}

func TestSerializeSecretKey(t *testing.T) {
	for _, level := range levels {
		t.Run(string(level), func(t *testing.T) {
			params, _ := core.GetParams(level)
			p := params.SLSS
			kp, _ := KeyGen(p, fixedSeed(5))
			data := SerializeSecretKey(kp.SecretKey, p)
			if len(data) != p.L*p.N/4 || len(data) != SecretKeySize(p) {
				t.Fatalf("secret key size %d", len(data))
			}
			// Spot-check the 2-bit codes.
			for i, s := range kp.SecretKey.S[:64] {
				code := (data[i/4] >> (2 * (i % 4))) & 3
				want := map[int8]byte{0: 0, 1: 1, -1: 2}[s]
				if code != want {
					t.Fatalf("entry %d = %d encoded as %02b", i, s, code)
				}
			}
			back, err := DeserializeSecretKey(data, p)
			if err != nil {
				t.Fatalf("DeserializeSecretKey failed: %v", err)
			}
			if !slices.Equal(back.S, kp.SecretKey.S) {
				t.Fatal("secret key round trip mismatch")
			}

			for _, n := range []int{0, len(data) - 1, len(data) + 1} {
				if _, err := DeserializeSecretKey(make([]byte, n), p); err == nil {
					t.Errorf("accepted %d-byte secret key", n)
				}
			}
			for _, pos := range []int{0, 1, 2, 3, 4*len(data) - 1} {
				bad := slices.Clone(data)
				bad[pos/4] |= 3 << (2 * (pos % 4))
				if _, err := DeserializeSecretKey(bad, p); err == nil {
					t.Errorf("accepted code 11 at entry %d", pos)
				}
			}
			if SerializeSecretKey(kmosaic.SLSSSecretKey{S: kp.SecretKey.S[1:]}, p) != nil {
				t.Error("SerializeSecretKey accepted a malformed key")
			}
		})
	}
	// Exhaustive 4-entry codes: the column holding the byte must decode
	// (no "11" code) and have weight exactly W = 1; the other columns are
	// filled with one +1 entry so that they have weight W too.
	p := core.MOS128Params.SLSS
	p.N, p.L, p.W = 4, 8, 1
	for x := 0; x < 256; x++ {
		data := make([]byte, SecretKeySize(p))
		for j := 0; j < p.L; j++ {
			data[j] = 0b01 // entry 0 of column j is +1
		}
		data[3] = byte(x)
		sk, err := DeserializeSecretKey(data, p)
		valid := true
		weight := 0
		for k := 0; k < 4; k++ {
			c := (x >> (2 * k)) & 3
			if c == 3 {
				valid = false
			}
			if c != 0 {
				weight++
			}
		}
		valid = valid && weight == p.W
		if valid != (err == nil) {
			t.Fatalf("byte %08b: valid=%v err=%v", x, valid, err)
		}
		if valid && !bytes.Equal(SerializeSecretKey(*sk, p), data) {
			t.Fatalf("byte %08b: round trip failed", x)
		}
	}
}

// TestDeterminism checks that KeyGen and Encrypt are deterministic functions
// of their seeds and pins their output, so that any change in sampling
// (which would break FO re-encryption across versions or platforms) is
// caught.
func TestDeterminism(t *testing.T) {
	want := map[kmosaic.SecurityLevel][3]string{
		kmosaic.MOS_128: {"74a9997b58a3356957979522c6438491", "10fc7e72816b8b8e86b5167aef2afc0c", "7bb0ab5a3a6cca4bbefa81b4e25cc20d"},
		kmosaic.MOS_256: {"840255601e81bc0597889aad592dc7d0", "12cbcbde0885f8daa776dc2efabe484b", "621ee37031bbac839ed0c946ec5610df"},
	}
	for _, level := range levels {
		t.Run(string(level), func(t *testing.T) {
			params, _ := core.GetParams(level)
			p := params.SLSS
			kp1, _ := KeyGen(p, fixedSeed(9))
			kp2, _ := KeyGen(p, fixedSeed(9))
			if !slices.Equal(kp1.PublicKey.T, kp2.PublicKey.T) || !slices.Equal(kp1.SecretKey.S, kp2.SecretKey.S) ||
				!slices.Equal(kp1.PublicKey.A, kp2.PublicKey.A) {
				t.Fatal("KeyGen is not deterministic")
			}
			msg := testMessage(p)
			ct1, _ := Encrypt(kp1.PublicKey, msg, p, fixedSeed(10))
			ct2, _ := Encrypt(kp2.PublicKey, msg, p, fixedSeed(10))
			if !slices.Equal(ct1.U, ct2.U) || !slices.Equal(ct1.V, ct2.V) {
				t.Fatal("Encrypt is not deterministic")
			}
			ct3, _ := Encrypt(kp1.PublicKey, msg, p, fixedSeed(11))
			if slices.Equal(ct1.U, ct3.U) {
				t.Fatal("Encrypt ignores its randomness")
			}

			digest := func(b []byte) string { return hex.EncodeToString(utils.SHA3256(b)[:16]) }
			got := [3]string{
				digest(SerializePublicKey(kp1.PublicKey)),
				digest(SerializeSecretKey(kp1.SecretKey, p)),
				digest(SerializeCiphertext(ct1, p)),
			}
			if got != want[level] {
				t.Errorf("known-answer digests changed:\n got  %q\n want %q", got, want[level])
			}
		})
	}
}

// TestDecryptionFailureRate runs many encryptions under one key, checks that
// all decrypt and that the empirical noise matches the analytic estimate in
// the package documentation (σ ≈ 129 at MOS-128, σ ≈ 138 at MOS-256, against
// a threshold of q/4 = 3072).
func TestDecryptionFailureRate(t *testing.T) {
	trials := map[kmosaic.SecurityLevel]int{kmosaic.MOS_128: 2000, kmosaic.MOS_256: 500}
	sigma := map[kmosaic.SecurityLevel]float64{kmosaic.MOS_128: 129.3, kmosaic.MOS_256: 137.6}
	for _, level := range levels {
		t.Run(string(level), func(t *testing.T) {
			params, _ := core.GetParams(level)
			p := params.SLSS
			n := trials[level]
			if testing.Short() {
				n = 50
			}
			kp, _ := KeyGen(p, fixedSeed(20))
			msg := make([]byte, MessageSize(p))
			randomness := make([]byte, 32)
			u := make([]int32, p.N)
			var sq float64
			var maxAbs int32
			samples := 0
			for trial := 0; trial < n; trial++ {
				randomness[0], randomness[1] = byte(trial), byte(trial>>8)
				randomness[2] = 0xA5
				for i := range msg {
					msg[i] = byte(trial*31 + i*17)
				}
				ct, err := Encrypt(kp.PublicKey, msg, p, randomness)
				if err != nil {
					t.Fatal(err)
				}
				if dec := Decrypt(ct, kp.SecretKey, p); !bytes.Equal(dec, msg) {
					t.Fatalf("trial %d: decryption failure", trial)
				}
				// Measure the noise directly.
				for i := range u {
					u[i] = decompress(ct.U[i], uint(p.DU))
				}
				for j := 0; j < p.L; j++ {
					sj := kp.SecretKey.S[j*p.N : (j+1)*p.N]
					var s int32
					for i, x := range sj {
						s += u[i] * int32(x)
					}
					bit := int32((msg[j/8] >> (j % 8)) & 1)
					e := centerMod(decompress(ct.V[j], uint(p.DV)) - s - bit*(q/2))
					sq += float64(e) * float64(e)
					samples++
					if e < 0 {
						e = -e
					}
					maxAbs = max(maxAbs, e)
				}
			}
			std := math.Sqrt(sq / float64(samples))
			t.Logf("%d bits: noise σ = %.1f (analytic %.1f), max |noise| = %d, threshold %d", samples, std, sigma[level], maxAbs, q/4)
			if std < 0.9*sigma[level] || std > 1.1*sigma[level] {
				t.Errorf("empirical σ %.1f deviates from analytic %.1f", std, sigma[level])
			}
			if maxAbs > q/8 {
				t.Errorf("max |noise| %d exceeds q/8; margin unexpectedly small", maxAbs)
			}
		})
	}
}

func benchParams(b *testing.B, level kmosaic.SecurityLevel) kmosaic.SLSSParams {
	params, err := core.GetParams(level)
	if err != nil {
		b.Fatal(err)
	}
	return params.SLSS
}

func BenchmarkSLSS(b *testing.B) {
	for _, level := range levels {
		p := benchParams(b, level)
		kp, _ := KeyGen(p, fixedSeed(1))
		msg := testMessage(p)
		ct, _ := Encrypt(kp.PublicKey, msg, p, fixedSeed(2))
		pkBytes := SerializePublicKey(kp.PublicKey)
		b.Run("KeyGen/"+string(level), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = KeyGen(p, fixedSeed(1))
			}
		})
		b.Run("Encrypt/"+string(level), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = Encrypt(kp.PublicKey, msg, p, fixedSeed(2))
			}
		})
		b.Run("Decrypt/"+string(level), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = Decrypt(ct, kp.SecretKey, p)
			}
		})
		b.Run("ExpandMatrix/"+string(level), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = ExpandMatrix(kp.PublicKey.Seed, p)
			}
		})
		b.Run("DeserializePublicKey/"+string(level), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = DeserializePublicKey(pkBytes, p)
			}
		})
	}
}
