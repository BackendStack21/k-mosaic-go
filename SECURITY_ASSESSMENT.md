# kMOSAIC Security Assessment

**Scope:** the Go implementation in this repository at commit `f14168f`
(the state after the first round of functional fixes), its README, CLI.md,
BenchmarkReport.md, and the claims they make. The TypeScript reference
implementation was consulted to tell porting bugs from design flaws.
Sections 1 and 2 describe the original design; section 3 the 2.0.0 fixes;
section 4 the 3.0.0 redesign that implements the original claims.

**Verdict:** the construction as published did not provide confidentiality
or unforgeability at all. Every finding below was reproduced with code in
this repository; the attack programs are kept as `test/claims_test.go`, where
they now run as regression tests that must *fail* as attacks.

This document has three parts: the attacks, the author's claims against the
evidence, and what was changed.

---

## 1. Reproduced attacks against the original implementation

### 1.1 KEM: the shared secret is recoverable from the public key and ciphertext alone

Severity: **total break of confidentiality** (KEM and hybrid encryption).
No lattice reduction, no secret key, milliseconds of work.

Three independent weaknesses combine:

1. **The TDD "encryption" never uses the secret key.** `tdd.Encrypt` derives
   its keystream from the masked matrix, and the masked matrix is placed in
   the ciphertext. `tdd.Decrypt` recomputes the same keystream from the
   ciphertext alone; the `sk` argument is unused. The TypeScript source
   even comments that the decryptor cannot recompute the contracted
   product. Share 2 is therefore public.
2. **The EGRW "encryption" never uses the secret key.** The keystream is
   `H(ephemeralVertex, VStart, VEnd)`; all three values are in the
   ciphertext or public key. Share 3 is public.
3. **The SLSS encryption reused a single inner product for every bit.** The
   ciphertext component was `v_i = ⟨t, r⟩ + e2_i + bit_i·⌊q/2⌋` with the
   *same* scalar `⟨t, r⟩` for all 256 bits and `|e2_i| ≲ 20`. The 256 values
   of `v` therefore form two tight clusters `q/2` apart. Reading off which
   cluster each `v_i` falls into gives the 32-byte share up to one global
   complement bit.

Reconstruct the ephemeral secret for both polarities, re-run deterministic
encapsulation, and keep the candidate whose ciphertext matches:

```
[MOS-128] shared secret recovered from public key + ciphertext only: true
[MOS-256] shared secret recovered from public key + ciphertext only: true
```

Because `kem.Encrypt` derives the AES-GCM key from this shared secret, every
message ever encrypted with the original library is recoverable from its
ciphertext.

### 1.2 Signatures: universal forgery with the public key only

Severity: **total break of unforgeability**.

`sign.Verify` recomputed `challenge = H(commitment, H(msg, binding), H(pk))`
and compared it with the signature's challenge. It never examined the
response. The response was `SHAKE(H(secret key bytes, challenge, witness))`,
a PRF output that a verifier cannot check without the secret key, so the
scheme was a MAC with no verification. Forging a signature on any message is:
pick any 32-byte commitment, compute the challenge from public data, attach
64 arbitrary bytes.

```
forged signature accepted by Verify: true
```

The TypeScript reference has the identical `verify`, so this is the design,
not a porting error. The repository's own test for a "modified response"
passed only because it mutated a slice shared with the challenge.

### 1.3 EGRW: the secret walk is not secret

Severity: component provides no hardness.

`SL(2, Z_1021)` has about `1.06 × 10^9` elements. A breadth-first search over
right-multiplication by the four generators finds a walk from `VStart` to
`VEnd` in milliseconds:

```
EGRW: equivalent walk of length 18 found after visiting 55396 vertices
      (secret walk length 128); reaches VEnd: true
```

The graph has small diameter, so a short equivalent walk always exists and
the 128-step secret walk is one of astronomically many preimages. Even with
a much larger prime, path-finding in Cayley graphs of `SL(2, F_p)` with the
standard `S`/`T` generators is known to be easy (Petit–Quisquater lifting
attacks on Zémor–Tillich-style hashes). Nothing can be built on this
component as instantiated.

### 1.4 Parameter strength of the LWE component

Even ignoring 1.1, the SLSS parameters did not deliver the advertised
security. A standard core-SVP primal (uSVP) estimate (Alkim et al. model,
secret rescaled for sparse ternary secrets, hybrid attacks *not* modelled,
so optimistic for the defender):

| Instance                                   | n    | samples | β   | classical | quantum |
| ------------------------------------------ | ---- | ------- | --- | --------- | ------- |
| MOS-128 key LWE (secret s, dim 512)        | 512  | 384     | 316 | 2^92      | 2^84    |
| MOS-128 ciphertext LWE (secret r, dim 384) | 384  | 768     | 223 | **2^65**  | **2^59**|
| MOS-256 key LWE                            | 1024 | 768     | 733 | 2^214     | 2^194   |
| MOS-256 ciphertext LWE (secret r, dim 768) | 768  | 1280    | 534 | 2^156     | 2^142   |

The ciphertext's ephemeral secret `r` lives in dimension `m = 384 < n`, so
the weaker instance governs. "MOS-128" was at best a ~65-bit scheme and
"MOS-256" at best ~142-bit (quantum core-SVP), before the sparse-secret
hybrid attack is taken into account.

### 1.5 Implementation-level defects (fixed in the previous round)

- `kem.Decapsulate` crashed the whole process on malformed ciphertexts
  (out-of-bounds indexing inside goroutines).
- Three deserializers panicked on truncated length prefixes.
- `VerifyNIZKProof` panicked on an oversized response part.
- TDD public tensors contained entries outside `[0, q)`.
- The CLI could not read back its own hex output.

---

## 2. The author's claims, checked

| Claim (README / CLI.md / white paper summary)                                   | Verdict | Evidence |
| ------------------------------------------------------------------------------- | ------- | -------- |
| "Post-quantum secure cryptographic framework"                                   | **False as published.** The KEM was breakable from the ciphertext alone and signatures were forgeable by anyone. | §1.1, §1.2 |
| "Combines three distinct hard problems to provide defense-in-depth security"    | **False.** TDD and EGRW shares are public, so breaking SLSS alone (or, originally, just clustering `v`) recovers everything. There was never any depth: the scheme was exactly as strong as its weakest component, and the two extra components had strength zero. | §1.1, §1.3 |
| "SLSS – Sparse Lattice Subset Sum Problem" is a hard problem of its own          | **Misleading.** It is plain LWE with a sparse ternary secret. That is a well-studied assumption, which is good, but sparse secrets *weaken* LWE (hybrid attacks) rather than add a new hardness source. | §1.4 |
| "TDD – Tensor Decomposition Decisional Problem" contributes security             | **False.** Nothing in the KEM depends on tensor decomposition being hard; the decryptor never uses the factors. | §1.1 |
| "EGRW – Expander Graph Random Walk Problem" contributes security                 | **False.** The group is tiny (p = 1021 / 2039) and path-finding takes milliseconds; the KEM never uses the walk either. | §1.3 |
| "MOS_128: 128-bit post-quantum security"                                         | **False.** ~2^59 quantum core-SVP for the ciphertext instance even before the structural breaks. | §1.4 |
| "MOS_256: 256-bit post-quantum security"                                         | **False.** ~2^142 quantum core-SVP. | §1.4 |
| "Multi-witness signatures: Fiat-Shamir scheme proving knowledge of three entangled witnesses" | **False.** The signature proved knowledge of nothing; the verifier ignored the response. No sigma protocol existed for any of the three witnesses. | §1.2 |
| "NIZK proof" in the KEM ciphertext                                               | **False, and this review initially got it wrong.** Section 2 of the 2.0/3.0 editions called the proof "harmless". The 4.0 panel review (§5.1) showed that its "responses" are the shares XOR-masked with a hash of the challenge, which is itself the first field of the proof, so anyone could unmask both shares and recover the ephemeral secret from the ciphertext alone. It has been removed. | §5.1 |
| CCA security via Fujisaki-Okamoto with implicit rejection                        | **Partially true.** The FO structure (derandomize on `H(m, binding)`, re-encrypt, constant-time select against a rejection value) is reasonable. It cannot help when the underlying PKE is not even CPA-secure, as was the case. | `kem.Decapsulate` |
| "Uses constant-time operations" / side-channel resistance                        | **Overstated.** Comparisons use `crypto/subtle`, and decoding avoids branches, but Go gives no constant-time guarantees for integer multiplication, map lookups in `sampleSparseVector`, or garbage-collected memory. `Zeroize` is best-effort because the GC may have copied the data. Treat the library as not side-channel hardened. | code review |
| "NOT formally verified by academic peer review" (warning in README)              | **True, and understated.** The warning should say the construction was found broken by elementary attacks, not merely "unverified". | this document |
| Benchmark figures (e.g. "Sign: 12 μs")                                           | **Meaningless for the original scheme.** A 12-microsecond signature is a hash of the secret key; it measured nothing cryptographic. The new scheme signs in ~15–30 ms. | BenchmarkReport.md |
| Interoperability with the TypeScript implementation                               | **Was true, no longer.** Both implementations shared the broken design, so compatibility has been deliberately dropped. Keys, ciphertexts and signatures from either previous version must be discarded. | §3 |

---

## 3. What was changed

### 3.1 KEM: the LWE component was redesigned (fixes §1.1 item 3 and §1.4)

- One secret column per message bit. The public key is now
  `T = A·S + E` with `S ∈ {-1,0,1}^{N×256}` (one sparse column per bit) and
  the ciphertext is `u = Aᵀr + e1`, `v_j = ⟨t_j, r⟩ + e2_j + bit_j·⌊q/2⌋`.
  Every `v_j` carries an independent LWE sample. The clustering attack now
  recovers the bits with coin-flip accuracy (`TestCiphertextDoesNotLeakMessage`).
- Parameters raised so that the ciphertext instance is as strong as the key
  instance (`m = n`) and both clear the advertised levels with margin under
  the same estimator:

  | Level   | n = m | w (per column) | q     | σ    | β    | classical | quantum |
  | ------- | ----- | -------------- | ----- | ---- | ---- | --------- | ------- |
  | MOS-128 | 768   | 192            | 12289 | 3.19 | 551  | 2^161     | 2^146   |
  | MOS-256 | 1152  | 288            | 12289 | 3.19 | 889  | 2^260     | 2^236   |

  These are estimates from a simple model; the sparse-secret hybrid attack
  and dual attacks were not run. A proper estimate (e.g. the Lattice
  Estimator) should be obtained before any deployment decision.
- The matrix `A` is expanded from a 32-byte public seed instead of being
  stored, which keeps the public key at 449 KB / 777 KB despite the 256
  columns of `T`.
- Decryption failure: per bit the noise is `⟨e_j, r⟩ − ⟨s_j, e1⟩ + e2_j`,
  standard deviation `σ·√(2w+1) ≈ 63` (MOS-128) / `77` (MOS-256) against a
  threshold of `q/4 = 3072`, i.e. more than 39σ. Failures are negligible.

### 3.2 KEM: TDD and EGRW are documented as contributing nothing

No sound public-key encryption can be built from the TDD and EGRW
constructions as designed (TDD has no trapdoor the decryptor can use; EGRW is
a non-commutative group with no Diffie-Hellman structure and a trivially
searchable group). They were left in place so the ciphertext layout and the
FO transform are unchanged, with package documentation stating plainly that
their shares are public. The KEM's security rests on unstructured LWE alone.
Anyone preferring to remove them should drop two XOR shares; nothing else
depends on them.

### 3.3 Signatures: replaced with a Dilithium-style lattice signature (fixes §1.2)

The signature is now the CRYSTALS-Dilithium / FIPS 204 construction
instantiated over unstructured matrices (no polynomial rings), proving
knowledge of short `(S1, S2)` with `T = A·S1 + S2 mod q`:

- `q = 8380417`, `γ1 = 2^19`, `γ2 = (q−1)/32`, 256-entry challenge vector.
- MOS-128 uses the ML-DSA-65 shape (`A` is 1536×1280, η = 4, τ = 49,
  48-byte challenge hash); MOS-256 uses the ML-DSA-87 shape (2048×1792,
  η = 2, τ = 60, 64-byte hash). Module structure does not enter the published
  core-SVP estimates, so ML-DSA's numbers (≈2^165 and ≈2^229 quantum) carry
  over to the unstructured instance.
- Rejection sampling on both `‖z‖∞ < γ1 − β` and `‖LowBits(A·y − S2·c)‖∞ < γ2 − β`
  (so no hint vector is needed because `T` is stored uncompressed).
- Hedged signing: a fresh 32-byte random value is mixed into the mask seed,
  so a weak RNG degrades to deterministic signing instead of leaking the key.
- Sizes: public key 1.18 MB / 1.57 MB, signature 3.9 KB / 5.4 KB. Keygen
  ≈ 0.2 s, sign ≈ 15–30 ms, verify ≈ 10 ms on 4 cores.
- `Sign` refuses a public key that does not match the secret key's stored
  hash, and `Verify` rejects any response outside the allowed range before
  doing any arithmetic.

The scheme no longer references TDD or EGRW. No witness for either could be
proven with a practical sigma protocol, and neither problem is hard as
instantiated.

### 3.4 Other changes

- Sparse-vector position sampling uses rejection sampling (no modulo bias).
- CLI key files store the binary secret-key encoding; the JSON secret-key
  format and the `kem slss-debug` command (which exposed ephemeral values)
  were removed.
- Library version bumped to 2.0.0; all serialized formats are new and
  incompatible with 1.x and with the TypeScript implementation.

### 3.5 What remains open

- The parameter estimates above come from a simple core-SVP model written
  for this review. Run the Lattice Estimator (including hybrid and dual
  attacks on the sparse ternary secret) before relying on the numbers.
- The implementation is not side-channel hardened. Secret-dependent memory
  access exists in sparse-vector sampling, Go does not guarantee
  constant-time arithmetic, and zeroization is best-effort.
- The TDD and EGRW components still exist and still look like encryption
  to a reader of the API. They are documented as insecure; removing them is
  the cleaner long-term choice.
- No external review has looked at the new signature or KEM code. The
  construction follows FIPS 204 and standard LWE encryption, but the
  transplant to unstructured matrices and the parameter choices are this
  review's, not a standard's.

---

## 4. Version 3.0: implementing the claims

The original claims were "three distinct hard problems" and "defense in
depth". Version 2.0 fixed the breaks but left a single-assumption library.
Version 3.0 makes the claims true with problems that are actually hard and
constructions that are actually usable.

### 4.1 Why the original three problems could not be kept

- **TDD (tensor decomposition).** The public tensor is `T = Σ a_i⊗b_i⊗c_i + E`
  and the ciphertext masks a contraction of `T` with a uniformly random
  tensor. Nothing the decryptor knows cancels that mask, so no decryption
  procedure exists; the "decryption" could only work by deriving the key from
  public data. A sound encryption scheme from noisy tensor decomposition
  would need a trapdoor that this problem does not offer.
- **EGRW (expander walks in SL(2, Z_p)).** The group is non-commutative, so
  there is no Diffie-Hellman-style key agreement, and the group is tiny
  (searchable in milliseconds, §1.3). Even with a large prime, path finding
  for the standard `S`/`T` generators is known to be easy.

### 4.2 The composition

| Primitive  | Components                                    | Combiner                                           |
| ---------- | --------------------------------------------- | -------------------------------------------------- |
| KEM        | SLSS (unstructured LWE), QCSD (HQC)           | XOR secret sharing: both shares needed to recover the ephemeral secret, then Fujisaki-Okamoto |
| Signatures | latsig (unstructured ML-DSA), uov, slhdsa     | AND combiner: all three signatures on `H(H(pk) ‖ M)` must verify |

For the KEM, IND-CPA of the composite PKE follows if either component PKE is
IND-CPA (an adversary who cannot distinguish one share learns nothing about
the XOR), and the FO transform yields IND-CCA in the ROM. For signatures,
EUF-CMA of the composite follows from EUF-CMA of any one component, because a
composite forgery contains a forgery of each component on the same digest.
Binding hashes over the component public keys, plus the inclusion of the
composite public-key hash in the signed digest, prevent an attacker from
swapping in components from other keys.

### 4.3 The components and their parameter provenance

- **SLSS** (`problems/slss`): §3.1 as of 3.0; 4.0 replaced the Gaussian sampler and added coefficient compression (§5).
- **QCSD** (`problems/qcsd`): the HQC construction with the published
  **hqc-256** parameters (ring length 57637, Reed-Solomon [90,32] with
  δ = 29, RM(1,7) duplicated 5×, weights 131/149/149). It is used at both
  levels because it is the HQC set that encrypts exactly a 32-byte share.
  HQC's decryption failure rate for this set is below 2^-256; the
  implementation's Reed-Solomon and Reed-Muller decoders are tested against
  injected errors up to their correction capability.
- **latsig** (`problems/latsig`): §3.3, unchanged.
- **uov** (`problems/uov`): UOV over F_256 with the **uov-Ip** (n = 112,
  m = 44) and **uov-V** (n = 244, m = 96) parameters of the NIST submission,
  compressed public keys (seed + P3 blocks, 43,576 / 446,992 bytes, matching
  the submission's sizes), salted signing. The implementation checks the
  defining property (every public form vanishes on the oil space) in its tests.
- **slhdsa** (`problems/slhdsa`): FIPS 205 SLH-DSA-SHAKE-**128f** and
  **256f**, "simple" tweakable hashes, hedged signing. Signature sizes
  (17,088 and 49,856 bytes) match the standard, and the WOTS+, XMSS, FORS
  and hypertree layers are tested separately.

Mixed NIST levels within a composite are deliberate: the composite is at
least as strong as its strongest component, and the weaker components still
force the attacker to break an additional, independent problem.

### 4.4 What this is and is not

- It **is** a sound composition of standard constructions whose security
  argument is the standard combiner argument, with every component's
  parameters taken from a published analysis (except SLSS, see §3.5).
- It **is not** externally reviewed. The transplant of ML-DSA to
  unstructured matrices, the SLSS parameters and the implementation itself
  are this repository's work.
- Side channels are only partly addressed (see §5.1 and §5.3 for the 4.0
  state): the code component's field arithmetic and decoder are branch-free,
  but UOV signing still uses lookup tables and a branching pivot search, and
  Go offers no constant-time guarantees.
- Cost is real: a composite signature public key is 1.2–2 MB and a signature
  21–56 KB, because unstructured lattices and three-way signatures are not
  small.

---

## 5. Version 4.0: expert-panel review and fixes

A panel of five independent reviewers examined the 3.0 code (lattice
components, code-based component, UOV and SLH-DSA, the composite layer and
CLI, and whole-library profiling). Every finding was either fixed or is
recorded below. The attack programs for the critical findings were run and
confirmed before fixing.

### 5.1 Security findings fixed

| Severity | Finding | Fix |
| --- | --- | --- |
| **Critical** | The share-binding "proof" carried in every 3.0 ciphertext leaked both KEM shares: responses were `share ⊕ SHA3(H(mask-domain, challenge))` and the challenge was public. The shared secret was recoverable from public data; confirmed with a 40-line program. (Also a correction of this document's earlier "harmless" verdict.) | Proof removed. Ciphertexts are exactly the two component ciphertexts; the Fujisaki-Okamoto re-encryption check is the only binding. Regression test `TestClaim_CiphertextCarriesNoShareInformation`. |
| **High** | A Reed-Solomon decoding failure in the code component returned `nil` and `Decapsulate` rejected early, a 3x timing difference. This is the published decryption-failure oracle against HQC and recovers the secret `y`. | `qcsd.Decrypt` always returns K bytes plus a constant-time `ok` flag; `Decapsulate` always re-encrypts and folds `ok` into the constant-time selection. |
| **High** | The Reed-Solomon decoder's running time grew with the number of errors (6 µs at 0 errors, 54 µs at 29), the known timing attack on HQC. | Constant-time decoder: fixed-iteration Berlekamp-Massey with masked updates, Chien/Forney at every position, branch-free GF(2^8) multiplication. Measured 42.0–42.4 µs for 0 to 90 errors. |
| **High** | `Decapsulate` never checked that the supplied public key belonged to the secret key: a key-mismatch oracle (attacker-chosen `T + Δ`) recovers the SLSS key. | The secret key's stored public-key hash is checked in constant time; mismatch returns `ErrKeyMismatch`. |
| **High** | Every length-prefix reader converted a `uint32` to `int` before bounds checking and panicked on 32-bit platforms (confirmed on GOARCH=386). | New `internal/wire` reader compares lengths as 64-bit values; parsers are exact-length; CI runs the parser tests under GOARCH=386. |
| **Medium** | Secret-dependent hardware division (`x % q` with a runtime `q`) in SLSS decryption and lattice signing: the KyberSlash pattern. | Moduli are compile-time constants with multiply-shift reductions and branch-free corrections; `Decompose` uses the FIPS 204 constant arithmetic. No runtime division remains on secret data. |
| **Medium** | Composite signatures were malleable: components from two signatures on the same message could be recombined (EUF-CMA but not SUF-CMA). | A 32-byte per-signature nonce is part of the signed digest; components of different signatures never share a digest. Regression test `TestClaim_SignatureComponentsCannotBeRecombined`. |
| **Medium** | Oversized trailing data in a ciphertext reached a hashing helper that panics above 100 MB; `Decapsulate(sk, pk, nil)` panicked. | Exact-length parsing with no trailer; nil checks on every entry point. |
| **Medium** | Secret-key parsing accepted any seed length (an empty seed made the implicit-rejection value public). | Seeds are exactly 32 bytes everywhere; the rejection value is a PRF under a key derived from the seed. |
| **Medium** | The SLSS error sampler used floating-point Box-Muller: not constant-time and not guaranteed bit-identical across architectures, which the FO re-encryption requires. | Integer centered-binomial sampler (η = 20, σ ≈ 3.16). Known-answer digests pin the outputs. |
| **Medium** (latent) | UOV derived keys from the whole seed but stored only 32 bytes, so a longer seed broke the secret-key round trip. | Seeds must be exactly 32 bytes. |
| Low | Deserializers in UOV and SLH-DSA did not validate parameters before slicing; lattice validation accepted parameter sets the code could not handle (τ > 64, other γ2 values). | Every deserializer validates parameters first; lattice parameters are restricted to the two supported shapes. |
| Low | `SecureRandomBytes` used `Read` rather than `io.ReadFull`. | Fixed. |
| Low | Secret intermediates (masks, `w`, low bits, vinegar, elimination state) were not zeroized. | Zeroized on every path. |

### 5.2 Performance changes (same 4-core container, loaded by concurrent work; ratios are more reliable than absolutes)

| Operation | 3.0 | 4.0 | Main change |
| --- | --- | --- | --- |
| KEM Encapsulate (MOS-128) | 3.9 ms | 0.6 ms | fused window multiply in the ring (6x on the dominant product), no per-rotation allocation |
| KEM Decapsulate (MOS-128) | 5.7 ms | 1.0 ms | as above; ciphertext serialized once |
| KEM DeserializePK (MOS-128) | 12 ms | 8 ms | 16-bit rejection sampling of A, parallel component parsing |
| Sign (MOS-128 / 256) | 75 / 229 ms | 19 / 53 ms | SLH-DSA: one hasher per worker, in-place chains, all leaves and FORS trees in parallel (5x); lattice: 4-way batched passes over A, sparse challenge products |
| Verify (MOS-128 / 256) | 20 / 29 ms | 3.1 / 4.8 ms | public-key hashes cached in the key structs instead of re-serializing and hashing 1–2 MB per call; UOV monomial-once evaluation |
| Sign KeyGen (MOS-256) | 591 ms | 238 ms | UOV nibble-table products (5.7x on its key generation) |
| Signature public key | 1.22 / 2.02 MB | 535 KB / 1.10 MB | FIPS 204 Power2Round (10-bit `t1`) with hints |
| KEM ciphertext | 18.8 / 20.3 KB | 15.6 / 16.2 KB | SLSS coefficients compressed to 11 and 5 bits (noise σ ≈ 130 against a 3072 threshold, more than 22σ) |

The SLH-DSA output remains byte-identical to the implementation that was
verified against an independent FIPS 205 reference; the only intentional
change is the FIPS 205 "pure" domain prefix (context string `kmosaic-v4`).

### 5.3 Still open

- **Cache-timing side channels.** The code component's fused multiply reads a
  window whose position depends on the secret support of `y`; SLSS key
  generation and encryption gather matrix rows at secret positions; UOV
  signing uses lookup tables indexed by secret values and a branching pivot
  search. These are documented in the package comments. Closing them needs a
  dense constant-time ring multiply (as HQC's reference did) and bitsliced
  field arithmetic for UOV.
- **No SIMD.** Lattice key generation is a 500M–940M multiply-add product
  with no vector kernel in pure Go; only an assembly kernel would change it.
- **Parameter estimates** for SLSS remain this repository's own (§3.5).
- **External review.** None yet.
