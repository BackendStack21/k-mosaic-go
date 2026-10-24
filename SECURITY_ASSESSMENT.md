# kMOSAIC Security Assessment

**Scope:** the Go implementation in this repository, its README, CLI.md,
BenchmarkReport.md, and the claims they make. The document has grown with
the code: sections 1 and 2 describe the original (1.x) design and are
**historical**; section 3 the 2.0.0 fixes (historical); section 4 the 3.0.0
redesign (historical, superseded by §5); section 5 the 4.0.0 review and
fixes; **sections 6 (the 4.1.0 validation pass) and 7 (4.2.0) together
describe the current code; §7 supersedes §6.3 and §6.5 where they
differ.** Sizes, parameters and verdicts in §1–§4 no longer apply.

**Verdict on the original construction:** it did not provide confidentiality
or unforgeability at all. Of the attack programs, only the SLSS clustering
attack survives as a regression test (`TestClaim_SLSSClusteringAttackFails`
in `test/claims_test.go`); the others targeted components that no longer
exist, so the outputs quoted in §1 are a record, not reproducible today.

**Verdict on 4.1.0 (§6):** the KEM and signature are sound compositions of
standard constructions at the level of the hard problems, in the classical
random-oracle model; the implementation passed an adversarial review of
seven separately briefed internal reviews with no cryptographic break, and every defect that
review found has been fixed. "Stronger" holds only against cryptanalysis of
the problems, and "bug free" is not a claim anyone can verify: §6.4 lists
what was tested, §6.5 what remains open. **Section 7 (4.2.0)** closes the
open items that code can close: every operation on secret data is now
memory-oblivious, the key-mismatch check no longer trusts a cached hash,
and parsed secret keys are validated structurally.

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
  and dual attacks were not run. *(Historical: §6.1 has the 4.1 estimates
  including hybrid and dual attacks, and `docs/estimator/` the script.)*
- The matrix `A` is expanded from a 32-byte public seed instead of being
  stored, which keeps the public key at 449 KB / 777 KB despite the 256
  columns of `T`. *(Historical: 4.0 packs `T` at 14 bits, 351 KB / 523 KB.)*
- Decryption failure: per bit the noise is `⟨e_j, r⟩ − ⟨s_j, e1⟩ + e2_j`,
  standard deviation `σ·√(2w+1) ≈ 63` (MOS-128) / `77` (MOS-256) against a
  threshold of `q/4 = 3072`. *(Historical: with 4.0's centered-binomial
  noise and ciphertext compression the total is 129 / 138, see §6.1.)*

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

*(Historical. This section describes 3.0.0 as it was designed; §5.1 shows
that 3.0.0 was still totally broken by its "proof" field, and §6 describes
the current state.)*

The original claims were "three distinct hard problems" and "defense in
depth". Version 2.0 fixed the breaks but left a single-assumption library.
Version 3.0 was meant to make the claims true with problems that are
actually hard and constructions that are actually usable.

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
  (17,088 and 49,856 bytes) match the standard; WOTS+ and XMSS have unit
  tests, FORS and the hypertree are covered end-to-end, and since 4.1 the
  whole component is checked bit-exactly against NIST ACVP vectors (§6).

Mixed NIST levels within a composite are deliberate: against cryptanalysis
the composite is as strong as its strongest component, and the weaker
components still force the attacker to break an additional problem. It is
not stronger than its strongest component, and the problems' independence
is a heuristic.

### 4.4 What this is and is not

- It **is intended as** a composition of standard constructions whose
  security argument is the standard combiner argument, with every
  component's parameters taken from a published analysis (except SLSS, see
  §3.5, and the lattice signature, whose ML-DSA levels are applied by
  analogy to an unstructured transplant). The composition itself has not
  been reviewed outside this repository.
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

## 5. Version 4.0: internal review and fixes

Five reviewers working inside this project, with separate briefs but not
independent of its authors and not external, examined the 3.0 code (lattice
components, code-based component, UOV and SLH-DSA, the composite layer and
CLI, and whole-library profiling). Every finding was either fixed or is
recorded below. The attack programs for the critical findings were run and
confirmed before fixing; the reports and programs are not in the repository.

### 5.1 Security findings fixed

| Severity | Finding | Fix |
| --- | --- | --- |
| **Critical** | The share-binding "proof" carried in every 3.0 ciphertext leaked both KEM shares: responses were `share ⊕ SHA3(H(mask-domain, challenge))` and the challenge was public. The shared secret was recoverable from public data; confirmed with a 40-line program. (Also a correction of this document's earlier "harmless" verdict.) | Proof removed. Ciphertexts are exactly the two component ciphertexts; the Fujisaki-Okamoto re-encryption check is the only binding. Regression test `TestClaim_CiphertextCarriesNoShareInformation`. |
| **High** | A Reed-Solomon decoding failure in the code component returned `nil` and `Decapsulate` rejected early, a 3x timing difference. This is the published decryption-failure oracle against HQC and recovers the secret `y`. | `qcsd.Decrypt` always returns K bytes plus a constant-time `ok` flag; `Decapsulate` always re-encrypts and folds `ok` into the constant-time selection. |
| **High** | The Reed-Solomon decoder's running time grew with the number of errors (6 µs at 0 errors, 54 µs at 29), the known timing attack on HQC. | Constant-time decoder: fixed-iteration Berlekamp-Massey with masked updates, Chien/Forney at every position, branch-free GF(2^8) multiplication. Measured 42.0–42.4 µs for 0 to 90 errors. |
| **High** | `Decapsulate` never checked that the supplied public key belonged to the secret key: a key-mismatch oracle (attacker-chosen `T + Δ`) recovers the SLSS key. | The secret key's stored public-key hash is checked in constant time; mismatch returns `ErrKeyMismatch`. The check trusts the hash cached in the public-key struct: keys from `GenerateKeyPair` and `DeserializePublicKey` are safe, a struct edited by hand with its old hash is not (documented on `PublicKeyHash`). |
| **High** | Every length-prefix reader converted a `uint32` to `int` before bounds checking and panicked on 32-bit platforms (confirmed on GOARCH=386). | New `internal/wire` reader compares lengths as 64-bit values; parsers are exact-length; CI runs the parser tests under GOARCH=386. |
| **Medium** | Secret-dependent hardware division (`x % q` with a runtime `q`) in SLSS decryption and lattice signing: the KyberSlash pattern. | Moduli are compile-time constants with multiply-shift reductions and branch-free corrections; `Decompose` uses the FIPS 204 constant arithmetic. *(4.0 still divided by the ring length in the code component's position sampler; removed in 4.1, §6.2.)* |
| **Medium** | Composite signatures were malleable: components from two signatures on the same message could be recombined (EUF-CMA but not SUF-CMA). | A 32-byte per-signature nonce is part of the signed digest; components of different signatures never share a digest. Regression test `TestClaim_SignatureComponentsCannotBeRecombined`. |
| **Medium** | Oversized trailing data in a ciphertext reached a hashing helper that panics above 100 MB; `Decapsulate(sk, pk, nil)` panicked. | Exact-length parsing with no trailer; nil checks on every entry point. |
| **Medium** | Secret-key parsing accepted any seed length (an empty seed made the implicit-rejection value public). | Seeds are exactly 32 bytes everywhere; the rejection value is a PRF under a key derived from the seed. |
| **Medium** | The SLSS error sampler used floating-point Box-Muller: not constant-time and not guaranteed bit-identical across architectures, which the FO re-encryption requires. | Integer centered-binomial sampler (η = 20, σ ≈ 3.16). Known-answer digests pin the outputs. |
| **Medium** (latent) | UOV derived keys from the whole seed but stored only 32 bytes, so a longer seed broke the secret-key round trip. | Seeds must be exactly 32 bytes. |
| Low | Deserializers in UOV and SLH-DSA did not validate parameters before slicing; lattice validation accepted parameter sets the code could not handle (τ > 64, other γ2 values). | Every deserializer validates parameters first; lattice parameters are restricted to the two supported shapes. |
| Low | `SecureRandomBytes` used `Read` rather than `io.ReadFull`. | Fixed. |
| Low | Secret intermediates (masks, `w`, low bits, vinegar, elimination state) were not zeroized. | Zeroized where practical; intermediate hash outputs, AES key schedules and garbage-collector copies are not, and Go gives no guarantee. |

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

### 5.3 Still open as of 4.0.0

*(Superseded by §6.5. Kept for the record: of the items below, the SLSS
gathers were closed in 4.1.0 and the SLSS estimates were re-derived with
hybrid and dual attacks; the code component's window, UOV's tables and
pivot search, SIMD and external review remain open.)*

- **Cache-timing side channels.** The code component's fused multiply reads a
  window whose position depends on the secret support of `y`; SLSS key
  generation and encryption gather matrix rows at secret positions; UOV
  signing uses lookup tables indexed by secret values and a branching pivot
  search.
- **No SIMD.** Lattice key generation is a 500M–940M multiply-add product
  with no vector kernel in pure Go; only an assembly kernel would change it.
- **Parameter estimates** for SLSS remain this repository's own (§3.5).
- **External review.** None yet.

---

## 6. Version 4.1.0: validation pass

The question put to this pass was whether two claims hold: *"this
encryption is quantum ready and stronger"* and *"this library is bug free"*.
Seven reviewers with separate adversarial briefs examined the 4.0.0 code
(be39551) and its documentation: (1) LWE parameter and combiner analysis
with an independently written core-SVP estimator; (2) chosen-ciphertext and
timing attacks on the KEM plus HQC fidelity; (3) forgery, malleability and
hint attacks on the signature plus FIPS 204/205 and UOV conformance; (4)
dynamic bug hunting (18 fuzz targets, property tests, race detector, 32-bit
and cross-compilation, resource limits, CLI abuse); (5) a line-by-line static
review; (6) a claim-by-claim audit of the documentation against the code and
fresh measurements; (7) scaled-down lattice and code attacks on the actual
constructions. The reviewers were not external to this project. Everything
they found is recorded here; everything fixable was fixed in 4.1.0.

### 6.1 Claim: "quantum ready and stronger"

**Verdict: justified only in a narrow sense, and the previous wording
overstated it.** What holds, and what does not:

- **Construction.** The KEM is an XOR-share combiner of unstructured LWE and
  HQC-256 under the FO⊥̸ transform (coins = G(m, H(pk)) split into
  per-component domains, K = H(m, H(c)), rejection value = PRF under a key
  derived from the seed). Two reviewers independently confirmed that this
  matches the standard analysis: IND-CCA in the classical random-oracle
  model if either component is IND-CPA; share derivation leaks nothing
  beyond what guessing m already allows; no correlation between the
  components through shared randomness. The signature AND-combiner is EUF-CMA
  if any component is. Security against quantum-accessible random oracles
  (QROM) follows only from the known non-tight FO⊥̸ results and was never
  stated before; it is now.
- **LWE strength, re-derived.** An estimator written for this pass
  (`docs/estimator/lwe_est.py`, calibrated to within 1 bit of the published
  ML-KEM-512/768/1024 figures) gives, in log2 classical / quantum core-SVP:

  | Instance | Primal | Dual | Guess zeros | Idealised hybrid | NIST level |
  | --- | --- | --- | --- | --- | --- |
  | MOS-128 key (n = m = 768, h = 192) | 160.9 / 146.0 | 160.0 / 145.2 | 160.9 / 145.8 | 160.0 / 151.6 | **1** (ML-KEM-512 is 118 / 107) |
  | MOS-128 ciphertext | 163.5 / 148.4 | 162.6 / 147.6 | 163.5 / 148.2 | 161.8 / 154.0 | 1 |
  | MOS-256 key (n = m = 1152, h = 288) | 259.3 / 235.3 | 257.5 / 233.7 | 259.3 / 234.7 | 251.2 / 240.3 | **≈ 5** (ML-KEM-1024 is 256 / 232) |
  | MOS-256 ciphertext | 263.1 / 238.8 | 261.6 / 237.4 | 263.1 / 238.2 | 255.2 / 243.3 | ≈ 5 |

  The sparse ternary secret (density 1/4) costs under 2 bits at MOS-128 and
  up to 8 bits classically at MOS-256; the 256 columns sharing `A` give the
  dual attack 1–2 bits and let one reduced basis serve every column, which
  does not change the cost of recovering a useful amount of key. The
  compressed `v` samples (5 bits, rounding noise σ ≈ 111) are useless to an
  attacker. Uncertainty is about ±10 bits; MATZOV-style dual improvements
  are not modelled. **The MOS-128 LWE component is NIST level 1, not level
  3 as the README previously implied.** If HQC-256 fell, the MOS-128 KEM
  would rest on a level-1 instance, below ML-KEM-768.
- **Decryption failure.** Computed exactly from the centered-binomial noise
  and the compression rounding (`docs/estimator/dfr.py`): total σ 129.4 /
  137.7 against a threshold of 3072; rigorous per-ciphertext bound 2^-1008 /
  2^-508. The composite rate is dominated by HQC-256's published < 2^-256;
  40,000 measured HQC decryptions (3.6 M Reed-Muller blocks) matched the
  Poisson-parity model (bit error rate 0.3725 measured vs 0.3716 predicted,
  at most 2 Reed-Solomon symbol errors against a capacity of 29) and
  extrapolate to about 2^-264.
- **Structural checks at full size** (reviewer 7): `T` is uniform mod q,
  columns are uncorrelated, ciphertexts from different messages and from
  the same key are independent, and the textbook "correlate `u` with rows of
  `A`" attack on the weight-192 ephemeral secret has no measurable advantage.
  Scaled-down instances of the same shape (n = 40) are recovered by lattice
  reduction and (n = 397) by information-set decoding, confirming the
  constructions have no accidental trapdoor and that hardness grows as the
  standard models predict.
- **"Stronger" than what.** Compared with ML-KEM-768/1024: two assumptions
  instead of one, but 351–523 KB public keys instead of 1.2–1.6 KB, an
  unreviewed implementation instead of audited and formally verified ones,
  and a self-estimated LWE component. The honest statement is: *a
  mathematical break of exactly one of the two problems does not break the
  KEM*. The combiner gives no protection against implementation or
  side-channel attacks, which can target each component separately (§6.2
  found exactly such a channel), and every total break in this library's
  history was in the glue code, not in the hard problems. The same
  two-assumption property is available with less new code from ML-KEM-1024
  plus HQC-256 under a standard KEM combiner.
- **Symmetric layer.** AES-256-GCM keyed by SHAKE256 of a single-use shared
  secret with a derived 12-byte nonce; Grover costs 2^128 (2^128/√T for T
  targets, as for ML-KEM); per-key domain separation is present everywhere
  it is needed (H(pk) in the coins, H(c) in the key, per-key rejection key).
  Not putting the KEM ciphertext in the AEAD's associated data is fine: it
  is bound through the key, as in HPKE.

### 6.2 Defects found in 4.0.0 and fixed in 4.1.0

Every row was confirmed by running code before it was fixed.

| Severity | Finding (reviewers) | Fix |
| --- | --- | --- |
| **Medium–High** | Re-encryption during decapsulation ran the sparse samplers with seed-dependent work: the SLSS position sampler needed 6/7/8 SHAKE blocks (MOS-128) or 10/11 (MOS-256, 10.4% of messages), measured 435 ns apart in isolation, and the code sampler had a similar loop plus a hardware `DIV` by the ring length on secret candidates. Since the re-encryption seed is a function of the decrypted message, this is a plaintext-checking oracle of the "Don't Reject This" class (Guo–Johansson–Nilsson, TCHES 2022) that implicit rejection does not hide, and the 4.0 statement "no runtime division remains on secret data" was false. (1, 2, 5, 6) | SLSS uses a sort-based constant-time sampler (61-bit keys with the ternary value in the low bits, bitonic sorting network; the method of NTRU and Classic McEliece); the code component uses Sendrier's constant-time Fisher–Yates variant with a multiply-shift map (no division) and a branch-free scatter, and sorts key positions with a sorting network. XOF usage, control flow and memory addresses now depend only on the dimensions. Known-answer digests were re-pinned; keys derived from a seed differ from 4.0.0. |
| **Medium** | SLSS key generation and encryption gathered rows of `A` and entries of `T` at secret positions (documented in 4.0 as a cache-timing channel, but the encryption half runs inside decapsulation). (1, 2, 5) | Both are dense products that touch every coefficient with a multiply. Cost: KEM key generation 51 / 99 ms instead of 16.5 / 33.5, encapsulation 1.5 / 2.2 ms instead of 0.8 / 0.8, decapsulation 2.3 / 2.4 ms instead of 2.2 / 1.4; see BenchmarkReport.md. |
| **Medium** | `core.isPrime` overflowed `i*i` and hung for ring lengths near `MaxInt` (reachable through `ValidateParams` and KEM key generation); on 32-bit it answered wrongly. (4) | `i <= n/i`; ring lengths are bounded by 2^24 before the test. Regression test `TestValidateCodeParams_HugeN`. |
| **Medium** | `kem.GenerateKeyPairFromSeed` accepted any dimensions under a valid level label (n = m = 16 keys with a MOS-128 header). (4) | Parameters must equal the published set for their level in key generation, encapsulation, decapsulation and serialization (`sign` already did this). |
| **Medium** | CLI: `--output` opened existing files with `O_TRUNC` and chmod'ed afterwards (secret key briefly world-readable if the file was 0644; symlinks followed; TOCTOU); the 100 MiB input limit was a `Stat` check bypassed by `/dev/zero`, FIFOs and growing files (out-of-memory); stdin was silently truncated at the limit; `-m ""` fell back to stdin; misspelled options were ignored (`--ouput` printed the secret key to stdout, `--levle 256` produced a MOS-128 key); `--iterations 1x` was accepted. (4, 5, 6) | Atomic write through a 0600 temporary file and rename; the limit applies to bytes read, over-limit input is an error; empty option values are literal; unknown options and stray arguments exit 2; strict integer parsing. Regression tests in `cmd/k-mosaic-cli/validation_pass_test.go`. |
| Low | In-memory ciphertext structs that were not canonical were handled inconsistently: out-of-range SLSS coefficients decapsulated to the real secret (they serialize identically) while a set padding bit in the code component took the fast rejection path; `bitsToBytes` emitted padding bits its own parser rejected. (2, 5) | Decapsulation rejects any non-canonical in-memory ciphertext before use (shape and encoding are public); `bitsToBytes` masks padding. |
| Low | `sign.Sign`, `Verify`, `GenerateKeyPair` and the deserializers recovered panics only on the calling goroutine; a panic inside the UOV or SLH-DSA goroutine would have crashed the process. Secret components already produced were not wiped when another component failed. (3, 5) | Each component goroutine converts a panic into an error (or `false`); error paths wipe the other components. |
| Low | The composite serializers emitted unparsable bytes for mismatched parameters (a MOS-128 signature under MOS-256 parameters became a MOS-256 object with an empty lattice field, which the CLI wrote with exit 0) and panicked on nil. (3, 4, 5) | Serializers return nil for nil, mis-shaped or mismatched inputs; `EncapsulateDeterministic` validates parameters, so a shared secret can no longer be bound to `SHA3(nil)`. |
| Low | The per-component tamper test in `sign_test.go` was vacuous: its clone dropped the nonce, so every clone was rejected before any component was examined. (3) | Full deep copy; the untouched clone must verify. |
| Low | 32-bit: `uov` and `utils` tests did not compile under GOARCH=386 (`1<<40` constants), `go vet` failed there, and the Reed-Solomon syndrome backstop truncated a 64-bit OR-fold to `int`. (4) | 64-bit mask helper, platform-safe test constants; CI vets 386 and arm and runs the fast packages' tests under 386. |
| Low | Exported helpers panicked or misbehaved on hostile arguments: `SafeReadLength` (offset overflow, negative or >2^32 limits), `SampleVectorZq` (q ≤ 0, n < 0), `Shake256*` (negative length), `wire.Reader.LV` consumed the prefix before validating and accepted a negative limit, `(*Reader)(nil).Done()`. (4, 5) | Fixed with regression tests. |
| Low | Validation gaps between `core` and the components (UOV n ≤ 512, SLH-DSA a ≤ 16, h/d ≤ 16, k ≤ 64, d ≤ 64, lattice ω ≤ 255 because hint counts are bytes). (5) | `core` now enforces the component limits. |
| Low | A secret key holding only its seed and hash decapsulated "successfully" to the rejection value. (4) | Secret key shape is validated; `ErrInvalidKey`. |
| Low | `kem.Encrypt` had no plaintext cap; above about 64 GiB AES-GCM panics. (2) | `ErrMessageTooLarge` above the GCM limit. |
| Info | Documentation: "3.x", "3.0.0 reintroduced", BenchmarkReport "describes 1.x", σ = 3.19, "discrete Gaussian", "at least as strong as its strongest component", "IND-CCA in the ROM" without a QROM caveat, "SUF-CMA from the nonce", "five independent reviewers", "attack programs kept as claims_test", "verified against an independent reference" with no test enforcing it, exit-code table, `-n` missing from the options table. (6) | Corrected in README, CLI.md, this document and the package comments. NIST ACVP vectors for SLH-DSA-SHAKE-128f/256f (key generation, deterministic and hedged signing through the internal and external "pure" interfaces with 1 and 4 workers, and verification including the modified-R, modified-FORS and modified-hypertree negatives) now run in CI, `problems/slhdsa/acvp_test.go`. |

### 6.3 Side-channel state after 4.1.0

What is constant-time by construction (control flow and memory addresses
independent of secret data), and what was measured:

- **KEM decapsulation path.** SLSS decryption (dense inner products), the
  code component's Reed-Solomon and Reed-Muller decoders (measured medians
  42,306 / 42,279 / 42,308 / 42,297 ns for 0 / 29 / 30 / 90 errors), the
  re-encryption samplers and products (4.1), the FO comparison and selection
  (branch-free since 4.1). Over 1,500 interleaved samples per class, the
  five full-path outcomes (valid, SLSS mismatch, code mismatch, decoding
  failure, random ciphertext) were indistinguishable on this machine
  (medians 1192–1228 µs); the two public early rejections (shape, padding)
  are 65 / 220 µs and reveal nothing about the key.
- **Lattice signature.** Reductions, `Decompose`, hints and key packing are
  branch-free; rejection sampling branches as in FIPS 204. Signing time
  showed no key dependence over two keys × 200 signatures.
- **Still data-dependent.** (a) The code component's sparse ring
  multiplication reads its window at offsets given by the secret support
  (`y` in decryption and key generation, `r2` in encryption): a cache-line
  granular leak that only a dense or bitsliced carry-less multiply would
  close. (b) UOV signing: GF(2^8) lookup tables, the bucket index of the
  evaluation and a branching pivot search. (c) SLH-DSA is inherently
  constant-time apart from the hash. (d) `recover()` paths and Go's runtime
  (allocation, garbage collection, scheduling) are outside any guarantee.
  A local attacker with cache access should be assumed able to exploit (a)
  and (b).

### 6.4 What was tested and found nothing

This is the evidence behind "no cryptographic break was found"; it is not
evidence of absence beyond what was tried.

- **KEM chosen-ciphertext tampering**: bit flips in every component field,
  truncated / nil / empty / extra-word shapes, decoding failures forced by
  inverting the code word: every case rejected, deterministically, with the
  same value as `implicitReject(serialize(ct))`, never equal to the real
  secret; a foreign key gives `ErrKeyMismatch`. 10,000 random and 10,000
  tampered ciphertexts: rejection outputs balanced and never colliding.
- **HQC fidelity**: the fused window multiply matches a naive reference at
  every wrap-around boundary for n ∈ {64, 65, 127, 128, 129, 191, 4096,
  4097, 57637}; the fixed-weight sampler is uniform (χ² = 57,706 on 57,636
  degrees of freedom); compression/decompression errors are within bound
  for all x ∈ [0, q); the 3072 threshold is 22–24σ.
- **Signatures**: `Decompose`/`Power2Round`/`UseHint` agree with textbook
  FIPS 204 for every r ∈ [0, q); removing, adding (all M indices),
  duplicating, unsorting, aliasing or overfilling hints is rejected; z at
  ±(γ1−β) is rejected and ±(γ1−β−1) accepted; 9.9 k byte mutations of a
  lattice signature all fail and all re-encode canonically; cross-key,
  cross-level and mixed-challenge signatures fail; every UOV public form
  vanishes on the oil space (all basis vectors and pairs) and the prepared,
  basic and bit-serial evaluations agree; 300 UOV signatures have 300
  distinct salts; SLH-DSA is byte-exact on NIST ACVP vectors (20 keyGen,
  56 sigGen, 56 sigVer in the review; a subset is now in CI); every
  component mutation, component swap and nonce swap of a composite
  signature fails; signing with and without the public key is
  interchangeable.
- **Serialization**: about 1,580 structure-aware mutations per object type
  (headers, every length prefix set to 0, ±1, 2^31−1, 2^32−1, 16 MiB+1,
  truncation at every prefix, trailing bytes, type confusion) for KEM and
  signature keys, ciphertexts, encrypted messages and signatures at both
  levels, plus 18 fuzz targets for 60–150 s each: no panic, hang, out-of-
  memory, accepted non-canonical input or verifying mutation. A 16 MiB or
  4 GiB length prefix on a 3-byte body is rejected with 0 bytes allocated.
- **Property tests**: 200 key pairs per level: byte-identical round trips
  of every object, decapsulation after round trip, verification after
  round trip, encrypt/decrypt of 0–70,000 bytes, sign/verify of 0, 1 and
  1 MiB messages, deterministic key generation, distinct keys from distinct
  seeds; about 130 nil/zero-value calls across the API each return an error
  or false (the panics found are in §6.2 and fixed).
- **Concurrency**: 16 goroutines sharing one KEM key pair and one signing
  key pair under the race detector for 30 s: no races, no goroutine leaks;
  `signWithRand` is identical for GOMAXPROCS 1/2/3/4/8 and 1–64 workers.
- **Platforms**: GOARCH=386 (whole suite, after the test-constant fixes),
  cross-compilation for linux/arm, arm64, riscv64, windows/amd64 and
  darwin/arm64; deterministic key generation and encapsulation are
  byte-identical on amd64 and 386 and with GOMAXPROCS 1 or 4. arm and
  riscv64 were compiled, not run.
- **Flakiness**: `go test ./...` three times, `-race`, `-cpu 1,2,7`, and the
  Reed-Solomon timing test 60 times under load (worst max/min ratio 1.012):
  no flakes.
- **Resources**: peak RSS 11 / 16 MB for KEM key generation (MOS-128/256)
  and 40 MB for MOS-256 signing key generation; no goroutine leaks.

### 6.5 Still open after 4.1.0

*(Superseded by §7.3 for the side-channel, cached-hash and dead-code
items; the rest still stands.)*

- **Not externally reviewed.** The seven briefs were run inside this project.
  No cryptographer outside it has examined the composition, the SLSS
  parameters, the lattice-signature transplant or the implementation.
- **Cache-timing channels** in the code component's ring multiplication and
  in UOV signing (§6.3). Closing them needs a dense or bitsliced carry-less
  multiply and bitsliced GF(2^8) arithmetic.
- **Parameter estimates** for SLSS are this repository's own (±10 bits, no
  Lattice Estimator run, newer dual attacks not modelled), and the lattice
  signature's levels are by analogy to ML-DSA.
- **QROM**: only the generic, non-tight FO⊥̸ results apply.
- **HQC interoperability**: the code component follows HQC's construction
  and parameters but is not bit-compatible with the HQC reference, so HQC's
  known-answer tests cannot be run against it.
- **Zeroization** is best-effort; Go's runtime copies and the hash and AES
  internals are not wiped.
- **Cost**: constant-time sampling and dense products made KEM key
  generation about 3× slower and encapsulation about 2× slower than 4.0.0;
  there is no SIMD.
- **Cached hashes** in the public-key structs are trusted; hand-edited key
  structs are the caller's responsibility.

### 6.6 Claim: "bug free"

**Verdict: not a claim this or any review can make, and 4.0.0 was not.**
The pass found one hang, one validation hole, three CLI defects with
security consequences, a timing channel in the one place that matters most
(FO re-encryption), a 32-bit truncation, a vacuous test and a dozen smaller
robustness defects in a code base that had already passed its own suite,
five internal reviewers, fuzzing and the race detector. All of them are fixed
and pinned by tests, and the review found no way to recover a key, decrypt a
ciphertext or forge a signature. That is the strongest statement the
evidence supports: *no known bugs, after an adversarial review whose scope
is listed in §6.4*. It is not "bug free", and the library should still not
be used where a failure would matter.

---

## 7. Version 4.2.0: closing the open items

4.2.0 addresses every item of §6.5 that code can address. No key, ciphertext
or signature changed: for fixed seeds, the UOV keys and signatures are
pinned by digests in `problems/uov/ct_test.go`, the composite KEM and
signature keys and a deterministic encapsulation by `kem/kat_test.go` and
`sign/kat_test.go`, and the code-component outputs were checked against an
unmodified copy for 20 seeds during development.

### 7.1 Side channels closed

| Item (§6.3/§6.5) | Change | Argument |
| --- | --- | --- |
| Code component's sparse ring multiplication read a window of the doubled vector at a word offset given by the secret position (key generation, encryption inside re-encryption, decryption). | `problems/qcsd/ringmul.go`: for each position the 902-word window is selected by a 10-stage barrel shifter whose every stage reads and writes buffers of fixed length (1413 … 902 words) under an AND mask, and the bit offset is applied with one `bits.Mul64` per word by a multiplier built from public constants (no shift by a secret amount). The two products of encryption share the masks. Work is split across goroutines by public quantities only. `Decrypt` no longer derives positions from the bit vector; keys must carry their position list. | Secret positions flow only into AND masks, XOR operands and multiplier operands. Loop bounds, slice offsets, buffer lengths, goroutine count and chunk boundaries depend on n, the weight, the operand count and GOMAXPROCS. Verified by reference comparison at every wrap-around boundary for 14 ring lengths, identical results for GOMAXPROCS 1–16, identical allocation counts for four supports, and an interleaved timing test over supports in the first 64 bits, the last 64 bits, evenly spread and random (max/min 1.006–1.01 single-threaded, 1.04–1.08 with 4 cores). |
| UOV signing used GF(2^8) lookup tables, bucket indices and a branching pivot search on secret data; key generation multiplied the secret oil matrix through tables. | `problems/uov`: packed constant-time field arithmetic (eight elements per word, doubling by shifts and xors, scalar products through masked doubling tables, inversion by a fixed addition chain), bit-plane accumulation of vᵀS_i and vᵀP1v with the vinegar values as masks, masked Gauss-Jordan elimination in the style of the UOV reference (every lower row conditionally added to the pivot row, singularity returned as a flag after the whole elimination), and masked products for s = v + O·x and for P3 in key generation. Verification and public-key expansion keep the tables (public data). Signing draws randomness through the library's injectable RNG. | Loop bounds, row and word indices and shift amounts depend only on m, v and the column index; the amd64 disassembly of the field primitives has no conditional jumps. Exhaustive equality with the table arithmetic (all 65,536 products, all 256 inverses). Interleaved timing tests: signing attempts with zero vinegar (singular), an adversarial anti-identity system, constant 0xFF vinegar and random vinegar give max/min 1.03–1.11; the solver alone 1.006 (it used to take 1.9 µs on a zero matrix against 197 µs on a random one). Allocation counts do not depend on the message. The retry on a singular system is visible, as in the reference. |
| Key-mismatch check trusted the cached public-key hash. | `kem.Decapsulate` recomputes SHA3-256 over the serialized public key and requires it to equal both the secret key's stored hash and the cache. | A public key edited in memory, with or without its cache, is rejected (`TestDecapsulateRecomputesPublicKeyHash`). Cost about 1 ms per decapsulation. |
| Parsed KEM secret keys were not validated beyond their encoding. | `slss.DeserializeSecretKey` requires every column to have exactly W non-zero entries (scanning every entry); the code component requires a strictly increasing position list below N (unchanged) and the KEM requires it to be present. | Corrupted or hand-built keys fail at parse time instead of silently producing rejection values. |
| Floating-point Gaussian sampler left in `utils`. | Removed (`SampleGaussianVector`); nothing used it. | Less attack surface; no float arithmetic remains in the library. |
| Intermediate hash outputs on the KEM path were not wiped. | The keyed inputs of the shared-secret, rejection and AES-key derivations are zeroized after use. | Best-effort only; see §7.3. |

### 7.2 Cost

Measured on the same 4-core container (BenchmarkReport.md has the full
table). KEM decapsulation 2.3 / 2.4 → 6.7 / 7.2 ms (two oblivious
multiplications in decryption plus two in re-encryption, and the hash
recomputation); encapsulation 1.5 / 2.2 → 2.1 / 2.0 ms; KEM key generation
51 / 99 → 56 / 113 ms. UOV signing 0.24 / 2.1 → 0.56 / 4.1 ms and UOV key
generation 4.9 / 69 → 8.6 / 172 ms, which is hidden inside the parallel
composite signing but visible in composite key generation and in loading a
MOS-256 signing key (58 → 84 ms).

### 7.3 Still open after 4.2.0

- **Not externally reviewed.** Everything in §6 and §7 was done inside this
  project.
- **What "constant-time" means here.** No branch, loop bound, memory address
  or shift amount depends on secret data in the library's own code, verified
  by reading, by disassembly of the field primitives, and by interleaved
  timing tests (`*TimingFlat`; statistical, so they are gated behind
  `KMOSAIC_TIMING_TESTS` and run one test binary at a time in CI, since
  concurrent test binaries on a small runner produce spreads of 1.3–1.5 with
  no consistent slow input). Not covered: the Go compiler's instruction selection (the
  language does not promise branch-free code for masked expressions; today's
  amd64 output is branch-free), the Go runtime (allocation, garbage
  collection and scheduling add timing noise that does not depend on the
  data), the standard library's SHA-3 and AES (constant-time on current
  hardware per Go's own documentation, not verified here), hardware whose
  64-bit multiply latency depends on operands, and the lattice signature's
  rejection sampling, which branches exactly as FIPS 204 does.
- **Parameter estimates** for SLSS are this repository's own (§6.1), and the
  lattice signature's levels are by analogy to ML-DSA.
- **QROM**: only the generic, non-tight FO⊥̸ results apply.
- **HQC interoperability**: not bit-compatible with the HQC reference.
- **Zeroization** is best-effort; Go's runtime copies and the hash and AES
  internals are not wiped.
- **No SIMD**; key generation is 56–335 ms.
