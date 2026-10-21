# kMOSAIC Security Assessment

**Scope:** the Go implementation in this repository at commit `f14168f`
(the state after the first round of functional fixes), its README, CLI.md,
BenchmarkReport.md, and the claims they make. The TypeScript reference
implementation was consulted to tell porting bugs from design flaws.

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
| "NIZK proof" in the KEM ciphertext                                               | **Overstated.** `GenerateNIZKProof` is a hash binding of the shares to the ciphertext hashes under a seed. It is deterministic in the ephemeral secret and is simply part of what the Fujisaki-Okamoto re-encryption compares. It proves nothing beyond what re-encryption already checks and has no zero-knowledge property to speak of. It is harmless and was left in place. | code review |
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
