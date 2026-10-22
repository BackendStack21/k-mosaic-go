# Changelog

All notable changes to the Go implementation. Dates are commit dates (UTC);
the wire format is version 4 throughout 4.x. Since 4.2.0 the module path is
`github.com/BackendStack21/k-mosaic-go/v4`.

## 4.2.0 — 2026-10-22

Security hardening; no key, ciphertext or signature changed.

- The code component's sparse ring multiplication is memory-oblivious: a
  masked barrel shifter selects each window over fixed-length buffers and the
  bit offset is applied with a multiply instead of a shift by a secret
  amount. Decryption requires the key's position list.
- UOV signing and key generation are constant-time: packed GF(2^8)
  arithmetic, bit-plane evaluation with the vinegar values as masks, masked
  Gauss-Jordan elimination with a singularity flag.
- `kem.Decapsulate` recomputes the public-key hash instead of trusting the
  cached one.
- Parsed SLSS secret keys must have exactly W non-zero entries per column.
- Hash intermediates on the KEM path are zeroized; the unused floating-point
  Gaussian sampler was removed.
- Cost: KEM decapsulation about 7 ms (was 2.3 ms); UOV key generation 2×.
- Module path moved to `/v4`; the entropy check on lattice seeds was removed.
- `SECURITY_ASSESSMENT.md` §7 records the changes and arguments.

## 4.1.0 — 2026-10-22

Validation pass by seven adversarial reviews; no cryptographic break found;
every defect found was fixed. **Keys derived from a seed differ from 4.0.0**
because the sparse-vector samplers changed.

- Constant-time sparse samplers (sort-based for SLSS, Sendrier's method for
  the code component) and dense SLSS products, closing a plaintext-checking
  timing oracle in FO re-encryption and a hardware division on secret data.
- Decapsulation rejects non-canonical in-memory ciphertexts consistently and
  folds validity without branching.
- Fixed: a hang in parameter validation for huge ring lengths; KEM key
  generation accepting weakened parameters under a valid level; CLI key
  files briefly readable or written through symlinks, input limit bypass,
  silent stdin truncation, empty option values, ignored unknown options;
  32-bit test builds and a 32-bit mask truncation; panics in component
  goroutines not caught; serializers emitting unparsable output for
  mismatched parameters; a vacuous tamper test; several helpers panicking
  on hostile arguments.
- NIST ACVP conformance vectors for SLH-DSA-SHAKE-128f/256f run in CI.
- `docs/estimator/` reproduces the LWE security and failure-rate figures.
- Documentation corrected: the MOS-128 LWE component is NIST level 1; the
  IND-CCA proof is classical-ROM; strong unforgeability is assumed of the
  components; historical sections of the assessment are marked.

## 4.0.0 — 2026-10-22

Breaking release after an internal five-reviewer review.

- Removed the ciphertext "proof" field that leaked the KEM shares in every
  earlier version; the ciphertext is exactly the two component ciphertexts.
- Self-describing wire format (8-byte header, exact-length parsing, 64-bit
  safe length checks); parsers take no parameters.
- Constant-time Reed-Solomon decoder, constant-modulus reductions, FIPS 204
  decompose arithmetic, integer centered-binomial sampler.
- Key-mismatch check in decapsulation; per-signature nonce in the signed
  digest; exact 32-byte seeds everywhere.
- ML-DSA-65/87 shapes with Power2Round and hints; UOV with compressed public
  keys; SLH-DSA with the FIPS 205 pure interface (context `kmosaic-v4`).
- Rewritten CLI with documented exit codes and file modes; every
  documentation snippet executed by the tests.

## 3.0.0 and earlier

Do not use. 1.x: the KEM shared secret was recoverable from the public key
and ciphertext, and signatures were forgeable with the public key. 2.0.0 and
3.0.0: the ciphertext carried a field that revealed the KEM shares. See
`SECURITY_ASSESSMENT.md` §1–§5.
