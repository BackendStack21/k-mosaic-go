# kMOSAIC-Go Security Review Report

**Date:** 2026-04-10  
**Scope:** Full codebase review of `github.com/BackendStack21/k-mosaic-go`  
**Reviewer:** Automated deep security review  
**Base commit:** `9457772` (v1.0.4)

---

## Executive Summary

A deep security review of the kMOSAIC-Go post-quantum cryptographic library was
conducted, covering all packages: `kem`, `sign`, `entanglement`, `problems/slss`,
`problems/tdd`, `problems/egrw`, `utils`, `core`, and the CLI tool.

Five vulnerabilities were identified and fixed in this review. Additionally, one
structural design limitation of the EGRW component is documented. All fixes
maintain full backward compatibility with existing tests.

| ID    | Title                                              | Severity | Status  |
|-------|----------------------------------------------------|----------|---------|
| V-01  | Dependency CVE: `golang.org/x/crypto` ≤ 0.34.0    | High     | **Fixed** |
| V-02  | `tdd.Decrypt` panics on malformed ciphertext       | High     | **Fixed** |
| V-03  | `slss.Decrypt` panics on mismatched vector lengths | High     | **Fixed** |
| V-04  | `DebugEncrypt` exposes LWE ephemeral error vectors | High     | **Fixed** |
| V-05  | `kem.DeserializePublicKey` missing size bounds     | Medium   | **Fixed** |
| D-01  | EGRW Decrypt doesn't use the secret key (design)  | Medium   | Documented |

---

## Vulnerability Details

### V-01 — Dependency CVE: `golang.org/x/crypto` ≤ 0.34.0

**Severity:** High  
**CWE:** CWE-400 (Uncontrolled Resource Consumption)  
**Affected file:** `go.mod`  
**Advisory:** [GHSA-](https://pkg.go.dev/vuln/GO-2025-3447)
`golang.org/x/crypto` before v0.35.0 is vulnerable to a Denial of Service
via a slow or incomplete SSH key exchange.

**Root cause:**  
The `go.mod` declared `golang.org/x/crypto v0.31.0`, which is in the affected
range.

**Impact:**  
Any kMOSAIC application that also uses `golang.org/x/crypto`'s `ssh` package
(directly or transitively) is exposed to remote DoS. The kMOSAIC library itself
uses only the `sha3` sub-package, reducing direct exposure, but the vulnerable
version is still present in the module graph and may be pulled into host
applications.

**Fix:**  
Upgraded `golang.org/x/crypto` to `v0.35.0` (and `golang.org/x/sys` to
`v0.30.0` as required by the new version).

---

### V-02 — `tdd.Decrypt` panics on malformed ciphertext

**Severity:** High  
**CWE:** CWE-125 (Out-of-Bounds Read) / CWE-20 (Improper Input Validation)  
**Affected file:** `problems/tdd/tdd.go` — `Decrypt` function  

**Root cause:**  
```go
func Decrypt(ct *kmosaic.TDDCiphertext, ...) []byte {
    encMsgLen := 8
    masked := ct.Data[:len(ct.Data)-encMsgLen]  // PANIC if len < 8
    ...
    v := ct.Data[len(ct.Data)-encMsgLen+i]      // PANIC if len < 8
```
When `len(ct.Data) < 8`, Go's runtime panics with "slice bounds out of range"
because the result of `len(ct.Data) - 8` is a negative index.

**Impact:**  
`tdd.Decrypt` is called from a goroutine inside `kem.Decapsulate`. A panic in a
goroutine that does not have its own `recover` propagates to the entire process,
causing a **program crash (process termination)**. An attacker who can supply a
crafted `TDDCiphertext` (e.g., via a deserialized public API call) can trigger an
unconditional crash — a complete Denial of Service.

**Fix:**  
Added an early-return guard:
```go
if len(ct.Data) < encMsgLen {
    return nil
}
```

---

### V-03 — `slss.Decrypt` panics on mismatched vector lengths

**Severity:** High  
**CWE:** CWE-125 (Out-of-Bounds Read)  
**Affected file:** `problems/slss/slss.go` — `Decrypt` and `innerProduct`

**Root cause:**  
```go
// innerProduct iterates over 'a' and indexes 'b' at the same position
func innerProduct(a []int32, b []int8, q int) int32 {
    for i := range a {
        sum += int64(a[i]) * int64(b[i])  // PANIC if len(b) < len(a)
    }
    ...
}
```
`slss.Decrypt` calls `innerProduct(ct.U, sk.S, q)` without first verifying that
`len(ct.U) == len(sk.S)`. If a caller (or attacker-controlled deserialized input)
provides a `SLSSCiphertext` where `len(ct.U)` differs from `len(sk.S)`, Go will
panic at runtime.

As with V-02, this panic occurs inside a goroutine in `kem.Decapsulate` and
therefore terminates the host process.

**Fix:**  
Added a vector-length guard at the top of `slss.Decrypt`:
```go
if len(ct.U) != len(sk.S) {
    return nil
}
```

---

### V-04 — `DebugEncrypt` exposes sensitive LWE ephemeral error vectors

**Severity:** High  
**CWE:** CWE-200 (Exposure of Sensitive Information to Unauthorized Actor)  
**Affected files:** `problems/slss/slss.go`, `cmd/k-mosaic-cli/main.go`

**Root cause:**  
The exported `DebugEncrypt` function returned a `SlssDebugInfo` struct
containing:
- `RIndices` / `RValues` — positions and values of the non-zero entries in the
  ephemeral sparse vector `r` used during encryption.
- `E1Head` / `E2Head` — first 8 elements of the LWE error vectors `e1` and
  `e2`.
- `UHead` / `VHead` — first 8 elements of the ciphertext components.

In an LWE/RLWE-based scheme the error vector is the secret that makes the
problem computationally hard. Revealing even partial error vector information
is a **fundamental cryptographic weakness**: it can directly assist lattice
reduction attacks (e.g., BKZ-style solvers) by improving the quality of the
input basis. Likewise, `r` and its support positions are ephemeral secrets —
exposing them can allow an adversary to reconstruct the encryption randomness
and consequently recover the plaintext (in this case, the secret share).

The CLI command `kem slss-debug` serialised this information to JSON and wrote
it to standard output or a file, making exfiltration trivial.

**Fix:**  
- Replaced `RIndices`, `RValues`, `E1Head`, `E2Head`, `UHead`, `VHead` with
  only structural (non-sensitive) fields: `ULen`, `VLen`, `W`, `RNNz` (the
  count of non-zero entries, not their positions or values).
- Added a `SECURITY WARNING` doc-comment to `DebugEncrypt` and `SlssDebugInfo`.
- Added a zeroization call for `r` and `rInt32` in `DebugEncrypt` (previously
  omitted).
- Updated the CLI output map and the CLI test accordingly.

---

### V-05 — `kem.DeserializePublicKey` missing `MaxComponentSize` checks

**Severity:** Medium  
**CWE:** CWE-400 (Uncontrolled Resource Consumption)  
**Affected file:** `kem/kem.go` — `DeserializePublicKey`

**Root cause:**  
`sign.DeserializePublicKey` guards every length-prefixed field against
`MaxComponentSize` (10 MB) before attempting to slice the buffer. The equivalent
function in the `kem` package did not perform these checks:

```go
// Before fix (kem package):
levelLen := int(binary.LittleEndian.Uint32(data[offset:]))
offset += 4
// No MaxComponentSize check here!
if offset+levelLen > len(data) { ... }
```

An attacker-provided byte stream with a crafted component length close to
`len(data) - offset` would pass the `> len(data)` check while causing a
maximally large `make([]byte, ...)` allocation — a potential memory-exhaustion
DoS. Additionally, missing explicit checks are a code-consistency risk that can
become an actual vulnerability if the buffer-size check is ever refactored.

**Fix:**  
Added explicit `> MaxComponentSize` early-return checks (identical to the sign
package) for `levelLen`, `slssLen`, `tddLen`, and `egrwLen`. Also added missing
`offset+4 > len(data)` guards before reading each length field for `slssLen`,
`tddLen`, and `egrwLen`. Defined `MaxComponentSize = 10 * 1024 * 1024` in the
kem package's constant block.

---

## Design Limitation (Not a Code Bug)

### D-01 — EGRW Decrypt does not use the secret key

**Severity:** Medium (design)  
**Affected file:** `problems/egrw/egrw.go` — `Decrypt` function  

**Description:**  
The EGRW `Decrypt` function derives the XOR keystream exclusively from the
public key components (`VStart`, `VEnd`) and the ciphertext vertex:

```go
keyInput := utils.HashConcat(
    utils.HashWithDomain(DomainMask, SL2ToBytes(ct.Vertex)),
    utils.HashWithDomain(DomainMask, SL2ToBytes(pk.VStart)),
    utils.HashWithDomain(DomainMask, SL2ToBytes(pk.VEnd)),
)
```

All three inputs are either in the ciphertext or in the **public** key. The
secret key `sk.Walk` is never used during decryption. This means any party that
holds the public key can independently compute the same keystream and recover the
EGRW share without the private key — i.e., the EGRW component provides **no
confidentiality**.

**Root cause:**  
A DH-style shared-secret exchange (analogous to ElGamal) requires an abelian
group; SL(2, Z_p) is non-abelian, so the standard trick
`Enc: K = g^(r·sk)`, `Dec: K = (g^r)^sk` does not hold. The current
implementation correctly derives an ephemeral vertex but cannot bind it to the
private walk in a symmetric way.

**Impact:**  
The kMOSAIC KEM splits the ephemeral secret into three XOR shares, one per
component. Because the EGRW share can be recovered by any public-key holder,
an adversary must only break **SLSS and TDD** to recover the full secret, rather
than all three. This reduces the effective security margin from the
advertised three-component barrier to a two-component barrier.

Both SLSS and TDD remain independently secure (lattice problem hardness), so the
overall scheme is not immediately broken. However, the security guarantee stated
in the README is not met.

**Recommendation:**  
Re-architect the EGRW component to contribute genuine confidentiality. Possible
directions:
1. Use EGRW as a **commitment/authentication** component rather than a
   confidentiality component (the walk provides a one-way proof of knowledge).
2. Replace EGRW with a hash-based KEM (e.g., a Kyber-style RLWE component or
   a CSIDH-style isogeny component) that naturally supports public-key
   encryption.
3. Explore non-abelian group-based key encapsulation schemes from the literature.

A `SECURITY NOTE` comment has been added to `problems/egrw/egrw.go` documenting
this limitation.

---

## Summary of Changes

| File | Change |
|------|--------|
| `go.mod` / `go.sum` | Upgrade `golang.org/x/crypto` v0.31.0 → v0.35.0; `golang.org/x/sys` v0.28.0 → v0.30.0 |
| `problems/tdd/tdd.go` | Add `len(ct.Data) < encMsgLen` guard in `Decrypt` |
| `problems/slss/slss.go` | Add `len(ct.U) != len(sk.S)` guard in `Decrypt`; redact sensitive fields from `SlssDebugInfo`; add security warning doc-comment; add missing zeroization in `DebugEncrypt` |
| `kem/kem.go` | Add `MaxComponentSize` constant; add per-field `> MaxComponentSize` guards and missing length-field truncation checks in `DeserializePublicKey` |
| `problems/egrw/egrw.go` | Add package-level security note documenting the design limitation |
| `cmd/k-mosaic-cli/main.go` | Update `slss-debug` output to use new non-sensitive `SlssDebugInfo` fields |
| `cmd/k-mosaic-cli/main_test.go` | Update `TestKEMSLSSDebug` to check for new non-sensitive fields |

---

## Testing

All existing tests pass after applying the fixes:

```
ok  github.com/BackendStack21/k-mosaic-go/cmd/k-mosaic-cli
ok  github.com/BackendStack21/k-mosaic-go/core
ok  github.com/BackendStack21/k-mosaic-go/entanglement
ok  github.com/BackendStack21/k-mosaic-go/kem
ok  github.com/BackendStack21/k-mosaic-go/problems/egrw
ok  github.com/BackendStack21/k-mosaic-go/problems/slss
ok  github.com/BackendStack21/k-mosaic-go/problems/tdd
ok  github.com/BackendStack21/k-mosaic-go/sign
ok  github.com/BackendStack21/k-mosaic-go/test
ok  github.com/BackendStack21/k-mosaic-go/utils
```

---

## Disclaimer

kMOSAIC is an **experimental cryptographic construction** that has not been
formally verified by academic peer review. As stated in the repository README,
it **must not be used in production systems protecting sensitive data**. This
security review covers implementation-level vulnerabilities; it does not
constitute a formal cryptanalysis of the underlying mathematical problems or the
security proofs of the scheme.
