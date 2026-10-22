# Security Policy

## Status

kMOSAIC is **experimental software that has not been reviewed by anyone
outside this repository**. Do not use it to protect real data. The current
state of the implementation, the attacks that were reproduced against earlier
versions, the audits that were run and what they did and did not cover are
recorded in [SECURITY_ASSESSMENT.md](SECURITY_ASSESSMENT.md); §6.5 and §7.3
list what remains open.

## Supported versions

| Version | Status |
| ------- | ------ |
| 4.2.x   | Current. Receives fixes. |
| 4.0.x, 4.1.x | Superseded. 4.0.0 has a timing oracle in decapsulation (§6.2); 4.1.0 has cache-timing channels in the code component and in UOV signing (§7.1). Upgrade. |
| < 4.0   | Broken by design (the shared secret and the signing key were recoverable from public data). Keys, ciphertexts and signatures from these versions must be discarded; 4.x refuses to parse them. |

## Reporting a vulnerability

Open a GitHub issue in this repository, or, if you prefer not to disclose
publicly, contact the maintainer through the e-mail address on the GitHub
profile of the repository owner. Please include a reproduction (a test or a
program against the current branch) where you can. There is no bug bounty
and no fixed response time, but reports are read and answered.

Findings against the design (parameters, the composition, the lattice
signature transplant) are as welcome as findings against the code: the
assessment records both.

## What a report about this library can reasonably claim

The library makes specific, bounded claims; a report that shows one of them
false is a valid finding:

- No key, ciphertext or signature changes without a wire-format version
  bump; the format is version 4.
- Every operation on secret data is constant-time by construction in the
  library's own code (§7.1 and §7.3 state the boundary of that claim).
- Every parser rejects malformed input with an error rather than a panic,
  and allocates nothing before validating lengths.
- The SLH-DSA component is bit-exact against NIST ACVP vectors.
- The documentation does not overstate what has been verified.
