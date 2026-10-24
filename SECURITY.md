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
| 2.0.x   | Current. Receives fixes. |
| 1.x     | Broken by design (the KEM shared secret was recoverable from public data, and signatures were forgeable with the public key). Keys, ciphertexts and signatures from these versions must be discarded; 2.x refuses to parse them. The `v1.0.x` tags of the old module path still exist; the current code lives under the `/v2` module path. |

The development revisions 2.0.0-dev.1 to 2.0.0-dev.4 were never tagged or
released. Their defects (including a decapsulation timing oracle in dev.3,
§6.2, and cache-timing channels in dev.4, §7.1) are recorded in
SECURITY_ASSESSMENT.md.

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

- No encoding changes without a wire-format version bump; the format is
  version 4. A change to the seed-to-key derivation (as in 2.0.0-dev.4) is
  stated in CHANGELOG.md and pinned by known-answer tests.
- Every operation on secret data is written to be constant-time in the
  library's own code (§7.1 and §7.3 state the boundary of that claim).
- Every parser rejects malformed input with an error rather than a panic,
  and allocates nothing before validating lengths.
- The SLH-DSA component is bit-exact against NIST ACVP vectors.
- The documentation does not overstate what has been verified.
