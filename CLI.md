# k-mosaic-cli Guide

`k-mosaic-cli` is the command-line interface of the kMOSAIC post-quantum
library: key generation, encapsulation, hybrid encryption and digital
signatures from a terminal.

> **Warning:** kMOSAIC is experimental and unreviewed. Do not use it to protect
> real secrets. Key, ciphertext and signature files from versions before 4.0.0
> are not readable by this version, and those versions were insecure; see
> [SECURITY_ASSESSMENT.md](SECURITY_ASSESSMENT.md).

Every `bash` block in this guide is executed against the current source tree
by `go test ./test/ -run TestDocumentationSnippets`, in order, in one shared
working directory per document (later blocks reuse files made by earlier
ones); blocks marked `sh` are illustrative (installation, tools that may be
absent) and are not run.

## TL;DR

```sh
go install github.com/BackendStack21/k-mosaic-go/v4/cmd/k-mosaic-cli@latest
```

```bash
# Keys: writes keys.json (both keys, mode 0600) and keys.json.pub (public key only)
k-mosaic-cli kem keygen -l 128 -o keys.json
k-mosaic-cli kem encrypt -pk keys.json.pub -m "Secret message" -o enc.json
k-mosaic-cli kem decrypt -sk keys.json -pk keys.json.pub -ct enc.json

# Signatures: the message must be given explicitly to verify
k-mosaic-cli sign keygen -l 128 -o sign.json
k-mosaic-cli sign sign -sk sign.json -pk sign.json.pub -m "Document" -o sig.json
k-mosaic-cli sign verify -pk sign.json.pub -sig sig.json -m "Document"
```

## Quick Reference

| Task                  | Command                                                                        |
| --------------------- | ------------------------------------------------------------------------------ |
| Check version         | `k-mosaic-cli version`                                                         |
| Generate KEM keys     | `k-mosaic-cli kem keygen -l 128 -o keys.json` (also writes `keys.json.pub`)    |
| Encrypt message       | `k-mosaic-cli kem encrypt -pk keys.json.pub -m "text" -o enc.json`             |
| Encrypt file          | `k-mosaic-cli kem encrypt -pk keys.json.pub -i file.txt -o enc.json`           |
| Decrypt               | `k-mosaic-cli kem decrypt -sk keys.json -pk keys.json.pub -ct enc.json`        |
| Encapsulate           | `k-mosaic-cli kem encapsulate -pk keys.json.pub -o encap.json`                 |
| Decapsulate           | `k-mosaic-cli kem decapsulate -sk keys.json -pk keys.json.pub -ct encap.json`  |
| Inspect a public key  | `k-mosaic-cli kem pk-inspect -pk keys.json.pub`                                |
| Generate signing keys | `k-mosaic-cli sign keygen -l 128 -o sign.json` (also writes `sign.json.pub`)   |
| Sign message          | `k-mosaic-cli sign sign -sk sign.json -pk sign.json.pub -m "text" -o sig.json` |
| Sign file             | `k-mosaic-cli sign sign -sk sign.json -i file.txt -o sig.json`                 |
| Verify signature      | `k-mosaic-cli sign verify -pk sign.json.pub -sig sig.json -m "text"`           |
| Run benchmark         | `k-mosaic-cli benchmark -l 128 -n 10`                                          |

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Key Files](#key-files)
- [Commands Reference](#commands-reference)
  - [Global Options](#global-options)
  - [KEM Operations](#kem-operations)
  - [Signature Operations](#signature-operations)
  - [Benchmarking](#benchmarking)
- [Exit Codes](#exit-codes)
- [Workflows](#workflows)
- [File Formats](#file-formats)
- [Sizes and Timings](#sizes-and-timings)
- [Security Considerations](#security-considerations)
- [Troubleshooting and FAQ](#troubleshooting-and-faq)

## Requirements

- Go 1.24 or later to build from source (the library has no dependencies
  outside the standard library)
- Linux, macOS or Windows

## Installation

### From source

```sh
git clone https://github.com/BackendStack21/k-mosaic-go.git
cd k-mosaic-go
go build -o k-mosaic-cli ./cmd/k-mosaic-cli
sudo mv k-mosaic-cli /usr/local/bin/   # or anywhere on your PATH
```

### With go install

```sh
go install github.com/BackendStack21/k-mosaic-go/v4/cmd/k-mosaic-cli@latest
export PATH="$PATH:$(go env GOPATH)/bin"   # add to your shell profile
```

### Cross-compiling

```sh
GOOS=linux   GOARCH=amd64 go build -o k-mosaic-cli-linux-amd64 ./cmd/k-mosaic-cli
GOOS=linux   GOARCH=arm64 go build -o k-mosaic-cli-linux-arm64 ./cmd/k-mosaic-cli
GOOS=darwin  GOARCH=arm64 go build -o k-mosaic-cli-darwin-arm64 ./cmd/k-mosaic-cli
GOOS=windows GOARCH=amd64 go build -o k-mosaic-cli-windows-amd64.exe ./cmd/k-mosaic-cli
```

### Verify the installation

```bash
k-mosaic-cli version
k-mosaic-cli help
k-mosaic-cli kem --help
k-mosaic-cli sign --help
```

## Key Files

`keygen --output FILE` writes two files:

- `FILE` (mode 0600): `security_level`, `public_key`, `secret_key`, `created_at`.
  Never share it.
- `FILE.pub` (mode 0644): the same without `secret_key`. This is the file you
  give to people who encrypt for you or verify your signatures.

Any option that takes a key file accepts either file: `--public-key` reads the
`public_key` field, `--secret-key` reads the `secret_key` field. Raw files
containing just the hex or base64 encoding of a key are accepted too.

KEM keys and signing keys are different objects; generate them separately with
`kem keygen` and `sign keygen`. Every serialized object carries an 8-byte
header with its format version, type and parameter level, so a signing key
cannot be mistaken for a KEM key and a file from an older release is rejected
with a clear error.

## Commands Reference

### Global Options

| Option         | Short  | Description                                                                  |
| -------------- | ------ | ---------------------------------------------------------------------------- |
| `--level`      | `-l`   | Parameter set: `128` or `256` (default `128`); also `MOS-128` / `MOS-256`    |
| `--output`     | `-o`   | Output file (default: stdout). `keygen` also writes `<file>.pub`             |
| `--format`     | `-f`   | Encoding of binary fields in JSON output: `base64` (default) or `hex`        |
| `--public-key` | `-pk`  | Public key file                                                              |
| `--secret-key` | `-sk`  | Secret key file                                                              |
| `--ciphertext` | `-ct`  | Ciphertext, encapsulation or encrypted-message file                          |
| `--signature`  | `-sig` | Signature file                                                               |
| `--message`    | `-m`   | Message text                                                                 |
| `--input`      | `-i`   | Message file; if neither `--message` nor `--input` is given, stdin is read   |
| `--timing`     | `-t`   | Print timing information to stderr                                           |
| `--verbose`    | `-v`   | Verbose output to stderr                                                     |
| `--iterations` | `-n`   | `benchmark` only: number of iterations (default 10)                          |

Option values are never interpreted as flags: `--message -v` signs the
literal text `-v`, and `--message ""` signs the empty message. Unknown or
misspelled options and stray arguments are errors (exit code 2), so a typo
such as `--ouput` cannot silently send a secret key to stdout. Input files
and stdin are limited to 100 MiB; larger input is an error, never silently
truncated.

### KEM Operations

#### keygen

```bash
k-mosaic-cli kem keygen --level 128 --output my-keypair.json --verbose
ls -l my-keypair.json my-keypair.json.pub
```

The `.pub` companion holds only the public key.

#### encrypt / decrypt

Hybrid encryption: the KEM produces a shared secret, which keys AES-256-GCM.
Empty messages are allowed.

```bash
# From --message
k-mosaic-cli kem encrypt --public-key my-keypair.json.pub --message "Hello, quantum-safe world!" --output encrypted.json
k-mosaic-cli kem decrypt --secret-key my-keypair.json --public-key my-keypair.json.pub --ciphertext encrypted.json

# From a file, writing the plaintext to a file
printf 'contract text\n' > document.txt
k-mosaic-cli kem encrypt --public-key my-keypair.json.pub --input document.txt --output document.enc.json
k-mosaic-cli kem decrypt --secret-key my-keypair.json --public-key my-keypair.json.pub --ciphertext document.enc.json --output document.dec.txt
cmp document.txt document.dec.txt

# From stdin
echo "Secret data" | k-mosaic-cli kem encrypt --public-key my-keypair.json.pub --output stdin.enc.json
```

Decryption needs both your secret key and your public key; the CLI checks that
they belong together and refuses mismatched pairs. A tampered ciphertext fails
authentication with exit code 1:

```bash
# Flip one character deep inside the base64 payload (jq keeps the JSON valid)
jq '.ciphertext |= (.[:1000] + (if .[1000:1001] == "A" then "B" else "A" end) + .[1001:])' encrypted.json > tampered.json
set +e
k-mosaic-cli kem decrypt --secret-key my-keypair.json --public-key my-keypair.json.pub --ciphertext tampered.json > /dev/null 2>&1
status=$?
set -e
test "$status" -eq 1 && echo "tampered ciphertext rejected (authentication failed)"
```

#### encapsulate / decapsulate

Key exchange without a message: the sender gets a ciphertext and a shared
secret, the recipient recovers the same secret.

```bash
k-mosaic-cli kem encapsulate --public-key my-keypair.json.pub --output encap.json
k-mosaic-cli kem decapsulate --secret-key my-keypair.json --public-key my-keypair.json.pub --ciphertext encap.json --output decap.json
test "$(jq -r .shared_secret encap.json)" = "$(jq -r .shared_secret decap.json)" && echo "shared secrets match"
```

#### pk-inspect

Shows the component hashes and binding of a serialized public key without
validating the binding, so a corrupted key can still be examined.

```bash
k-mosaic-cli kem pk-inspect --public-key my-keypair.json.pub
```

### Signature Operations

#### keygen

```bash
k-mosaic-cli sign keygen --level 128 --output my-signkeys.json --verbose
```

#### sign

`--public-key` is optional; when given it is checked against the secret key.

```bash
k-mosaic-cli sign sign --secret-key my-signkeys.json --public-key my-signkeys.json.pub --message "I approve this transaction" --output approval.sig.json
k-mosaic-cli sign sign --secret-key my-signkeys.json --input document.txt --output document.sig.json
echo "piped message" | k-mosaic-cli sign sign --secret-key my-signkeys.json --output piped.sig.json
```

#### verify

The message must be supplied with `--message` or `--input`; the copy stored in
the signature file is informational only. Exit code 0 means valid, 1 invalid,
2 error.

```bash
k-mosaic-cli sign verify --public-key my-signkeys.json.pub --signature approval.sig.json --message "I approve this transaction"
k-mosaic-cli sign verify --public-key my-signkeys.json.pub --signature document.sig.json --input document.txt --verbose

# A different message is rejected with exit code 1
set +e
k-mosaic-cli sign verify --public-key my-signkeys.json.pub --signature approval.sig.json --message "I do not approve" > verify.json
status=$?
set -e
test "$status" -eq 1 && grep -q '"valid": false' verify.json && echo "wrong message rejected"
```

### Benchmarking

```bash
k-mosaic-cli benchmark --level 128 --iterations 2
```

Sample output (4-core x86-64 container):

```text
kMOSAIC Benchmark Results
Security Level: MOS-128
Iterations: 2

Key Encapsulation Mechanism (KEM)
  KeyGen:      64.963897ms (avg)
  Encapsulate: 2.70019ms (avg)
  Decapsulate: 6.771502ms (avg)
  Encrypt:     2.560988ms (avg)
  Decrypt:     6.610278ms (avg)

Digital Signatures
  KeyGen:      189.768978ms (avg)
  Sign:        19.621093ms (avg)
  Verify:      5.455732ms (avg)

Benchmark complete!
```

## Exit Codes

| Code | Meaning                                                                                                       |
| ---- | ------------------------------------------------------------------------------------------------------------- |
| 0    | Success; for `sign verify`, the signature is valid                                                            |
| 1    | A well-formed signature that does not verify, or decryption failed authentication                             |
| 2    | Usage error, unreadable or malformed input (including a truncated signature or ciphertext), or any other runtime error |

`kem decapsulate` cannot detect tampering: a modified ciphertext yields an
unrelated shared secret with exit code 0 (implicit rejection). Use
`kem encrypt` / `kem decrypt`, whose AES-GCM tag fails with exit code 1,
when you need to know.

```bash
set +e
k-mosaic-cli kem encrypt --message "no key given" > /dev/null 2>&1; echo "missing option -> exit $?"
k-mosaic-cli kem keygen --level 512 > /dev/null 2>&1;           echo "bad level -> exit $?"
set -e
```

## Workflows

### Encrypted message between two people

```bash
# Bob generates his key pair and shares ONLY bob-keys.json.pub
k-mosaic-cli kem keygen --level 128 --output bob-keys.json

# Alice encrypts for Bob with the .pub file
k-mosaic-cli kem encrypt --public-key bob-keys.json.pub --message "Hi Bob! This is private." --output for-bob.json

# Bob decrypts with his key pair file and his public key
k-mosaic-cli kem decrypt --secret-key bob-keys.json --public-key bob-keys.json.pub --ciphertext for-bob.json
```

### Signed document

```bash
# Alice generates signing keys and shares alice-sign.json.pub
k-mosaic-cli sign keygen --level 128 --output alice-sign.json
printf 'Terms: payable on delivery.\n' > contract.txt
k-mosaic-cli sign sign --secret-key alice-sign.json --input contract.txt --output contract.sig.json

# Bob verifies with Alice's public key, the document and the signature
if k-mosaic-cli sign verify --public-key alice-sign.json.pub --input contract.txt --signature contract.sig.json; then
  echo "valid: the document is from Alice and unmodified"
else
  echo "INVALID: do not trust this document"; exit 1
fi
```

### Key exchange with MOS-256

```bash
k-mosaic-cli kem keygen --level 256 --output alice-256.json
k-mosaic-cli kem encapsulate --public-key alice-256.json.pub --format hex --output encap-256.json
k-mosaic-cli kem decapsulate --secret-key alice-256.json --public-key alice-256.json.pub --ciphertext encap-256.json --format hex --output decap-256.json
test "$(jq -r .shared_secret encap-256.json)" = "$(jq -r .shared_secret decap-256.json)" && echo "MOS-256 shared secrets match"
```

Keys, ciphertexts and signatures of different levels do not mix; the CLI
reports a level mismatch instead of attempting the operation.

## File Formats

All binary fields are base64 by default (`--format hex` switches to hex). The
decoder accepts either encoding when reading. Secret keys are always base64.

Key pair file (`FILE`):

```json
{
  "security_level": "MOS-128",
  "public_key": "a01PUwQBAQA...",
  "secret_key": "a01PUwQCAQA...",
  "created_at": "2026-10-22T10:30:00Z"
}
```

Public key file (`FILE.pub`):

```json
{
  "security_level": "MOS-128",
  "public_key": "a01PUwQBAQA...",
  "created_at": "2026-10-22T10:30:00Z"
}
```

Encrypted message, encapsulation result and signature files:

```json
{ "ciphertext": "a01PUwQEAQA..." }
```

```json
{ "ciphertext": "a01PUwQDAQA...", "shared_secret": "..." }
```

```json
{ "message": "SSBhcHByb3Zl...", "signature": "a01PUwQHAQA..." }
```

Every decoded object begins with the bytes `kMOS`, the format version (4), an
object type byte and the level byte; `base64("kMOS\x04...")` is why public
keys start with `a01PUwQ`.

## Sizes and Timings

Serialized sizes before base64 encoding (JSON files are about 4/3 larger):

| Object               | MOS-128 | MOS-256 |
| -------------------- | ------- | ------- |
| KEM public key       | 351 KB  | 523 KB  |
| KEM secret key       | 49 KB   | 74 KB   |
| KEM ciphertext       | 15.6 KB | 16.2 KB |
| Signature public key | 535 KB  | 1.10 MB |
| Signature secret key | 1.0 MB  | 1.2 MB  |
| Signature            | 20.6 KB | 54.8 KB |

Typical timings on a 4-core x86-64 container: KEM key generation 56–113 ms,
encapsulation about 2 ms, decapsulation about 7 ms; signature key generation
0.19–0.34 s, signing 22–56 ms, verification 4–6 ms. Loading a signing key
costs 21–84 ms because the lattice matrix and the UOV secret key are
re-expanded from their seeds.

## Security Considerations

- Protect `FILE` (the key pair): it is created with mode 0600 through a
  private temporary file and an atomic rename (an existing file or symlink at
  that path is replaced, never written through); back it up encrypted; never
  commit it to version control; never send it over an unencrypted channel.
  Share only `FILE.pub`.
- The output of `kem encapsulate` contains the shared secret as well as the
  ciphertext. Send the recipient only the `ciphertext` field, never the whole
  file.
- Decryption and signing need the secret key; verification and encryption need
  only the public key.
- The CLI refuses to use a secret key with a public key it does not belong to.
- Always pass the message you actually received to `sign verify`; do not rely
  on the `message` field inside the signature file.
- Rotate keys periodically and immediately on suspected compromise:

```sh
k-mosaic-cli kem keygen --level 128 --output keys-2027.json
shred -u keys-2026.json      # Linux; use `rm -P` or `srm` on macOS
```

What kMOSAIC provides, and what it does not, is described in
[SECURITY_ASSESSMENT.md](SECURITY_ASSESSMENT.md): against cryptanalysis the
KEM rests on unstructured LWE and quasi-cyclic syndrome decoding (both must
break), signatures on unstructured lattices, multivariate quadratics and hash
functions (all three must break). This gives no protection against
implementation or side-channel attacks beyond the library's own code (the
constant-time argument has stated limits, §7.3 of the assessment), and no
review outside this repository has taken place. Do not use it for anything
that matters.

## Troubleshooting and FAQ

**"command not found"**: the binary is not on your PATH; run it as
`./k-mosaic-cli` or add its directory to PATH.

**"invalid key: wire: bad header"**: the file is not a 4.x object (an older
key file, a signing key passed where a KEM key is expected, or the wrong field
extracted). Regenerate the key with this version.

**"public key does not match secret key"**: the `--public-key` and
`--secret-key` files come from different key pairs.

**"--message or --input is required for verification"**: `sign verify` never
trusts the message stored in the signature file; pass the message explicitly.

**Can I use one key pair for both encryption and signing?** No. `kem keygen`
and `sign keygen` produce different objects for different schemes.

**How do I extract a public key from an old key pair file without the `.pub`?**

```sh
jq '{security_level, public_key, created_at}' keys.json > keys.json.pub
```

**I lost my secret key. Can I recover it from the public key?** No. Generate a
new pair and distribute the new `.pub` file.

**Why are the keys so large?** The lattice components are deliberately
unstructured (plain matrices rather than polynomial rings) and the signature
carries three component signatures. See the sizes table above.

## License

MIT License - See [LICENSE](LICENSE) file for details.
