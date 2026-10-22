# Contributing

Contributions are welcome, with one rule above all others: **a change to
anything cryptographic must come with evidence**. A new sampler needs a
uniformity test; a new arithmetic path needs equality with a reference and,
if it touches secret data, an interleaved timing test; a parameter change
needs the estimator output (`docs/estimator/`). The assessment
(`SECURITY_ASSESSMENT.md`) records what has been verified and how; keep it
true.

## Workflow

```sh
make check        # gofmt, go vet, go test ./...
make test-race    # race detector on every package
make test-386     # vet and tests on a 32-bit target
make lint         # golangci-lint (pinned version, see Makefile)
go test ./test/ -run TestDocumentationSnippets   # every README/CLI.md go and bash block
```

CI (`.github/workflows/ci.yml`) runs gofmt, lint, vet on amd64/386/arm, the
tests, the race detector on the cryptographic packages, 32-bit tests and a
short fuzzing pass of every deserializer. A pull request must keep all of it
green.

## Ground rules

- No dependencies outside the Go standard library.
- Every serialized object is self-describing (see `internal/wire`); a change
  to any encoding is a format version bump and must be stated in
  `CHANGELOG.md`.
- Keys and ciphertexts derived from a seed are pinned by known-answer
  digests (composite KEM and signature keys in `kem/kat_test.go` and
  `sign/kat_test.go`; components in their own packages). If a change
  legitimately alters them, update the digests in the same commit and say
  why in the commit message.
- Secret data must not reach a branch, a loop bound, a memory address or a
  shift amount. If you cannot avoid it, document it in the package comment
  and in the assessment's "still open" list rather than hiding it.
- Do not add claims to the documentation that the tests do not enforce.
- Commit messages describe the change and its evidence; the first line is
  under 72 characters.

## Reporting security issues

See `SECURITY.md`.
