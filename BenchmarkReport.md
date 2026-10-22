# kMOSAIC Go Benchmark Report (4.0.0)

**Date:** October 22, 2026
**Platform:** Linux, 4 vCPU Intel Xeon @ 2.80 GHz (shared container; numbers vary by ±30% between runs)
**Go:** 1.24
**Command:** `go test ./kem/ ./sign/ ./problems/... -run '^$' -bench . -benchmem`

Reports for versions before 4.0.0 were deleted: 1.x measured a signature that
was a hash of the secret key, and 3.0 carried a ciphertext field that leaked
the KEM shares. Neither described a working scheme.

## Composite operations

| Operation                   | MOS-128 | MOS-256 | Memory (128 / 256)  |
| --------------------------- | ------- | ------- | ------------------- |
| KEM KeyGen                  | 16.5 ms | 33.5 ms | 6.6 MB / 11.6 MB    |
| KEM Encapsulate             | 0.81 ms | 0.80 ms | 152 KB / 159 KB     |
| KEM Decapsulate             | 2.2 ms  | 1.4 ms  | 283 KB / 295 KB     |
| KEM DeserializePublicKey    | 10.6 ms | 14.0 ms | 3.2 MB / 6.5 MB     |
| Sign KeyGen                 | 164 ms  | 299 ms  | 17.6 MB / 38.4 MB   |
| Sign                        | 17.9 ms | 47.2 ms | 328 KB / 815 KB     |
| Verify                      | 3.3 ms  | 4.4 ms  | 28 KB / 49 KB       |
| Sign DeserializePublicKey   | 16.8 ms | 33.8 ms | 10.0 MB / 22.5 MB   |
| Sign DeserializeSecretKey   | 21.1 ms | 44.9 ms | 10.9 MB / 24.5 MB   |

Memory is bytes allocated per operation; deserialization expands the public
matrices, which dominate the in-memory size of the keys.

## Component operations

| Component / operation            | MOS-128 (level-1/3 set) | MOS-256 (level-5 set) |
| -------------------------------- | ----------------------- | --------------------- |
| SLSS (LWE) KeyGen                | 13.7 ms                 | 33.4 ms               |
| SLSS Encrypt / Decrypt           | 0.15 / 0.18 ms          | 0.38 / 0.24 ms        |
| SLSS ExpandMatrix                | 3.4 ms                  | 6.9 ms                |
| QCSD (HQC-256) KeyGen            | 0.20 ms                 | same set              |
| QCSD Encrypt / Decrypt           | 0.37 / 0.28 ms          | same set              |
| QCSD ring multiply (fused / old) | 0.15 / 1.26 ms          | same set              |
| QCSD RS decode (0 / 29 errors)   | 88 / 45 µs (noise)      | same set              |
| Lattice signature KeyGen         | 120 ms                  | 214 ms                |
| Lattice Sign / Verify            | 5.3 / 2.3 ms            | 7.5 / 4.0 ms          |
| UOV KeyGen                       | 6.7 ms (uov-Ip)         | 71 ms (uov-V)         |
| UOV Sign / Verify                | 0.52 / 0.19 ms          | 2.0 / 0.84 ms         |
| UOV DeserializeSecretKey         | 3.0 ms                  | 51 ms                 |
| SLH-DSA KeyGen                   | 0.87 ms (128f)          | 2.4 ms (256f)         |
| SLH-DSA Sign (parallel / 1 core) | 14.5 / 53.6 ms          | 42.9 / 170 ms         |
| SLH-DSA Verify                   | 3.0 ms                  | 4.5 ms                |

The Reed-Solomon decoder is constant-time by construction; the 0-error and
29-error figures differ only by benchmark noise on this shared machine (a
dedicated measurement shows 42.0–42.4 µs for 0 to 90 errors).

## Serialized sizes

| Object               | MOS-128 | MOS-256 |
| -------------------- | ------- | ------- |
| KEM public key       | 351,381 B | 523,413 B |
| KEM secret key       | 49,494 B  | 74,070 B  |
| KEM ciphertext       | 15,637 B  | 16,165 B  |
| Signature public key | 535,223 B | 1,102,511 B |
| Signature secret key | 999,775 B | 1,221,023 B |
| Signature            | 20,577 B  | 54,795 B  |

## Where the time goes

- **Composite Sign** is bounded by SLH-DSA (about 128k / 420k SHAKE256 calls),
  which runs its hypertree layers and FORS trees in parallel; on one core it
  takes 54 / 170 ms.
- **Composite Verify** is the sum of the three verifications plus one 64-byte
  SHAKE over the message; public-key hashes are cached in the key structs.
- **KEM Encapsulate / Decapsulate** are dominated by the code component's
  sparse ring multiplications (fused window multiply, 149 positions over
  57,637 bits).
- **Key generation** is dominated by the lattice signature's dense product
  `A·S1` (500M–940M multiply-adds in pure Go, no SIMD) and, for the KEM, by
  expanding the LWE matrix.

## Raw data

```text
BenchmarkMOS128/KeyGen-4                   5    16522790 ns/op   6584449 B/op   1111 allocs/op   (kem)
BenchmarkMOS128/Encapsulate-4              5      813226 ns/op    151756 B/op     55 allocs/op
BenchmarkMOS128/Decapsulate-4              5     2202555 ns/op    283401 B/op     88 allocs/op
BenchmarkMOS128/DeserializePublicKey-4     5    10589512 ns/op   3187395 B/op     41 allocs/op
BenchmarkMOS256/KeyGen-4                   5    33476493 ns/op  11625228 B/op   1109 allocs/op
BenchmarkMOS256/Encapsulate-4              5      797788 ns/op    159262 B/op     56 allocs/op
BenchmarkMOS256/Decapsulate-4              5     1388781 ns/op    294657 B/op     88 allocs/op
BenchmarkMOS256/DeserializePublicKey-4     5    13958448 ns/op   6531862 B/op     40 allocs/op
BenchmarkMOS128/KeyGen-4                   5   164059075 ns/op  17599328 B/op    131 allocs/op   (sign)
BenchmarkMOS128/Sign-4                     5    17859818 ns/op    328305 B/op    100 allocs/op
BenchmarkMOS128/Verify-4                   5     3335856 ns/op     27502 B/op     31 allocs/op
BenchmarkMOS128/DeserializePublicKey-4     5    16845405 ns/op  10038387 B/op     47 allocs/op
BenchmarkMOS128/DeserializeSecretKey-4     5    21094781 ns/op  10917435 B/op     54 allocs/op
BenchmarkMOS256/KeyGen-4                   5   299385766 ns/op  38437961 B/op    127 allocs/op
BenchmarkMOS256/Sign-4                     5    47187474 ns/op    815323 B/op     84 allocs/op
BenchmarkMOS256/Verify-4                   5     4429632 ns/op     48580 B/op     33 allocs/op
BenchmarkMOS256/DeserializePublicKey-4     5    33760795 ns/op  22531817 B/op     49 allocs/op
BenchmarkMOS256/DeserializeSecretKey-4     5    44889826 ns/op  24483464 B/op     53 allocs/op
```
