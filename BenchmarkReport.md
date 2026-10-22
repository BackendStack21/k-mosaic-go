# kMOSAIC Go Benchmark Report (4.1.0)

**Date:** October 22, 2026
**Platform:** Linux, 4 vCPU Intel Xeon @ 2.80 GHz (shared container; numbers vary by ±30% between runs)
**Go:** 1.24
**Command:** `go test ./kem/ ./sign/ ./problems/... -run '^$' -bench . -benchmem -benchtime=5x`

Reports for versions before 4.0.0 were deleted: 1.x measured a signature that
was a hash of the secret key, and 3.0 carried a ciphertext field that leaked
the KEM shares. Neither described a working scheme. The 4.1.0 numbers differ
from 4.0.0 where the sparse-secret samplers and products were made
constant-time (SECURITY_ASSESSMENT.md §6.2): KEM key generation 16.5 / 33.5
→ 51 / 99 ms, encapsulation 0.8 / 0.8 → 1.5 / 2.2 ms, decapsulation
2.2 / 1.4 → 2.3 / 2.4 ms. Signatures are unchanged within noise.

## Composite operations

| Operation                   | MOS-128 | MOS-256 | Memory (128 / 256)  |
| --------------------------- | ------- | ------- | ------------------- |
| KEM KeyGen                  | 51 ms   | 99 ms   | 8.8 MB / 15.0 MB    |
| KEM Encapsulate             | 1.5 ms  | 2.2 ms  | 172 KB / 190 KB     |
| KEM Decapsulate             | 2.3 ms  | 2.4 ms  | 304 KB / 326 KB     |
| KEM DeserializePublicKey    | 9.4 ms  | 14.3 ms | 3.2 MB / 6.5 MB     |
| Sign KeyGen                 | 196 ms  | 365 ms  | 17.6 MB / 38.4 MB   |
| Sign                        | 21.7 ms | 50.4 ms | 328 KB / 820 KB     |
| Verify                      | 3.7 ms  | 4.4 ms  | 27 KB / 44 KB       |
| Sign DeserializePublicKey   | 21.7 ms | 45.1 ms | 10.0 MB / 22.5 MB   |
| Sign DeserializeSecretKey   | 19.7 ms | 57.7 ms | 10.9 MB / 24.5 MB   |

Memory is bytes allocated per operation; deserialization expands the public
matrices, which dominate the in-memory size of the keys.

## Component operations

| Component / operation            | MOS-128 (level-1 set)   | MOS-256 (level-5 set) |
| -------------------------------- | ----------------------- | --------------------- |
| SLSS (LWE) KeyGen                | 48 ms                   | 75 ms                 |
| SLSS Encrypt / Decrypt           | 0.69 / 0.09 ms          | 1.50 / 0.13 ms        |
| SLSS ExpandMatrix                | 3.7 ms                  | 6.1 ms                |
| QCSD (HQC-256) KeyGen            | 0.47 ms                 | same set              |
| QCSD Encrypt / Decrypt           | 0.86 / 0.30 ms          | same set              |
| QCSD ring multiply (fused / old) | 0.14 / 1.27 ms          | same set              |
| QCSD RS decode (0 … 90 errors)   | 44.0–45.0 µs (flat)     | same set              |
| Lattice signature KeyGen         | 155 ms                  | 280 ms                |
| Lattice Sign / Verify            | 5.5 / 1.6 ms            | 8.7 / 3.4 ms          |
| UOV KeyGen                       | 4.5 ms (uov-Ip)         | 68 ms (uov-V)         |
| UOV Sign / Verify                | 0.64 / 0.10 ms          | 2.0 / 0.95 ms         |
| UOV DeserializeSecretKey         | 3.4 ms                  | 50 ms                 |
| SLH-DSA KeyGen                   | 0.90 ms (128f)          | 2.5 ms (256f)         |
| SLH-DSA Sign (parallel / 1 core) | 16.9 / 49.7 ms          | 43.2 / 172 ms         |
| SLH-DSA Verify                   | 3.0 ms                  | 6.4 ms                |

The Reed-Solomon figure comes from `TestReedSolomonTimingFlat`, which
measures the eleven error counts 0…90 interleaved (max/min ratio 1.021 on
this run). The sequential `BenchmarkRSDecode` sub-benchmarks drift with the
background load of the shared machine and should not be read as a timing
difference: the decoder has a fixed number of iterations and no
data-dependent branch.

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

- **KEM KeyGen** is now the dense product `T = A·S` over every coefficient
  (151M / 340M multiply-adds, register-blocked, split across cores) plus the
  sort-based constant-time sampling of 256 secret columns. The 4.0 version
  gathered only the 192 / 288 non-zero rows per column and leaked their
  positions through the cache.
- **KEM Encapsulate / Decapsulate** are dominated by the dense `Aᵀ·r`
  product (0.69 / 1.5 ms) and the code component's sparse ring
  multiplications (fused window multiply, 149 positions over 57,637 bits).
  Decapsulation runs both decryptions and a full re-encryption.
- **Composite Sign** is bounded by SLH-DSA (about 128k / 420k SHAKE256
  calls), which runs its hypertree layers and FORS trees in parallel; on one
  core it takes 50 / 172 ms.
- **Composite Verify** is the sum of the three verifications plus one 64-byte
  SHAKE over the message; public-key hashes are cached in the key structs.
- **Signature key generation** is dominated by the lattice signature's dense
  product `A·S1` (500M–940M multiply-adds in pure Go, no SIMD).

## Raw data

```text
BenchmarkMOS128/KeyGen-4                   5    51446816 ns/op   8849024 B/op   1369 allocs/op   (kem)
BenchmarkMOS128/Encapsulate-4              5     1478666 ns/op    172289 B/op     61 allocs/op
BenchmarkMOS128/Decapsulate-4              5     2322330 ns/op    304344 B/op     95 allocs/op
BenchmarkMOS128/DeserializePublicKey-4     5     9398701 ns/op   3186384 B/op     40 allocs/op
BenchmarkMOS256/KeyGen-4                   5    99251440 ns/op  14970116 B/op   1363 allocs/op
BenchmarkMOS256/Encapsulate-4              5     2183883 ns/op    190132 B/op     60 allocs/op
BenchmarkMOS256/Decapsulate-4              5     2388831 ns/op    325700 B/op     94 allocs/op
BenchmarkMOS256/DeserializePublicKey-4     5    14297123 ns/op   6532713 B/op     41 allocs/op
BenchmarkMOS128/KeyGen-4                   5   196275103 ns/op  17599020 B/op    130 allocs/op   (sign)
BenchmarkMOS128/Sign-4                     5    21661288 ns/op    328241 B/op    100 allocs/op
BenchmarkMOS128/Verify-4                   5     3650087 ns/op     26916 B/op     30 allocs/op
BenchmarkMOS128/DeserializePublicKey-4     5    21720505 ns/op  10039436 B/op     48 allocs/op
BenchmarkMOS128/DeserializeSecretKey-4     5    19686128 ns/op  10917041 B/op     54 allocs/op
BenchmarkMOS256/KeyGen-4                   5   364983465 ns/op  38433577 B/op    125 allocs/op
BenchmarkMOS256/Sign-4                     5    50355249 ns/op    819963 B/op     86 allocs/op
BenchmarkMOS256/Verify-4                   5     4409263 ns/op     43992 B/op     30 allocs/op
BenchmarkMOS256/DeserializePublicKey-4     5    45121230 ns/op  22531478 B/op     48 allocs/op
BenchmarkMOS256/DeserializeSecretKey-4     5    57721928 ns/op  24483982 B/op     54 allocs/op
```
