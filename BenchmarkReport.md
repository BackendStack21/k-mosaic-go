# kMOSAIC Go Benchmark Report (2.0.0)

**Date:** October 22, 2026
**Platform:** Linux, 4 vCPU Intel Xeon @ 2.80 GHz (shared container; numbers vary by ±30% between runs)
**Go:** 1.24
**Command:** `go test ./kem/ ./sign/ ./problems/... -run '^$' -bench . -benchmem -benchtime=5x`

Reports for earlier designs were deleted: 1.x measured a signature that
was a hash of the secret key, and 2.0.0-dev.2 carried a ciphertext field that
leaked the KEM shares. Neither described a working scheme. The 2.0.0-dev.4
and 2.0.0 numbers differ from 2.0.0-dev.3 where secret-dependent operations were made
constant-time (SECURITY_ASSESSMENT.md §6.2 and §7): KEM key generation
16.5 / 33.5 → 56 / 113 ms, encapsulation 0.8 / 0.8 → 2.1 / 2.0 ms,
decapsulation 2.2 / 1.4 → 6.7 / 7.2 ms. Signatures are unchanged within
noise except that loading a MOS-256 signing key takes longer (constant-time
UOV key expansion).

## Composite operations

| Operation                   | MOS-128 | MOS-256 | Memory (128 / 256)  |
| --------------------------- | ------- | ------- | ------------------- |
| KEM KeyGen                  | 56 ms   | 113 ms  | 9.0 MB / 15.1 MB    |
| KEM Encapsulate             | 2.1 ms  | 2.0 ms  | 411 KB / 429 KB     |
| KEM Decapsulate             | 6.7 ms  | 7.2 ms  | 1.4 MB / 1.8 MB     |
| KEM DeserializePublicKey    | 9.1 ms  | 16.5 ms | 3.2 MB / 6.5 MB     |
| Sign KeyGen                 | 186 ms  | 335 ms  | 17.6 MB / 38.5 MB   |
| Sign                        | 22.1 ms | 56.2 ms | 317 KB / 808 KB     |
| Verify                      | 6.4 ms  | 5.6 ms  | 28 KB / 48 KB       |
| Sign DeserializePublicKey   | 23.6 ms | 46.4 ms | 10.0 MB / 22.5 MB   |
| Sign DeserializeSecretKey   | 21.3 ms | 83.8 ms | 10.9 MB / 24.5 MB   |

Memory is bytes allocated per operation; deserialization expands the public
matrices, which dominate the in-memory size of the keys. Verify's code did
not change between 2.0.0-dev.4 (3.7 / 4.4 ms) and this run; the difference is the
shared machine's load.

## Component operations

| Component / operation            | MOS-128 (level-1 set)   | MOS-256 (level-5 set) |
| -------------------------------- | ----------------------- | --------------------- |
| SLSS (LWE) KeyGen                | 48 ms                   | 75 ms                 |
| SLSS Encrypt / Decrypt           | 0.69 / 0.09 ms          | 1.50 / 0.13 ms        |
| SLSS ExpandMatrix                | 3.7 ms                  | 6.1 ms                |
| QCSD (HQC-256) KeyGen            | 1.2 ms                  | same set              |
| QCSD Encrypt / Decrypt           | 2.0 / 0.91 ms           | same set              |
| QCSD oblivious multiply / naive  | 0.73 / 2.05 ms          | same set              |
| QCSD RS decode (0 … 90 errors)   | 44.0–45.0 µs (flat)     | same set              |
| Lattice signature KeyGen         | 155 ms                  | 280 ms                |
| Lattice Sign / Verify            | 5.5 / 1.6 ms            | 8.7 / 3.4 ms          |
| UOV KeyGen                       | 8.6 ms (uov-Ip)         | 172 ms (uov-V)        |
| UOV Sign / Verify                | 0.56 / 0.18 ms          | 4.1 / 1.2 ms          |
| UOV DeserializeSecretKey         | 4.1 ms                  | 59 ms                 |
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
  sort-based constant-time sampling of 256 secret columns. The 2.0.0-dev.3 version
  gathered only the 192 / 288 non-zero rows per column and leaked their
  positions through the cache.
- **KEM Encapsulate / Decapsulate** are dominated by the dense `Aᵀ·r`
  product (0.69 / 1.5 ms) and the code component's memory-oblivious ring
  multiplications (a 10-stage barrel shifter per position, 149 positions
  over 57,637 bits, about 0.7 ms per fused multiply on 4 cores).
  Decapsulation runs both decryptions, a full re-encryption and a SHA3-256
  of the public key.
- **Composite Sign** is bounded by SLH-DSA (about 128k / 420k SHAKE256
  calls), which runs its hypertree layers and FORS trees in parallel; on one
  core it takes 50 / 172 ms.
- **Composite Verify** is the sum of the three verifications plus one 64-byte
  SHAKE over the message; public-key hashes are cached in the key structs.
- **Signature key generation** is dominated by the lattice signature's dense
  product `A·S1` (500M–940M multiply-adds in pure Go, no SIMD).

## Raw data

```text
BenchmarkMOS128/KeyGen-4         	       5	  56428242 ns/op	 8972358 B/op	    1390 allocs/op   (kem)
BenchmarkMOS128/Encapsulate-4    	       5	   2062853 ns/op	  411038 B/op	      84 allocs/op
BenchmarkMOS128/Decapsulate-4    	       5	   6738630 ns/op	 1386926 B/op	     146 allocs/op
BenchmarkMOS128/DeserializePublicKey-4         	       5	   9139581 ns/op	 3186780 B/op	      41 allocs/op
BenchmarkMOS256/KeyGen-4                       	       5	 113234761 ns/op	15095032 B/op	    1390 allocs/op
BenchmarkMOS256/Encapsulate-4                  	       5	   1966712 ns/op	  429300 B/op	      83 allocs/op
BenchmarkMOS256/Decapsulate-4                  	       5	   7224855 ns/op	 1753872 B/op	     149 allocs/op
BenchmarkMOS256/DeserializePublicKey-4         	       5	  16460932 ns/op	 6532579 B/op	      42 allocs/op
BenchmarkMOS128/KeyGen-4         	       5	 186096504 ns/op	17626620 B/op	     131 allocs/op   (sign)
BenchmarkMOS128/Sign-4           	       5	  22095842 ns/op	  317012 B/op	      89 allocs/op
BenchmarkMOS128/Verify-4         	       5	   6421205 ns/op	   27748 B/op	      31 allocs/op
BenchmarkMOS128/DeserializePublicKey-4         	       5	  23557051 ns/op	10039417 B/op	      48 allocs/op
BenchmarkMOS128/DeserializeSecretKey-4         	       5	  21321796 ns/op	10916916 B/op	      53 allocs/op
BenchmarkMOS256/KeyGen-4                       	       5	 334872497 ns/op	38548713 B/op	     127 allocs/op
BenchmarkMOS256/Sign-4                         	       5	  56207180 ns/op	  807844 B/op	      87 allocs/op
BenchmarkMOS256/Verify-4                       	       5	   5649551 ns/op	   48222 B/op	      32 allocs/op
BenchmarkMOS256/DeserializePublicKey-4         	       5	  46382019 ns/op	22532425 B/op	      50 allocs/op
BenchmarkMOS256/DeserializeSecretKey-4         	       5	  83758767 ns/op	24483176 B/op	      53 allocs/op
```
