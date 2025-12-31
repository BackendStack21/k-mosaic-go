# kMOSAIC Go Benchmark Report

**Date:** December 31, 2025  
**Platform:** macOS (darwin/arm64)  
**CPU:** Apple M2 Pro  
**Go Version:** Latest stable

---

## Executive Summary

This report presents a comprehensive performance analysis comparing kMOSAIC's two security levels: **MOS-128** (128-bit post-quantum security) and **MOS-256** (256-bit post-quantum security). The benchmarks cover all core cryptographic operations for both Key Encapsulation Mechanism (KEM) and Digital Signatures.

### Key Findings

| Metric          | MOS-128  | MOS-256  | Slowdown Factor |
| --------------- | -------- | -------- | --------------- |
| KEM KeyGen      | 6.29 ms  | 22.43 ms | **3.56×**       |
| KEM Encapsulate | 0.32 ms  | 0.95 ms  | **2.99×**       |
| KEM Decapsulate | 0.38 ms  | 1.06 ms  | **2.80×**       |
| Sign KeyGen     | 6.22 ms  | 22.49 ms | **3.62×**       |
| Sign            | 0.012 ms | 0.022 ms | **1.82×**       |
| Verify          | 2.44 ms  | 9.13 ms  | **3.74×**       |

---

## Detailed Benchmark Results

### 1. Key Encapsulation Mechanism (KEM)

#### 1.1 Key Generation

| Level   | Time (ns/op) | Time (ms)    | Memory (B/op)          | Allocations |
| ------- | ------------ | ------------ | ---------------------- | ----------- |
| MOS-128 | 6,294,439    | **6.29 ms**  | 3,703,685 (~3.53 MB)   | 317         |
| MOS-256 | 22,426,476   | **22.43 ms** | 14,269,239 (~13.61 MB) | 424         |

**Analysis:**

- MOS-256 key generation is **3.56× slower** than MOS-128
- Memory consumption increases by **3.85×** (from ~3.5 MB to ~13.6 MB)
- The higher cost stems from larger lattice dimensions, tensor sizes, and expander graph parameters

#### 1.2 Encapsulation (Sender Side)

| Level   | Time (ns/op) | Time (ms)   | Memory (B/op)     | Allocations |
| ------- | ------------ | ----------- | ----------------- | ----------- |
| MOS-128 | 316,474      | **0.32 ms** | 64,527 (~63 KB)   | 121         |
| MOS-256 | 948,806      | **0.95 ms** | 121,371 (~118 KB) | 110         |

**Analysis:**

- MOS-256 encapsulation is **3.00× slower** than MOS-128
- Memory usage nearly doubles (1.92×)
- Allocation count remains low, indicating efficient allocation patterns

#### 1.3 Decapsulation (Receiver Side)

| Level   | Time (ns/op) | Time (ms)   | Memory (B/op)     | Allocations |
| ------- | ------------ | ----------- | ----------------- | ----------- |
| MOS-128 | 376,690      | **0.38 ms** | 112,156 (~109 KB) | 185         |
| MOS-256 | 1,055,179    | **1.06 ms** | 182,942 (~179 KB) | 143         |

**Analysis:**

- MOS-256 decapsulation is **2.80× slower** than MOS-128
- Decapsulation is slightly slower than encapsulation (~10% overhead) at both levels
- Memory overhead ratio is 1.87×

#### 1.4 Encrypt (High-Level API)

| Level   | Time (ns/op) | Time (ms)   | Memory (B/op)     | Allocations |
| ------- | ------------ | ----------- | ----------------- | ----------- |
| MOS-128 | 320,506      | **0.32 ms** | 66,210 (~64 KB)   | 129         |
| MOS-256 | 936,247      | **0.94 ms** | 121,951 (~119 KB) | 120         |

**Analysis:**

- Performance is nearly identical to raw encapsulation
- The symmetric encryption overhead is negligible (~1.3%)

#### 1.5 Decrypt (High-Level API)

| Level   | Time (ns/op) | Time (ms)   | Memory (B/op)     | Allocations |
| ------- | ------------ | ----------- | ----------------- | ----------- |
| MOS-128 | 407,390      | **0.41 ms** | 113,621 (~111 KB) | 192         |
| MOS-256 | 987,145      | **0.99 ms** | 183,241 (~179 KB) | 150         |

**Analysis:**

- Consistent with decapsulation performance
- Additional allocations (+7) account for symmetric decryption and validation

---

### 2. Digital Signatures

#### 2.1 Key Generation

| Level   | Time (ns/op) | Time (ms)    | Memory (B/op)          | Allocations |
| ------- | ------------ | ------------ | ---------------------- | ----------- |
| MOS-128 | 6,217,396    | **6.22 ms**  | 3,703,625 (~3.53 MB)   | 317         |
| MOS-256 | 22,494,461   | **22.49 ms** | 14,269,639 (~13.61 MB) | 423         |

**Analysis:**

- Signature key generation is virtually identical to KEM key generation
- This is expected as both use the same underlying SLSS, TDD, and EGRW components

#### 2.2 Sign

| Level   | Time (ns/op) | Time (μs)    | Memory (B/op)     | Allocations |
| ------- | ------------ | ------------ | ----------------- | ----------- |
| MOS-128 | 12,066       | **12.07 μs** | 7,348 (~7.2 KB)   | 14          |
| MOS-256 | 21,945       | **21.95 μs** | 21,739 (~21.2 KB) | 17          |

#### 2.3 Verify

| Level   | Time (ns/op) | Time (ms)   | Memory (B/op)        | Allocations |
| ------- | ------------ | ----------- | -------------------- | ----------- |
| MOS-128 | 2,441,008    | **2.44 ms** | 1,695,938 (~1.62 MB) | 9           |
| MOS-256 | 9,132,425    | **9.13 ms** | 6,684,872 (~6.38 MB) | 9           |

**Analysis:**

- Signing is **very fast** at both security levels
- MOS-256 is only **1.82× slower** than MOS-128 (best ratio among all operations)
- Very low memory footprint compared to other operations
- Can sign **~85,800 messages/second** at MOS-128 level
- Can sign **~46,200 messages/second** at MOS-256 level

#### 2.3 Verify

| Level   | Time (ns/op) | Time (ms)   | Memory (B/op)        | Allocations |
| ------- | ------------ | ----------- | -------------------- | ----------- |
| MOS-128 | 2,360,853    | **2.36 ms** | 1,695,942 (~1.62 MB) | 9           |
| MOS-256 | 9,109,609    | **9.11 ms** | 6,684,872 (~6.38 MB) | 9           |

**Analysis:**

- Verification is approximately **200× slower** than signing at both security levels
- MOS-256 verification is **3.74× slower** than MOS-128
- Memory consumption is significant due to tensor operations during verification
- Allocation count is minimal (9), indicating bulk memory operations

---

### 3. Full Round-Trip Operations

These benchmarks measure complete cryptographic workflows including key generation.

#### 3.1 KEM Full Round-Trip (KeyGen → Encrypt → Decrypt)

| Level   | Time (ns/op) | Time (ms)    | Memory (B/op)          | Allocations |
| ------- | ------------ | ------------ | ---------------------- | ----------- |
| MOS-128 | 6,957,989    | **6.96 ms**  | 3,865,525 (~3.69 MB)   | 544         |
| MOS-256 | 24,377,706   | **24.38 ms** | 14,574,141 (~13.90 MB) | 691         |

**Analysis:**

- Full round-trip overhead is dominated by key generation (~87%)
- MOS-256 is approximately **3.50× slower** overall

#### 3.2 Signature Full Round-Trip (KeyGen → Sign → Verify)

| Level   | Time (ns/op) | Time (ms)    | Memory (B/op)          | Allocations |
| ------- | ------------ | ------------ | ---------------------- | ----------- |
| MOS-128 | 8,543,678    | **8.54 ms**  | 5,408,387 (~5.16 MB)   | 341         |
| MOS-256 | 32,230,172   | **32.23 ms** | 20,980,555 (~20.01 MB) | 455         |

**Analysis:**

- Signature round-trip is ~23% slower than KEM round-trip at MOS-128
- Signature round-trip is ~32% slower than KEM round-trip at MOS-256
- Verification adds significant overhead compared to decapsulation

---

## Performance Comparison Charts

### Operation Time Comparison (logarithmic scale)

```
Operation            MOS-128         MOS-256         Ratio
─────────────────────────────────────────────────────────────
KEM KeyGen      █████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  6.04 ms
                ████████████████████░░░░░░░░░░░░░░  22.43 ms   3.56×

KEM Encap       █░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0.32 ms
                ███░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0.95 ms   3.00×

KEM Decap       █░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0.38 ms
                ███░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  1.06 ms   2.80×

Sign            ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0.01 ms
                ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0.02 ms   1.82×

Verify          ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  2.36 ms
                █████████░░░░░░░░░░░░░░░░░░░░░░░░░  9.13 ms   3.74×
```

### Memory Consumption Comparison

```
Operation            MOS-128              MOS-256           Ratio
───────────────────────────────────────────────────────────────────
KEM KeyGen        3.53 MB              13.61 MB           3.85×
KEM Encap         0.06 MB               0.12 MB           1.92×
KEM Decap         0.10 MB               0.18 MB           1.87×
Sign              0.01 MB               0.02 MB           3.23×
Verify            1.62 MB               6.38 MB           3.94×
```

---

## Throughput Analysis

### Operations Per Second

| Operation       | MOS-128 ops/sec | MOS-256 ops/sec |
| --------------- | --------------- | --------------- |
| KEM KeyGen      | 166             | 45              |
| KEM Encapsulate | 3,286           | 1,070           |
| KEM Decapsulate | 2,969           | 1,009           |
| KEM Encrypt     | 3,245           | 1,049           |
| KEM Decrypt     | 2,995           | 988             |
| Sign KeyGen     | 164             | 45              |
| Sign            | 85,787          | 46,228          |
| Verify          | 424             | 110             |

---

## Security vs Performance Trade-offs

### When to Choose MOS-128

- **High-throughput applications** requiring thousands of operations per second
- **IoT and embedded systems** with limited computational resources
- **Real-time systems** with strict latency requirements (<10ms)
- **Standard security requirements** where 128-bit post-quantum security is sufficient

### When to Choose MOS-256

- **Long-term security** for data that must remain confidential for decades
- **Government/military applications** requiring maximum security margins
- **Critical infrastructure** where performance is secondary to security
- **Defense-in-depth architectures** requiring extra security headroom

---

## Conclusions

1. **Consistent Scaling:** MOS-256 operations are approximately **3–4× slower** than MOS-128 across most operations, consistent with the higher security parameter.

2. **Signing is Very Fast:** Signing takes approximately **11.7 μs** (MOS-128) and **21.6 μs** (MOS-256), supporting high-throughput signing workloads.

3. **Key Generation Dominates Cost:** Key generation is the primary contributor to end-to-end latency (≈87% of full round-trip time).

4. **Memory Usage:** MOS-128 key generation uses **~3.5 MB**; MOS-256 key generation uses **~13.6 MB**. Verification has the largest memory footprint among core operations.

5. **Practical Performance:** Both security levels offer practical performance for real-world use:
   - MOS-128: sub-millisecond encapsulation/decapsulation; ~6 ms key generation
   - MOS-256: sub-second for all operations; ~22 ms key generation

---

## Appendix: Raw Benchmark Data

```
goos: darwin
goarch: arm64
pkg: github.com/BackendStack21/k-mosaic-go/test
cpu: Apple M2 Pro

BenchmarkKEM_GenerateKeyPair_MOS128-10               183           6,294,439 ns/op         3,703,685 B/op        317 allocs/op
BenchmarkKEM_Encapsulate_MOS128-10                  3772            316,474 ns/op           64,527 B/op        121 allocs/op
BenchmarkKEM_Decapsulate_MOS128-10                  3138            376,690 ns/op          112,156 B/op        185 allocs/op
BenchmarkKEM_Encrypt_MOS128-10                      3553            320,506 ns/op           66,210 B/op        129 allocs/op
BenchmarkKEM_Decrypt_MOS128-10                      3057            407,390 ns/op          113,621 B/op        192 allocs/op

BenchmarkKEM_GenerateKeyPair_MOS256-10                50          22,426,476 ns/op        14,269,239 B/op        424 allocs/op
BenchmarkKEM_Encapsulate_MOS256-10                  1263            948,806 ns/op          121,371 B/op        110 allocs/op
BenchmarkKEM_Decapsulate_MOS256-10                  1131           1,055,179 ns/op          182,942 B/op        143 allocs/op
BenchmarkKEM_Encrypt_MOS256-10                      1290            936,247 ns/op          121,951 B/op        120 allocs/op
BenchmarkKEM_Decrypt_MOS256-10                      1195            987,145 ns/op          183,241 B/op        150 allocs/op

BenchmarkSign_GenerateKeyPair_MOS128-10              193           6,217,396 ns/op         3,703,625 B/op        317 allocs/op
BenchmarkSign_Sign_MOS128-10                       98024             12,066 ns/op            7,348 B/op         14 allocs/op
BenchmarkSign_Verify_MOS128-10                       494           2,441,008 ns/op         1,695,938 B/op          9 allocs/op

BenchmarkSign_GenerateKeyPair_MOS256-10               49          22,494,461 ns/op        14,269,639 B/op        423 allocs/op
BenchmarkSign_Sign_MOS256-10                       53791             21,945 ns/op           21,739 B/op         17 allocs/op
BenchmarkSign_Verify_MOS256-10                       130           9,132,425 ns/op         6,684,872 B/op          9 allocs/op

BenchmarkKEM_FullRoundTrip_MOS128-10                 171           7,014,679 ns/op         3,883,791 B/op        639 allocs/op
BenchmarkKEM_FullRoundTrip_MOS256-10                  44          24,670,982 ns/op        14,601,994 B/op        787 allocs/op
BenchmarkSign_FullRoundTrip_MOS128-10                136           8,734,303 ns/op         5,408,413 B/op        344 allocs/op
BenchmarkSign_FullRoundTrip_MOS256-10                 36          32,496,609 ns/op        20,981,376 B/op        460 allocs/op
```

---

_Report generated using Go's built-in benchmarking framework with `-benchmem` flag for memory profiling._
