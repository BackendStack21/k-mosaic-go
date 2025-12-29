# kMOSAIC Go Benchmark Report

**Date:** December 29, 2025  
**Platform:** macOS (darwin/arm64)  
**CPU:** Apple M2 Pro  
**Go Version:** Latest stable

---

## Executive Summary

This report presents a comprehensive performance analysis comparing kMOSAIC's two security levels: **MOS-128** (128-bit post-quantum security) and **MOS-256** (256-bit post-quantum security). The benchmarks cover all core cryptographic operations for both Key Encapsulation Mechanism (KEM) and Digital Signatures.

### Key Findings

| Metric          | MOS-128  | MOS-256  | Slowdown Factor |
| --------------- | -------- | -------- | --------------- |
| KEM KeyGen      | 6.04 ms  | 22.25 ms | **3.68×**       |
| KEM Encapsulate | 0.30 ms  | 0.93 ms  | **3.07×**       |
| KEM Decapsulate | 0.34 ms  | 0.99 ms  | **2.94×**       |
| Sign KeyGen     | 6.11 ms  | 22.31 ms | **3.65×**       |
| Sign            | 0.012 ms | 0.022 ms | **1.86×**       |
| Verify          | 2.36 ms  | 9.11 ms  | **3.86×**       |

---

## Detailed Benchmark Results

### 1. Key Encapsulation Mechanism (KEM)

#### 1.1 Key Generation

| Level   | Time (ns/op) | Time (ms)    | Memory (B/op)          | Allocations |
| ------- | ------------ | ------------ | ---------------------- | ----------- |
| MOS-128 | 6,041,387    | **6.04 ms**  | 3,703,413 (~3.53 MB)   | 314         |
| MOS-256 | 22,250,110   | **22.25 ms** | 14,269,288 (~13.61 MB) | 422         |

**Analysis:**

- MOS-256 key generation is **3.68× slower** than MOS-128
- Memory consumption increases by **3.85×** (from ~3.5 MB to ~13.6 MB)
- The higher cost stems from larger lattice dimensions, tensor sizes, and expander graph parameters

#### 1.2 Encapsulation (Sender Side)

| Level   | Time (ns/op) | Time (ms)   | Memory (B/op)     | Allocations |
| ------- | ------------ | ----------- | ----------------- | ----------- |
| MOS-128 | 304,337      | **0.30 ms** | 63,132 (~62 KB)   | 89          |
| MOS-256 | 934,400      | **0.93 ms** | 121,369 (~118 KB) | 110         |

**Analysis:**

- MOS-256 encapsulation is **3.07× slower** than MOS-128
- Memory usage nearly doubles (1.92×)
- Allocation count remains low, indicating efficient allocation patterns

#### 1.3 Decapsulation (Receiver Side)

| Level   | Time (ns/op) | Time (ms)   | Memory (B/op)     | Allocations |
| ------- | ------------ | ----------- | ----------------- | ----------- |
| MOS-128 | 336,870      | **0.34 ms** | 97,561 (~95 KB)   | 122         |
| MOS-256 | 991,434      | **0.99 ms** | 182,938 (~179 KB) | 143         |

**Analysis:**

- MOS-256 decapsulation is **2.94× slower** than MOS-128
- Decapsulation is slightly slower than encapsulation (~10% overhead) at both levels
- Memory overhead ratio is 1.87×

#### 1.4 Encrypt (High-Level API)

| Level   | Time (ns/op) | Time (ms)   | Memory (B/op)     | Allocations |
| ------- | ------------ | ----------- | ----------------- | ----------- |
| MOS-128 | 308,167      | **0.31 ms** | 63,709 (~62 KB)   | 99          |
| MOS-256 | 953,193      | **0.95 ms** | 121,954 (~119 KB) | 120         |

**Analysis:**

- Performance is nearly identical to raw encapsulation
- The symmetric encryption overhead is negligible (~1.3%)

#### 1.5 Decrypt (High-Level API)

| Level   | Time (ns/op) | Time (ms)   | Memory (B/op)     | Allocations |
| ------- | ------------ | ----------- | ----------------- | ----------- |
| MOS-128 | 333,909      | **0.33 ms** | 97,862 (~96 KB)   | 129         |
| MOS-256 | 1,011,805    | **1.01 ms** | 183,248 (~179 KB) | 150         |

**Analysis:**

- Consistent with decapsulation performance
- Additional allocations (+7) account for symmetric decryption and validation

---

### 2. Digital Signatures

#### 2.1 Key Generation

| Level   | Time (ns/op) | Time (ms)    | Memory (B/op)          | Allocations |
| ------- | ------------ | ------------ | ---------------------- | ----------- |
| MOS-128 | 6,113,639    | **6.11 ms**  | 3,703,573 (~3.53 MB)   | 315         |
| MOS-256 | 22,311,797   | **22.31 ms** | 14,269,156 (~13.61 MB) | 421         |

**Analysis:**

- Signature key generation is virtually identical to KEM key generation
- This is expected as both use the same underlying SLSS, TDD, and EGRW components

#### 2.2 Sign

| Level   | Time (ns/op) | Time (μs)    | Memory (B/op)     | Allocations |
| ------- | ------------ | ------------ | ----------------- | ----------- |
| MOS-128 | 11,657       | **11.66 μs** | 7,348 (~7.2 KB)   | 14          |
| MOS-256 | 21,632       | **21.63 μs** | 23,739 (~23.2 KB) | 17          |

**Analysis:**

- Signing is **very fast** at both security levels
- MOS-256 is only **1.86× slower** than MOS-128 (best ratio among all operations)
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
- MOS-256 verification is **3.86× slower** than MOS-128
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
                ████████████████████░░░░░░░░░░░░░░ 22.25 ms   3.68×

KEM Encap       █░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0.30 ms
                ███░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0.93 ms   3.07×

KEM Decap       █░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0.34 ms
                ███░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0.99 ms   2.94×

Sign            ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0.01 ms
                ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0.02 ms   1.86×

Verify          ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  2.36 ms
                █████████░░░░░░░░░░░░░░░░░░░░░░░░░  9.11 ms   3.86×
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

BenchmarkKEM_GenerateKeyPair_MOS128-10    194    6,041,387 ns/op   3,703,413 B/op   314 allocs/op
BenchmarkKEM_Encapsulate_MOS128-10       3832      304,337 ns/op      63,132 B/op    89 allocs/op
BenchmarkKEM_Decapsulate_MOS128-10       3445      336,870 ns/op      97,561 B/op   122 allocs/op
BenchmarkKEM_Encrypt_MOS128-10           3849      308,167 ns/op      63,709 B/op    99 allocs/op
BenchmarkKEM_Decrypt_MOS128-10           3439      333,909 ns/op      97,862 B/op   129 allocs/op

BenchmarkKEM_GenerateKeyPair_MOS256-10     49   22,250,110 ns/op  14,269,288 B/op   422 allocs/op
BenchmarkKEM_Encapsulate_MOS256-10       1294      934,400 ns/op     121,369 B/op   110 allocs/op
BenchmarkKEM_Decapsulate_MOS256-10       1202      991,434 ns/op     182,938 B/op   143 allocs/op
BenchmarkKEM_Encrypt_MOS256-10           1273      953,193 ns/op     121,954 B/op   120 allocs/op
BenchmarkKEM_Decrypt_MOS256-10           1209    1,011,805 ns/op     183,248 B/op   150 allocs/op

BenchmarkSign_GenerateKeyPair_MOS128-10   195    6,113,639 ns/op   3,703,573 B/op   315 allocs/op
BenchmarkSign_Sign_MOS128-10           102409       11,657 ns/op       7,348 B/op    14 allocs/op
BenchmarkSign_Verify_MOS128-10            507    2,360,853 ns/op   1,695,942 B/op     9 allocs/op

BenchmarkSign_GenerateKeyPair_MOS256-10    49   22,311,797 ns/op  14,269,156 B/op   421 allocs/op
BenchmarkSign_Sign_MOS256-10            55612       21,632 ns/op      23,739 B/op    17 allocs/op
BenchmarkSign_Verify_MOS256-10            130    9,109,609 ns/op   6,684,872 B/op     9 allocs/op

BenchmarkKEM_FullRoundTrip_MOS128-10      174    6,957,989 ns/op   3,865,525 B/op   544 allocs/op
BenchmarkKEM_FullRoundTrip_MOS256-10       45   24,377,706 ns/op  14,574,141 B/op   691 allocs/op
BenchmarkSign_FullRoundTrip_MOS128-10     136    8,543,678 ns/op   5,408,387 B/op   341 allocs/op
BenchmarkSign_FullRoundTrip_MOS256-10      36   32,230,172 ns/op  20,980,555 B/op   455 allocs/op
```

---

_Report generated using Go's built-in benchmarking framework with `-benchmem` flag for memory profiling._
