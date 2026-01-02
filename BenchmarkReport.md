# kMOSAIC Go Benchmark Report

**Date:** January 2, 2026  
**Platform:** macOS (darwin/arm64) - Apple M2 Pro  
**Go Version:** 1.21+

---

## Performance Summary

| Operation           | MOS-128  | MOS-256  | Slowdown | Memory 128 | Memory 256 |
| ------------------- | -------- | -------- | -------- | ---------- | ---------- |
| **KEM KeyGen**      | 6.16 ms  | 22.15 ms | 3.60×    | 3.53 MB    | 13.61 MB   |
| **KEM Encapsulate** | 0.32 ms  | 0.95 ms  | 2.99×    | 63 KB      | 120 KB     |
| **KEM Decapsulate** | 0.37 ms  | 1.04 ms  | 2.82×    | 109 KB     | 202 KB     |
| **Sign KeyGen**     | 6.27 ms  | 22.26 ms | 3.55×    | 3.53 MB    | 13.61 MB   |
| **Sign**            | 11.82 μs | 21.99 μs | 1.86×    | 7.2 KB     | 23.2 KB    |
| **Verify**          | 2.38 ms  | 9.53 ms  | 4.00×    | 1.62 MB    | 6.38 MB    |
| **KEM Round-Trip**  | 7.02 ms  | 24.35 ms | 3.47×    | 3.70 MB    | 13.93 MB   |
| **Sign Round-Trip** | 8.81 ms  | 32.55 ms | 3.69×    | 5.16 MB    | 20.02 MB   |

---

## Throughput (Operations/Second)

| Operation       | MOS-128 | MOS-256 |
| --------------- | ------- | ------- |
| KEM KeyGen      | 162     | 45      |
| KEM Encapsulate | 3,161   | 1,056   |
| KEM Decapsulate | 2,702   | 960     |
| Sign KeyGen     | 159     | 45      |
| Sign            | 84,618  | 45,474  |
| Verify          | 420     | 105     |

---

## Key Insights

### Performance Characteristics

- **Key Generation**: Dominates overall latency (85-90% of full round-trip time). MOS-256 is 3.5-3.6× slower than MOS-128.
- **Signing**: Extremely fast at both levels (11.8-22.0 μs), enabling high-throughput applications (45K-85K signatures/sec).
- **Verification**: ~200× slower than signing due to tensor operations. MOS-256 is 4× slower than MOS-128.
- **Memory**: MOS-256 uses ~3.8-4× more memory than MOS-128. Key generation has the highest memory footprint (~13.6 MB for MOS-256).

### Security Level Selection

**Choose MOS-128 for:**

- High-throughput systems (>1000 ops/sec)
- Real-time applications (<10ms latency)
- Resource-constrained environments
- Standard 128-bit post-quantum security

**Choose MOS-256 for:**

- Long-term data protection (decades)
- Maximum security margins
- Critical infrastructure
- Government/defense applications

---

## Raw Benchmark Data

```
goos: darwin
goarch: arm64
pkg: github.com/BackendStack21/k-mosaic-go/test
cpu: Apple M2 Pro

BenchmarkKEM_GenerateKeyPair_MOS128-10               193           6157114 ns/op         3703690 B/op        318 allocs/op
BenchmarkKEM_Encapsulate_MOS128-10                  3718            316840 ns/op           64523 B/op        121 allocs/op
BenchmarkKEM_Decapsulate_MOS128-10                  3079            370160 ns/op          112150 B/op        185 allocs/op
BenchmarkKEM_Encrypt_MOS128-10                      3728            318976 ns/op           66206 B/op        129 allocs/op
BenchmarkKEM_Decrypt_MOS128-10                      3058            393399 ns/op          113615 B/op        192 allocs/op
BenchmarkKEM_GenerateKeyPair_MOS256-10                49          22151573 ns/op        14269238 B/op        424 allocs/op
BenchmarkKEM_Encapsulate_MOS256-10                  1266            946871 ns/op          122764 B/op        142 allocs/op
BenchmarkKEM_Decapsulate_MOS256-10                  1143           1042438 ns/op          207134 B/op        206 allocs/op
BenchmarkKEM_Encrypt_MOS256-10                      1255            948946 ns/op          124447 B/op        150 allocs/op
BenchmarkKEM_Decrypt_MOS256-10                      1137           1067164 ns/op          208597 B/op        213 allocs/op
BenchmarkSign_GenerateKeyPair_MOS128-10              184           6273749 ns/op         3703853 B/op        318 allocs/op
BenchmarkSign_Sign_MOS128-10                      100731             11816 ns/op            7349 B/op         14 allocs/op
BenchmarkSign_Verify_MOS128-10                       501           2384249 ns/op         1695937 B/op          9 allocs/op
BenchmarkSign_GenerateKeyPair_MOS256-10               50          22261139 ns/op        14269193 B/op        424 allocs/op
BenchmarkSign_Sign_MOS256-10                       54386             21994 ns/op           23739 B/op         17 allocs/op
BenchmarkSign_Verify_MOS256-10                       130           9533680 ns/op         6684872 B/op          9 allocs/op
BenchmarkKEM_FullRoundTrip_MOS128-10                 168           7022817 ns/op         3883741 B/op        639 allocs/op
BenchmarkKEM_FullRoundTrip_MOS256-10                  48          24352596 ns/op        14601960 B/op        787 allocs/op
BenchmarkSign_FullRoundTrip_MOS128-10                135           8813675 ns/op         5408874 B/op        346 allocs/op
BenchmarkSign_FullRoundTrip_MOS256-10                 36          32550679 ns/op        20981186 B/op        458 allocs/op
```

---

_Last updated: January 2, 2026_
