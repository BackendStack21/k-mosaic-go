# kMOSAIC Go Implementation Plan

## Overview

This document outlines the plan for porting the kMOSAIC post-quantum cryptographic library from TypeScript (k-mosaic-node) to Go. The Go implementation will leverage Go's native concurrency model for parallelism and use standard library crypto functions where available.

---

## 1. Project Structure

```
k-mosaic-go/
├── go.mod
├── go.sum
├── README.md
├── LICENSE
├── mosaic.go                 # Main package exports
├── types.go                  # Type definitions
├── core/
│   └── params.go             # Parameter sets (MOS_128, MOS_256)
├── entanglement/
│   └── entanglement.go       # Secret sharing, binding, NIZK proofs
├── kem/
│   └── kem.go                # Key Encapsulation Mechanism
├── sign/
│   └── sign.go               # Digital Signatures
├── problems/
│   ├── slss/
│   │   └── slss.go           # Sparse Lattice Subset Sum
│   ├── tdd/
│   │   └── tdd.go            # Tensor Decomposition Distinguishing
│   └── egrw/
│       └── egrw.go           # Expander Graph Random Walk
├── utils/
│   ├── random.go             # Secure random generation
│   ├── shake.go              # SHAKE256/SHA3 utilities
│   └── constant_time.go      # Constant-time operations
├── examples/
│   ├── basic/
│   │   └── main.go
│   └── benchmark/
│       └── main.go
└── test/
    ├── kem_test.go
    ├── sign_test.go
    ├── slss_test.go
    ├── tdd_test.go
    ├── egrw_test.go
    ├── entanglement_test.go
    └── utils_test.go
```

---

## 2. Type Mappings (TypeScript → Go)

| TypeScript Type      | Go Type                                 | Notes                                            |
| -------------------- | --------------------------------------- | ------------------------------------------------ |
| `Uint8Array`         | `[]byte`                                | Standard Go byte slice                           |
| `Int8Array`          | `[]int8`                                | For sparse vectors                               |
| `Int32Array`         | `[]int32`                               | For matrices and tensors                         |
| `number`             | `int` / `int32` / `int64`               | Context-dependent                                |
| `Promise<T>`         | `T`                                     | Go doesn't use promises; use goroutines if async |
| `interface { }`      | `struct`                                | Go structs for data structures                   |
| `enum SecurityLevel` | `type SecurityLevel string` + constants | Go's idiomatic enum pattern                      |

### Core Types

```go
// types.go

type SecurityLevel string

const (
    MOS_128 SecurityLevel = "MOS-128"
    MOS_256 SecurityLevel = "MOS-256"
)

type SLSSParams struct {
    N     int     // Lattice dimension
    M     int     // Number of equations
    Q     int     // Prime modulus
    W     int     // Sparsity weight
    Sigma float64 // Error standard deviation
}

type TDDParams struct {
    N     int     // Tensor dimension
    R     int     // Tensor rank
    Q     int     // Modulus
    Sigma float64 // Noise standard deviation
}

type EGRWParams struct {
    P int // Prime for SL(2, Z_p)
    K int // Walk length
}

type MOSAICParams struct {
    Level SecurityLevel
    SLSS  SLSSParams
    TDD   TDDParams
    EGRW  EGRWParams
}

type SL2Element struct {
    A, B, C, D int
}

// ... (full type definitions in implementation)
```

---

## 3. Native Go Crypto Usage

Go 1.25 provides excellent cryptographic primitives. We will use:

| Functionality            | Go Package                 | Notes                           |
| ------------------------ | -------------------------- | ------------------------------- |
| SHAKE256 (XOF)           | `golang.org/x/crypto/sha3` | Native SHAKE256 support         |
| SHA3-256                 | `golang.org/x/crypto/sha3` | For binding commitments         |
| CSPRNG                   | `crypto/rand`              | Cryptographically secure random |
| Constant-time comparison | `crypto/subtle`            | `subtle.ConstantTimeCompare`    |
| Constant-time selection  | `crypto/subtle`            | `subtle.ConstantTimeSelect`     |

### Example Usage

```go
import (
    "crypto/rand"
    "crypto/subtle"
    "golang.org/x/crypto/sha3"
)

// SHAKE256 XOF
func shake256(input []byte, outputLen int) []byte {
    h := sha3.NewShake256()
    h.Write(input)
    output := make([]byte, outputLen)
    h.Read(output)
    return output
}

// Constant-time equality
func constantTimeEqual(a, b []byte) bool {
    return subtle.ConstantTimeCompare(a, b) == 1
}

// Secure random bytes
func secureRandomBytes(n int) ([]byte, error) {
    buf := make([]byte, n)
    _, err := rand.Read(buf)
    return buf, err
}
```

---

## 4. Go Parallelism Strategy

The kMOSAIC algorithm has several opportunities for parallelization:

### 4.1 Key Generation (Parallel Component Generation)

Generate SLSS, TDD, and EGRW keys concurrently:

```go
func generateKeyPairFromSeed(params MOSAICParams, seed []byte) (*MOSAICKeyPair, error) {
    var wg sync.WaitGroup
    var slssKP *SLSSKeyPair
    var tddKP *TDDKeyPair
    var egrwKP *EGRWKeyPair
    var slssErr, tddErr, egrwErr error

    // Derive component seeds (no parallelism needed - fast)
    slssSeed := hashWithDomain("kmosaic-kem-slss-v1", seed)
    tddSeed := hashWithDomain("kmosaic-kem-tdd-v1", seed)
    egrwSeed := hashWithDomain("kmosaic-kem-egrw-v1", seed)

    wg.Add(3)

    go func() {
        defer wg.Done()
        slssKP, slssErr = slssKeyGen(params.SLSS, slssSeed)
    }()

    go func() {
        defer wg.Done()
        tddKP, tddErr = tddKeyGen(params.TDD, tddSeed)
    }()

    go func() {
        defer wg.Done()
        egrwKP, egrwErr = egrwKeyGen(params.EGRW, egrwSeed)
    }()

    wg.Wait()
    // Check errors and compose keys...
}
```

### 4.2 Encapsulation (Parallel Encryption)

Encrypt the three shares concurrently:

```go
func encapsulateDeterministic(pk *MOSAICPublicKey, ephemeralSecret []byte) (*EncapsulationResult, error) {
    // Split secret into 3 shares
    shares := secretShareDeterministic(ephemeralSecret, 3, randomness)

    var wg sync.WaitGroup
    var c1 *SLSSCiphertext
    var c2 *TDDCiphertext
    var c3 *EGRWCiphertext
    var err1, err2, err3 error

    wg.Add(3)

    go func() {
        defer wg.Done()
        c1, err1 = slssEncrypt(pk.SLSS, shares[0], params.SLSS, rand1)
    }()

    go func() {
        defer wg.Done()
        c2, err2 = tddEncrypt(pk.TDD, shares[1], params.TDD, rand2)
    }()

    go func() {
        defer wg.Done()
        c3, err3 = egrwEncrypt(pk.EGRW, shares[2], params.EGRW, rand3)
    }()

    wg.Wait()
    // Compose ciphertext...
}
```

### 4.3 Decapsulation (Parallel Decryption)

Decrypt the three ciphertext components concurrently:

```go
func decapsulate(sk *MOSAICSecretKey, pk *MOSAICPublicKey, ct *MOSAICCiphertext) ([]byte, error) {
    var wg sync.WaitGroup
    var m1, m2, m3 []byte
    var err1, err2, err3 error

    wg.Add(3)

    go func() {
        defer wg.Done()
        m1, err1 = slssDecrypt(ct.C1, sk.SLSS, params.SLSS)
    }()

    go func() {
        defer wg.Done()
        m2, err2 = tddDecrypt(ct.C2, sk.TDD, pk.TDD, params.TDD)
    }()

    go func() {
        defer wg.Done()
        m3, err3 = egrwDecrypt(ct.C3, sk.EGRW, pk.EGRW, params.EGRW)
    }()

    wg.Wait()
    // Reconstruct secret...
}
```

### 4.4 Matrix Operations (Parallel Row/Column Processing)

For large matrix operations, parallelize row processing:

```go
func matVecMulParallel(A []int32, v []int8, m, n, q int) []int32 {
    result := make([]int32, m)
    numWorkers := runtime.GOMAXPROCS(0)
    rowsPerWorker := (m + numWorkers - 1) / numWorkers

    var wg sync.WaitGroup
    for w := 0; w < numWorkers; w++ {
        start := w * rowsPerWorker
        end := min(start+rowsPerWorker, m)
        if start >= m {
            break
        }

        wg.Add(1)
        go func(start, end int) {
            defer wg.Done()
            for i := start; i < end; i++ {
                sum := int64(0)
                rowOffset := i * n
                for j := 0; j < n; j++ {
                    sum += int64(A[rowOffset+j]) * int64(v[j])
                }
                result[i] = int32(mod(sum, int64(q)))
            }
        }(start, end)
    }
    wg.Wait()
    return result
}
```

### 4.5 Tensor Operations (Parallel Outer Products)

TDD tensor construction can parallelize rank contributions:

```go
func constructTensorParallel(factors TDDFactors, n, r, q int) []int32 {
    T := make([]int32, n*n*n)
    var mu sync.Mutex
    var wg sync.WaitGroup

    for i := 0; i < r; i++ {
        wg.Add(1)
        go func(i int) {
            defer wg.Done()
            partial := computeOuterProduct(factors.A[i], factors.B[i], factors.C[i], n, q)

            mu.Lock()
            for j := range T {
                T[j] = int32(mod(int64(T[j])+int64(partial[j]), int64(q)))
            }
            mu.Unlock()
        }(i)
    }
    wg.Wait()
    return T
}
```

---

## 5. Implementation Phases

### Phase 1: Core Infrastructure (Week 1)

1. **Project Setup**

   - Initialize `go.mod` with module path
   - Add dependencies (`golang.org/x/crypto/sha3`)
   - Create directory structure

2. **Types & Parameters** (`types.go`, `core/params.go`)

   - Define all type structures
   - Implement `MOS_128` and `MOS_256` parameter sets
   - Implement `GetParams()` and `ValidateParams()`

3. **Utilities** (`utils/`)
   - `shake.go`: SHAKE256, SHA3-256, hash utilities
   - `random.go`: Secure random, Gaussian sampling, seed validation
   - `constant_time.go`: Constant-time operations

### Phase 2: Problem Implementations (Week 2)

4. **SLSS Problem** (`problems/slss/slss.go`)

   - Matrix operations (matVecMul, matTVecMul)
   - Sparse vector sampling
   - Gaussian error sampling
   - Key generation, encryption, decryption
   - Serialization/deserialization

5. **TDD Problem** (`problems/tdd/tdd.go`)

   - 3D tensor operations
   - Factor sampling
   - Noise tensor generation
   - Key generation, encryption, decryption
   - Serialization/deserialization

6. **EGRW Problem** (`problems/egrw/egrw.go`)
   - SL(2, Z_p) group operations
   - Generator caching with LRU eviction
   - Random walk computation
   - Key generation, encryption, decryption
   - Serialization/deserialization

### Phase 3: Entanglement & KEM (Week 3)

7. **Entanglement Layer** (`entanglement/entanglement.go`)

   - XOR-based secret sharing
   - Binding commitment generation
   - NIZK proof generation/verification

8. **KEM Implementation** (`kem/kem.go`)
   - Key pair generation (with parallelism)
   - Encapsulation (with parallelism)
   - Decapsulation (with parallelism)
   - Encrypt/Decrypt (symmetric key encryption)
   - Serialization/deserialization

### Phase 4: Digital Signatures (Week 4)

9. **Signature Implementation** (`sign/sign.go`)
   - Mask sampling (SLSS, TDD, EGRW)
   - Commitment generation
   - Challenge computation (Fiat-Shamir)
   - Response generation with rejection sampling
   - Signature verification
   - Serialization/deserialization

### Phase 5: Testing & Examples (Week 5)

10. **Unit Tests** (`test/`)

    - Port all tests from TypeScript
    - Add Go-specific edge case tests
    - Benchmark tests

11. **Examples** (`examples/`)

    - Basic usage example
    - Benchmark example

12. **Documentation**
    - Update README.md
    - Add GoDoc comments
    - Create DEVELOPER_GUIDE.md for Go

---

## 6. Performance Optimization Considerations

### 6.1 Memory Management

- **Pre-allocate slices** when size is known
- **Reuse buffers** in hot loops to reduce GC pressure
- **Use `sync.Pool`** for frequently allocated temporary buffers

```go
var bufferPool = sync.Pool{
    New: func() interface{} {
        return make([]byte, 4096)
    },
}
```

### 6.2 SIMD Considerations

- Go's compiler can auto-vectorize simple loops
- For critical paths, consider using assembly or CGo for SIMD
- Alternative: Use `gonum.org/v1/gonum` for optimized linear algebra

### 6.3 Parallelism Thresholds

Only parallelize when beneficial:

```go
const (
    ParallelMatrixThreshold = 256  // Min rows for parallel matVecMul
    ParallelTensorThreshold = 16   // Min dimension for parallel tensor ops
)

func matVecMul(A []int32, v []int8, m, n, q int) []int32 {
    if m >= ParallelMatrixThreshold {
        return matVecMulParallel(A, v, m, n, q)
    }
    return matVecMulSequential(A, v, m, n, q)
}
```

### 6.4 Profiling

Use Go's built-in profiling:

```bash
go test -cpuprofile=cpu.prof -memprofile=mem.prof -bench .
go tool pprof cpu.prof
```

---

## 7. Security Considerations

### 7.1 Constant-Time Operations

- Use `crypto/subtle` for all secret-dependent comparisons
- Avoid early returns in secret-dependent loops
- Use bitwise operations for conditional selection

```go
// WRONG: timing leak
if secret[i] == 0 {
    continue
}

// CORRECT: constant-time
for i := 0; i < len(secret); i++ {
    result[i] += A[i] * int32(secret[i])  // Always executes
}
```

### 7.2 Memory Zeroization

Zeroize sensitive data after use:

```go
func zeroize(b []byte) {
    for i := range b {
        b[i] = 0
    }
    // Use runtime.KeepAlive if needed to prevent optimization
    runtime.KeepAlive(b)
}
```

### 7.3 Error Handling

- Never leak timing information through error paths
- Use implicit rejection for decryption failures
- Return consistent error types

---

## 8. Testing Strategy

### 8.1 Unit Tests

- Test each component in isolation
- Test edge cases (empty inputs, max values)
- Test error conditions

### 8.2 Integration Tests

- Full KEM roundtrip tests
- Full signature roundtrip tests
- Cross-test with known test vectors

### 8.3 Fuzzing

Use Go's native fuzzing:

```go
func FuzzEncapsulateDecapsulate(f *testing.F) {
    f.Add([]byte("seed0123456789012345678901234567"))
    f.Fuzz(func(t *testing.T, seed []byte) {
        if len(seed) < 32 {
            return
        }
        // Test encapsulate/decapsulate roundtrip
    })
}
```

### 8.4 Benchmarks

```go
func BenchmarkKEMKeyGen(b *testing.B) {
    for i := 0; i < b.N; i++ {
        _, _ = GenerateKeyPair(MOS_128)
    }
}

func BenchmarkKEMEncapsulate(b *testing.B) {
    kp, _ := GenerateKeyPair(MOS_128)
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, _ = Encapsulate(&kp.PublicKey)
    }
}
```

---

## 9. API Design

### 9.1 Public API (Main Package)

```go
package kmosaic

// KEM
func KEMGenerateKeyPair(level SecurityLevel) (*MOSAICKeyPair, error)
func Encapsulate(pk *MOSAICPublicKey) (*EncapsulationResult, error)
func Decapsulate(sk *MOSAICSecretKey, pk *MOSAICPublicKey, ct *MOSAICCiphertext) ([]byte, error)
func Encrypt(pk *MOSAICPublicKey, plaintext []byte) (*EncryptedMessage, error)
func Decrypt(sk *MOSAICSecretKey, pk *MOSAICPublicKey, em *EncryptedMessage) ([]byte, error)

// Signatures
func SignGenerateKeyPair(level SecurityLevel) (*MOSAICKeyPair, error)
func Sign(sk *MOSAICSecretKey, pk *MOSAICPublicKey, message []byte) (*MOSAICSignature, error)
func Verify(pk *MOSAICPublicKey, message []byte, sig *MOSAICSignature) bool

// Parameters
func GetParams(level SecurityLevel) MOSAICParams
```

### 9.2 Error Handling

Use structured errors:

```go
type MOSAICError struct {
    Op      string // Operation that failed
    Problem string // Which problem (SLSS, TDD, EGRW, or general)
    Err     error  // Underlying error
}

func (e *MOSAICError) Error() string {
    return fmt.Sprintf("kmosaic: %s failed in %s: %v", e.Op, e.Problem, e.Err)
}
```

---

## 10. Dependencies

### Required

```go
// go.mod
module github.com/BackendStack21/k-mosaic-go

go 1.25

require (
    golang.org/x/crypto v0.x.x  // For sha3.NewShake256()
)
```

### Optional (for enhanced performance)

```go
// Consider for future optimization
// gonum.org/v1/gonum  // Optimized linear algebra
```

---

## 11. Compatibility Goals

1. **Interoperability**: Serialized keys and ciphertexts should be compatible between Go and TypeScript implementations
2. **Determinism**: Same seeds should produce identical keys across implementations
3. **Test Vectors**: Generate shared test vectors for cross-implementation validation

---

## 12. Deliverables Checklist

- [ ] `go.mod` and project structure
- [ ] `types.go` - All type definitions
- [ ] `core/params.go` - Parameter sets
- [ ] `utils/shake.go` - Hash utilities
- [ ] `utils/random.go` - Random generation
- [ ] `utils/constant_time.go` - Constant-time ops
- [ ] `problems/slss/slss.go` - SLSS implementation
- [ ] `problems/tdd/tdd.go` - TDD implementation
- [ ] `problems/egrw/egrw.go` - EGRW implementation
- [ ] `entanglement/entanglement.go` - Entanglement layer
- [ ] `kem/kem.go` - KEM implementation
- [ ] `sign/sign.go` - Signature implementation
- [ ] `mosaic.go` - Main exports
- [ ] Unit tests for all components
- [ ] Benchmark tests
- [ ] Example applications
- [ ] README.md documentation

---

## 13. Risk Assessment

| Risk                            | Impact   | Mitigation                                                          |
| ------------------------------- | -------- | ------------------------------------------------------------------- |
| Performance gap vs TypeScript   | Medium   | Extensive profiling, parallel optimization                          |
| Numerical precision differences | High     | Use int64 for intermediate computations, validate with test vectors |
| Memory leaks in crypto code     | High     | Strict zeroization, use `defer` consistently                        |
| Side-channel vulnerabilities    | Critical | Code review focused on constant-time, use `crypto/subtle`           |
| Cross-platform issues           | Low      | Test on Linux, macOS, Windows                                       |

---

## 14. Success Criteria

1. All unit tests pass
2. Cross-implementation test vectors match
3. Performance within 2x of TypeScript implementation (ideally faster)
4. No detected timing side-channels
5. Clean Go linting (`golangci-lint`)
6. GoDoc documentation coverage

---

## Questions for Review

1. **Module path**: Should we use `github.com/BackendStack21/k-mosaic-go` or a different path?
2. **Minimum Go version**: Confirmed Go 1.25 - any backward compatibility needs?
3. **Build tags**: Should we support alternative implementations (e.g., pure Go vs CGo)?
4. **Serialization format**: Binary-compatible with TypeScript or define new format?
5. **Additional dependencies**: Any preference for linear algebra libraries?

---

_Please review this plan and provide feedback before implementation begins._
