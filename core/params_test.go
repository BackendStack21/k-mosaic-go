package core

import (
	"testing"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
)

func TestGetParams(t *testing.T) {
	// Test MOS_128
	params128, err := GetParams(kmosaic.MOS_128)
	if err != nil {
		t.Fatalf("GetParams(128) failed: %v", err)
	}
	if params128.Level != kmosaic.MOS_128 {
		t.Errorf("Expected MOS_128, got %s", params128.Level)
	}

	// Test MOS_256
	params256, err := GetParams(kmosaic.MOS_256)
	if err != nil {
		t.Fatalf("GetParams(256) failed: %v", err)
	}
	if params256.Level != kmosaic.MOS_256 {
		t.Errorf("Expected MOS_256, got %s", params256.Level)
	}

	// Test invalid
	_, err = GetParams("INVALID")
	if err == nil {
		t.Error("GetParams(INVALID) should fail")
	}
}

func TestValidateParams(t *testing.T) {
	params, _ := GetParams(kmosaic.MOS_128)

	// Test valid params
	if err := ValidateParams(params); err != nil {
		t.Errorf("ValidateParams failed for valid params: %v", err)
	}

	// Test invalid SLSS params
	invalid := params
	invalid.SLSS.N = 0
	if err := ValidateParams(invalid); err == nil {
		t.Error("ValidateParams should reject N=0")
	}

	invalid = params
	invalid.SLSS.W = invalid.SLSS.N + 1
	if err := ValidateParams(invalid); err == nil {
		t.Error("ValidateParams should reject W > N")
	}

	invalid = params
	invalid.SLSS.Q = 10
	if err := ValidateParams(invalid); err == nil {
		t.Error("ValidateParams should reject non-prime Q")
	}

	// Test invalid TDD params
	invalid = params
	invalid.TDD.N = 0
	if err := ValidateParams(invalid); err == nil {
		t.Error("ValidateParams should reject TDD N=0")
	}

	// Test invalid EGRW params
	invalid = params
	invalid.EGRW.K = 0
	if err := ValidateParams(invalid); err == nil {
		t.Error("ValidateParams should reject EGRW K=0")
	}
}

func TestIsPrime(t *testing.T) {
	// isPrime is unexported, but we are in package core
	primes := []int{2, 3, 5, 7, 11, 13, 17, 19, 3329}
	nonPrimes := []int{1, 4, 6, 8, 9, 10, 12, 14, 15, 20, 3330}

	for _, p := range primes {
		if !isPrime(p) {
			t.Errorf("isPrime(%d) returned false", p)
		}
	}

	for _, np := range nonPrimes {
		if isPrime(np) {
			t.Errorf("isPrime(%d) returned true", np)
		}
	}
}

func BenchmarkIsPrime(b *testing.B) {
	testCases := []struct {
		name string
		n    int
	}{
		// Edge cases
		{"Edge_Zero", 0},
		{"Edge_One", 1},
		{"Edge_Two", 2},
		{"Edge_Three", 3},

		// Small numbers
		{"Small_Prime", 17},
		{"Small_Composite_Even", 18},
		{"Small_Composite_Odd", 21},     // 3*7
		{"Small_Composite_ByThree", 27}, // 3^3

		// Actual project primes (from MOS128/256 params)
		{"Project_EGRW128_Prime", 1021},
		{"Project_EGRW256_Prime", 2039},
		{"Project_TDD_Prime", 7681},
		{"Project_SLSS_Prime", 12289},

		// Composites near project primes (harder cases)
		{"Near_1021_Composite", 1023},   // 3*11*31
		{"Near_2039_Composite", 2041},   // 13*157
		{"Near_7681_Composite", 7685},   // 5*29*53
		{"Near_12289_Composite", 12291}, // 3*4097

		// Large primes (worst case - need many checks)
		{"Large_Prime_Near_Square", 104729}, // sqrt ≈ 323
		{"Large_Prime_100k", 104743},
		{"Very_Large_Prime", 1000003},

		// Large composites (various patterns)
		{"Large_Composite_Even", 104730},
		{"Large_Composite_Odd", 104731},      // 181*579
		{"Large_Composite_Product", 1000001}, // 101*9901
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				isPrime(tc.n)
			}
		})
	}
}
