// Package timingtest gates the library's timing-flatness tests.
//
// Those tests compare the running time of constant-time code on inputs that
// drove earlier, data-dependent implementations down different paths. They
// are statistical and need a quiet machine: when `go test ./...` runs
// packages concurrently on a small CI runner they produce spreads of 1.3–1.5
// from scheduling noise alone, with no consistent slow input. They are
// therefore skipped unless the environment variable KMOSAIC_TIMING_TESTS is
// set, and CI runs them in a dedicated step with `-p 1` so that only one
// test binary executes at a time (see .github/workflows/ci.yml and `make
// test-timing`).
package timingtest

import (
	"os"
	"testing"
)

// EnvVar enables the timing tests when set to a non-empty value.
const EnvVar = "KMOSAIC_TIMING_TESTS"

// Gate skips t unless the timing tests are enabled and the run is neither
// -short nor under the race detector (which multiplies run time unevenly).
func Gate(t testing.TB, raceEnabled bool) {
	t.Helper()
	if testing.Short() {
		t.Skip("timing test skipped in -short mode")
	}
	if raceEnabled {
		t.Skip("timing test skipped under the race detector")
	}
	if os.Getenv(EnvVar) == "" {
		t.Skipf("timing test skipped: set %s=1 and run with -p 1 on a quiet machine", EnvVar)
	}
}
