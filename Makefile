# kMOSAIC Go - Makefile
# Post-quantum cryptographic library

.PHONY: all build test test-verbose test-race test-386 bench bench-full bench-128 bench-256 coverage coverage-html lint fmt vet security deps verify update example doc clean install check ci help

# Default target
all: fmt vet test

# Build the library
build:
	@echo "Building kMOSAIC..."
	go build ./...

# Run all tests
test:
	@echo "Running tests..."
	go test ./...

# Run tests with verbose output
test-verbose:
	@echo "Running tests (verbose)..."
	go test -v ./...

# Run tests with race detector
test-race:
	@echo "Running tests with race detector..."
	go test -race ./...

# Run short benchmarks
bench:
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./test/ -run=^$

# Run comprehensive benchmarks (3 iterations)
bench-full:
	@echo "Running comprehensive benchmarks..."
	go test -bench=. -benchmem ./test/ -run=^$ -count=3

# Run benchmarks for MOS-128 only
bench-128:
	@echo "Running MOS-128 benchmarks..."
	go test -bench='MOS128' -benchmem ./test/ -run=^$

# Run benchmarks for MOS-256 only
bench-256:
	@echo "Running MOS-256 benchmarks..."
	go test -bench='MOS256' -benchmem ./test/ -run=^$

# Generate coverage report
coverage:
	@echo "Generating coverage report..."
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

# Generate HTML coverage report
coverage-html: coverage
	@echo "Generating HTML coverage report..."
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run linter (requires golangci-lint)
lint:
	@echo "Running linter..."
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.5.0)
	golangci-lint run ./...

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Run go vet
vet:
	@echo "Running go vet..."
	go vet ./...

# Clean build artifacts
clean:
	@echo "Cleaning..."
	go clean ./...
	rm -f coverage.out coverage.html

# Install dependencies
deps:
	@echo "Installing dependencies..."
	go mod download
	go mod tidy

# Verify dependencies
verify:
	@echo "Verifying dependencies..."
	go mod verify

# Update dependencies
update:
	@echo "Updating dependencies..."
	go get -u ./...
	go mod tidy

# Run the basic example
example:
	@echo "Running basic example..."
	go run ./examples/basic/main.go

# Security check (requires govulncheck)
security:
	@echo "Running security check..."
	@which govulncheck > /dev/null || (echo "Installing govulncheck..." && go install golang.org/x/vuln/cmd/govulncheck@latest)
	govulncheck ./...

# Generate documentation
doc:
	@echo "Package documentation (use 'go doc -all ./<package>' for details):"
	go doc ./...

# Quick check (fmt + vet + test)
check: fmt vet test
	@echo "All checks passed!"

# Run the parser tests on a 32-bit target
test-386:
	@echo "Vetting and testing with GOARCH=386..."
	GOARCH=386 go vet ./...
	GOARCH=386 go test ./internal/wire/ ./kem/ ./sign/ -run 'Deserialize|Truncated|Header|Huge'
	GOARCH=386 go test ./core/ ./utils/ ./problems/qcsd/ ./problems/uov/ ./problems/slhdsa/

# CI pipeline simulation
ci: fmt vet lint test test-race test-386
	@echo "Local CI pipeline completed (the hosted CI additionally fuzzes the deserializers)"

# Help
help:
	@echo "kMOSAIC Go - Available Commands"
	@echo ""
	@echo "Build & Run:"
	@echo "  make build        - Build the library"
	@echo "  make example      - Run the basic example"
	@echo ""
	@echo "Testing:"
	@echo "  make test         - Run all tests"
	@echo "  make test-verbose - Run tests with verbose output"
	@echo "  make test-race    - Run tests with race detector"
	@echo ""
	@echo "Benchmarks:"
	@echo "  make bench        - Run benchmarks"
	@echo "  make bench-full   - Run benchmarks (3 iterations)"
	@echo "  make bench-128    - Run MOS-128 benchmarks only"
	@echo "  make bench-256    - Run MOS-256 benchmarks only"
	@echo ""
	@echo "Coverage:"
	@echo "  make coverage     - Generate coverage report"
	@echo "  make coverage-html - Generate HTML coverage report"
	@echo ""
	@echo "Code Quality:"
	@echo "  make fmt          - Format code"
	@echo "  make vet          - Run go vet"
	@echo "  make lint         - Run linter (golangci-lint)"
	@echo "  make security     - Run security check (govulncheck)"
	@echo ""
	@echo "Dependencies:"
	@echo "  make deps         - Install dependencies"
	@echo "  make update       - Update dependencies"
	@echo "  make verify       - Verify dependencies"
	@echo ""
	@echo "Utilities:"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make doc          - Start documentation server"
	@echo "  make check        - Quick check (fmt + vet + test)"
	@echo "  make ci           - Run full CI pipeline"
	@echo "  make help         - Show this help message"
