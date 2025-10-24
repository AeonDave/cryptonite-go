# Testing Guidance

Cryptonite-go relies heavily on deterministic Known Answer Tests (KATs), fuzzing harnesses, and regression suites. This
document covers how to extend the testing matrix when adding new primitives.

## Running the Test Suite

```bash
go test ./...
go test ./test/...
go test -race ./...
```

Run these commands before submitting pull requests. Include `-bench` benchmarks when performance regressions are a
concern.

## Adding KAT Vectors

1. Place vector files under the relevant package's `testdata/` directory or the shared `test/` folder.
2. Use JSON or the existing delimiter-separated formats for consistency.
3. Document the vector source (RFC, NIST, academic paper) in a comment within the test file.
4. Ensure tests cover both valid and invalid cases (e.g., tag tampering, nonce misuse).

## Fuzzing

- Leverage Go's built-in fuzzing (`go test -fuzz=Fuzz*`) for stateful primitives.
- Fuzz targets live under `test/fuzz/`. If you add a new fuzz target, include seed corpus files to accelerate discovery.

## Benchmarks

- Benchmarks reside in `test/benchmark_*.go` or package-level `_test.go` files.
- Include throughput numbers for new primitives and compare them against baseline implementations.

## Continuous Integration Expectations

- Pull requests should run `go fmt ./...`, `go vet ./...`, and `golangci-lint run` locally before submission.
- Keep benchmark output in PR descriptions when performance optimizations are proposed.

