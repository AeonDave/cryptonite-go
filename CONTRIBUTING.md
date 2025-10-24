# Contributing to Cryptonite-go

## Development Setup
```bash
git clone https://github.com/AeonDave/cryptonite-go
cd cryptonite-go
go test ./...
```

## Guidelines

- **Tests required**: Add KAT vectors for new algorithms
- **Formatting**: Run `go fmt ./...` and `golangci-lint run`
- **Performance**: Include benchmarks in `test/`
- **Documentation**: Update docs/ if adding features

## Adding Test Vectors

See [docs/TESTING.md](docs/TESTING.md) for KAT format.

## PR Checklist

- [ ] Tests pass (`go test -race ./...`)
- [ ] Benchmarks included
- [ ] Documentation updated
- [ ] Commit messages descriptive

