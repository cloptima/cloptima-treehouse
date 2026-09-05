# Contributing

## Build

Requirements: Go 1.25+

```bash
go build -trimpath -ldflags "-s -w" -o treehouse ./cmd/treehouse
```

## Test

```bash
gofmt -l cmd internal   # must print nothing
go vet ./...
go test -race ./...
```

These are the same checks CI runs on every PR.

## Project layout

- `cmd/treehouse` — entrypoint
- `internal/cli` — command surface (`login`, `pair`, `add`, `run`, `version`, ...)
- `internal/crypto` — key derivation and diff sealing
- `internal/git` — local git shellouts (read-only)
- `internal/ingest` — wire client for `/v1/treehouse/ingest`
- `internal/watch` — fsnotify-based worktree watcher
- `internal/config`, `internal/auth`, `internal/tray`, `internal/update`, `internal/payload`, `internal/loginitem` — supporting packages

Darwin-only code (`internal/tray`, `internal/loginitem`) is gated by `darwin && cgo` build tags; every other platform falls back to the corresponding `_other.go` no-op implementation. A change to one side usually needs the other kept in sync so the build doesn't silently diverge per platform.

## Submitting changes

- Open a PR against `master`.
- Keep `gofmt`, `go vet`, and `go test -race ./...` clean — CI enforces all three.
- Changes to `internal/crypto` should keep `internal/crypto/interop_gen_test.go` green; it guards byte-for-byte compatibility with the web client's decryption and is the thing that catches silent format drift between the two.

## Security issues

See [SECURITY.md](SECURITY.md).

## License

By contributing, you agree your contribution is licensed under this project's [Apache License 2.0](LICENSE).
