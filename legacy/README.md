# Legacy Go implementation

This directory contains the previous Go implementation and its archived GitHub
Actions workflows. GitHub only executes workflows under the repository-root
`.github/workflows`, so `legacy/.github/workflows` is retained for history and is
not active.

The Rust implementation at the repository root is the production implementation.
The Go code remains available as a compatibility reference and rollback source.

## Build and test

```bash
cd legacy
go test ./...
go build -o easysub .
```

The runtime configuration remains shared at the repository-root `workdir/`.
To run the legacy binary from this directory, copy the shared files first:

```bash
cp -R ../workdir/. .
cp pref.example.toml pref.toml
./easysub
```
