# Windows development setup

## Prerequisites

- Windows 10 or newer;
- stable Rust toolchain with Cargo;
- TAP-Windows installed for later platform tests;
- Bun for the VitePress documentation site;
- Git with long-path support recommended.

TAP creation and network configuration normally require an elevated terminal.
Pure library tests and documentation builds do not require elevation.

## Verify the workspace

```powershell
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
bun run docs:build
```

## Run the placeholder binaries

Phase 0 contains compileable entry points only:

```powershell
cargo run -p stella-server
cargo run -p stella-client
```

They intentionally report that the functional implementation is not yet
available.
