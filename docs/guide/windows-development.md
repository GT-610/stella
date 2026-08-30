# Windows development setup

## Prerequisites

- Windows 10 or newer;
- stable Rust toolchain with Cargo;
- TAP-Windows installed for later platform tests;
- Bun for the VitePress documentation site;
- Git with long-path support recommended.

TAP creation and network configuration normally require an elevated terminal.
Pure library tests and documentation builds do not require elevation.

The runtime opens a pre-installed TAP-Windows Adapter V9; it does not install a
driver or create an adapter. When more than one TAP-Windows adapter is present,
configuration must select the intended Windows connection name or interface
GUID. Driver MTU and persistent MAC changes are administrator operations that
require a miniport restart before Stella opens the adapter.

## Verify the workspace

```powershell
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
bun run docs:build
```

The real-adapter test is opt-in because it temporarily changes TAP media state
and requires exclusive access:

```powershell
$env:STELLA_TAP_WINDOWS_ADAPTER = 'Local Area Connection'
cargo test -p stella-tap --test windows_tap -- --ignored --nocapture
```

The test restores media-disconnected state and does not install, remove,
rename, enable, or disable an adapter.

## Run the placeholder binaries

Phase 0 contains compileable entry points only:

```powershell
cargo run -p stella-server
cargo run -p stella-client
```

They intentionally report that the functional implementation is not yet
available.
