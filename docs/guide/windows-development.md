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

## Run a development controller

Initialize a disposable deployment outside the source tree, create a network
and one pair of single-use client tokens, then run the TLS controller:

```powershell
$Config = Join-Path $env:TEMP 'stella-dev\server.toml'

cargo run -p stella-server -- --config $Config init `
  --listen 127.0.0.1:44900

$NetworkId = cargo run -q -p stella-server -- `
  --config $Config network create --name 'Development LAN'
$EnrollmentToken = cargo run -q -p stella-server -- `
  --config $Config enrollment-token create
$JoinToken = cargo run -q -p stella-server -- `
  --config $Config join-token create --network $NetworkId

cargo run -p stella-server -- --config $Config run
```

Record the initialization output, network ID, and tokens before starting the
daemon. The tokens are sensitive and printed only once. Press Ctrl+C to drain
active sessions and shut down cleanly.

The controller control plane is functional. `stella-client` does not yet form a
usable virtual LAN; its Windows control-plane and data-plane integration are
the next implementation milestone. For a persistent deployment, follow the
[Windows controller deployment guide](./server-deployment.md).
