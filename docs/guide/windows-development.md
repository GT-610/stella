# Windows development setup

## Prerequisites

- Windows 10 or newer;
- stable Rust toolchain with Cargo;
- TAP-Windows installed for the runtime and platform tests;
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

The controller and Windows client now form an experimental virtual LAN. Generate
separate enrollment and join tokens for every client, then initialize, join, and
run each client as described in the [Windows client CLI guide](/api/client-cli).
Each client needs a distinct installed TAP-Windows adapter, a reachable UDP
endpoint published in its client configuration, and firewall or NAT rules that
allow peer UDP traffic. Run the active client from an elevated PowerShell
session so it can open the TAP adapter.

The initial client configuration has an empty `advertised_endpoints` list. Before
running a client, replace that list with an endpoint whose port matches
`udp_bind`; for example:

```toml
[[transport.advertised_endpoints]]
address = "192.168.1.20:45100"
priority = 10
max_datagram_size = 1200
```

Stella forwards Ethernet frames and does not assign IP addresses or run DHCP.
Configure suitable addresses on the TAP adapters, or provide DHCP within the
virtual LAN. For a persistent deployment, follow the
[Windows controller deployment guide](./server-deployment.md).
