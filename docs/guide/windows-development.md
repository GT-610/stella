# Windows development setup

## Prerequisites

- Windows 10 or newer;
- stable Rust toolchain with Cargo;
- the signed TAP-Windows Adapter V9 driver package installed in Driver Store;
- Bun for the VitePress documentation site;
- Git with long-path support recommended.

TAP creation and network configuration normally require an elevated terminal.
Pure library tests and documentation builds do not require elevation.

The runtime does not install a driver package. It creates one persistent root
TAP-Windows device per network from the package already in Driver Store, names
it `Stella <network-id>`, and reuses it across runs. `leave` removes that
network's managed device. Driver MTU and persistent MAC changes remain external
administrator operations that require a miniport restart before Stella opens
the adapter.

## Verify the workspace

```powershell
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
bun run docs:build
```

The existing-adapter test is opt-in because it temporarily changes TAP media
state and requires exclusive access:

```powershell
$env:STELLA_TAP_WINDOWS_ADAPTER = 'Local Area Connection'
cargo test -p stella-tap --test windows_tap `
  installed_adapter_supports_lifecycle_frame_write_and_cancellation `
  -- --ignored --exact --nocapture
```

That test restores media-disconnected state and does not create, remove, or
rename an adapter. A second elevated test verifies automatic provisioning. It
creates a uniquely named TAP device, reuses and opens it, then removes it even
when the test unwinds:

```powershell
cargo test -p stella-tap --test windows_tap `
  provisioning_creates_reuses_opens_and_removes_adapter `
  -- --ignored --exact --nocapture
```

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
Each join creates or reuses its network's distinct managed TAP-Windows adapter.
Direct ICE discovery and the configured relay carriers remove the need for
client port forwarding; an optional explicit HTTP proxy can carry the secure
WebSocket fallback. Run join, leave, and the active client from an elevated
PowerShell session so Stella can manage and open TAP devices.

The initial client configuration has an empty `advertised_endpoints` list. Leave
it empty when the controller supplies STUN and relay services. A known static
public mapping may still be published as an extra direct candidate; its port
must match `udp_bind`:

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
