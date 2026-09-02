# Server administration CLI

`stella-server` initializes a controller deployment, runs its TLS control-plane
service and TURN UDP/TCP/TLS/secure-WebSocket relays, creates protected relay
credential keys, and provides authority administration commands. Commands that use deployment state
load the strict TOML configuration named by `--config` (default: `server.toml`). Commands that
access authority state derive the controller ID from the protected controller
identity, open the configured redb database, and perform database work on the
serialized authority thread.

## Common syntax

```powershell
stella-server --config C:\Stella\server.toml <command>
```

Network IDs and node IDs are canonical 16-byte identifiers written as exactly
32 hexadecimal digits. Hexadecimal input is case-insensitive; output is lower
case. Successful mutation commands print only the result needed by scripts.
Errors and diagnostic context go to stderr and produce a non-zero exit code.

## Initialize a deployment

```powershell
stella-server --config C:\Stella\server.toml init `
  --listen 0.0.0.0:44900 `
  --tls-name controller.example.net
```

`init` creates the configuration, `state` and `secrets` directories, protected
controller and TLS private keys, a self-signed Ed25519 TLS certificate, and a
controller-bound redb database. It never overwrites an existing target. An
initialization failure removes only files and empty directories created by that
invocation.

The certificate always contains `localhost`, `127.0.0.1`, and `::1`. Repeat
`--tls-name` for additional DNS names or IP addresses. `--tls-validity-days`
defaults to 825 and accepts 1 through 3650. Successful output contains:

```text
controller_id=<32 lowercase hexadecimal digits>
tls_spki_pin=sha256/<standard padded base64>
tls_not_after=<Unix timestamp>
config=<configuration path>
```

Transfer the controller ID and SPKI pin to clients over a trusted channel. The
private keys are never printed, and `run` will not regenerate missing files.

## Create a relay credential key

```powershell
stella-server relay-key create `
  --output C:\Stella\secrets\relay-credential.key
```

`relay-key create` obtains a random non-zero 256-bit deployment key from the
operating system, creates the destination with the same native protected-file
policy as controller identities, writes and synchronizes it, and prints only
`key=<path>`. It never overwrites an existing path and never emits key bytes.
The parent directory must already exist. Keep the file with the controller and
every separately deployed relay process that verifies its credentials; never
copy it to clients.

## Run a TURN relay

```powershell
stella-server --config C:\Stella\server.toml relay run `
  --id 01010101010101010101010101010101 `
  --carrier udp `
  --listen 0.0.0.0:3478 `
  --advertise 192.0.2.30
```

`relay run` selects the relay with the matching ID from `[connectivity]`, loads
the configured protected credential key, and serves the carrier selected by
`--carrier udp|tcp|tls|websocket` until Ctrl+C. UDP remains the default for command
compatibility. The listener port must equal the selected relay's advertised
`turn_udp`, `turn_tcp`, `turn_tls`, or `secure_websocket` port. The
advertised address is returned as the relayed address and therefore must be an
address that remote peers can actually reach. Use `--allocation-bind` when the
allocation sockets should bind a different local IP from the listener.

Run TCP on its configured port in a separate process:

```powershell
stella-server --config C:\Stella\server.toml relay run `
  --id 01010101010101010101010101010101 `
  --carrier tcp `
  --listen 0.0.0.0:3479 `
  --advertise 192.0.2.30
```

Run TLS on its configured port, commonly TCP 5349, in another process:

```powershell
stella-server --config C:\Stella\server.toml relay run `
  --id 01010101010101010101010101010101 `
  --carrier tls `
  --listen 0.0.0.0:5349 `
  --advertise 192.0.2.30
```

Run secure WebSocket on public TCP 443 as the final strict-firewall fallback:

```powershell
stella-server --config C:\Stella\server.toml relay run `
  --id 01010101010101010101010101010101 `
  --carrier websocket `
  --listen 0.0.0.0:443 `
  --advertise 192.0.2.30
```

TLS and secure WebSocket load the certificate and protected PKCS#8 private key
from the top-level `[tls]` configuration, permit TLS 1.3 only, disable early
data, and use `limits.tls_handshake_timeout_seconds` for each accepted
connection. The certificate must cover the advertised Relay TLS name and match
the Web PKI or SPKI trust material distributed by the controller.

Secure WebSocket accepts only `GET /stella/turn/v1` with subprotocol
`stella-turn.v1`, one canonical `Authorization: Stella ...` credential, and no
WebSocket extensions. Authentication completes before the HTTP upgrade, after
which the normal TURN challenge and message-integrity checks still apply. Each
binary message contains exactly one bounded TURN record. The listener terminates
TLS itself; use a distinct IP or hostname plus L4 TLS/SNI passthrough if TCP 443
must also serve a website.

The default capacity is 1024 concurrent allocations globally, four per node,
and 128 permissions and channels per allocation. The corresponding
`--max-allocations`, `--max-allocations-per-node`,
`--max-permissions-per-allocation`, and `--max-channels-per-allocation` options
bound memory and socket use. Datagram size, allocation lifetime, idle timeout,
credential lifetime, and credential key path come from the selected configured
relay service.

The built-in relay supports TURN UDP, TURN TCP, TURN TLS, and secure WebSocket.
All four create a UDP relayed allocation because Stella carries datagrams; TCP,
TLS, and WebSocket only change the client-to-relay control and data carrier.
Windows clients try them in the order UDP, TCP, TLS, then secure WebSocket. Each allocation uses an
operating-system-selected UDP port rather than a configurable allocation port
pool. A public deployment must permit those sockets through the host firewall;
if the relay host is behind NAT, the public address and the operating system's
UDP dynamic port range must also be forwarded. Running the relay directly on a
public address is strongly preferred. A bounded allocation port pool remains
future work.

## Run the controller

```powershell
stella-server --config C:\Stella\server.toml run
```

`run` validates the complete configuration, protected controller identity, TLS
certificate and private key, controller-bound database, and persisted
invariants before binding the configured TCP address. It then serves TLS 1.3
control sessions for registration, authentication, network membership,
endpoint publication, snapshots, heartbeats, and proactive membership-grant
refreshes. When `[connectivity]` is configured, version 0.2 authentication also
delivers the deployment STUN and relay service list with node-scoped,
short-lived credentials. The controller proactively replaces the complete
configuration halfway through the remaining credential lifetime.

The `[logging].filter` value uses `tracing-subscriber` filter syntax. The
generated value `info,stella_server=info` writes human-readable operational
logs to stderr without exposing bearer tokens or private keys. Invalid filters
are rejected before the listener starts.

Press Ctrl+C once to stop accepting connections. The daemon asks active
sessions to shut down, waits up to `limits.shutdown_timeout_seconds`, aborts any
remaining session tasks, orders authority shutdown after already admitted
commands, and joins the authority thread. A clean shutdown exits with code 0.
Configuration, identity, TLS, persistence, bind, session-runtime, or shutdown
failures are reported to stderr and exit with a non-zero code.

`run` never creates or repairs missing deployment files. Use `init` once, keep
both files under `secrets` readable only by the controller account, and use the
state maintenance commands below for verification and backups.

## Network management

Create a network and let the operating system generate its ID:

```powershell
stella-server --config C:\Stella\server.toml network create --name "Game LAN"
```

The command prints the new network ID. `--id` accepts an explicit non-zero
network ID for deterministic deployments and tests. The default policy is:

| Option | Default |
| --- | ---: |
| `--confidentiality` | `encrypt` |
| `--max-frame-size` | 1514 bytes |
| `--max-flood-peers` | 32 |
| `--flood-rate` | 1000 frames/s |
| `--flood-burst` | 2000 frames |
| `--mac-age-seconds` | 300 |
| `--heartbeat-seconds` | 10 |
| `--peer-lease-seconds` | 30 |
| `--session-lifetime-seconds` | 900 |
| `--reassembly-timeout-ms` | 3000 |

`--confidentiality authenticate-only` keeps Ethernet payload bytes visible but
still requires authenticated data packets. Policy values are validated by the
canonical protocol codec before the network is committed.

```powershell
stella-server --config C:\Stella\server.toml network list
stella-server --config C:\Stella\server.toml network show --network <network-id>
stella-server --config C:\Stella\server.toml network delete --network <network-id>
```

Deletion is idempotent. It atomically removes the network, memberships,
endpoints, and unused join tokens and prints `deleted` or `absent`.

## Single-use tokens

```powershell
stella-server --config C:\Stella\server.toml enrollment-token create
stella-server --config C:\Stella\server.toml join-token create --network <network-id>
```

Both commands accept `--ttl-seconds`; the default is 3600 seconds and zero is
rejected. A successful command writes one unpadded base64url bearer token and a
newline to stdout exactly once. Redirect stdout to a protected destination if
the token must be transferred programmatically. The database stores only a
domain-separated digest, and each token is consumed atomically with its
enrollment or join operation.

## Nodes and memberships

```powershell
stella-server --config C:\Stella\server.toml node list
stella-server --config C:\Stella\server.toml node disable --node <node-id>
stella-server --config C:\Stella\server.toml node enable --node <node-id>

stella-server --config C:\Stella\server.toml member add --network <network-id> --node <node-id>
stella-server --config C:\Stella\server.toml member suspend --network <network-id> --node <node-id>
stella-server --config C:\Stella\server.toml member resume --network <network-id> --node <node-id>
stella-server --config C:\Stella\server.toml member remove --network <network-id> --node <node-id>
```

Effective authorization changes rotate the affected grant serial and advance
the network epoch and peer-snapshot revision in the same transaction. Repeating
an already satisfied operation is safe. Disabling a node invalidates all of its
network grants immediately.

## State maintenance

```powershell
stella-server --config C:\Stella\server.toml state verify
stella-server --config C:\Stella\server.toml state backup --output C:\Stella\backups\controller.redb
```

`state verify` walks all authority records and prints `ok` only if every schema
and cross-record invariant holds. `state backup` creates a point-in-time copy
through the authority thread, synchronizes it, opens it independently, and
runs the same verifier before reporting its byte size. The output path must not
exist; live database files must not be copied directly.
