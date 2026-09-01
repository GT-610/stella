# Server administration CLI

`stella-server` initializes a controller deployment, runs its TLS control-plane
service, creates protected relay credential keys, and provides authority
administration commands. Commands that use deployment state load the strict
TOML configuration named by `--config` (default: `server.toml`). Commands that
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
