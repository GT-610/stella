# Server administration CLI

`stella-server` provides offline authority administration commands. Every
command loads the strict TOML configuration named by `--config` (default:
`server.toml`), derives the controller ID from the protected controller
identity, opens the configured redb database, and performs database work on the
serialized authority thread.

The daemon lifecycle commands are documented separately when they become
available. The commands on this page are implemented and covered by tests.

## Common syntax

```powershell
stella-server --config C:\Stella\server.toml <command>
```

Network IDs and node IDs are canonical 16-byte identifiers written as exactly
32 hexadecimal digits. Hexadecimal input is case-insensitive; output is lower
case. Successful mutation commands print only the result needed by scripts.
Errors and diagnostic context go to stderr and produce a non-zero exit code.

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
