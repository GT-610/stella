# Windows client CLI

`stella-client` owns one protected node identity, strict controller trust, the
durable desired-network list, and the Windows TAP/data-plane runtime. Commands
use `--config client.toml` unless another path is supplied.

## Prerequisites and reachability

Each client needs its own pre-installed TAP-Windows Adapter V9. The controller
must be reachable over its configured TLS/TCP address, either directly or
through the optional explicit HTTPS proxy. The runtime gathers direct UDP
candidates and uses controller-provided STUN and relay services. A manually
forwarded client port is optional: if direct ICE checks fail, the client tries
TURN UDP, TCP, TLS, then secure WebSocket. At least one direct or relay path
must succeed. Run `run` from an elevated PowerShell session so the process can
open its TAP adapter.

Stella is a Layer-2 overlay: it does not assign IP addresses or provide DHCP.
Configure addresses on the TAP adapters yourself, or provide DHCP inside the
virtual LAN.

## Initialize

```powershell
stella-client --config C:\Stella\client.toml init `
  --controller 203.0.113.10:44900 `
  --tls-name controller.example.net `
  --controller-id 0123456789abcdef0123456789abcdef `
  --spki-pin sha256/BASE64_SHA256_SPKI_DIGEST= `
  --display-name "Gaming PC" `
  --udp-bind 0.0.0.0:45100 `
  --https-proxy 192.0.2.40:8080
```

Omit `--https-proxy` on networks that permit direct outbound controller TCP.

`init` creates the configuration and `secrets/node.pk8` with create-new
semantics. On Windows, identity inheritance is disabled and only the current
account and `LocalSystem` receive access. Existing targets are never replaced;
failed initialization removes only targets created by that invocation.

Successful output contains the lowercase node ID and configuration path. The
configuration initially has no network entries and an empty
`transport.advertised_endpoints` list. It is valid to leave this list empty when
the controller supplies usable STUN or relay services. Add an endpoint only
when the deployment has a known externally reachable mapping whose port matches
`udp_bind`:

```toml
[[transport.advertised_endpoints]]
address = "192.0.2.20:45100"
priority = 10
max_datagram_size = 1200
```

Static endpoints improve direct-path discovery but are not a substitute for a
real public mapping. Do not publish an unroutable private address as an Internet
candidate. When `transport.https_proxy` is present, controller bootstrap first
connects to that numeric proxy and sends a bounded HTTP CONNECT for the
configured controller TLS name and port. After authentication, the same proxy
is used for the last secure WebSocket relay fallback:

```toml
[transport]
udp_bind = "0.0.0.0:45100"
https_proxy = "192.0.2.40:8080"
```

TLS 1.3, server-name and SPKI verification, Stella controller authentication,
and Relay TLS/WSS authentication remain end to end inside their tunnels. The
proxy does not affect direct UDP, TURN UDP, TURN TCP, or direct TURN TLS, which
retain their normal earlier attempts. The first profile supports proxies that
do not require authentication. A `407` response fails closed, and Stella never
sends enrollment, join, controller, or relay credentials in a plaintext
CONNECT request.

Enrollment and join tokens are never accepted by `init` and are never written
to disk.

## Join

```powershell
stella-client --config C:\Stella\client.toml join `
  --network <id> `
  --token <unpadded-base64url-token> `
  --tap-adapter "Stella LAN"
```

For a node not yet enrolled with the controller, add the one-use
`--enrollment-token <unpadded-base64url-token>` argument. Both token forms must
decode to exactly 32 bytes. They remain process-local, are redacted from debug
output, and are never written to the configuration.

`join` authenticates and waits for a complete validated controller snapshot
before atomically persisting the network ID and TAP adapter. Repeating an
already accepted join may omit `--token`; repeating it with the same TAP adapter
is idempotent, while a conflicting adapter is rejected before contacting the
controller.

## Status

```powershell
stella-client --config C:\Stella\client.toml status
```

`status` is an offline command. It validates the configuration and protected
identity, then prints the derived node ID, controller address/name/ID, optional
HTTPS proxy, UDP bind, and each desired network with its TAP adapter. It never
prints SPKI pins, credentials, private key material, or the private-key path.

## Leave

```powershell
stella-client --config C:\Stella\client.toml leave --network <id>
```

`leave` requires an existing desired-network entry. It starts with no active
forwarding state, authenticates without accepting token material, validates the
controller's authoritative `LEAVE_RESULT`, and only then atomically removes the
network from local configuration. A failed or ambiguous request never enables
forwarding and preserves durable intent for recovery or retry.

## Run

```powershell
stella-client --config C:\Stella\client.toml run
```

`run` validates the configuration and protected identity, initializes the
configured tracing filter, authenticates, rejoins desired networks in stable ID
order without stored tokens, and publishes the complete configured endpoint
set. It then owns the active controller state, applying snapshots, peer deltas,
grant refreshes, and heartbeat reconciliation.

Controller failures withdraw all in-memory forwarding authorization before a
full-jitter reconnect delay. Backoff starts at 250 ms and caps at 30 seconds.
A heartbeat is treated as lost only after three policy heartbeat periods elapse
without its acknowledgement. Ctrl+C cancels the session and drops all active
state before the process exits. On Windows, the active owner binds the
configured UDP socket, opens each exact TAP adapter, completes peer handshakes,
and forwards authenticated Layer-2 frames. Invalid peer datagrams are dropped
without reconnecting the controller; TAP, UDP, or worker failures end the
active session and use the normal fail-closed reconnect path.
