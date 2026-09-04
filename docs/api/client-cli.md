# Client CLI

`stella-client` owns one protected node identity, strict controller trust, the
durable desired-network list, and the native Windows or macOS TAP/data-plane
runtime. Commands use `--config client.toml` unless another path is supplied.

## Prerequisites and reachability

Windows clients need one pre-installed TAP-Windows Adapter V9 per configured
network and run from an elevated PowerShell session. macOS clients need two
distinct numeric feth names per network that are not owned by another active
process. A matching Stella-owned persistent pair may already exist and is
reused when the client starts. The normal client remains unprivileged; a
separately started root `stella-tap-helper` creates or reuses the pair and
performs only bounded TAP operations.

The controller must be reachable over its configured TLS/TCP address, either
directly or through the optional explicit HTTPS proxy. The runtime gathers
direct UDP candidates and uses controller-provided STUN and relay services. A
manually forwarded client port is optional: if direct ICE checks fail, the
client tries TURN UDP, TCP, TLS, then secure WebSocket. At least one direct or
relay path must succeed.

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
semantics. Windows disables identity inheritance and grants access only to the
current account and `LocalSystem`. macOS requires a single-link regular file
with mode `0600` and refuses symlinks. Existing targets are never replaced;
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

Windows selects the exact pre-installed adapter:

```powershell
stella-client --config C:\Stella\client.toml join `
  --network <id> `
  --token <unpadded-base64url-token> `
  --tap-adapter "Stella LAN"
```

macOS selects both ends of one feth pair. The first name is host-visible; the
second is reserved for Stella packet I/O:

```sh
stella-client --config /etc/stella/client.toml join \
  --network <id> \
  --token <unpadded-base64url-token> \
  --tap-adapter feth100 \
  --tap-peer feth101
```

For a node not yet enrolled with the controller, add the one-use
`--enrollment-token <unpadded-base64url-token>` argument. Both token forms must
decode to exactly 32 bytes. They remain process-local, are redacted from debug
output, and are never written to the configuration.

`join` validates the local TAP selection, authenticates, and waits for a
complete validated controller snapshot before atomically persisting the
network ID and selection. Repeating an already accepted join may omit
`--token`; the same Windows adapter or same complete macOS pair is idempotent.
A conflicting adapter or peer is rejected before contacting the controller.

The resulting macOS entry remains configuration version 1:

```toml
[[networks]]
id = "fedcba9876543210fedcba9876543210"
tap_adapter = "feth100"
tap_peer = "feth101"
```

## Status

```powershell
stella-client --config C:\Stella\client.toml status
```

`status` is an offline command. It validates the configuration and protected
identity, then prints the derived node ID, controller address/name/ID, optional
HTTPS proxy, UDP bind, and each desired network with its TAP selection. macOS
entries include both `tap_adapter` and `tap_peer`. It never prints SPKI pins,
credentials, private key material, or the private-key path.

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

Windows:

```powershell
stella-client --config C:\Stella\client.toml run
```

macOS:

```sh
sudo stella-tap-helper --allow-uid "$(id -u)"
# In another terminal:
stella-client --config /etc/stella/client.toml run
```

`run` validates the configuration and protected identity, initializes the
configured tracing filter, authenticates, rejoins desired networks in stable ID
order without stored tokens, and publishes the complete configured endpoint
set. It then owns the active controller state, applying snapshots, peer deltas,
grant refreshes, and heartbeat reconciliation.

Unexpected controller failures retain the native data runtime while the
client waits for a full-jitter reconnect delay, reauthenticates, and rejoins
its configured networks. Retained forwarding uses only the last completely
validated in-memory view: it cannot add peers or extend grants, connectivity
credentials, network epochs, or peer-session lifetimes. Backoff starts at 250
ms and caps at 30 seconds. A heartbeat is treated as lost only after three
policy heartbeat periods elapse without its acknowledgement. Ctrl+C interrupts
the control loop and waits for TAP, UDP, and Relay cleanup before the process
exits.

Windows opens each exact TAP-Windows adapter and sets it media-disconnected on
shutdown. On macOS the root helper creates or reuses each exact feth pair, uses
BPF receive and AF_NDRV transmit, and sets the host-visible interface down
without deleting the pair. The client and helper authenticate each other with
Unix peer credentials. Invalid peer datagrams are dropped without reconnecting the controller;
TAP, UDP, or worker failures close the data runtime and use the normal
fail-closed reconnect path.
