# Deploy a controller on Windows

This guide creates one self-hosted Stella controller deployment on Windows.
Together with configured Windows clients, the controller forms an experimental
Layer-2 virtual LAN. It is not a production networking release.

## Build the server

From the repository root:

```powershell
cargo build --release -p stella-server
New-Item -ItemType Directory -Force C:\Stella | Out-Null
Copy-Item .\target\release\stella-server.exe C:\Stella\
```

Run the remaining commands from an account that will also run the service.
`init` protects generated private keys for that Windows account and
LocalSystem; a different account is intentionally unable to load them.

## Initialize the deployment

Choose every DNS name or IP address that clients will use to reach the
controller. The certificate always includes `localhost`, `127.0.0.1`, and
`::1` in addition to these values.

```powershell
C:\Stella\stella-server.exe --config C:\Stella\server.toml init `
  --listen 0.0.0.0:44900 `
  --tls-name controller.example.net `
  --tls-name 192.0.2.10
```

The command refuses to overwrite an existing deployment. Record the printed
`controller_id` and `tls_spki_pin` through a trusted channel; clients use both
values to authenticate this controller. Never transfer files from
`C:\Stella\secrets` to clients.

Review `C:\Stella\server.toml` before continuing. Relative database,
certificate, and key paths resolve from the configuration file's directory.
Allow inbound TCP port 44900, or the custom port in `listen`, through the host
and upstream firewalls.

## Configure connectivity services

This optional version 0.2 section lets the controller distribute STUN servers,
Relay locations, TLS trust, and short-lived node-scoped Relay credentials. The
built-in server can run the configured TURN UDP, TURN TCP, TURN TLS, and secure
WebSocket services. STUN still requires a separately deployed service.

Create the shared credential authority key without exposing it on stdout:

```powershell
& C:\Stella\stella-server.exe relay-key create `
  --output C:\Stella\secrets\relay-credential.key
```

Then add a deployment revision and at least one STUN server and Relay service:

```toml
[connectivity]
revision = 1
credential_key = "secrets/relay-credential.key"
credential_lifetime_seconds = 300
stun_servers = ["192.0.2.20:3478"]

[[connectivity.relays]]
id = "01010101010101010101010101010101"
priority = 0
region = "primary"
hostname = "relay.example.net"
tls_server_name = "relay.example.net"
require_web_pki = true
turn_udp = 3478
turn_tcp = 3479
turn_tls = 5349
secure_websocket = 443
addresses = ["192.0.2.30", "2001:db8::30"]
```

The Relay ID must be a unique non-zero 16-byte hexadecimal value. A non-zero
carrier port enables that carrier. `credential_lifetime_seconds` defaults to
300 and accepts 60 through 600 seconds. Address and STUN list order is
preference order; Relay services are canonicalized by `priority` and ID. For a
private TLS authority, omit `require_web_pki` and configure one or more
canonical `sha256/<standard-base64>` values in `spki_pins`. Increase `revision`
whenever the deployment service definition changes.

Keep the credential key readable only by the controller account and trusted
Relay processes. Clients receive only short-lived credentials bound to their
node identity and a specific Relay ID. The controller refreshes them halfway
through their remaining lifetime over the authenticated control channel.

Start the four built-in carriers in separate processes. This example reserves
public TCP 443 for secure WebSocket so clients on networks that permit direct
outbound HTTPS/WSS retain their final fallback:

```powershell
$Server = 'C:\Stella\stella-server.exe'
$Config = 'C:\Stella\server.toml'

& $Server --config $Config relay run `
  --id 01010101010101010101010101010101 `
  --carrier udp `
  --listen 0.0.0.0:3478 `
  --advertise 192.0.2.30

& $Server --config $Config relay run `
  --id 01010101010101010101010101010101 `
  --carrier tcp `
  --listen 0.0.0.0:3479 `
  --advertise 192.0.2.30

& $Server --config $Config relay run `
  --id 01010101010101010101010101010101 `
  --carrier tls `
  --listen 0.0.0.0:5349 `
  --advertise 192.0.2.30

& $Server --config $Config relay run `
  --id 01010101010101010101010101010101 `
  --carrier websocket `
  --listen 0.0.0.0:443 `
  --advertise 192.0.2.30
```

Allow inbound UDP 3478 and TCP 3479, 5349, and 443 through the host and upstream
firewalls. The advertised IP must be reachable by every client. All carriers ask Windows for a
dynamic UDP port for each allocation, so those sockets must also be allowed by
the host firewall. If the relay is behind NAT, forward the Windows UDP dynamic
port range as well as 3478; a directly assigned public IP is preferable. You
can inspect the current range with `netsh int ipv4 show dynamicport udp`.

Each process refuses a listener port that differs from the selected relay's
matching `turn_udp`, `turn_tcp`, `turn_tls`, or `secure_websocket` value and exits
cleanly on Ctrl+C. TLS and secure WebSocket reuse the certificate and protected
key from `[tls]`; that certificate must cover `tls_server_name`. The WebSocket
endpoint is fixed at `/stella/turn/v1`, requires subprotocol `stella-turn.v1`,
authenticates before upgrade, and does not negotiate compression. Run it
directly on public TCP 443. Sharing that port with a website requires a distinct
IP or hostname and an L4 TLS/SNI passthrough proxy; an ordinary plaintext HTTP
upstream is not this listener. Use `--allocation-bind` for a specific local
allocation address. Capacity flags and current carrier limits are documented in
the [server CLI reference](/api/server-cli#run-a-turn-relay).

Windows clients try configured relay carriers in the order UDP, TCP, TLS, then
secure WebSocket. Failure of an earlier carrier automatically advances to the
next configured address without requiring port forwarding on the client.
On proxy-only networks, set the client's numeric
`transport.secure_websocket_proxy` address. The client establishes HTTP CONNECT
to the relay authority and then performs the unchanged Relay TLS and WSS
handshakes inside that tunnel. The first profile does not support proxy
authentication.

## Create a network and enrollment material

```powershell
$Server = 'C:\Stella\stella-server.exe'
$Config = 'C:\Stella\server.toml'

$NetworkId = & $Server --config $Config network create --name 'Game LAN'
$EnrollmentToken = & $Server --config $Config enrollment-token create
$JoinToken = & $Server --config $Config join-token create --network $NetworkId

$NetworkId
$EnrollmentToken
$JoinToken
```

Enrollment and join tokens are bearer credentials, expire after one hour by
default, are printed only once, and are consumed by the first successful use.
Keep them out of shell history, logs, and source control. Generate distinct
tokens for each node instead of sharing one token between clients.

## Verify and run

```powershell
& $Server --config $Config state verify
& $Server --config $Config run
```

`state verify` must print `ok`. The daemon validates deployment state again,
binds the configured TCP address, and writes operational logs to stderr. Press
Ctrl+C for an orderly shutdown; do not terminate the process while an offline
administration command is using the same database.

## Back up authority state

Use the coordinated backup command instead of copying the live redb file:

```powershell
New-Item -ItemType Directory -Force C:\Stella\backups | Out-Null
& $Server --config $Config state backup `
  --output C:\Stella\backups\controller-2026-08-31.redb
```

The destination must not already exist. Store the verified database backup
together with protected copies of the controller and TLS identities; the
database alone cannot recreate the same controller trust identity. If
connectivity services are enabled, also back up the Relay credential key; a
replacement invalidates credentials issued under the prior key.

For every administration command and policy default, see the
[server CLI reference](/api/server-cli).
