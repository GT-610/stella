# Deploy a controller on Windows

This guide creates one self-hosted Stella controller deployment on Windows.
The controller is functional, but the Windows client and Ethernet data plane
are still under development; these steps prepare the control plane rather than
forming a usable virtual LAN by themselves.

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
database alone cannot recreate the same controller trust identity.

For every administration command and policy default, see the
[server CLI reference](/api/server-cli).
