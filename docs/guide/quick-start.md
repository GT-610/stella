# Quick start

This page shows the shortest current path into the Stella reference
implementation. Stella remains experimental: binaries must currently be built
from source, and Windows and macOS clients still need a native Layer-2
interface. Invitations reduce the controller identity, certificate pin, and
token material that users must transfer without weakening those checks.

## Join an existing network

Obtain these items from the administrator:

- `stella-client`, plus `stella-tap-helper` on macOS;
- one single-use invitation beginning with `stella1:`;
- the Windows TAP-Windows adapter name or two unused macOS feth names;
- the IP address and subnet mask assigned for this Layer-2 network.

An invitation contains single-use bearer credentials and expires after one hour
by default. Deliver it through a trusted private channel; do not post it to a
group chat, log, ticket, or source repository.

Run this from an elevated PowerShell on Windows:

```powershell
$Invitation = Read-Host 'Stella invitation'
$Invitation | C:\Stella\stella-client.exe --config C:\Stella\client.toml join `
  --invite-file - `
  --display-name $env:COMPUTERNAME `
  --tap-adapter 'Stella LAN'
$Invitation = $null
```

On macOS:

```sh
printf 'Stella invitation: ' >&2
IFS= read -r -s invitation
printf '\n' >&2
printf '%s\n' "$invitation" | stella-client --config /etc/stella/client.toml join \
  --invite-file - \
  --display-name "$(scutil --get ComputerName)" \
  --tap-adapter feth100 \
  --tap-peer feth101
unset invitation
```

`--invite-file -` reads the invitation from standard input, keeping it out of
the process argument list and shell history. A path to a permission-protected
file may be supplied instead.

When no configuration exists, `join` creates a protected node identity and a
strict controller trust configuration from the invitation, then enrolls the
node and joins the network. With an existing configuration, the invitation's
controller address, TLS name, controller ID, and SPKI pin must match the stored
trust. After a successful join, inspect local state with:

```powershell
C:\Stella\stella-client.exe --config C:\Stella\client.toml status
```

## Configure the Layer-2 interface

Stella transparently carries Ethernet frames; it does not allocate IP addresses
or provide DHCP. Configure the administrator-assigned address on `Stella LAN`
on Windows or the host-visible `feth100` end on macOS. Nodes must use the same
virtual subnet without address conflicts.

macOS also needs the narrowly privileged helper in one terminal:

```sh
sudo stella-tap-helper --allow-uid "$(id -u)"
```

## Run the client

Windows:

```powershell
C:\Stella\stella-client.exe --config C:\Stella\client.toml run
```

macOS, in another terminal:

```sh
stella-client --config /etc/stella/client.toml run
```

## Create a network and invitations

These commands assume the controller and connectivity services have been set up
with the [server deployment guide](./server-deployment). Create the network:

```powershell
$NetworkId = & C:\Stella\stella-server.exe --config C:\Stella\server.toml `
  network create --name 'Game LAN'
```

Generate a separate invitation for every client. `--controller` must be the
numeric address that client can actually reach, and `--tls-name` must be present
in the controller certificate:

```powershell
& C:\Stella\stella-server.exe --config C:\Stella\server.toml invite create `
  --network $NetworkId `
  --controller 203.0.113.10:44900 `
  --tls-name controller.example.net
```

The command prints the invitation exactly once. Each invitation is for one new
node and must not be reused across devices. Once the controller is running, the
client can follow the first section of this page.

The detailed [client CLI](../api/client-cli) and
[server CLI](../api/server-cli) remain available when an operator needs to
manage enrollment tokens, join tokens, or multiple SPKI pins separately.
