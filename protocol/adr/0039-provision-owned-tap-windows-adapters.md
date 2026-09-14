# ADR 0039: Provision owned per-network TAP-Windows adapters

- Status: Accepted
- Date: 2026-09-13
- Supersedes: ADR 0012

## Context

ADR 0012 required users to provision and select one TAP-Windows adapter for
every Stella network. That makes multi-network membership depend on Windows
driver tooling that ordinary users should not need to understand. Installing or
reconfiguring a signed kernel driver package remains a machine-wide operation,
but creating a root device from an already installed package has a narrower
lifecycle that the client can own.

Friendly names alone do not prove device ownership. Concurrent client processes
can also race while one process creates, opens, commits, rolls back, or removes
an adapter. Automatic provisioning therefore needs persistent identity evidence
and a transaction boundary that spans the complete client operation.

## Decision

The signed TAP-Windows Adapter V9 package must already be present in Windows
Driver Store. Stella does not install or remove that package, persist a MAC,
edit the driver MTU, or restart a miniport.

`stella-tap` provisions one root device per network through SetupAPI. It creates
a network-class device with hardware ID `tap0901`, lets `DiInstallDevice` choose
the installed signed package, waits for `NetCfgInstanceId`, records that
canonical interface GUID in a Stella-specific driver registry value, and then
renames the connection. A failure after registration removes the partial device.
Reuse and removal require the persisted marker to match the device's current
interface GUID; a friendly-name match without that proof is rejected.

Device management is serialized across Stella processes by a named Windows
mutex. The reference client holds the transaction guard across each complete
`join`, `run`, or `leave` command, including ensure, provisioning, configuration
commit, rollback, and removal. The current-thread Tokio runtime preserves the
thread-affine mutex ownership until the guard is released.

`stella-client` maps every network deterministically to
`Stella <32-character-network-id>`. Configuration schema version 2 enforces that
derived name for newly written or edited Windows entries. Version 1 entries are
normalized in memory and rewritten as version 2 on the next network-intent
mutation. `join` ensures the adapter before consuming join credentials and
removes a device newly created by that attempt if controller joining or local
persistence fails. `run` recreates a missing managed adapter. Normal shutdown
keeps the persistent device for reuse, while a confirmed `leave` removes it and
always removes the durable network intent even if device cleanup fails.

The complete-frame, overlapped-I/O, cancellation, MTU, and media-state behavior
from ADR 0012 remains unchanged.

## Consequences

Users install the TAP-Windows driver package once. Joining multiple Stella
networks automatically creates isolated, stable adapters without exposing a
Windows adapter selector, and leaving a network removes only a device whose
persisted identity proves Stella created it.

Creation and removal still require elevation. An older unmarked adapter that
happens to use a Stella-derived friendly name is not adopted or deleted; an
administrator must resolve that conflict explicitly. Only one Stella client
process can own the Windows TAP management transaction at a time.
