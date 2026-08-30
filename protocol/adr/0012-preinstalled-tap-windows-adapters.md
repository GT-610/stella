# ADR 0012: Open pre-installed TAP-Windows adapters by stable identity

- Status: Accepted
- Date: 2026-08-30

## Context

The Windows reference client needs a Layer-2 adapter, but installing, removing,
renaming, or restarting a kernel network driver is a machine-administration
operation with rollback and signing requirements. TAP-Windows exposes an
exclusive userspace device path derived from the adapter GUID, while the
connection name shown by Windows is mutable. Its packet I/O can remain pending
indefinitely, and its driver MTU is fixed when the miniport starts.

The library must preserve complete Ethernet frames, support orderly client
shutdown, and avoid silently selecting the wrong adapter on machines with
multiple VPN products.

## Decision

`stella-tap` opens an already installed TAP-Windows Adapter V9. Driver
installation, adapter creation, removal, rename, enable/disable, persistent MAC
changes, and driver restart remain installer or administrator responsibilities.

Windows adapters are enumerated through the IP Helper API. An explicit selector
matches either the connection-friendly name or the canonical interface GUID,
case-insensitively. Without a selector, exactly one TAP-Windows candidate must
exist; zero and multiple candidates are typed errors. The chosen device path is
`\\.\Global\{interface-guid}.tap`, and the implementation accepts it only after
the TAP driver answers its version, MAC, and MTU control requests.

The device is opened exclusively with overlapped I/O. A separate cancellation
handle can call `CancelIoEx` while a blocking worker owns the device, allowing a
pending frame read or write to finish with a typed cancellation result. Creation
sets media connected and enables reconstruction of 802.1Q metadata. Explicit
destroy and best-effort drop set media disconnected before closing the handle.

Configuration carries both the Layer-3 MTU and the largest complete frame the
network will accept. The frame bound is 14 through 9,216 bytes and must be at
least `mtu + 14`. A read buffer smaller than that configured bound is rejected
before issuing a driver read, so TAP-Windows cannot consume a frame and expose a
truncated prefix. Writes are one overlapped operation and partial completion is
an error.

TAP-Windows has no runtime driver-MTU setter. The backend therefore rejects an
MTU above the driver-reported ceiling. For a supported value, it updates the
Windows IPv4 and IPv6 interface MTUs transactionally through IP Helper and rolls
back the first family if the second update fails. Jumbo support requires an
administrator to configure and restart the adapter before Stella opens it.

All Windows FFI uses the `windows` crate. Unsafe blocks stay inside the Windows
backend, expose no raw handles, and document their pointer and lifetime
invariants.

## Consequences

Runtime code cannot unexpectedly install or reconfigure a kernel driver, and
adapter selection is deterministic. Client shutdown can wake a blocked TAP
worker without terminating the process. Complete-frame semantics are enforced
before bytes enter protocol processing.

Users must install and provision one TAP-Windows V9 adapter per Stella network.
Changing the driver MTU or persistent MAC still needs elevated administrative
tooling and a miniport restart. Machines with several candidate adapters must
name the intended one explicitly.
