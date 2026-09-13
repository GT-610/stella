# ADR 0012: Provision per-network TAP-Windows adapters from Driver Store

- Status: Accepted
- Date: 2026-08-30
- Updated: 2026-09-13

## Context

The Windows reference client needs one isolated Layer-2 adapter per joined
network. Requiring users to create and name every adapter makes multi-network
membership depend on Windows driver tooling that ordinary users should not need
to understand. Installing or removing a signed kernel driver package and
changing its persistent settings still have machine-wide signing, rollback, and
restart consequences, but creating a root device from an already installed
package has a narrower lifecycle that the client can own.

TAP-Windows exposes an exclusive userspace device path derived from the adapter
GUID, while the connection name shown by Windows is mutable. Its packet I/O can
remain pending indefinitely, and its driver MTU is fixed when the miniport
starts.

The library must preserve complete Ethernet frames, support orderly client
shutdown, and avoid silently selecting the wrong adapter on machines with
multiple VPN products.

## Decision

The signed TAP-Windows Adapter V9 package must already be present in Windows
Driver Store. Stella does not install or remove that package, persist a MAC,
edit the driver MTU, or restart a miniport.

`stella-tap` owns creation, naming, reuse, and removal of Stella's root devices.
For a missing friendly name, it creates a network-class device with hardware ID
`tap0901`, registers it through SetupAPI, calls `DiInstallDevice` without an
explicit driver list so Windows selects the existing signed package, waits for
`NetCfgInstanceId`, and assigns the requested connection name. Any failure after
registration removes the partial device. Removal uses SetupAPI and waits for
the interface to disappear unless Windows reports that a reboot is required.

`stella-client` deterministically maps each network to
`Stella <32-character-network-id>`. `join` ensures the adapter before consuming
join credentials and removes a device newly created by that attempt if joining
or persistence fails. `run` recreates a missing configured adapter before
controller traffic starts. Normal shutdown keeps the persistent device for
reuse and only sets media disconnected; `leave` removes the managed device.
Creation and removal require elevation.

Windows adapters are enumerated through the IP Helper API. The lower-level
library selector matches either the connection-friendly name or the canonical
interface GUID, case-insensitively. A missing GUID is never treated as a name to
create. Without a selector, exactly one TAP-Windows candidate must exist; zero
and multiple candidates are typed errors. The chosen device path is
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

Users install the TAP-Windows driver package once; Stella provisions one stable,
persistent adapter per network without exposing adapter selection in the Windows
CLI. Joining multiple networks therefore creates multiple isolated adapters,
and leaving a network removes only its deterministic managed device. A failed
join does not leave a newly created orphan.

Stella still cannot silently install or reconfigure a kernel driver package.
Changing the driver MTU or persistent MAC needs external elevated tooling and a
miniport restart. Client shutdown can wake a blocked TAP worker without
terminating the process, and complete-frame semantics are enforced before bytes
enter protocol processing.
