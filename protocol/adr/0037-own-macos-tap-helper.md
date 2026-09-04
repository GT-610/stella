# ADR 0037: Own the macOS TAP backend behind a privileged helper

- Status: Accepted
- Date: 2026-09-04
- Supersedes: ADR 0036's `tun-rs` dependency and root-client process boundary

## Context

ADR 0036 selected persistent feth pairs and a released `tun-rs` backend for the
first macOS Layer-2 milestone. That prototype proved the visible/peer model,
BPF receive, `AF_NDRV` transmit, cancellation, and persistent reuse. Further
review found that Stella used only a small subset of a dependency that also
maintains unrelated Layer-3 backends, while the exact synchronous feth behavior
and its open issues remained outside Stella's control.

Running the entire client as root also exposed controller credentials, node
identity, transport sockets, Relay state, and switching logic to privileges
needed only for feth setup and raw packet descriptors.

The implementation was informed by the macOS SDK, public Darwin/XNU behavior,
and independent tests. The released `tun-rs` code was reviewed as a behavioral
reference but is not copied, vendored, forked, or linked. ZeroTier's MPL-2.0
`osdep` material informed only the high-level separate-agent architecture; no
source was copied or translated, and its `nonfree` tree was not used.

## Decision

`stella-tap` owns the macOS backend. Unsafe code is concentrated in narrow
wrappers around documented SDK layouts and system calls. The implementation:

- creates explicit numeric feth interfaces with Darwin cloning ioctls;
- pairs them using the absolute `/sbin/ifconfig` executable without a shell or
  `PATH` lookup;
- receives complete frames through nonblocking BPF and strictly parses every
  aligned record in a kernel batch before polling again;
- transmits complete frames through nonblocking `AF_NDRV`, including frames
  larger than 2,048 bytes;
- uses close-on-exec descriptors and a nonblocking self-pipe for pending-only
  cancellation;
- applies pair MTUs with rollback and records persistent pair ownership only
  after all setup succeeds; and
- refuses to take over existing interfaces without matching root-owned Stella
  ownership metadata.

The normal macOS `PlatformTapDevice` is a proxy. A foreground root
`stella-tap-helper` owns native TAP handles and exposes a versioned,
length-prefixed Unix-socket protocol at `/var/run/stella-tap-helper.sock`.
Startup requires an explicit authorized UID. The socket is mode `0600` and
owned by that UID; the helper verifies the client peer UID, while the client
requires the server peer UID to be root.

Each helper connection owns at most one feth pair. Message sizes, diagnostic
sizes, the per-session command queue, and total sessions are bounded. A separate
cancel message can interrupt pending device I/O. EOF or protocol failure
cancels I/O, closes the native device, sets the pair down, and releases its
lock. The pair remains present for same-boot reuse.

The helper never receives controller trust, enrollment or join credentials,
the node private key, peer-session keys, UDP sockets, Relay allocations, or L2
switch state. Those remain in the unprivileged `stella-client` process.

Windows continues to use Stella's existing native TAP-Windows V9 backend. No
kext, DriverKit system extension, `tun-rs` dependency, fork, or vendored network
backend is introduced.

## Consequences

Stella now owns more macOS-specific unsafe code and must validate it against
future SDK and kernel changes. In exchange, the complete-frame behavior,
cancellation rules, BPF queue handling, ownership checks, and error model are
reviewed and tested with the rest of Stella rather than inherited indirectly.

The ordinary client no longer needs root. An administrator must still build,
install, and supervise the root helper and explicitly authorize one local UID.
The current implementation supplies a runnable foreground service and secure
IPC boundary; packaging it as a launch daemon is a separate deployment task.

Real feth lifecycle and two-node tests still require root. Their results must
not be inferred from compilation or unprivileged protocol tests.
