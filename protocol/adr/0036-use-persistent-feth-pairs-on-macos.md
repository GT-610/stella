# ADR 0036: Use persistent feth pairs for macOS Layer-2 access

- Status: Accepted
- Date: 2026-09-04

## Context

Stella requires complete Ethernet frames. macOS `utun` devices expose Layer 3,
so they cannot carry ARP, Ethernet broadcast, or arbitrary non-IP frames. A
kernel extension would add installation and signing requirements around an API
Apple has deprecated, while a DriverKit system extension or privileged helper
would substantially enlarge the first macOS deployment and security boundary.

macOS includes fake-Ethernet (`feth`) interfaces that can be paired like a
Linux veth pair. The host can configure one side as an ordinary Ethernet
interface. Packet I/O on the other side requires BPF for receive and AF_NDRV
for transmit; BPF injection alone has a 2,048-byte ceiling. These APIs are
low-level and partly undocumented.

`tun-rs` 2.8.8 already implements this feth, BPF, and AF_NDRV design, including
interruptible synchronous I/O and persistent-device reuse. Reimplementing that
unsafe ioctl and socket code inside Stella would duplicate a working upstream
implementation without improving the protocol boundary.

## Decision

The macOS `stella-tap` backend uses the exact released `tun-rs` version 2.8.8
with default features disabled and only `interruptible` enabled. Stella does
not copy, fork, or expose the upstream unsafe implementation.

Every configured macOS TAP is an explicit pair of distinct numeric `feth<N>`
names:

- `TapConfig::name` is the host-visible interface on which users configure IP
  addresses or run DHCP;
- `TapConfig::peer_name` is the packet-I/O side bound by BPF and AF_NDRV.

Physical interfaces and implicit allocation are rejected. The client stores
both names in version 1 configuration as `tap_adapter` and `tap_peer` and
compares the complete pair for idempotent join and conflict detection.

Creation selects `Layer::L2`, enables device reuse and persistence, and uses
nonblocking interruptible I/O. Reads preserve one complete BPF-delivered
Ethernet frame. Writes use the upstream AF_NDRV path, including frames larger
than 2,048 bytes, and treat partial completion as an error.

The requested network-policy MTU is capped by a lower existing interface MTU
when a pair is opened. An explicit later MTU update applies to both sides of the
pair. The protocol complete-frame ceiling remains independently enforced.

Cooperating Stella processes acquire a canonical pair lock in the root-owned,
mode-`0700` `/var/run/stella/` directory. The lock key is identical if the two
names are reversed. A second process receives a typed busy error instead of
re-pairing interfaces already owned by an active client.

Cancellation triggers the upstream interrupt event only while a read or write
is pending. Completion clears the pending state and resets the event; an idle
cancel does not affect the next operation, and an already completed frame wins
a simultaneous cancellation race.

The first implementation requires the client process to run as root. It does
not install a kernel extension, DriverKit extension, launch daemon, privileged
helper, or separate packet service. `destroy` and `Drop` stop I/O, release the
lock, and set the host-visible interface down, but they do not delete the pair.
The same names are reused on the next start, so host IP configuration can
survive client restarts during the current boot. Explicit test or administrator
tooling may delete a pair after confirming ownership.

## Consequences

The macOS client exposes the same complete-frame `TapDevice` contract as the
Windows client without adding Stella-owned unsafe networking code. ARP,
broadcast, multicast, non-IP Ethernet, and jumbo frames within the Stella limit
can use built-in macOS facilities.

Running the active data plane requires root, and persistent feth interfaces
remain visible after a normal client exit. The advisory lock prevents conflicts
only among cooperating processes. Administrators must allocate two distinct
feth names per Stella network and must not assign host IP configuration to the
packet-I/O peer.

Stella now depends on the pinned behavior of `tun-rs` 2.8.8. A future upstream
upgrade requires repeating the real feth lifecycle, cancellation, MTU,
large-frame, reuse, locking, and two-node Layer-2 verification.

Layer-3 `utun`, copied unsafe ioctl code, a deprecated kernel extension, and a
new privileged helper or daemon are rejected for this milestone. A later ADR
may replace the root process with a narrower privileged architecture after its
installation, update, IPC, and threat model are designed.
