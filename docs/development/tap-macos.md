# macOS feth TAP implementation

`stella-tap` presents a persistent macOS feth pair as the same synchronous,
complete-Ethernet-frame contract used by the rest of Stella. The backend uses
the released `tun-rs` 2.8.8 implementation instead of duplicating its unsafe
BPF, AF_NDRV, and ioctl code.

## Interface roles

| Stella field | Example | Role |
| --- | --- | --- |
| `TapConfig::name` / `tap_adapter` | `feth100` | Host-visible interface for IP configuration, DHCP, and packet capture |
| `TapConfig::peer_name` / `tap_peer` | `feth101` | Stella-only packet-I/O side; BPF receives and AF_NDRV transmits |

Both values are required on macOS, must be distinct, and must match the exact
numeric `feth<N>` form. Physical interfaces such as `en0` are rejected. ICE
host-candidate enumeration excludes both names so the virtual pair cannot be
mistaken for an underlay path.

## Creation and ownership

The backend first acquires an exclusive advisory lock in `/var/run/stella/`.
That directory must be root-owned and inaccessible to group or other users.
The lock filename is based on the sorted pair, so `feth100/feth101` conflicts
with `feth101/feth100`.

It then asks `tun-rs::DeviceBuilder` for `Layer::L2` with the explicit visible
and peer names, `reuse_dev(true)`, and `persist(true)`. I/O is nonblocking and
uses the interruptible synchronous API. The first release requires the owning
client process to run as root; there is no Stella helper, daemon, kext, or
DriverKit component.

`destroy` and `Drop` disable the host-visible interface, close packet I/O, and
release the lock. They deliberately leave both feth interfaces present. A later
client start re-pairs and reuses them, which preserves host IP configuration
within the current boot. Administrators should delete a pair only after
stopping every owner and confirming the exact names.

## Frame I/O and cancellation

The upstream macOS Layer-2 implementation uses BPF to receive complete frames
from the peer and AF_NDRV to inject frames toward the host-visible interface.
AF_NDRV is required because BPF injection cannot carry frames above 2,048
bytes. Stella still validates the configured 14-to-9,216-byte complete-frame
bound before I/O and rejects partial writes.

One mutex-protected state records whether an operation is pending and whether
it was cancelled. An idle cancellation returns successfully without triggering
the interrupt event. A pending cancellation triggers it, completion clears the
state and resets the event, and a successful completed frame is retained if
completion races cancellation. The cancellation handle is weak and remains an
idempotent no-op after the device closes.

## MTU behavior

At open time the backend reads the existing feth MTU and applies the lower of
that value and the signed network-policy limit. It never raises a lower host
setting merely to reach the policy maximum. `set_mtu` validates the complete
frame relationship and uses `tun-rs` to update both feth interfaces.

The host-visible interface is the only side on which applications should
configure IP. The peer exists only to satisfy the packet-I/O architecture.

## Verification

Portable macOS unit tests cover feth names, frame and MTU bounds, idle and
pending cancellation, repeated cancellation, event reset, completion races,
and redacted diagnostics. The ignored root-only test creates an isolated pair,
checks MAC and both MTUs, captures a 4,096-byte AF_NDRV transmission, cancels a
pending read, reads a host-generated ARP frame, verifies lock conflicts, and
confirms down-but-persistent reuse.

```sh
cargo test -p stella-tap
cargo test -p stella-tap --test macos_tap --no-run
sudo "$(find target/debug/deps -type f -name 'macos_tap-*' -perm -111 -print -quit)" \
  --ignored --nocapture
```

The full two-client scenario is documented in
[`tests/two-node-lan/README.md`](https://github.com/GT-610/stella/blob/main/tests/two-node-lan/README.md).
It reuses the Scapy verifier for ARP, bidirectional IPv4, broadcast, multicast,
LAN discovery, shutdown persistence, and same-pair restart.
