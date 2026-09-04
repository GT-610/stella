# macOS feth TAP implementation

`stella-tap` presents a persistent macOS feth pair as the same synchronous,
complete-Ethernet-frame contract used by the rest of Stella. The implementation
is owned by Stella: BPF receives frames, `AF_NDRV` transmits them, and a narrow
root helper exposes that device through a bounded local protocol to the
unprivileged client.

## Interface roles

| Stella field | Example | Role |
| --- | --- | --- |
| `TapConfig::name` / `tap_adapter` | `feth100` | Host-visible interface for IP configuration, DHCP, and packet capture |
| `TapConfig::peer_name` / `tap_peer` | `feth101` | Stella-only packet-I/O side; BPF receives and `AF_NDRV` transmits |

Both values are required on macOS, must be distinct, and must match the exact
numeric `feth<N>` form. Physical interfaces such as `en0` are rejected. ICE
host-candidate enumeration excludes both names so the virtual pair cannot be
mistaken for an underlay path.

## Native backend and ownership

The root backend acquires a canonical exclusive lock in `/var/run/stella/`.
The directory and lock must be private and root-owned. A successful initial
creation records the visible and peer roles in the lock file. Reuse requires
that ownership record; Stella refuses to re-pair pre-existing feth interfaces
that it cannot prove it previously managed.

The backend creates missing interfaces with the Darwin interface-cloning ioctl,
queries and configures the peer relationship with feth driver-specific ioctls,
assigns each newly created host-visible interface a random locally administered
unicast MAC address, and opens nonblocking, close-on-exec packet descriptors.
An already correct relationship is reused without issuing another `SET_PEER`;
an unpaired pair is connected, while a conflicting relationship is rejected.
Setup tracks which interfaces this attempt created. A failure before the
ownership record is committed restores reused interface state and destroys only
interfaces created by that attempt. Numeric feth units are limited to the
kernel-supported `0..=9999` range.

`destroy` and `Drop` close packet I/O, set both feth interfaces down, and release
the lock. They deliberately leave the pair present. A later helper session can
reuse it, preserving host IP configuration within the current boot.

## Frame I/O and cancellation

BPF is receive-only. One kernel read can contain several aligned records, so
the parser validates every header, captured/original length, boundary, and
alignment step before queueing complete frames. The user-space queue is drained
before polling BPF again. Truncated records are rejected.

Writes always use `AF_NDRV`, including frames above BPF's practical 2,048-byte
injection ceiling. A short system write becomes `PartialFrameWrite`; diagnostics
never include frame bytes.

A nonblocking self-pipe interrupts `poll`. It is triggered only while an
operation is pending, repeated cancellation is idempotent, and completion
drains the pipe before the next operation. If packet I/O and cancellation are
both ready, the backend attempts packet I/O first so an already completed frame
is retained.

## Privileged helper

The normal macOS `PlatformTapDevice` is `MacosTapProxyDevice`. It connects to
`/var/run/stella-tap-helper.sock` and verifies that the server peer UID is root.
The foreground `stella-tap-helper` process requires root and an explicit
`--allow-uid`; its mode-`0600` socket is owned by that user, and it independently
checks every client's peer UID.

The protocol is versioned and length-prefixed. Messages and diagnostics have
hard size limits, each connection can open only one pair, the device-command
queue holds one pending command, and the service permits at most 64 sessions.
Cancellation travels separately from a pending request. Client EOF cancels I/O,
sets the pair down, releases its lock, and closes the session. The helper never
receives node keys, controller credentials, Stella session keys, UDP packets,
or Relay state.

## MTU behavior

At open time the backend reads the existing visible-side MTU and applies the
lower of that value and the signed network-policy limit. It never raises a
lower host setting merely to reach the policy maximum. Explicit MTU changes
update both interfaces; failure on the peer restores the visible side, and a
failed rollback is reported separately.

macOS defaults `net.link.fake.max_mtu` to a value that can be lower than
Stella's protocol ceiling. XNU copies that value into each feth when the
interface is created, so the root backend raises the runtime, system-wide limit
to `9202` before creating either side of a pair. It verifies the per-interface
ceiling when opening a pair and reports an explicit error for an older feth that
was created with a lower ceiling. It never lowers an existing value or restores
the previous limit during shutdown; doing so could invalidate another process's
concurrently active feth interface. The setting is not persisted across a
reboot.

## Verification

Unprivileged tests cover feth names, ioctl constants, strict BPF batches,
helper message bounds and round trips, peer authentication, idle and pending
cancellation, disconnect cleanup, proxy frame I/O, and MTU requests. The
ignored root-only test covers real feth lifecycle, MAC, both MTUs, a 4,096-byte
`AF_NDRV` transmission, BPF receive, locking, cancellation, persistence, and
reuse.

```sh
cargo test -p stella-tap
cargo test -p stella-tap --test macos_tap --no-run
sudo "$(find target/debug/deps -type f -name 'macos_tap-*' -perm -111 -print -quit)" \
  --ignored --nocapture
```

The full helper-backed two-client scenario is documented in
[`tests/two-node-lan/README.md`](https://github.com/GT-610/stella/blob/main/tests/two-node-lan/README.md).
