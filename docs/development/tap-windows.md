# Windows TAP implementation

`stella-tap` presents TAP-Windows Adapter V9 as a safe, synchronous complete-
Ethernet-frame device. It is intended to run on a dedicated blocking worker;
the asynchronous client runtime must not call frame I/O on a Tokio worker.

## Ownership boundary

The library requires the signed TAP-Windows Adapter V9 driver package to be
present in Windows Driver Store. It does not install or remove that package,
persist a MAC address, edit the driver MTU, or restart a miniport. Package and
miniport configuration remain installer or administrator responsibilities
because they can affect unrelated VPN software.

Stella does own root-device lifecycle for its named adapters. `ensure_adapter`
reuses a matching TAP adapter or creates one through SetupAPI with hardware ID
`tap0901`, lets `DiInstallDevice` select the existing signed package, waits for
its `NetCfgInstanceId`, records that GUID in a Stella-specific driver registry
value, and assigns the requested Windows connection name. Failure after
registration removes the partial device. Reuse and `remove_adapter` require the
marker to match the current interface GUID; a friendly-name match alone is
rejected. Removal waits for the interface to disappear unless Windows reports
that a reboot is required.

The client maps each network to `Stella <32-character-network-id>`. `join`
ensures that persistent adapter before using credentials, `run` recreates it if
it is missing, ordinary shutdown leaves it media-disconnected for later reuse,
and `leave` removes it. These device-management operations require elevation.
The client holds a named Windows mutex across each complete `join`, `run`, or
`leave` command so separate Stella processes cannot race device startup,
configuration commit, rollback, or removal.

One open `WindowsTapDevice` exclusively owns one TAP-Windows device handle. The
handle is closed by `destroy` or `Drop`; both first request media-disconnected
state. Drop is best effort because Rust destructors cannot report an operating-
system error.

## Adapter discovery and selection

The backend enumerates network adapters with the Windows IP Helper API. A
`TapConfig::name` selector may be either:

- the Windows connection-friendly name, such as `Local Area Connection`; or
- the interface GUID, with or without surrounding braces.

Matching is case-insensitive. A missing friendly-name selector is provisioned;
a missing GUID selector remains a not-found error. If no selector is supplied,
creation succeeds only when exactly one TAP-Windows candidate is installed.
Ambiguity is reported instead of depending on enumeration order.

The selected adapter GUID forms the documented TAP device path:

```text
\\.\Global\{INTERFACE-GUID}.tap
```

After opening that path, Stella queries the driver version, current MAC, and
driver MTU. A path that does not implement the TAP-Windows control interface is
rejected even if its display text looked similar.

## Configuration bounds

`TapConfig` separates two limits:

- `mtu` is the Windows Layer-3 MTU;
- `max_frame_size` is the largest complete Ethernet frame, without FCS, that
  Stella may accept from or write to this adapter.

The default is MTU 1,500 and frame size 1,514. `max_frame_size` must be between
14 and the Stella hard limit of 9,216 bytes and must be at least `mtu + 14`.
An 802.1Q network normally chooses 1,518. The configured frame size must not
exceed the TAP driver's MTU plus its four-byte VLAN allowance.

TAP-Windows reads its driver MTU when the miniport starts and has no IOCTL to
change it. Stella never edits that persistent registry setting behind the
administrator's back. `set_mtu` can select a value at or below the reported
driver ceiling and updates the IPv4 and IPv6 IP Helper rows. If the second
family fails, the first is restored before an error is returned. A larger MTU
requires external configuration and a driver restart.

## Frame I/O

The handle uses overlapped `ReadFile`, `WriteFile`, and `DeviceIoControl` calls.
Each call owns its event and `OVERLAPPED` storage until completion. The driver
returns one complete frame per read and rejects a short output buffer without
copying a prefix. Stella performs a stricter preflight check: caller storage
must hold the configured maximum before a read is submitted.

Writes validate the 14-byte Ethernet minimum and configured maximum, then issue
exactly one driver write. A short successful write is treated as an invariant
failure; the remainder is never submitted as a second frame.

TAP-Windows maps an incoming 802.1Q header to NDIS metadata. Stella enables the
driver behavior that reconstructs that header on outbound frames when the
metadata carries a VLAN ID or user priority.

No error or debug representation contains raw Ethernet bytes.

## Cancellation and shutdown

`WindowsTapDevice::cancellation_handle` returns a lightweight handle that does
not keep the adapter open. Another thread can call `cancel_pending_io`, which
uses `CancelIoEx` on the exact shared device handle. A pending read or write then
returns `TapError::Cancelled`.

The client shutdown sequence is:

1. stop submitting new outbound frames;
2. cancel pending TAP I/O;
3. join the blocking TAP worker;
4. call `destroy` to set media disconnected and close the device.

Cancellation is idempotent. Calling it when no I/O is pending is successful.

## Error model

Errors distinguish invalid bounds, no adapter, ambiguous selection, an
unsupported driver version, a busy or inaccessible device, cancellation,
short buffers, invalid frame lengths, partial writes, MTU transaction failure,
and other operating-system operations. Diagnostics may contain adapter names,
GUIDs, sizes, and stable operation names, but never frame contents.

## Verification

Portable unit tests cover configuration, frame bounds, selection, and error
classification. Windows unit tests additionally verify the control-code ABI,
GUID normalization, managed-name bounds, and hardware-ID encoding. One opt-in
platform test opens a real installed TAP-Windows adapter, checks driver metadata
and lifecycle, exercises one complete write, and cancels pending overlapped I/O.
A second elevated test creates, reuses, opens, and removes a uniquely named
adapter. Both tests clean up their owned state before returning.
