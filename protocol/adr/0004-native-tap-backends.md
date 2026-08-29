# ADR 0004: Use native TAP backends behind one safe interface

- Status: Accepted
- Date: 2026-08-29

## Context

Layer-2 transparency requires complete Ethernet frames. Platform APIs differ:
Windows uses TAP-Windows device handles and control codes, Linux uses
`/dev/net/tun`, and macOS requires a suitable Layer-2-capable backend strategy.

## Decision

The `stella-tap` crate exposes one synchronous `TapDevice` contract for device
lifecycle, frame reads and writes, MAC address access, and MTU updates.
Platform modules are selected with `cfg` attributes. Windows uses the
`windows` crate and `DeviceIoControl`; the project does not use `winapi`.

The Windows backend is implemented and tested first. Unsupported platform
backends return a typed error until implemented rather than silently emulating
Layer 2 with a Layer-3 interface.

## Consequences

Upper layers remain independent of operating-system handles, and unsafe FFI is
contained. A synchronous contract is easy to test and can be integrated with
Tokio using a dedicated blocking task. Platform-specific installation and
privilege requirements remain unavoidable.
