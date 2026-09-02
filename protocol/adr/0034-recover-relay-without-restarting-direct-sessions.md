# ADR 0034: Recover relay without restarting direct sessions

- Status: Accepted
- Date: 2026-09-02

## Context

The relay specification requires direct peer sessions to continue when a warm
relay fails. The Windows reference runtime previously treated a relay receive
or actor failure as a fatal data-plane error. Its supervisor then closed the
TAP devices, erased every direct session, reauthenticated the controller, and
rebuilt the complete runtime before attempting another relay.

That process eventually reconnects, but it turns an isolated relay or proxy
failure into avoidable disruption for peers that already have working direct
paths. It also couples relay availability to controller and TAP availability.

## Decision

The Windows data runtime owns relay recovery independently from the controller,
TAP workers, UDP socket, and established peer sessions. When the live relay
fails, the runtime removes only relay carrier availability, creates a fresh
local connectivity generation without the failed relay candidate, and asks the
control loop to publish that change. Existing direct sessions and forwarding
state remain active. Frames without a confirmed path continue to be dropped by
the existing bounded data plane rather than queued for recovery.

The runtime starts a replacement allocation in a separate owned task so DNS,
TCP, TLS, WebSocket, proxy, and TURN deadlines cannot stop direct packet or TAP
processing. The task uses the latest authenticated connectivity configuration,
ADR 0032's shared DNS preparation deadline, and ADR 0031's carrier budgets.
Failure schedules another attempt with full jitter and an exponential ceiling
from one to thirty seconds. Only one recovery task or retry timer exists.

On success, the runtime installs the authenticated allocation, prepares current
relay peer permissions, creates a new local connectivity generation, and asks
the control loop to publish it. A newer controller connectivity revision aborts
obsolete recovery work before applying the new configuration. Runtime shutdown
also aborts and joins recovery work.

Recovery errors and logs remain redacted. They may identify safe relay,
carrier, and retry timing metadata but never credentials, proxy response
content, packet bytes, session keys, or Ethernet addresses.

## Consequences

A relay restart, proxy disconnect, or stream failure no longer tears down
healthy direct game traffic or recreates TAP devices. Relay-only peers are
temporarily unreachable and their frames are dropped until a replacement path
is authenticated and published.

The runtime retains one owned copy of the latest controller-issued connectivity
configuration so it can retry without waiting for another control message.
Credentials remain zeroizing and bounded by the existing eight-service limit.
Background allocation briefly overlaps direct I/O but does not introduce an
unbounded task, queue, or retry rate.
