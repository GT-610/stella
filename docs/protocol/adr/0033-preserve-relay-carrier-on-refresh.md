# ADR 0033: Preserve the reachable relay carrier on refresh

- Status: Accepted
- Date: 2026-09-02

## Context

The controller periodically replaces short-lived relay credentials and may
publish a new connectivity configuration revision. Initial relay allocation
uses the bounded UDP, TCP, TLS, and secure WebSocket fallback defined by ADR
0031. A client behind a strict firewall may therefore be online through
WebSocket even though unreachable UDP selections remain earlier in the
controller's preference order.

Re-evaluating only the first preferred selection during every configuration
revision attempts UDP again and ignores the proven WebSocket path. A silent
firewall can block the refresh, prevent the new revision from being applied,
and let the otherwise healthy relay allocation age past its credential expiry.

## Decision

For a new connectivity configuration, the Windows client builds the complete
ordered relay selection set. If that set contains settings exactly matching the
current live allocation, the client first refreshes its credentials in place,
regardless of where that carrier appears in preference order. The complete
refresh operation has a ten-second monotonic deadline.

If no exact selection remains, or the in-place refresh fails or times out, the
client applies the full carrier fallback and shared budgets from ADR 0031 to
the new selection set. Replacement is make-before-break: the old allocation is
retained until a new authenticated allocation is ready. The client then
installs the replacement and retires the old allocation as part of the same
revision application before publishing an updated connectivity generation.

Removing all relay selections shuts down the old allocation. The client records
the new connectivity revision only after the refresh, replacement, or removal
and all dependent local state changes succeed. A failed replacement therefore
cannot falsely acknowledge a configuration it did not apply.

Diagnostics identify only safe relay and carrier metadata. Credentials,
secrets, proxy responses, and packet content remain excluded.

## Consequences

A client that reached the network through secure WebSocket keeps using that
known-reachable carrier across ordinary credential rotations instead of
retesting silently blocked carriers on every revision. Material service,
address, trust, proxy, or capacity changes still produce a fresh allocation
using the complete bounded fallback sequence.

In-place refresh failure may briefly overlap the old allocation with a new
connection attempt. This preserves availability and is bounded by the same
controller-issued allocation and client queue limits. Operators can still move
clients to a new carrier by removing or materially changing the old selection.
