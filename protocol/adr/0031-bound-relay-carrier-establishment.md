# ADR 0031: Bound relay carrier establishment

- Status: Accepted
- Date: 2026-09-02

## Context

ADR 0025 keeps a relay allocation warm while direct ICE checks proceed. The
Windows client prefers TURN over UDP, TCP, TLS, and then secure WebSocket. TURN
transactions already have deadlines, and HTTP CONNECT has a bounded exchange,
but operating-system TCP connection attempts, TLS handshakes, WebSocket
upgrades, and the complete multi-step allocation did not share an outer
deadline.

A strict firewall can silently discard an earlier carrier instead of rejecting
it. The client can then wait for an operating-system timeout before reaching a
carrier that the network permits. Applying an independent timeout to every
published relay address would still let the delay grow with the number of relay
services and IPv4 or IPv6 addresses supplied by the controller.

## Decision

The Windows client gives each relay carrier class one ten-second monotonic
establishment budget, in preference order: TURN UDP, TURN TCP, TURN TLS, and
secure WebSocket. The budget is shared by every relay service and address tried
for that carrier and covers the complete attempt, including socket connection,
HTTP CONNECT when applicable, TLS, WebSocket upgrade, TURN authentication, and
allocation.

An immediate failure may advance to another service or address while time
remains in the current carrier budget. If the budget expires, the in-flight
attempt is cancelled, all remaining selections for that carrier are skipped,
and fallback continues with the next carrier. The recorded error identifies
only the relay ID and carrier; it contains no credential, proxy response,
hostname, certificate, or packet content. Existing narrower transaction
deadlines remain defense in depth.

Relay hostname resolution remains a separate bounded preparation step. A
successful allocation ends fallback immediately. If every selection fails or
times out, startup returns the last safe allocation error rather than silently
running without the relay required by the received connectivity configuration.

## Consequences

A silent UDP, raw TCP, or direct TLS path cannot indefinitely prevent a client
from attempting the HTTPS-compatible WebSocket relay. With prepared relay
selections, WebSocket establishment begins after at most thirty seconds of
earlier-carrier budgets, independent of the number of published relay
addresses.

Ten seconds allows the normal challenge and authenticated TURN allocation to
complete on a reachable path while keeping the full four-carrier fallback
bounded. Very slow paths can be abandoned even if the operating system would
eventually connect; operators should provide a reachable WebSocket relay and
keep controller-issued relay lists ordered and small.
