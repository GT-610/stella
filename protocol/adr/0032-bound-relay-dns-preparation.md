# ADR 0032: Bound relay DNS preparation

- Status: Accepted
- Date: 2026-09-02

## Context

Relay service records may contain both controller-provided numeric addresses
and a canonical hostname. The Windows client augments numeric addresses with
operating-system DNS results before applying the carrier establishment budgets
from ADR 0031.

The protocol permits up to eight relay services. Resolving each service
sequentially with an independent five-second timeout lets a strict or broken
resolver delay relay fallback by approximately forty seconds before any
carrier is attempted. That delay grows with configuration size and sits outside
the otherwise fixed fallback bound.

## Decision

The Windows client starts every required relay hostname lookup concurrently and
gives the complete relay DNS preparation step one shared five-second monotonic
deadline. Completion order does not change the controller-provided service
order or the subsequent carrier preference order.

A successful lookup contributes unique usable addresses up to the protocol
limit. A lookup failure or shared-deadline expiry keeps the service's numeric
addresses when any were provided. A DNS-only service records a safe hostname
resolution or timeout error and contributes no selections. Proxy-resolved
secure WebSocket-only services do not consume local DNS work.

The implementation polls owned resolver futures together without spawning
detached tasks or adding a dependency. Dropping unfinished lookups at the shared
deadline cancels their Stella-side futures. No credential, relay secret, proxy
response, or packet content is passed to the resolver or included in the new
timeout path.

## Consequences

Relay selection preparation takes at most five seconds regardless of whether
the controller publishes one or eight services. Together with ADR 0031, a
client reaches the secure WebSocket carrier after a fixed preparation and
earlier-carrier bound instead of a delay proportional to service count.

Concurrent lookups can briefly consume up to eight operating-system resolver
operations. This is already the protocol maximum and is preferable to holding
startup serially. Numeric relay addresses remain important for resilience when
local DNS is filtered or unavailable.
