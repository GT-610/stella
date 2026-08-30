# ADR 0021: Refresh membership grants on monotonic deadlines

- Status: Accepted
- Date: 2026-08-30

## Context

Every successful join and full snapshot carries a controller-signed local
membership grant with an exclusive expiration time. The controller must send a
`GRANT_REFRESH` before that grant expires. Relying only on client heartbeats is
not sufficient because version 0.1 permits a short grant lifetime together
with a longer heartbeat interval. Reissuing a grant on every heartbeat would
also couple authorization traffic to liveness traffic and create avoidable
signing and network work.

Wall-clock deadlines are unsuitable for in-process scheduling. The signed
grant necessarily uses Unix time, but an operating-system clock adjustment
must not silently postpone an already planned refresh. Concurrent timer and
request writers would additionally risk control message reordering.

## Decision

After the controller successfully sends a join snapshot, requested snapshot,
reconciliation snapshot, or grant refresh, it decodes the exact local grant it
sent and schedules the next refresh at the midpoint of that grant's validity
interval. The delay is represented with Tokio's monotonic `Instant`; Unix time
is consulted again only when the replacement grant is issued.

The authenticated session loop selects among the next framed request,
controller shutdown, and the earliest refresh deadline. A due refresh reads a
new atomic network session view, signs a new local grant and canonical policy,
and sends one unsolicited `GRANT_REFRESH` with correlation zero. Multiple due
networks are processed in network-ID order by the same sequential writer.

A newly sent full snapshot replaces that network's existing deadline because
it already contains a fresh grant. Leave, network deletion, missing or
suspended membership, and other authorization loss remove the deadline.
Node-wide disablement sends the registered denial when possible and closes the
TLS session. Refresh work is bounded by the same per-request execution timeout
used for authenticated authority operations.

## Consequences

Grant validity no longer depends on heartbeat timing, and wall-clock rollback
cannot defer an established in-process deadline. Refresh occurs with half of
the signed lifetime remaining, leaving time for bounded processing and network
delivery. The sequential loop preserves message-ID and write ordering without
an outbound queue.

Process suspension or a clock jump may still make a replacement grant late.
Clients therefore continue to fail closed when their last valid grant expires;
the controller never extends validity locally without sending a newly signed
object.
