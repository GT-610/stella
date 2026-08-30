# ADR 0020: Serve authenticated control requests from atomic views

- Status: Accepted
- Date: 2026-08-30

## Context

After node authentication, one control connection carries network joins,
leaves, endpoint publication, snapshot requests, and heartbeats. These requests
refer to controller epoch, snapshot revision, local membership, peer
memberships, node keys, endpoint leases, policy, and signed grants. Reading each
record in a separate redb transaction could combine values that never existed
together, for example a new epoch with an old membership or a snapshot revision
with only part of its peer set.

The protocol permits correlated requests but does not require a controller to
execute them concurrently. Concurrent mutation within one connection would
also complicate message-ID ordering, duplicate request handling, shutdown, and
per-network lease refresh without improving the first interoperable Windows
implementation.

## Decision

Each authenticated connection has one sequential active-session loop. It reads
exactly the next inbound message ID, accepts only client-to-controller active
message types, and completes one request before reading the next. Each request
is bounded by `request_timeout_seconds`; timeout is fatal for the connection.
Direct responses correlate to the request message ID, while controller events
use correlation zero. The loop retains the authentication phase's advanced
inbound and outbound sequences.

The connection tracks the set of networks for which it has returned a
successful join during this TLS session. Reconnecting clients repeat their
configured joins. An already-active persisted membership makes join
idempotently successful even if the retry still carries its originally
configured, already-consumed token. A missing membership requires a valid
single-use join token. A suspended membership is denied without consuming a
token.

The authority exposes one read-only `network_session_view` command. One redb
read transaction returns the authenticated local node, network, local
membership, and every online peer's node, active membership, and endpoint lease
at one controller epoch and snapshot revision. The local node is never included
as a peer. A persisted endpoint lease, including an empty endpoint set, means
the peer is online; an absent lease means offline and the peer is omitted. The
view validates keys and authorization relationships before leaving the
authority thread.

The session signs the local and peer membership grants from that immutable
view, encodes the canonical policy once, and builds both `JOIN_RESULT` and the
following full `PEER_SNAPSHOT` from the same view. Snapshot requests also
return a full snapshot. Version 0.1 server implementation may use full
snapshots instead of deltas whenever state changes; it never constructs a
delta from independently read records.

Endpoint updates and heartbeats are accepted only for networks joined on this
connection. Endpoint publication uses the serialized authority mutation and
returns its committed epoch and snapshot revision. A heartbeat refreshes only
existing leases for the connection's joined networks and then reports current
authoritative revisions. It does not create an online lease before the client
has published an endpoint set.

Orderly controller shutdown stops new reads, sends `SERVER_SHUTDOWN` with the
drain deadline when possible, shuts down the TLS writer, and returns. Malformed,
misdirected, discontinuous, or invalid-state input is fatal. Authenticated
request denials use registered status codes and bounded static text only;
tokens, signatures, grants, keys, and attacker-provided text are never echoed.

## Consequences

Every emitted grant, policy, revision, and peer record describes one coherent
authority snapshot. Per-connection execution is simple, bounded, and
deterministic, while the shared authority thread still serializes mutations
from all connections. Full snapshots cost more bytes than deltas but avoid
inventing change history and are bounded by the network flood-member limit.

The joined-network set is session-local rather than a replacement for
persistent membership. A reconnect must replay joins, which naturally obtains
fresh grants and current snapshots. Endpoint liveness remains explicit: an
empty published set is online without a direct candidate, while a missing lease
is offline.
