# ADR 0022: Rebuild client forwarding state from the controller

- Status: Accepted
- Date: 2026-08-31

## Context

The Windows client needs a durable node identity and operator configuration,
but the controller remains authoritative for membership, policy, epochs,
grants, endpoint leases, and peer snapshots. Persisting received authorization
objects as if they were current would make restart behavior depend on stale
wall-clock state and could reactivate peers that were revoked while the client
was offline.

The control protocol is full duplex after authentication. Correlated join,
endpoint, snapshot, and heartbeat responses share one inbound sequence with
unsolicited snapshots, deltas, grant refreshes, errors, and shutdown notices.
Multiple independent writers would risk message-ID gaps or reordered requests.
Enrollment also has an ambiguous-commit case: the controller may commit a new
node and lose the connection before the client receives `AUTH_RESULT`.

Version 0.1 permits valid peer sessions to outlive a transient control failure,
but continuing to forward requires careful proof that every cached grant,
epoch, policy, and session remains usable. The first Windows milestone favors
a smaller, fail-closed state machine over disconnected forwarding.

## Decision

The client persists only operator intent and long-lived trust material:

- one locally generated Ed25519 node identity in a protected PKCS#8 file;
- the controller socket address, TLS server name, expected controller ID, and
  one or more explicit SHA-256 SPKI pins;
- the display name, local transport settings, TAP selection, and desired
  network IDs.

Enrollment and join bearer tokens are command inputs. They remain in redacted,
zeroizing memory only until the corresponding operation succeeds or the
command ends; they are never written to the client configuration or status
output. A client with an ambiguous enrollment result first retries
authentication without the token. Success proves that the prior transaction
committed; `ENROLLMENT_REQUIRED` permits one later retry with the retained
token.

One control supervisor owns each TLS connection. It validates the pinned TLS
identity and server name, verifies the configured Stella controller ID and
exporter-bound controller proof, authenticates the node, and rejoins every
configured network. One sequential event loop owns the outbound sequence,
correlation tracker, and TLS writer while selecting among inbound messages,
heartbeat deadlines, bounded local commands, and shutdown. No other task writes
control records.

Network grants, policy, epochs, revisions, peer records, heartbeat counters,
and correlation state are connection-local memory. A complete snapshot is
validated into temporary bounded state, including every controller signature,
before it atomically replaces the active view. Deltas apply only to the exact
next revision. Grant refreshes replace a valid local grant only after full
validation.

On TCP, TLS, authentication, sequencing, correlation, or message-validation
failure, the first Windows implementation immediately disables TAP forwarding,
erases peer sessions, and discards all received network state. Reconnect uses
full-jitter exponential backoff bounded from 250 milliseconds to 30 seconds,
then authenticates and reconstructs state from fresh joins and snapshots.
Three missed heartbeat acknowledgements force the same reconnect path. A clean
controller shutdown delays reconnect until its advertised deadline.

## Consequences

Restart and reconnect never treat serialized controller output as current
authority. The client has one ordered control writer and one place to enforce
message sequencing, correlations, heartbeat liveness, and redacted token
ownership. Ambiguous enrollment can recover without duplicating identities or
discarding a possibly unconsumed credential.

Transient control loss also interrupts data forwarding even when old grants
could technically remain valid. This is intentionally conservative and may
cause a short virtual-link outage. A future ADR may permit disconnected
forwarding after it defines and tests the complete cached-state validity proof;
it must not weaken the behavior chosen here implicitly.
