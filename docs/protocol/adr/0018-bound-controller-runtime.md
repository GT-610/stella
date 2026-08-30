# ADR 0018: Bound controller runtime admission and shutdown

- Status: Accepted
- Date: 2026-08-30

## Context

The controller loads protected long-term identities, an embedded authority
database, and a TLS listener in one process. A listener that becomes reachable
before identity and database validation completes can expose a half-ready
service. Accepting sockets before enforcing a connection limit permits the
process to accumulate unbounded tasks, while an unbounded TLS handshake lets a
slow peer retain scarce capacity indefinitely.

Shutdown also needs an explicit ordering. Stopping the process while authority
commands or sessions are still active can discard responses, and waiting
forever for an untrusted peer prevents service management from completing.

## Decision

The reference controller loads and validates the strict configuration,
controller identity, controller-ID database binding, TLS certificate and key,
and authority invariants before it binds the configured TCP address. Structured
logging is initialized from the validated filter before operational startup
events are emitted. Startup fails closed on any mismatch and never falls back
to plaintext or a newly generated identity.

One bounded semaphore represents simultaneous accepted control connections. An
owned permit is acquired before `accept`, remains attached to the connection
task through TLS and application session teardown, and is released only when
that task exits. TLS negotiation is TLS 1.3 only and has its own configurable
deadline. Application authentication starts with a fresh deadline after TLS
completes.

The accept loop owns and reaps all connection tasks. A one-second maintenance
tick submits endpoint-lease expiry through the serialized authority queue; it
never edits redb directly. Task failures are logged with the numeric peer
address and no credentials.

On Ctrl+C or an injected test shutdown signal, the listener stops admitting
new sockets. Existing sessions receive cancellation and have a configurable
drain deadline. Remaining tasks are aborted after that deadline, then fully
reaped. Maintenance stops, the ordered authority shutdown command drains all
earlier mutations, and its blocking thread is joined before process success is
reported.

Version 1 configuration adds bounded `tls_handshake_timeout_seconds` and
`shutdown_timeout_seconds` values, both defaulting to 10 seconds. Existing
version 1 documents remain valid through field defaults.

## Consequences

The controller has fixed connection and task growth, slow TLS clients cannot
hold capacity indefinitely, and normal shutdown preserves committed authority
ordering. Acquiring a permit before `accept` leaves excess clients in the
operating-system listen backlog rather than application memory. A forced
shutdown may terminate in-flight protocol responses after the drain deadline,
but it cannot leave the authority worker unjoined or continue accepting new
work.

