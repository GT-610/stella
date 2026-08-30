# Controller implementation

`stella-server` is the self-hosted authority and control-plane endpoint. It
never becomes a mandatory unicast data relay: authenticated nodes receive
signed grants, policy, peer identities, and direct UDP endpoints, then exchange
data with one another.

## Process structure

The process has three explicit boundaries:

- the Tokio runtime accepts TCP, completes TLS 1.3, and runs one bounded session
  task per authenticated connection;
- a dedicated blocking authority thread owns the redb database and executes
  typed commands in commit order;
- an event distributor converts committed authority changes into bounded peer
  snapshots, deltas, grant refreshes, and availability changes.

Connection tasks never hold database transactions. They send a command through
a bounded channel and await a oneshot reply. Slow clients have bounded outbound
queues; replaceable state is coalesced into a fresh snapshot, and persistently
slow connections are closed.

## Configuration and identity

Configuration is strict UTF-8 TOML with `version = 1` and unknown fields denied.
It names the listen address, database path, TLS certificate chain and PKCS#8
private key, controller Ed25519 identity key, operational limits, and logging
filter. Secrets are separate files and are never accepted inline.

The reference schema uses `[state]`, `[identity]`, `[tls]`, `[limits]`, and
`[logging]` tables; `examples/server.toml` is the canonical deployable sample.
Relative paths resolve against the configuration file directory. The parser
bounds input to 1 MiB, rejects non-UTF-8 input and unknown fields at every
nesting level, and validates non-zero listen ports, queue sizes, connection
limits, authentication/request deadlines, and logging-filter text before any
socket or database is opened.

`init` generates the controller Ed25519 identity and a TLS identity suitable
for an explicitly pinned self-hosted deployment, creates the database, and
writes an example configuration without overwriting existing files. `run`
loads the configured identities, verifies that stored controller IDs agree,
and refuses unsupported schema or configuration versions.

The server enables only TLS 1.3 through `tokio-rustls` and the `ring` provider.
TLS 1.2, early data, renegotiation, plaintext fallback, and disabled certificate
validation are not supported. Application authentication must finish within
ten seconds after TLS establishment.

## Authority store

The redb schema separates metadata, nodes, networks, memberships, endpoints,
enrollment-token digests, and join-token digests. Every persisted value begins
with an internal format version and is decoded with explicit size and semantic
bounds.

The authority thread enforces these transaction groups:

- consume enrollment token plus register node;
- consume join token plus activate membership, advance epoch and revision, and
  record new grant state;
- leave, suspend, resume, revoke, or change policy plus all corresponding epoch,
  revision, and grant changes;
- publish endpoints plus snapshot revision advancement.

Bearer tokens are generated from operating-system randomness, displayed once
as URL-safe text, and stored only as domain-separated SHA-256 digests with
expiry and use metadata. Authentication comparisons are constant time.

## Administrative CLI

The `stella-server` executable provides:

- `init` and `run`;
- network create, list, show, and delete;
- enrollment-token and join-token generation;
- node list, enable, and disable;
- member add, remove, suspend, and resume;
- coordinated state backup and offline verification.

Mutating commands open the same authority abstraction as the daemon, validate
all input before starting a write transaction, and print identifiers rather
than secret database contents. Commands return non-zero on validation,
authorization, persistence, or output failure.

## Session state machine

After TLS completes, the server sends `SERVER_HELLO`, negotiates exactly one
version and suite, proves the controller identity using the TLS exporter, and
verifies the node proof. Unknown nodes may atomically enroll with a valid token;
known disabled nodes receive only the protocol's generic pre-authentication
failure behavior.

Only an active session may join, leave, publish endpoints, request snapshots,
or send heartbeats. Successful commits are the sole source of response epochs,
revisions, grants, and distributed peer state. A connection-local failure never
partially updates authority state.

## Verification

Unit tests use temporary databases and deterministic clocks/random sources to
exercise schema decoding, crash-visible transaction boundaries, token replay,
idempotent join and leave, epoch/revision advancement, and invariant checks.
Loopback integration tests use a real TLS 1.3 connection and validate
authentication, enrollment, join, endpoint publication, snapshots, deltas,
heartbeats, reconnect, malformed input, timeout, and slow-client limits.
