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

Startup validates the configuration, protected controller key, database
controller binding, database invariants, and TLS identity before binding TCP.
Connection admission uses an owned semaphore permit acquired before `accept`;
the permit remains held through TLS and application teardown. TLS negotiation,
application authentication, correlated requests, and shutdown drain have
separate bounded deadlines.

Connection tasks never hold database transactions. They send a command through
a bounded channel and await a oneshot reply. Slow clients have bounded outbound
queues; replaceable state is coalesced into a fresh snapshot, and persistently
slow connections are closed.

The authority queue capacity is a validated non-zero configuration value.
Every request owns all of its inputs, including a temporary zeroizing copy of
any bearer token, before it enters the queue. The authority thread processes
commands strictly in receive order with `blocking_recv`; it completes the redb
operation synchronously and sends the typed result before taking the next
command. Dropping a request future may discard its reply but never cancels a
mutation that has already entered the queue.

Shutdown is itself an ordered command. Once it reaches the head of the queue,
all earlier requests have completed and the receiver is closed. Senders still
waiting to enter observe a closed-queue error; any command already admitted
behind shutdown is discarded and observes a lost reply. The process then joins
the authority thread. A thread panic, closed request queue, and lost reply are
distinct application errors and are never confused with a persistence error
returned by redb.

Ctrl+C first stops admission and broadcasts cancellation to active sessions.
The accept loop owns and reaps every connection task, waits up to the configured
shutdown deadline, aborts any remaining tasks, and only then sends the ordered
authority shutdown command and joins its thread. A one-second maintenance tick
expires peer leases through the same serialized queue.

## Configuration and identity

Configuration is strict UTF-8 TOML with `version = 1` and unknown fields denied.
It names the listen address, database path, TLS certificate chain and PKCS#8
private key, controller Ed25519 identity key, operational limits, and logging
filter. Secrets are separate files and are never accepted inline.

The controller identity is unencrypted Ed25519 PKCS#8 DER bounded to 4 KiB.
`init` creates an empty file with create-new semantics, hardens and verifies its
permissions, and only then writes and syncs the key. On Windows the DACL is
protected from inheritance and grants full access only to the current process
account and LocalSystem. Loading rejects reparse points, non-regular files,
inherited or additional ACEs, unexpected access masks, malformed PKCS#8, and
oversized input. Temporary DER buffers are zeroized. Failure during creation
removes the new file, and a failed cleanup is surfaced explicitly.

The reference schema uses `[state]`, `[identity]`, `[tls]`, `[limits]`, and
`[logging]` tables; `examples/server.toml` is the canonical deployable sample.
Relative paths resolve against the configuration file directory. The parser
bounds input to 1 MiB, rejects non-UTF-8 input and unknown fields at every
nesting level, and validates non-zero listen ports, queue sizes, connection
limits, TLS-handshake/authentication/request/shutdown deadlines, and
logging-filter text before any socket or database is opened.

`init` generates the controller Ed25519 identity and a TLS identity suitable
for an explicitly pinned self-hosted deployment, creates the database, and
writes an example configuration without overwriting existing files. `run`
loads the configured identities, verifies that stored controller IDs agree,
and refuses unsupported schema or configuration versions.

Initialization is an explicit transaction rather than a startup side effect.
The generated Ed25519 TLS certificate contains loopback subject names plus any
operator-supplied DNS names or IP addresses. The CLI prints a `sha256/` SPKI pin
for trusted out-of-band enrollment, while both private keys receive the exact
protected Windows DACL. Failure rolls back only files and empty directories
created by that invocation; an existing target always stops initialization.

The server enables only TLS 1.3 through `tokio-rustls` and the `ring` provider.
TLS 1.2, early data, renegotiation, plaintext fallback, and disabled certificate
validation are not supported. Application authentication must finish within
ten seconds after TLS establishment.

## Authority store

The redb schema separates metadata, nodes, networks, memberships, online
endpoint leases, version 0.2 connectivity generations, enrollment-token
digests, and join-token digests. Every persisted value begins with an internal
format version and is decoded with explicit size and semantic bounds.

Database creation uses create-new file semantics. Metadata binds schema version
2 to the controller ID, and startup opens every declared table before serving.
Opening schema version 1 performs an atomic one-way migration that creates the
empty connectivity table and advances metadata to version 2; older binaries
then reject the database rather than leaving connectivity state stale. Node and
network values have independent magic/version fields, bounded UTF-8 display
names, explicit big-endian counters, and canonical public-key or policy bytes.
`state verify` walks every record and confirms that its derived node, network,
authorization, and online-lease relationships match the redb key.

The authority thread enforces these transaction groups:

- consume enrollment token plus register node;
- consume join token plus activate membership, advance epoch and revision, and
  record new grant state;
- leave, suspend, resume, revoke, or change policy plus all corresponding epoch,
  revision, and grant changes;
- enable or disable a node plus one epoch/revision advance and grant-serial
  rotation for every network in which that node is a member;
- publish endpoints plus snapshot revision advancement; and
- publish or withdraw a complete connectivity generation while refreshing the
  same online lease and shared snapshot revision.

The maintenance transaction expires online leases and connectivity generations
against their independent deadlines. Lease expiry removes both records;
generation expiry advances the shared snapshot revision but preserves a
recently refreshed online lease.

Bearer tokens are generated from operating-system randomness, displayed once
and stored only as domain-separated SHA-256 digests with an expiry. Enrollment
and network-scoped join tokens are single-use: their digest is removed in the
same write transaction that creates the node or membership, so a failed
mutation leaves the token available while a committed mutation cannot be
replayed.

Membership add, token join, leave, suspend, and resume operations are
idempotent where the requested state is already present. Every effective
authorization change advances both the network controller epoch and peer
snapshot revision and rotates the affected grant serial in the same write
transaction. Changing a node's enabled state performs the same invalidation for
all of its memberships; disabling therefore invalidates old grants and active
sessions immediately through the new epoch, rather than waiting for their
normal expiry.

Grant issuance combines only a current enabled node, active membership, and
matching network record. It encodes the canonical policy, hashes those exact 64
bytes, copies the committed epoch and grant serial, uses the policy's bounded
session lifetime, signs the version 1 domain-separated 176-byte grant body, and
decodes and verifies the completed 240-byte object before returning it to a
session. Disabled, suspended, mismatched, stale, or overflowing inputs fail
without producing a grant.

An endpoint-table row represents one online peer lease, including when its
canonical endpoint set is empty. Creating or changing that visible peer record
advances only the network snapshot revision; publishing the same set or
refreshing it from a heartbeat updates the controller-observed activity time
without revision churn. The timestamp never moves backwards. Expiry uses the
network's signed `peer_lease_seconds`, removes all expired rows in one
transaction, and advances each affected network once. Leave, suspension, and
node disablement remove related rows inside their existing authority
transactions.

Endpoint values repeat the network and node IDs stored in their composite key.
Startup verification also requires an existing enabled node, an existing
network, an active membership, and a canonical zero-to-eight-entry endpoint
set. Empty sets remain stored because they mean online but currently
unavailable for direct UDP sessions; a missing row means offline.

Network deletion is idempotent and removes the network record, every
membership and endpoint keyed to it, and every unconsumed join-token digest
scoped to it in one write transaction. A deleted network ID may later be
recreated, but old join tokens remain unusable and authority counters restart
from the newly created record rather than inheriting deleted state.

`state backup` is an ordered authority command. With no transaction active and
no later command able to run, it opens one consistent redb read transaction and
copies every table's raw keys and values into a create-new redb database. It
commits and synchronizes the destination, then opens the copy as a separate
database to run the full invariant verifier. Failures remove the partial
destination; a failed cleanup is reported explicitly. The command never
overwrites a prior backup and copying the live database file outside this
authority command remains unsupported.

## Administrative CLI and daemon

The current `stella-server` executable initializes and runs a complete
control-plane deployment and provides authority management:

- deployment initialization and the long-running TLS controller;
- network create, list, show, and delete;
- enrollment-token and join-token generation;
- node list, enable, and disable;
- member add, remove, suspend, and resume;
- coordinated state backup and offline verification.

`run` installs the configured logging filter, serves the active authenticated
session state machine, and maps Ctrl+C to the bounded shutdown path described
above. See the [Windows deployment guide](/guide/server-deployment) and
[server administration CLI reference](/api/server-cli) for exact syntax,
defaults, output contracts, and secret-handling guidance.

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
or send heartbeats. Requests are handled sequentially per connection, and each
successful response is built from one committed authority view. Successful
commits are the sole source of response epochs, revisions, grants, and
distributed peer state. A connection-local failure never partially updates
authority state.

Endpoint publication creates or refreshes a bounded peer lease. Heartbeats use
monotonic counters, acknowledge the authoritative network epoch and snapshot
revision, and trigger a complete atomic snapshot when the client's revision is
stale. Membership grants are refreshed proactively at the midpoint of their
validity using a monotonic local deadline. Authorization changes clear obsolete
grant deadlines immediately, so a revoked, suspended, or departed membership
cannot be refreshed from connection-local state.

## Verification

Unit tests use temporary databases and deterministic clocks/random sources to
exercise schema decoding, crash-visible transaction boundaries, token replay,
idempotent join and leave, epoch/revision advancement, and invariant checks.
Loopback integration tests use a real TLS 1.3 connection and validate
authentication, enrollment, join, endpoint publication, snapshots, deltas,
heartbeats, reconnect, malformed input, timeout, and slow-client limits.
