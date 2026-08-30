# ADR 0014: Store controller authority state in redb

- Status: Accepted
- Date: 2026-08-30

## Context

The self-hosted controller needs durable, transactional authority state without
requiring a separately administered database service. Enrollment and join
tokens are single-use credentials, and consuming one may need to atomically
create a node or membership while advancing an epoch and snapshot revision.
Plain files cannot provide that guarantee across crashes.

The controller is asynchronous, while embedded database transactions and disk
I/O are blocking. Holding a database transaction across `.await` would tie
executor progress and transaction lifetime to an untrusted network peer.

## Decision

The reference controller uses `redb` 2.6.3 for its authoritative store. It is a
pure-Rust embedded database compatible with the workspace Rust 1.85 baseline.
The on-disk schema has explicit tables for metadata, nodes, networks,
memberships, endpoint sets, enrollment-token digests, and join-token digests.
Values use an internal versioned binary encoding; Rust memory layout and Serde
formats are not persisted directly.

One dedicated blocking authority thread owns database access. Asynchronous
connection tasks send typed commands through a bounded Tokio channel and await
typed replies through oneshot channels. The authority thread opens, reads,
writes, commits, and drops every transaction before replying. No redb
transaction, table guard, or borrowed database value crosses an asynchronous
boundary.

Security-sensitive mutations use one write transaction. In particular:

- enrollment token consumption and node registration commit together;
- join token consumption, membership activation, epoch advancement, grant
  issuance metadata, and snapshot revision advancement commit together;
- leave, suspension, revocation, policy changes, and endpoint publication
  advance all required authoritative counters in the same transaction.

Only domain-separated cryptographic token digests are stored. Raw bearer
tokens are returned once when generated and never logged or persisted. Startup
validates schema version, controller identity binding, table invariants, and
non-zero monotonic counters before accepting TLS connections.

## Consequences

The controller remains a single deployable executable and one state file while
gaining atomic credential use and crash-consistent authority changes. Database
work is serialized initially; this is acceptable for the low-rate control
plane and provides deterministic ordering. A later performance change may
introduce read concurrency only if transaction and ordering invariants remain
unchanged.

Backup copies are produced through a controller command that coordinates with
the authority thread. Copying a live database file behind the controller is not
a supported backup procedure.
