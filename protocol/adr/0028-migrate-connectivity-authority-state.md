# ADR 0028: Migrate authority state before storing connectivity generations

- Status: Accepted
- Date: 2026-09-01

## Context

The version 0.2 controller must persist each online member's latest complete
connectivity generation separately from its stable membership and version 0.1
endpoint lease. The existing redb schema version 1 has no table for that state.

Adding a table while leaving the schema version unchanged would let an older
controller binary reopen the database. That binary would not remove
connectivity rows when a node leaves, is suspended or disabled, or when its
online lease expires. A later upgrade would then observe stale rows that no
longer have the authorization and lease relationships required by ADR 0027.

Rejecting every version 1 database would avoid that downgrade problem but would
also make existing self-hosted deployments discard or manually rebuild valid
authority state.

## Decision

The reference controller upgrades authority schema version 1 to version 2 in
one redb write transaction during `AuthorityStore::open`. The transaction
creates an empty `connectivity` table and changes the metadata schema version
to 2. Existing node, network, membership, endpoint, and token records are not
rewritten. A failed transaction leaves the version 1 database unchanged.

Schema version 2 stores one record under the existing `network_id || node_id`
composite key. The value repeats the network ID and embeds one complete,
canonically validated version 0.2 connectivity record. The embedded record
repeats the node ID, so startup verification can detect key/value mismatches
without interpreting credentials as identity.

A connectivity row is valid only while the same key has an online endpoint
lease, enabled node, existing network, and active membership. Publishing a
generation creates or refreshes the online lease in the same transaction.
Replacing or withdrawing visible connectivity and creating a missing lease
advance the shared network snapshot revision exactly once. Identical
publication only refreshes the lease. Lease expiry and every authorization
cleanup remove both rows atomically. Generation expiry removes only the
connectivity row when the independently refreshed online lease remains valid.

Backups copy the new table and retain schema version 2. Version 1 binaries
reject the upgraded metadata instead of mutating state they do not understand.

## Consequences

Existing databases upgrade without losing authority state, while unsafe
downgrade is prevented. The migration is deliberately one-way; operators must
restore a pre-upgrade backup if they need to run an older binary.

Connectivity credentials are present in the controller database and its
backups for their bounded generation lifetime. Diagnostics expose only safe
metadata, and in-memory owned record buffers are zeroized when dropped.
