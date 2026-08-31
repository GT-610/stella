# ADR 0027: Distribute connectivity separately from membership records

- Status: Accepted
- Date: 2026-08-31

## Context

Version 0.1 peer records combine identity, a signed membership grant, and up to
eight administrator-published UDP endpoints. Version 0.2 connectivity adds an
independently changing ICE generation with credentials, candidates, relay
allocations, and a much shorter lifetime than membership authority.

Appending that state to the version 0.1 peer record would make its endpoint
record boundary ambiguous to an older implementation. Replacing the peer list
for every NAT rebinding would also couple high-frequency reachability changes to
otherwise stable grants and public keys.

Connectivity still has to be ordered with membership. A client must not apply a
candidate generation for a removed, suspended, or expired peer, and a stale
connectivity delta must not revive reachability after a newer network snapshot.

## Decision

Version 0.2 keeps the version 0.1 peer-record and endpoint-set encodings
unchanged. It introduces a separate connectivity record keyed by node ID and a
node-ID-sorted connectivity list. A peer snapshot carries the ordinary peer
list plus the currently published connectivity records. A peer is allowed to
have no connectivity record while it gathers or republishes a generation.

Membership, endpoint, and connectivity changes share the existing per-network
snapshot revision sequence. Version 0.2 peer deltas add operations that replace
or withdraw one peer's complete connectivity record. A client applies such a
delta only at the next exact revision and only when the named node remains in
its authenticated peer view.

A client publishes its own complete generation with `CONNECTIVITY_UPDATE`.
Omitting the generation withdraws it without leaving the network. The
controller validates the complete replacement before committing it, increments
the network snapshot revision once, and distributes the corresponding delta.

Deployment-scoped STUN and relay configuration is delivered separately from
network membership. Relay credentials are sent only to their authenticated
owner; they never appear in peer records or connectivity generations.

## Consequences

Version 0.1 byte layouts remain unambiguous and can continue to be selected
during rolling upgrades. Version 0.2 clients can update NAT mappings and relay
candidates without rotating grants or duplicating identity records.

The controller and client must validate consistency across two lists and one
revision stream. A connectivity record for an absent peer is invalid, while a
peer without a connectivity record is authorized but temporarily unreachable.

Connectivity credentials remain visible to the controller and authorized
network peers. Relay allocation credentials remain private to one authenticated
controller session and require independent redaction, expiry, and renewal.
