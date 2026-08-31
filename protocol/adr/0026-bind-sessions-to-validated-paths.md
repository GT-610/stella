# ADR 0026: Bind peer sessions to validated paths

- Status: Accepted
- Date: 2026-08-31

## Context

The Windows 0.1 runtime owns one UDP socket and pins a confirmed peer session to
an exact source IP address and port. Automatic connectivity introduces multiple
host, reflexive, mapped, relay, TLS, and WebSocket paths. A `SocketAddr` can no
longer identify every delivery mechanism, while silently accepting an existing
session on a new source would weaken path validation and reply routing.

Transport failover must not duplicate membership logic inside ICE, TURN, or a
relay. It must also avoid nonce reuse, replay-window confusion, or an attacker
redirecting authenticated traffic onto a path that was never nominated.

## Decision

The client runtime will route complete datagrams through opaque, locally unique
`PathId` values. A path owns its transport kind, exact remote delivery metadata,
conservative datagram limit, state generation, liveness, and cancellation. UDP,
TURN, TLS relay, and WebSocket relay implementations expose the same bounded
datagram contract to the Stella data plane.

The connectivity layer may discover, check, nominate, fail, or rank paths, but
it cannot install a data session. After nomination, Stella runs the normal peer
handshake over that exact path. The resulting session is pinned to its `PathId`
and path generation. Packets arriving through another path are not accepted
into it.

The first 0.2 implementation changes paths by establishing a fresh Stella
session on the replacement path. The prior session becomes receive-only for the
existing bounded rekey grace and is then erased. In-place key migration is not
permitted. Revocation, epoch changes, grant changes, and path authorization
failure still remove all affected sessions immediately.

The runtime may keep a nominated direct path and a ready relay path
simultaneously. Selection prefers policy-compliant direct paths, falls back to
relay without changing network membership, and periodically attempts a fresh
direct session while relay is active.

## Consequences

The data plane no longer depends on numeric UDP endpoints and can use multiple
transports without moving identity or authorization into them. Re-handshake on
path change is more expensive than in-place migration but preserves the
existing cryptographic invariants and gives independent implementations one
unambiguous transition.

`ClientDataRuntime`, `NetworkDataPlane`, routed datagrams, error types, and tests
must be generalized before ICE or relay code can be integrated. Version 0.1
source-tuple pinning remains valid for negotiated 0.1 sessions; this ADR
supersedes that implementation restriction only for the 0.2 path architecture.
