# ADR 0030: Bootstrap controller TLS through the local HTTP proxy

- Status: Accepted
- Date: 2026-09-02
- Supersedes: ADR 0029's WSS-only configuration scope

## Context

ADR 0029 allows secure WebSocket relay traffic to traverse an explicit HTTP
proxy. A client cannot use that relay until it first authenticates to the
controller and receives the relay service record and short-lived credential.
The existing controller connection is direct TCP, so a proxy-only network fails
before the WebSocket fallback can be discovered or authorized.

Using separate proxy settings for control and relay would create an easy
misconfiguration where bootstrap succeeds but data fallback does not, or vice
versa. Both connections are outbound TLS to operator-controlled authorities and
need the same local egress policy.

## Decision

The Windows client uses one optional numeric `https_proxy` socket address for
both the controller TLS connection and secure WebSocket relay. This replaces
the `secure_websocket_proxy` field introduced by ADR 0029. The setting remains
local, is never sent to the controller, and does not affect direct UDP, TURN
UDP, TURN TCP, or direct TURN TLS attempts.

Before controller TLS, the client connects to the proxy and sends the same
strict bounded HTTP/1.1 CONNECT profile defined for WebSocket relay. The target
and Host field are the configured controller TLS name plus controller port.
The plaintext request contains no enrollment token, join token, node proof,
controller proof, SPKI pin, or Stella record. A non-2xx response, including 407,
fails closed.

After CONNECT succeeds, the existing TLS 1.3 handshake, server-name and SPKI
checks, TLS exporter binding, and mutual Stella identity proof run unchanged
inside the tunnel. The same reusable CONNECT implementation and limits serve
controller and WebSocket connections so parser and logging behavior cannot
drift between bootstrap and data fallback.

## Consequences

A client in an unauthenticated proxy-only network can authenticate, receive
connectivity configuration, create its WSS relay allocation, and join the L2
overlay without a direct TCP route or port mapping. The proxy observes target
authorities, timing, and byte volume, but TLS protects controller and relay
credentials and content end to end.

Authenticated proxy schemes remain outside the first profile. Supporting them
requires an operating-system credential and impersonation design rather than
placing reusable proxy passwords in the Stella TOML file.
