# ADR 0035: Preserve valid forwarding during controller reconnect

- Status: Accepted
- Date: 2026-09-02

## Context

The control-plane specification permits established peer data sessions to
continue across a transient controller failure while their grants, network
epoch, and session lifetime remain valid. ADR 0022 deliberately chose a
smaller first Windows implementation that destroyed the complete data runtime
whenever its TLS control session ended.

That fail-closed milestone prevents stale controller state from surviving a
process restart, but it also turns a controller restart, proxy interruption, or
brief TLS outage into an avoidable L2 outage. Healthy direct and relayed game
traffic loses its TAP devices and authenticated peer sessions even though the
data plane already owns all authorization material needed to enforce their
remaining lifetime.

## Decision

The Windows control supervisor owns the data runtime across individual
controller TLS sessions. Unexpected control failure and an authenticated
`SERVER_SHUTDOWN` close only the current control connection. While waiting for
reconnect backoff, opening TLS, authenticating, and replaying configured joins,
the supervisor continues bounded TAP, direct UDP, relay, ICE, keepalive,
handshake, expiry, and relay-recovery processing.

Disconnected forwarding uses only the last completely validated in-memory
network views. It never persists received grants, policies, peer records,
connectivity generations, or relay credentials and never extends any
controller-issued lifetime. Existing packet, handshake, grant, epoch, and
session validation remains authoritative. Cached peers may keep, rekey, or
re-establish authenticated sessions only while those same signed bounds remain
valid; the client cannot discover or authorize a peer absent from the cached
view.

After a fresh authenticated connection has rejoined every configured network,
the supervisor publishes current endpoints and connectivity, applies the
latest relay configuration, and reconciles the retained data runtime against
the new complete controller views. Removed or revoked networks and peers are
withdrawn before normal multiplexed control processing resumes. A failed data
runtime operation still closes that runtime and creates a replacement only
after fresh controller activation; a control-plane failure does not.

The existing full-jitter reconnect ceiling remains in force. An authenticated
shutdown deadline and registered retry delay are minimum waits, not trust in a
replacement endpoint. Relay connectivity changes that occur while offline
remain latched and are published after the next authenticated connection.

This decision supersedes only ADR 0022's requirement to destroy forwarding
state on every control-session failure. ADR 0022's persistence, fresh-join,
sequencing, correlation, and validation requirements remain unchanged.

## Consequences

Controller maintenance and transient TLS or proxy failures no longer interrupt
otherwise valid L2 game traffic. Reconnect work cannot starve data processing,
because data I/O and maintenance remain selected alongside every wait and
control activation future.

A revoked peer can remain reachable during a controller partition only until
the previously issued cryptographic authorization or session expires. This is
the bounded stale-authority window already permitted by the protocol; no state
survives client restart and a successful reconnect immediately applies newer
authority.

