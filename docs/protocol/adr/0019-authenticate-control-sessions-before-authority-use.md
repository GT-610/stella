# ADR 0019: Authenticate control sessions before authority use

- Status: Accepted
- Date: 2026-08-30

## Context

TLS 1.3 authenticates the controller certificate and protects the carrier, but
it does not identify a Stella node or bind that node identity to the exact TLS
connection. The controller must implement the version 0.1 hello and proof
exchange before it accepts any network-scoped operation. The exchange also
contains an optional single-use enrollment credential, so parsing, proof
verification, authority mutation, and failure behavior need one explicit
ordering.

Authentication runs on an untrusted socket. A client can stall between records,
send discontinuous message IDs, misuse correlations, select an unadvertised
suite, claim an ID unrelated to its key, or probe whether a node or token
exists. Partial authentication must not escape into the active-session loop.

## Decision

Each admitted TLS connection runs one linear authentication state machine under
the configured application-authentication deadline. The controller generates a
fresh non-zero 32-byte nonce from the operating-system cryptographic random
source, sends `SERVER_HELLO` as outbound message ID 1, and accepts only
`V0_1_SUITE_1` in `CLIENT_HELLO` inbound message ID 1. The client hello must
correlate to the server hello, contain a non-zero client nonce, and claim the
node ID derived from its validated Ed25519 public key.

The controller obtains the 32-byte Stella exporter from the established rustls
connection and signs `SERVER_PROOF` over the normative exporter-bound
transcript. `SERVER_PROOF` is outbound message ID 2 and correlates to the client
hello. `NODE_AUTH` must be inbound message ID 2 and correlate to the server
proof. The controller verifies the node proof before consulting enrollment
state, so bearer credentials are never evaluated for an unauthenticated key.

For an existing node, the stored public key must match, the node must be
enabled, and no enrollment token or display name is accepted because version
0.1 has no re-enrollment policy. For an unknown node, a valid proof without an
enrollment token returns `ENROLLMENT_REQUIRED`; a token is accepted only with a
display name and is consumed together with node creation through the serialized
authority command. All other key, node, token, disabled-state, or enrollment
failures collapse to `AUTHENTICATION_FAILED`.

`AUTH_RESULT` is outbound message ID 3 and correlates to `NODE_AUTH`. Only a
committed status-zero result creates an authenticated-session value containing
the node identity, owned TLS stream, and advanced inbound and outbound sequence
state. Failed authentication sends no attacker-controlled text, waits a small
operating-system-randomized delay, and then closes. Malformed records, invalid
hello state, unsupported negotiation, EOF, and the overall deadline close
without a detailed response when no authenticated request correlation exists.

The active-session loop can only be entered with that authenticated-session
value. It therefore cannot accidentally process join, endpoint, heartbeat, or
snapshot messages before proof verification and authority policy complete.

## Consequences

Stella identity is cryptographically tied to one TLS 1.3 connection, message
ordering and response correlations are exact, and a token cannot be used before
the presenting node key is authenticated. Enrollment-required remains a useful
bootstrap signal after a valid proof, while ordinary authentication failures do
not reveal whether a node, key, disabled flag, or token exists.

The state machine is intentionally sequential during authentication. This adds
one authority round trip for known nodes and one transactional command for new
nodes, but keeps the security boundary small and ensures the active loop never
observes partial enrollment.
