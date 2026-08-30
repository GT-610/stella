# ADR 0016: Initialize controller TLS identity explicitly

- Status: Accepted
- Date: 2026-08-30

## Context

A self-hosted Stella controller needs three independent durable identities: the
Stella Ed25519 controller key, the TLS server key and certificate, and the redb
authority database bound to the controller ID. A deployment must be
initializable without an external certificate service, while still allowing an
operator to replace the generated certificate with one issued by a public or
private CA.

Silently creating missing secrets during `run` makes configuration mistakes
look like key rotation and can permanently disconnect pinned clients. Writing
secrets with ordinary inherited Windows permissions can expose them to other
local accounts. Partially overwriting an existing deployment is likewise more
dangerous than failing before startup.

## Decision

`stella-server init` is the only command that creates controller deployment
state. It uses the configured paths and create-new semantics for the
configuration file, controller key, TLS private key, certificate, and redb
database. It creates missing parent directories, but never overwrites or adopts
an existing target. If initialization fails, it removes only files and empty
directories created by that invocation and reports any cleanup failure.

The generated TLS identity is an Ed25519 self-signed certificate created with
`rcgen`. Its subject alternative names contain `localhost`, `127.0.0.1`, and
`::1`, plus validated DNS names or IP addresses supplied by the operator. Its
default validity is 825 days and the CLI bounds custom validity to one through
3,650 days. The generated identity is intended for explicit SPKI pinning; an
operator may instead install a CA-issued certificate and matching PKCS#8 key
before the first `run`.

Initialization prints the controller ID and the TLS public-key pin as
`sha256/` followed by standard padded base64 of SHA-256 over the exact DER
SubjectPublicKeyInfo. It never prints either private key. The TLS private key is
PKCS#8 PEM and uses the same protected Windows DACL as the controller identity:
only the current process account and LocalSystem receive access, inheritance is
disabled, and loading verifies the opened file rather than trusting path
metadata. The certificate and configuration are public but still use
create-new, bounded, synchronized writes.

`stella-server run` never generates or repairs state. Before binding it loads
the strict configuration, verifies both secret-file permission policies,
parses a bounded certificate chain and exactly one compatible PKCS#8 private
key, derives the controller ID, opens and verifies the bound authority
database, and constructs an explicit `rustls` server configuration using the
`ring` provider and TLS 1.3 protocol version only. Early data remains disabled,
there is no TLS 1.2 or plaintext fallback, and TLS exporter material uses the
label fixed by the security specification.

The listener limits admitted connections before spawning tasks. Each TLS
handshake and Stella authentication exchange has a configured deadline.
Shutdown first stops accepting TCP connections, then closes session tasks and
finally drains and joins the serialized authority thread.

## Consequences

A controller can be bootstrapped unattended on Windows with explicit,
inspectable trust material. Missing, mismatched, malformed, oversized, or
insecure secrets fail closed and never trigger implicit replacement. A
self-signed deployment requires clients to receive the printed SPKI pin over a
trusted channel; losing that pin or rotating the TLS key requires an explicit
client configuration change.

The reference implementation gains `rcgen`, `rustls`, `rustls-pemfile`, and
`tokio-rustls` dependencies. These audited libraries perform certificate and
TLS primitives; Stella does not implement ASN.1, signatures, or TLS itself.
Rollback is best-effort when the operating system refuses cleanup, and such a
failure is surfaced for administrator intervention rather than hidden.
