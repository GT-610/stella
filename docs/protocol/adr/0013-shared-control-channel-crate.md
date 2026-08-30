# ADR 0013: Share control-channel mechanics in a dedicated crate

- Status: Accepted
- Date: 2026-08-30

## Context

Both the controller and every client must implement the same TLS-carried record
framing, outbound message construction, message-ID sequencing, correlation
tracking, and exporter-bound proof transcript. Keeping those mechanics in both
binaries would make subtle differences likely, while placing asynchronous I/O
inside `stella-proto` would violate that crate's pure-codec boundary.

The shared layer must not become a second protocol model or a place for
controller policy. The byte-level wire format remains normative in the
specification and implemented by `stella-proto`.

## Decision

The workspace includes a `stella-control` library used by `stella-server` and
`stella-client`. It depends on `stella-proto` for validation and encoding and
provides:

- an asynchronous framed reader and writer generic over Tokio `AsyncRead` and
  `AsyncWrite` carriers;
- validation of the four-byte record length before allocation, with the
  protocol's 1 MiB hard limit;
- owned decoded records and an owned message builder so no borrowed input
  survives an asynchronous boundary;
- per-direction monotonic message-ID state and bounded request correlation;
- canonical controller and node TLS-exporter proof transcript construction.

The crate does not open TCP sockets, configure TLS trust, choose controller
policy, consume credentials, persist authority state, or perform network join
authorization. Those responsibilities stay in the binaries or their private
modules.

The reader treats EOF between records as a clean carrier close and EOF inside a
prefix or body as truncation. The writer emits one complete prefix and body in
order and never exposes a partially constructed protocol message. I/O tests use
fragmented and coalesced in-memory streams because TLS record boundaries have
no Stella meaning.

## Consequences

Client and server share one security-sensitive implementation of connection
mechanics without coupling their policy state machines. The extra crate makes
the workspace dependency graph slightly larger, but keeps asynchronous I/O out
of the pure codec and makes loopback integration tests independent of TCP and
certificate setup.

Any future control carrier must satisfy the same ordered byte-stream contract
or add a separate ADR. It must not bypass record bounds, sequencing, or proof
construction.
