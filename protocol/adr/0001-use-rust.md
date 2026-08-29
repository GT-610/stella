# ADR 0001: Use Rust for the reference implementation

- Status: Accepted
- Date: 2026-08-29

## Context

Stella processes untrusted network input, performs cryptographic operations,
and calls platform APIs. The implementation needs predictable latency without
garbage-collector pauses and must remain practical on Windows, Linux, and
macOS.

## Decision

The reference implementation uses stable Rust edition 2021 or newer. The
workspace uses Tokio for asynchronous application I/O, `thiserror` for library
errors, `anyhow` at binary boundaries, Clap derive for command-line parsing,
and `tracing` for structured diagnostics.

Unsafe Rust is restricted to operating-system calls inside `stella-tap`, must
be hidden behind a safe API, and must document every safety invariant.

## Consequences

Memory safety and explicit ownership reduce parser and concurrency risk. The
project accepts Rust's compilation cost, platform FFI complexity, and the need
to keep the public protocol independent of Rust-specific layouts.
