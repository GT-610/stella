# ADR 0011: Use TOML for local configuration

- Status: Accepted
- Date: 2026-08-29

## Context

The controller and client need readable configuration for addresses, paths,
limits, certificates, network policy, and logging. Supporting both YAML and
TOML would duplicate validation and examples without improving the protocol.

## Decision

The reference implementation uses UTF-8 TOML files decoded with Serde. Unknown
fields are errors. Command-line arguments may select a file and override a
small documented set of operational values, but they do not create a second
configuration schema.

Long-term identity keys, private TLS keys, and reusable join secrets are stored
in separate files or an operating-system credential facility and referenced by
path. They are not embedded in the main TOML file. Windows setup validates that
secret files are not broadly writable and warns when their ACL cannot be
verified.

Configuration structures are versioned independently from the Stella wire
protocol. A binary refuses an unsupported configuration version and never
guesses the meaning of renamed fields.

## Consequences

Deployments have one documented configuration syntax with strict validation.
Secret provisioning remains a separate operational concern, and future schema
changes need explicit migration documentation.
