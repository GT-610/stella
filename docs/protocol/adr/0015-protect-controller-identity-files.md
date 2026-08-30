# ADR 0015: Protect controller identity files with native ACLs

- Status: Accepted
- Date: 2026-08-30

## Context

The controller Ed25519 private key is an unencrypted PKCS#8 document because
the server must start without an interactive passphrase. Relying on inherited
directory permissions would make the effective security policy deployment
dependent and could expose the key to another local account. Writing the key
before permissions are hardened also creates a window in which secret bytes
exist under an unknown ACL.

The reference implementation forbids project-owned `unsafe` outside
`stella-tap`. Windows security descriptor APIs require unsafe FFI, so the
controller needs an audited safe boundary instead of invoking those APIs in
application code.

## Decision

Controller identity files use bounded unencrypted Ed25519 PKCS#8 DER. Creation
uses create-new semantics and never overwrites an existing path. On Windows,
the empty file is opened with DACL-management rights, its inherited entries
are removed, and a protected DACL is installed before any private-key bytes are
written. Exactly two principals receive `FILE_ALL_ACCESS`: the current process
account and LocalSystem. If they are the same SID, only one entry is written.

The Windows implementation pins `windows-acl` 0.3.0, published by Trail of
Bits, as the safe wrapper around security descriptor FFI. `stella-server`
contains no unsafe block and does not import `winapi`; the dependency's unsafe
implementation remains outside the workspace's trusted application code.

Every load opens the file first and checks the ACL through that file handle,
then rejects inherited entries, deny entries, unknown ACE forms, unexpected
principals, duplicate principals, or masks other than `FILE_ALL_ACCESS`.
Reparse-point and non-regular files are rejected. Input is bounded by the
cryptographic library's 4 KiB PKCS#8 limit and temporary DER storage is cleared
on drop.

If hardening, verification, writing, or syncing a newly created file fails,
the implementation closes and removes that file. A cleanup failure is reported
explicitly because a partial artifact may remain. Non-Windows builds expose the
same API but return an unsupported-platform error until their native permission
backends are implemented.

## Consequences

The Windows controller can start unattended while keeping its long-term
identity limited to the service account and LocalSystem. Administrators retain
Windows ownership-recovery mechanisms, but ordinary inherited users and groups
cannot read or replace the key through its DACL.

Identity loading deliberately fails closed after manual ACL edits. Moving a
key between accounts requires an explicit permission-hardening operation or a
new identity. The pinned ACL dependency introduces legacy `winapi` internally,
but that dependency is isolated and does not change Stella's use of
`windows-rs` for project-owned Windows system integration.
