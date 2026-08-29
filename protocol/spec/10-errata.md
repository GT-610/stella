# Stella Protocol Errata

- Status: Active
- Applies to: Protocol version 0.1 draft
- Last updated: 2026-08-29

## 1. Purpose

This document records confirmed errors, ambiguities, and interoperability
clarifications discovered after a protocol draft is published. It is normative
only for entries explicitly marked `Accepted`.

The current version 0.1 draft has no accepted errata.

## 2. Entry format

Each erratum receives a stable identifier `E-0.1-NNNN` and records:

- status: Proposed, Accepted, Rejected, or Superseded;
- affected document and exact section or field;
- original text or behavior;
- corrected text or behavior;
- whether wire bytes, signatures, security, state, or interoperability change;
- implementation and test impact;
- date and protocol editor rationale.

Accepted entries are append-only. A later correction supersedes an earlier
entry without deleting it.

## 3. Classification

### 3.1 Editorial

Spelling, formatting, broken links, and wording changes that cannot affect a
conforming implementation may be corrected directly in source history. They do
not need an erratum unless published copies would remain dangerously ambiguous.

### 3.2 Clarification

A clarification selects one behavior already required by all byte layouts,
security invariants, and state machines, but expressed ambiguously in prose. It
may become an accepted erratum for the same protocol tuple.

### 3.3 Incompatible correction

A correction that changes accepted bytes, signature input, key derivation,
authorization, recipient selection, required state transition, or security
boundary cannot silently amend deployed version 0.1. It requires a new
protocol or signed-object version and a versioning analysis. The erratum points
to that superseding version instead of redefining old wire behavior.

### 3.4 Security emergency

A vulnerability may require retiring a tuple or object immediately. The entry
documents safe shutdown and migration. Implementations fail closed; maintaining
connectivity is secondary to preventing known compromise.

## 4. Resolution process

1. Reproduce the issue with specification text, bytes, or an implementation
   test.
2. Determine whether independent conforming implementations could disagree.
3. Analyze security and downgrade consequences.
4. Propose exact replacement language and vectors.
5. Accept only through a reviewed specification change and ADR when the
   architecture changes.
6. Add or update tests before marking implementation support complete.

Questions and implementation bugs are not automatically protocol errata. An
implementation that contradicts unambiguous normative text is fixed without
changing the protocol.

## 5. Known implementation deviations

Reference implementation deviations are tracked separately from accepted
protocol errata. Until a deviation is fixed, documentation identifies the
affected release, platform, and test gap; it does not weaken normative text to
match the bug.

No implementation deviations are recorded because the functional version 0.1
reference implementation has not yet been released.

## 6. Errata table

| ID | Status | Affected text | Summary |
| --- | --- | --- | --- |
| None | | | No accepted errata |
