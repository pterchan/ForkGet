# Changelog

## Unreleased - v0.1.0-rc.1

The first public candidate is being prepared. No downloadable release artifacts
or production qualification are announced by this entry.

- Consistent snapshot import, pinned branches, read-only defaults, explicit
  writable native copies, finite leases and visible cleanup state.
- Admitted MySQL/PostgreSQL/TiDB SQLAlchemy workflows with normal initialization,
  reflection, generated keys, bulk flush, optimistic locking and typed replay.
- Direct-row transaction budgets, independently reviewed temporary grants and
  explicit opt-in statement approval.
- Durable write intent, same-transaction SQL witnesses, synchronous outcome
  delivery, write backpressure and bounded recovery without business-DML retry.
- Truthful standalone MongoDB partial/unknown observations and late delivery;
  unacknowledged writes refused before native send.
- Coordinated protocol-3 upgrades, witness-only preparation and explicit storage
  restore/incarnation handling.
- Bounded MySQL result-metadata batching and a session-bound logical compiler.
- Complete typed result export, staged replay and exact verification.
- A packaged nine-language Console with memory-only tokens and exact integers.
- Exact namespace and literal-prefix checks before MySQL/TiDB provisioning and
  cleanup, preserving unregistered objects and refusing incomplete validation.
- Corrected MongoDB replay guidance in all nine Console languages, including
  its non-atomic execution and unknown-outcome boundary.
- A versioned performance-acceptance policy calibrated to the current local
  baseline. A policy change does not establish faster execution or managed
  qualification, and does not rewrite historical outcomes.

TiDB concurrent foreign-key integrity remains blocked: a concurrent delete/insert
race can commit an orphan on the native engine and through Forkget. This candidate
does not repair or reliably refuse that path. See [limitations](doc/limitations.md).
