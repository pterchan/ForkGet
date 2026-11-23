# Changelog

English · [简体中文](CHANGELOG.zh-CN.md)

## 0.1.1

The stable release candidate covers the documented subsets of MySQL 8.0.43,
PostgreSQL 16.14 and MongoDB 7.0.48. TiDB is outside this release's support
scope because of an unresolved concurrent foreign-key integrity issue.
Qualification depends on validation of the exact release candidate.

- Provide English and Simplified Chinese editions of all public documentation.
- Read MongoDB counts and distinct values from the materialized branch copy.
- Check duplicate keys across MongoDB cursor batches.
- Return complete, sorted MongoDB `distinct` values on sparse and native
  branches. Replies exceeding the 16 MiB BSON limit return `FG-2002`.
- Preserve Compose forwarding of the optional native free-space attestation.
  An empty value leaves capacity estimated. An explicit zero remains a known
  shortage.
- Show the available operator commands with `fg-control --help` or `-h` without
  loading deployment settings.
- Describe how to install the matching release archives and run the downloaded
  Linux binaries against a dedicated PostgreSQL deployment.

### MySQL performance

A diagnostic on Google Cloud SQL for MySQL 8.0.43 used 16 clients and three
paired proxy and direct runs per workload on the same instance. Each run used
10 seconds of warmup and 15 seconds of measurement. The median paired p95
latency ratios (proxy divided by direct) were 1.06× for point queries, 0.81×
for range queries, 7.62× for single-row INSERT and 7.54× for UPDATE. Median
proxy p95 was 32.06 ms for INSERT and 32.39 ms for UPDATE. These measurements
describe the tested workloads. Write-intensive workloads can incur higher tail
latency.

See the [support matrix](doc/support-matrix.md) and [known limitations](doc/limitations.md).

## 0.0.9 - Experimental early release

An early version for local evaluation with disposable, non-production data.
This entry records the behavior and limits of that release.

### Behavior

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

### Known limitations

- TiDB concurrent foreign-key integrity remains blocked: a concurrent
  delete/insert race can commit an orphan on the native engine and through
  Forkget. Version 0.0.9 does not repair or reliably refuse that path. This
  remains a correctness blocker for a qualified four-engine release.
- SQL support is a finite admitted application/query profile. Client DDL,
  arbitrary catalog queries and unrestricted ORM migrations are outside it.
- Writable SQL branches copy the snapshot; provisioning time and storage grow
  with the data.
- Standalone MongoDB operations can be partial or unknown and do not provide
  SQL-style multi-document transactions.

See [limitations](doc/limitations.md) before choosing an engine or workload.
