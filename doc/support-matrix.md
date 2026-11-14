# Supported subsets

This is the implemented source subset for an experimental candidate. It does not
establish release qualification or arbitrary native-engine compatibility. Check
`forkget capabilities` and branch status for actual deployment limits.

| Engine baseline | Admitted protocol/storage | Boundary |
|---|---|---|
| MySQL 8.0.43 | Native protocol; shared read-only base and writable native copies | One logical database; verified TLS |
| PostgreSQL 16.14 | Native protocol; shared read-only base and writable native copies | One logical schema; verified TLS |
| TiDB 8.5.8 | MySQL frontend with separate native import and plan mapping | Concurrent FK integrity remains blocked, including with real TiKV |
| MongoDB 7.0.48 | OP_MSG, document deltas and native copies | Single direct endpoint, independent pool per branch, non-atomic standalone writes |

**TiDB is not qualified for concurrent foreign-key integrity.** Its delete/insert
race can commit an orphan, and Forkget does not reliably reject it. Read the
[known limitations](limitations.md) before selecting this engine.

## SQL application profile

Admitted imports describe integer/composite primary keys, generated BIGINT keys,
exact decimals, text, binary, booleans, dates, microsecond time types, declared
indexes, unique/CHECK constraints and acyclic same-schema foreign keys. Native
inspection compares concrete definitions; unsupported details are not silently
stripped. Views, triggers, routines, extensions, cross-schema dependencies and
cyclic foreign keys are outside this import profile. Admission can refuse a
specific native definition even when its general type appears in this list.

SQLAlchemy 2.1.8 with ordinary PyMySQL 1.1.1 or psycopg 3.2.9 is the representative
application profile. It retains normal initialization, logical reflection,
generated keys, bulk flush, optimistic locks, transaction rollback and reconnect.
The [finite business profile](../test/application/README.md) describes its concrete
queries; this is not a promise to support every ORM or catalog query.

Client DDL/migrations, locking reads, SERIALIZABLE and arbitrary INSERT SELECT
are outside the proxy SQL subset. JSON EXPLAIN admits supported SELECT only;
ANALYZE and write plans are refused. Plans map admitted execution to logical
object roles and remove physical names and opaque native expressions.

## Writes and recovery

New branches default to read-only. Writable SQL uses native copies with visible
provisioning/space cost. Budgets charge direct rows per transaction, with a table
limit and small-table floor. Independent temporary grants and opt-in one-use
statement approvals are separate mechanisms.

Durable intent precedes possible mutation. SQL commits include a private witness
inside the business transaction and a fresh pre-commit fence. Outcome delivery
is awaited; known success is preserved during delivery failure while protected
writes pause. Delivery retries never repeat DML. Lost native acknowledgements
and irreducible unknowns retain their actual uncertainty. See
[audit delivery and storage recovery](audit-recovery.md).

MongoDB accepts a quiescent source copy or consistent native backup with BSON
and index metadata. A continuously written standalone does not provide a
whole-database consistency guarantee. Replica/SRV/Atlas profiles and SQL-style
multi-document transactions are outside this subset. Use a separate direct pool
per branch with retryable writes disabled. Partial effects remain partial and
unknown remains unknown.

## Bounded resources

| Resource | Limit or rule |
|---|---|
| New access | Read-only; staging always read-only |
| SQL text / tokens / binds | 1 MiB / 65,536 / 16,384 |
| Inserted rows per statement | 1,024 |
| Generations | Two physical generations; retained references may block refresh |
| Native copies | Sixteen slots; retained blockers stay visible |
| Lease | At most 24 hours per lease; seven days absolute lifetime |
| Default small-table floor | Ten directly touched rows, subject to transaction cap |
| Temporary grant | One branch; default 15 minutes, maximum one hour and branch expiry |
| Complete export | Default 1 GiB total, 64 MiB per record; complete stream or failure |

FG refusals include stable reasons and safe actionable details. Limits are
explained in [known limitations](limitations.md); result retention is covered by
the [application workflow](workflow.md).

## Source capability inventory

The [machine-readable inventory](../test/support-matrix.json) maps source files
and declared case IDs. `make matrix` checks that source inventory and this table
agree; it does not execute native tests or certify release quality. Status labels
below preserve the inventory's declared implementation/release boundaries.

| Capability ID | Current status | Engines |
| --- | --- | --- |
| `relation.mysql` | Implemented; source inventory only | mysql |
| `relation.postgres` | Implemented; source inventory only | postgresql |
| `relation.tidb` | Implemented; source inventory only | tidb |
| `relation.mongodb` | Implemented; source inventory only | mongodb |
| `metadata.validation` | Implemented; source inventory only | mysql, postgresql |
| `sql.parser` | Implemented; source inventory only | mysql, postgresql |
| `protocol.mysql` | Planned; release boundary | mysql |
| `protocol.postgres` | Planned; release boundary | postgresql |
| `protocol.tidb` | Implemented; source inventory only | tidb |
| `protocol.mongodb` | Implemented; source inventory only | mongodb |
| `write.insert_explicit` | Implemented; source inventory only | mysql, postgresql, mongodb |
| `write.update_delete` | Implemented; source inventory only | mysql, postgresql, mongodb |
| `write.generated_ids` | Implemented; source inventory only | mysql, postgresql |
| `write.transactions` | Implemented; source inventory only | mysql, postgresql |
| `lifecycle.branch` | Planned; release boundary | mysql, postgresql |
| `lifecycle.local_dev` | Implemented; source inventory only | mysql, postgresql |
| `lifecycle.local_ttl` | Implemented; source inventory only | mysql, postgresql |
| `lifecycle.refresh` | Implemented; source inventory only | mysql, postgresql |
| `policy.dryrun` | Implemented; source inventory only | mysql, postgresql |
| `integration.rowdiff` | Implemented; source inventory only | mysql, postgresql |
| `integration.github_app` | Implemented; source inventory only | mysql, postgresql |
| `integration.ci` | Implemented; source inventory only | mysql, postgresql |
| `integration.row_replay` | Implemented; source inventory only | mysql, postgresql |
| `verification.local_smoke` | Implemented; source inventory only | mysql, postgresql, tidb |
| `verification.gate_tools` | Implemented; source inventory only | mysql, postgresql, tidb |
| `deployment.managed_transport` | Implemented; source inventory only | mysql, postgresql, tidb, mongodb |
| `sql.ddl` | Planned; release boundary | mysql, postgresql |
| `sql.locking_serializable` | Planned; release boundary | mysql, postgresql |
| `sql.bulk_input` | Planned; release boundary | mysql, postgresql |
| `branch.access_layout` | Implemented; source inventory only | mysql, postgresql, tidb, mongodb |
| `snapshot.mysql` | Implemented; source inventory only | mysql |
| `snapshot.postgres` | Implemented; source inventory only | postgresql |
| `snapshot.tidb` | Implemented; source inventory only | tidb |
| `snapshot.mongodb` | Implemented; source inventory only | mongodb |
| `application.sqlalchemy` | Implemented; source inventory only | mysql, postgresql, tidb |
| `policy.scoped_budgets` | Implemented; source inventory only | mysql, postgresql, tidb, mongodb |
| `artifact.v2` | Implemented; source inventory only | mysql, postgresql, tidb, mongodb |
| `lifecycle.recovery` | Implemented; source inventory only | mysql, postgresql, tidb, mongodb |
| `diagnostics.capabilities` | Implemented; source inventory only | mysql, postgresql, tidb, mongodb |
| `storage.preflight` | Implemented; source inventory only | mysql, postgresql, tidb, mongodb |
