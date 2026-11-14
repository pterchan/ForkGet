# Limits and known limitations

Forkget admits a finite set of engine objects, queries and commands. Native
protocol compatibility does not mean arbitrary SQL, DDL or ORM migrations are
accepted. Consult [capabilities and supported subsets](support-matrix.md) before
using a schema. Unsupported requests fail explicitly.

## TiDB concurrent foreign keys

TiDB 8.5.8 concurrent parent deletion and child insertion can commit an orphan,
both through Forkget and on the native engine with real TiKV. Pessimistic mode
and a parent primary-key pre-lock did not prevent the observed race. Rollback
variants also failed the required waiting barrier. Forkget currently neither
repairs nor reliably refuses this concurrent path.

This is a correctness blocker for the candidate. Do not rely on this TiDB path
for concurrent foreign-key integrity. Serial imports, application runs and
successful ordinary queries do not establish that guarantee. This limitation
is independent of any performance-policy change.

## Storage and retention

- New branches are read-only; staging stays read-only. A legacy MongoDB branch
  may retain its historical write permission, which is reported separately.
- Writable SQL branches use native copies. Provisioning time and native space
  grow with the snapshot. Read-only branches share the pinned baseline.
- Two physical generations and sixteen native-copy slots are retained resources.
  Failed work is not automatically evicted. Inspect blockers before refreshing
  or creating another writable branch.
- A lease lasts at most 24 hours and absolute branch lifetime at most seven days.
  Renew before expiry using its current lease version.
- A complete result needs its original retained baseline for replay. It is not
  a merge onto a newer snapshot or a full database backup.

## Query and budget boundaries

The admitted SQL profile has 1 MiB SQL text, 65,536 tokens, 16,384 parameters and
1,024 inserted rows per statement. Reflection uses a closed logical catalog.
Arbitrary system-catalog queries, client DDL, locking reads, SERIALIZABLE and
arbitrary INSERT SELECT are outside this subset. JSON EXPLAIN admits supported
SELECT only; ANALYZE and write plans are refused.

Budgets accumulate directly affected rows within a transaction, subject to the
transaction cap, table share and small-table floor. Native cascades can add work
outside that direct-row count. This is not a cumulative quota for an entire
agent task. Temporary grants need independent review and do not carry from a
source branch to a replay target.

## MongoDB standalone

Use one independent direct client pool per branch with retryable writes disabled.
A connection binds to its first branch data command. Replica/SRV discovery,
Atlas deployment profiles and SQL-style multi-document transactions are outside
the supplied subset. Unacknowledged writes and unsupported one-way commands are
refused before native send.

A continuously written standalone source does not provide a globally consistent
whole-database backup. Capture needs a quiescent copy or consistent backup.
Partial writes and lost acknowledgements remain partial or unknown. Current BSON
contents cannot prove an earlier command committed atomically.

## Operational boundary

Control and drain are loopback services; use an authenticated SSH tunnel for
remote control. The supplied Compose template is one local SQL deployment,
not a hosted service or high-availability arrangement. Verify TLS identities.
Read [audit recovery](audit-recovery.md) before upgrade or independent restore.
A native success can be preserved while audit delivery is pending and new
protected writes pause. Never retry business DML merely to repair delivery.
