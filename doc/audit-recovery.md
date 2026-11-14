# Durable audit, upgrades and storage restore

Protected writes use a durable attempt identity. SQL work in one native
transaction shares an attempt, including savepoints. MongoDB uses one attempt
per admitted write command. The audit journal stores safe identity, policy,
counts and delivery state; it does not store statements, parameters, filters,
documents or native error messages.

SQL places a private commit witness in the same native transaction as business
changes. The witness stays outside logical catalogs, reflection, diff, export
and replay. A fresh fence checks branch/lease, policy and effective grant state
immediately before native commit. It is not a reusable authorization grant.

The proxy awaits durable outcome delivery before returning the native result.
If native success is known but outcome delivery cannot be confirmed, it preserves
that success and pauses new protected writes on the proxy. A background worker
retries delivery, never business DML. A lost native COMMIT acknowledgement
remains unknown. Current document contents cannot establish an old MongoDB
command's historical atomicity.

## Inspect the actual state

```sh
forkget status --id 42
forkget audit --id 42
fg-control status --json
fg-control doctor
```

Branch status includes witness readiness, pending outcomes, unresolved SQL facts,
MongoDB unknown/partial observations and cleanup holds. Owners see their own
branches. Operator status and doctor include deployment audit health. Run doctor
with the control service and proxy available.

`pending_delivery` includes admitted open transactions; it alone does not mean
writes are paused. `protected_writes_paused` is the proxy's actual backpressure
state and is null when the proxy cannot be reached.

## Coordinated protocol upgrade

Internal protocol **3** requires matching control/proxy binaries. Mixed rolling
upgrades are unsupported. Restarting control alone does not stop an old proxy.
Back up metadata, serving data and retained capture/result storage coherently.

1. Stop accepting new work and stop every old proxy and controller. Close
   application pools and confirm old native service sessions have drained.
2. Run `fg-control migrate` with the migration account and apply the updated
   [metadata runtime grants](../deploy/runtime-grants.sql). Do not reset old
   checksums or remove the installed migration history.
3. Before starting the new pair, run `fg-control audit prepare` with the native
   administration settings and `FG_BACKEND_DSN` for the same service account and
   backend. Preparation independently observes native service quiescence; a live
   proxy is not required. It adds only private SQL witness storage and grants,
   preserving existing branch IDs and business tables.
4. Start the matching control/proxy pair. Startup also checks native service
   quiescence. A SQL branch whose witness preparation failed stays readable and
   refuses protected writes with `reason=audit_storage_unprepared`.
5. Inspect doctor and branch status before reopening application pools.

The witness service grant is INSERT only; the collector gets SELECT/DELETE and
necessary PostgreSQL schema usage. Preparation validates exact identity, types,
keys, constraints and transactional storage. Triggers, foreign keys, unlogged
storage and incompatible definitions are refused. Ordinary preparation never
silently rebuilds a missing or mismatched ready witness.

MySQL's dedicated branch administrator needs scoped TRIGGER visibility on its
existing write namespaces; service and collector accounts do not. An empty
trigger listing under an unprivileged account is not absence proof. TiDB uses
its separate privilege profile and requires native metadata locking. Witness
collection acquires its own native lock before administrator attestation and
keeps it until commit. Metadata records collection only after native COMMIT
acknowledgement. See [serving roles](../deploy/README.md).

After new attempts exist, repair forward. Do not restart old binaries against
the upgraded deployment.

## Reconcile orphaned or unknown work

```sh
fg-control audit reconcile
fg-control audit reconcile --id 42 --drain
```

A pass is bounded. Healthy current-proxy transactions are left running. Explicit
branch drain closes the selected branch's sessions and reconciles its pending
attempts. Recovery first seals an attempt against further commit authorization
and confirms its old service session is absent, then checks trusted SQL storage:

- A matching transaction witness proves commit.
- An absent witness proves rollback only with the registered relation, header,
  identity and continuous storage history intact.
- Unreachable, missing, incompatible or untrusted storage preserves unknown and
  the evidence needed for later recovery.

A proven resolution is appended; the original unknown event is never rewritten.
Unresolved facts and pending delivery block physical cleanup and generation
retirement. Acknowledged witnesses are collected in bounded batches while the
reserved storage header remains.

## Independent restore, replacement or PITR

Independent storage restore breaks continuity. Stop application access, control
and proxy before restore. After restoring metadata/native data, invalidate the
old incarnation **before starting new processes**:

```sh
fg-control audit invalidate-storage --id 42 --operator operator-name
```

With proxy offline, this uses the configured service account to prove old native
service sessions are absent. It seals old attempts, disables protected writes
and prevents old absence proofs from becoming fabricated rollbacks. With proxy
available it drains the branch first. Unannounced native storage changes are
unsupported.

When proof cannot be recovered, an operator can explicitly acknowledge retaining
an unknown. Close application pools and use the exact attempt ID from status:

```sh
fg-control audit acknowledge-unknown --attempt <attempt-id> --operator operator-name
```

This appends attributed acknowledgement and releases its cleanup hold. It does
not turn unknown into commit, rollback or atomic MongoDB execution. After old
facts are durable or explicitly acknowledged, replace invalidated witness storage:

```sh
fg-control audit prepare --replace-untrusted --id 42 --operator operator-name
```

Replacement requires recorded invalidation, quiescence and cleared recovery
holds. It changes only the witness relation and records a new storage incarnation;
it does not rebuild application tables.

## MongoDB standalone boundary

Durable intent precedes the first possible native send. Multi-step capture and
replay acknowledge the previous observation and arm the next send atomically
in metadata. At most one physical step can remain uncertain. `w:0` and unsupported
one-way writes are refused before native send.

Native acknowledgements retain their original reply. Safe observations record
complete acknowledgement, acknowledgement with errors, not-sent or unknown,
with optional counts and numeric error codes. Partial effects are never called
a rolled-back transaction. Standalone recovery cannot infer historical commit
from current BSON state.

A durable unknown remains unknown. After old service-session quiescence and
durable delivery, it need not permanently pin branch storage. A delayed native
acknowledgement may append one exact late observation without replacing the
original unknown; conflicting late observations are refused. Replay quarantine
and verification rules remain in force.
