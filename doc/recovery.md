# Result retention and recovery

English · [简体中文](recovery.zh-CN.md)

Save a complete result while its source branch and baseline remain available:

```sh
forkget status --id 42
forkget export --id 42 --output result.ndjson
forkget replay --engine postgresql --input result.ndjson --check
```

Use your actual branch ID and engine. Export publishes only a complete stream;
a truncated UI diff is not a complete result. Typed changes, catalog, provenance
and generated keys travel with the package. Default limits are 1 GiB total and
64 MiB per record. Protect the file as application data.

Replay uses the original complete retained generation, including an eligible
retiring generation. It does not merge onto a newer baseline. Its target remains
exclusive until typed verification completes. Source budget grants do not carry
to the target; use [staged replay and independent review](workflow.md#stage-and-replay).
After an uncertain apply, verify the existing job before retrying. A result
package is not a backup of metadata, serving databases or live transactions.

## Leases and failed tasks

```sh
forkget renew --id 42 --ttl-seconds 3600 --expected-lease-version 1
```

Use the version from current status. A lease is at most 24 hours and absolute
lifetime at most seven days. Renewal needs a live unexpired branch and does not
revive expired credentials, dropping branches or dropped branches. Existing
sessions observe authoritative renewed deadlines.

Successful jobs should drop their branch immediately. Failed CI jobs retain a
finite fallback lease; an explicit failure callback can renew within the absolute
limit. Keep immutable IDs because a reused name may identify a different branch.
Two physical generations and sixteen native-copy slots bound retained work.
Capacity conflicts identify blockers and cleanup state instead of evicting work.
After generation reclamation starts, new references and replay are refused.

## Interrupted imports and cleanup

Inspect `fg-control snapshot status` after interruption. Retry the recorded
owned cleanup with `fg-control snapshot retry-cleanup --id <job-id>` rather than
manually deleting guessed native objects. Failed import preserves the previously
active generation. Cleanup failures stay visible until repaired.

GitHub environment recreation after expiry is explicit: inspect
`forkget github list`, then use the expected old branch ID with
`forkget github recreate`. Duplicate webhook delivery does not renew or recreate
an environment. Inspect command help for the exact provider configuration.

## Upgrade and restore

A protocol upgrade needs coordinated control/proxy binaries and witness-only
preparation before traffic resumes. Independent native restore or PITR needs
storage-incarnation invalidation before new processes start. Follow the full
[audit upgrade and restore guide](audit-recovery.md); migration alone is not a
complete recovery procedure.

Preserve coherent metadata/native backups plus state and capture/result volumes.
Do not reset migration checksums, delete audit history or treat a missing witness
after restore as rollback. A known native success can survive an audit-delivery
outage while new protected writes pause; delivery retries never repeat business
DML. Irrecoverable unknown facts require explicit operator acknowledgement.
