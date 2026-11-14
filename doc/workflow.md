# From a source snapshot to a saved result

Use the [installation guide](install.md) to capture and import an admitted source
schema. Keep source backup credentials separate from serving credentials. Check
[supported objects and queries](support-matrix.md) before running an application.
TiDB's [concurrent foreign-key limitation](limitations.md) remains unresolved.

## Create and connect

Set `FG_OWNER_TOKEN` privately and use the loopback `FG_CONTROL_URL`, or run the
commands through the configured deployment operator container:

```sh
forkget capabilities
forkget fork order-review --write --class agent --ttl-seconds 3600
forkget status --id 42
forkget policy effective --id 42
```

Replace `42` with the immutable returned branch ID. Creation is asynchronous;
wait for active before connecting. Omitting `--write` creates a read-only branch.
SQL writes use a native copy, so provisioning time and space depend on snapshot
size. Check actual access and layout instead of inferring permission from a
legacy mode label.

Use your frontend database account, the branch name as the database, and
verified TLS. Owner API tokens are not database passwords. Keep ordinary
SQLAlchemy initialization, reflection and generated-key behavior enabled for
the admitted profile. MongoDB needs a separate direct client pool per branch.
See [connection examples](connecting.md).

## Keep work within its policy

Default Agent policies execute automatically within hard direct-row limits.
Budgets accumulate within one native transaction, rather than across an entire
agent task. Table limits and the small-table floor remain subject to the
transaction cap. Native cascades can add work beyond the direct-row count.

A refusal rolls back guarded SQL work. An independent authorized reviewer can
approve a temporary, branch-specific budget increase; begin a fresh transaction
after refusal. A grant does not revive an aborted transaction or extend the
branch lease. Explicit one-use statement approval is a separate opt-in policy.
See [budget commands](cli.md#budgets-and-independent-review).

A native success can be returned while audit delivery is temporarily unavailable.
The proxy then pauses new protected writes until delivery or recovery completes.
A lost native acknowledgement remains unknown. Do not replay business DML merely
to repair an audit event; inspect [audit status and recovery](audit-recovery.md).

## Inspect and save

```sh
forkget diff --id 42 --output diff.json
forkget export --id 42 --output result.ndjson
```

Diff output and the Console download are inspection views. A complete versioned
result includes typed net changes, catalog, provenance and generated-key data.
SQL export uses one native read snapshot; MongoDB capture drains existing branch
sessions and requires a new pool afterwards. A completed file is published only
after the stream succeeds. Default complete export is bounded to 1 GiB and
64 MiB per record; exceeding a cap fails and retains the source branch.

Result files contain application data. Protect them as sensitive data, even
when their audit metadata contains no statement parameters or document values.
Save while the source branch and original baseline are retained. A result is
not a complete deployment backup.

## Stage and replay

```sh
forkget replay --engine postgresql --input result.ndjson --check
forkget replay --engine postgresql --input result.ndjson --name reviewed-replay --stage-only
```

Select the package's engine. Preflight validates the package and original
retained baseline before creating a target. It does not merge onto a newer
generation. Staging returns a job and target branch ID without starting the
business transaction. The target remains exclusive until verification succeeds.

A source grant does not carry to the replay target. Obtain an independent
reviewed target grant if its normal policy is too small, then use the returned
job ID:

```sh
forkget replay --engine postgresql --apply-job 12
forkget replay --engine postgresql --verify-job 12
```

Verification compares exact typed changes. Generated IDs are preserved internally
and allocator state advances. An uncertain apply must be verified before another
apply is considered; it is not automatically repeated. MongoDB replay retains
its non-atomic and partial/unknown boundaries.

## Finish or retain

```sh
forkget drop --id 42
forkget status --id 42
```

Confirm cleanup. For work that needs more time, renew before expiry using the
current lease version. Each lease is bounded to 24 hours and absolute lifetime
to seven days. Expired, dropping and dropped branches are not resurrected by
renewal. Capacity conflicts identify retained blockers rather than evicting
failed work automatically. See [retention and recovery](recovery.md).
