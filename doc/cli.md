# Owner and operator commands

English · [简体中文](cli.zh-CN.md)

`forkget` is the owner CLI. Set `FG_OWNER_TOKEN` privately and use
`FG_CONTROL_URL` for the HTTP loopback control origin (default
`http://127.0.0.1:8081`). Remote owners use an SSH tunnel. Success prints JSON;
an FG refusal prints a typed error and exits nonzero.

```sh
forkget capabilities
forkget fork first-task
forkget fork write-task --write --class agent --ttl-seconds 3600
forkget list
forkget status --id 42
forkget policy effective --id 42
forkget renew --id 42 --ttl-seconds 7200 --expected-lease-version 1
forkget diff --id 42 --output diff.json
forkget export --id 42 --output result.json
forkget replay --engine postgresql --input result.json --check
forkget replay --engine postgresql --input result.json --name replay-task
forkget drop --id 42
```

Replace immutable IDs and lease versions with the returned values. Branch
names are 3–63 lowercase letters, digits and hyphens, beginning with a letter.
Creation is asynchronous. `--write` expresses access; the returned layout
describes storage. Staging is always read-only. `drop` executes immediately and
drains sessions before owned cleanup. Retained lifecycle records can still be
listed after deletion. Inspect status when a name has been reused.

## Budgets and independent review

Default Agent policies execute automatically within per-transaction hard row
limits. A larger reviewed task can request a temporary branch-specific grant:

```sh
forkget budget request --id 42 --max-transaction-rows 2000 \
  --table-limit-bps 10000 --small-table-floor 2000 \
  --for-seconds 900 --reason 'Reviewed application experiment'
```

Use the separately authorized reviewer identity for review:

```sh
forkget budget inbox --state pending
forkget budget approve --id 42 --request-id 7
forkget budget deny --id 42 --request-id 8
forkget budget revoke --id 42 --grant-id 3
```

Requests alone authorize nothing. The reviewer needs independent policy-admin
permission for the owner. A grant lasts at most an hour and no longer than the
branch; its default is 15 minutes. It does not restore a rolled-back
transaction. Revocation, expiry and policy updates invalidate the effective
context, including guarded commit. Start a fresh transaction after refusal.

Explicit opt-in statement approval is distinct from a temporary grant:

```sh
forkget approval list --id 42
forkget approval approve --id 42 --approval-id 9
forkget approval deny --id 42 --approval-id 10
forkget audit --help
```

Inspect class policy with `forkget policy get agent`. Updating a shared class
policy requires administrative authorization and an expected version; see
`forkget policy set --help`. Direct touched rows accumulate inside a native
transaction. This is not a cumulative budget across an entire Agent task.

## Operator workflows

The operator configures independent source backup, serving administrator,
runtime and metadata migration accounts. It uses `fg-control` to inspect,
capture and import real snapshots:

```sh
fg-control snapshot inspect --source-env FG_SOURCE_DSN \
  --schema commerce --name commerce-v1 --output plan.json
fg-control snapshot capture --source-env FG_SOURCE_DSN \
  --schema commerce --name commerce-v1 --output commerce-bundle
fg-control snapshot import --input commerce-bundle
fg-control doctor
fg-control status --json
```

Output paths must not already exist. Supply the source DSN and CA through the
private operator environment. Inspect snapshot status after an interrupted
job and retry only its owned cleanup using `snapshot retry-cleanup`. The
[installation](install.md), [backup account](source-backup-roles.md) and
[recovery](recovery.md) guides describe role and retention boundaries.

GitHub bindings are listed with `forkget github list`. Recreating an expired
environment is explicit and checks its expected old branch ID; use
`forkget github recreate --help`. Duplicate webhooks do not renew environments.
The CLI never merges an experiment into a production source automatically.

## Audit administration

Protocol upgrades require matching control/proxy binaries, native service
quiescence and witness-only preparation. Inspect `forkget status --id 42`,
`fg-control status --json` and `fg-control doctor` before resuming traffic.
`fg-control audit prepare`, `audit reconcile`, `audit invalidate-storage` and
explicit unknown acknowledgement have different safety effects. Follow the
[complete operator procedure](audit-recovery.md), rather than rebuilding
private storage or retrying a business write after an uncertain response.
