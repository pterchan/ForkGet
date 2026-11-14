# Differential harness

`fg-diff` executes the selected corpus and compares column names/types, NULLs,
values, duplicate multiplicity, affected rows and stable error classes. SQL
fixtures use independent native databases or schemas. MongoDB command fixtures
compare canonical native command replies.

## Local self-check

Configure the four disposable engine passwords as described in
[the local environment guide](../local/README.md), then run:

```sh
make local-up
make diff-test TAG=smoke
```

This command runs all four engines in `reference-vs-reference` mode. It proves
that equivalent native executions agree with the comparator. It does not prove
proxy behavior or promote a capability in the support matrix.

To run one axis directly, set its reference and candidate URL environment
variables and select a corpus tag. For example:

```sh
export FG_DIFF_MYSQL_REF_URL="$MYSQL_TEST_DSN"
export FG_DIFF_MYSQL_CAND_URL="$MYSQL_TEST_DSN"
cargo run --locked -p fg-diff -- run --engine mysql --tag smoke \
  --report-root target/differential
```

CLI engine values are `mysql`, `postgres`, `tidb` and `mongodb`. TiDB uses a
`mysql://` connection URL. Keep credentials out of shell history and reports.
Missing endpoints, unknown tags and empty selections fail rather than producing
a passing report. Exit codes are 0 for success, 1 for mismatches and 2 for
usage/transport failures.

## Reference versus a read branch

`fg-diff run --mode reference-vs-proxy` compares preseeded SQL reference tables
with a real read branch. Supply the normal engine-specific reference/candidate
URL variables, plus `FG_DIFF_REF_CA` and `FG_DIFF_PROXY_CA`. Both connections
verify the server identity. The mode supports row comparisons and candidate-only
refusals with exact FG code, SQLSTATE and MySQL errno. It does not accept
mutation corpus steps or MongoDB proxy sessions.

`make p2-test ENGINE=mysql` runs the isolated branch harness with its own native
oracle and prepared-metadata checks. `make p2-mongo-test` exercises actual
MongoDB branch behavior separately. Passing a serial suite does not resolve the
[TiDB concurrent foreign-key limitation](../../doc/limitations.md).

## Corpus and comparison boundaries

JSON case arrays live under `corpus/`; deterministic native fixtures live under
`fixtures/`. Case IDs are globally unique. SQL steps declare `rows`, `affected`,
`error` or supported proxy-refusal expectations; MongoDB steps declare commands.
Total-order comparisons require an explicit complete ordering. Multiset
comparisons preserve duplicate counts.

The harness compares exact values rather than applying floating-point
tolerances. Empty result sets may lack native column metadata through the
client layer. Final state must be checked by explicit SELECT steps. MySQL
affected-row observations reflect SQLx's `CLIENT_FOUND_ROWS` setting and count
matched rows. These boundaries must remain visible when interpreting results.

Reports contain observations, versions and source identity, with connection
URLs omitted. Use `--report-root` to keep generated output in an ignored or
external directory. User-provided fixtures and native diagnostics may contain
data; review reports before sharing them.
