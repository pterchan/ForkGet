# SQLAlchemy business profile

English · [简体中文](README.zh-CN.md)

The finite profile uses SQLAlchemy 2.1.8, ordinary PyMySQL 1.1.1 or psycopg 3.2.9,
and the same model/business code against native source and Forkget. TiDB uses
the ordinary MySQL dialect. It retains initialization, reflection, generated
keys, bulk behavior, optimistic version checks and autoflush.

```sh
python3 -m venv .venv-application
.venv-application/bin/pip install -r test/application/requirements.txt
FG_GATE_BUILD_REVISION="$(git rev-parse HEAD)" cargo build --locked --workspace
.venv-application/bin/python test/application/run.py --engine mysql \
  --report-dir target/application-acceptance
```

The fixture creates disposable TLS native/metadata databases, an actual source
schema and a native snapshot bundle. It imports that bundle, then starts the
control service and proxy with restricted runtime roles. Docker and the pinned
native dump/restore clients must be available on PATH. Use a new report path;
never substitute a production source or target.

Five related tables model customers, products, orders, lines and payments.
The workflow checks existing rows, generated BIGINT keys, unique business keys,
five foreign keys, decimals, booleans, dates, microsecond timestamps and an
optimistic order version. It flushes 1,001 line objects normally. PostgreSQL's
normal batch path crosses its 1,000-plus-1 page boundary; generated-key behavior
is not disabled to simplify the test.

The default direct-row budget must reject the large flush and roll back every
table before an independent reviewer grants a temporary branch budget. The
ordinary ORM then verifies committed rows, constraints and reconnect behavior.
Supported JSON EXPLAIN maps native plans to logical fields and refuses ANALYZE
or write plans.

The final phase exports typed net changes, stages a replay target, obtains its
separate reviewed budget and applies the job. Native/proxy/replay typed state,
relationships and actual keys are compared. Subsequent allocations must not
collide with replayed keys. A verification result does not open arbitrary SQL,
DDL or catalog queries beyond the admitted profile.

`--engine postgresql` or `--engine tidb` selects another engine; `all` runs them
serially. `--native-preflight` checks source ORM/capture prerequisites without
starting proxy/control. A TiDB serial application pass does not close the
[concurrent foreign-key blocker](../../doc/limitations.md).

Reports contain synthetic typed rows, generated IDs, safe statement sizes,
sanitized plans, artifacts and cleanup results. Treat reports from your own
adapted model as application data. Credentials and private keys belong only in
the fixture's temporary private state.
