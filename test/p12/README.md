# Native audit and recovery tests

English · [简体中文](README.zh-CN.md)

These fixtures exercise durable intent, native SQL witnesses, truthful MongoDB
observations, audit-delivery failures and cleanup boundaries. They create owned
disposable databases. Do not point them at user or production data.

Install Python requirements in a private virtual environment and build binaries
with the source identity used by the fixtures:

```sh
python3 -m venv .venv
.venv/bin/pip install -r test/p10/requirements.txt
FG_GATE_BUILD_REVISION="$(git rev-parse HEAD)" cargo build --locked --release --workspace
.venv/bin/python test/p12/test_mongo_audit.py -v
.venv/bin/python test/p12/test_witness_storage.py -v
```

The pure tests cover framing, TLS readiness, partial sends, ACK correlation,
private recovery target selection and safe diagnostics. They do not replace
native execution. Native fixtures additionally need Docker, native clients and
tools on PATH, and free loopback ports:

```sh
.venv/bin/python test/p12/sql_audit.py --engine mysql --report-dir target/audit-sql
.venv/bin/python test/p12/mongo_audit.py --report-dir target/audit-mongo
.venv/bin/python test/p12/witness_storage.py --engine mysql --report-dir target/audit-storage
```

Use a new report path for every attempt and preserve failures. Run SQL engines
serially to limit competing local stacks. Reported success must include cleanup
confirmation. The source/binary identity checks must remain enabled.

SQL tests cover native errors, savepoints, commit reply loss, outcome-delivery
backpressure and private protocol boundaries. Witness tests cover malformed
storage, least-privilege grants, trigger/DDL visibility, interrupted cleanup,
restore invalidation and explicit replacement. MongoDB tests preserve ordered
and unordered partial replies, unknown ACK loss, late delivery, capture/drain
cuts and one-way write refusal without replaying business mutations.

Use [operator recovery](../../doc/audit-recovery.md) for actual upgrades. These
fault fixtures and timings are diagnostics; they do not establish managed
performance or resolve TiDB's [concurrent-FK limitation](../../doc/limitations.md).
