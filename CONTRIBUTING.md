# Contributing

English · [简体中文](CONTRIBUTING.zh-CN.md)

Use [issues and pull requests](https://github.com/pterchan/ForkGet) for reproducible
problems and focused changes. Include engine/client versions, an admitted feature,
a minimal synthetic schema and the FG error category. Remove credentials and
application data. Keep potential vulnerability details private.

Use English for code, comments and public technical documentation. Preserve legal
attributions and useful technical explanations. Stay within the explicit
[supported subset](doc/support-matrix.md). Correctness and truthful failures take
priority over additional features or benchmark results.

## Build and check

Use the Rust toolchain from rust-toolchain.toml and committed lockfiles:

```sh
cargo build --locked --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --locked --workspace
```

Native tests need disposable databases, Docker and the pinned native clients/tools.
Never run them against a database that contains work you need to retain. See
[test engines](test/local/README.md), [audit failure tests](test/p12/README.md) and
the [SQLAlchemy profile](test/application/README.md). Default-ignored native tests
need their explicit fixtures; a default unit-test pass does not execute them.

For the Console, use Node.js 24.19.0 and the committed npm lockfile:

```sh
cd apps/console
npm ci
npm run check
npm test
npm run build
```

Protocol, policy, write, cleanup and recovery changes need meaningful tests of
their failure boundaries. Preserve native replies, cancellation, rollback,
unknown outcomes and cleanup evidence. Do not disable real ORM behavior or reduce
workload size to manufacture a passing result.

Performance checks record a versioned acceptance policy. The current policy is
calibrated to an observed local baseline; revising that criterion is not a speedup
or a managed-environment measurement. Retain each historical run's original policy
and outcome rather than relabeling it under a newer policy.
