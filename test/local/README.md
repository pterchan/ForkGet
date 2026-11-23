# Disposable native test engines

English · [简体中文](README.zh-CN.md)

The local Compose fixture contains MySQL 8.0.43, PostgreSQL 16.14, TiDB 8.5.8
and MongoDB 7.0.48. It is for synthetic test data. TiDB's single-process fixture
does not establish concurrent foreign-key integrity; see
[known limitations](../../doc/limitations.md).

Keep one shell and its generated passwords when reusing volumes:

```sh
export FG_TEST_MYSQL_ROOT_PASSWORD="$(openssl rand -hex 24)"
export FG_TEST_POSTGRES_PASSWORD="$(openssl rand -hex 24)"
export FG_TEST_TIDB_ROOT_PASSWORD="$(openssl rand -hex 24)"
export FG_TEST_MONGO_ROOT_PASSWORD="$(openssl rand -hex 24)"
make local-up
make diff-test TAG=smoke
make local-down
```

`local-down` stops the fixture and retains volumes. `local-reset` deletes its
volumes and starts fresh data. Never use it on work that must be retained.
Choose a separate Compose project and unused ports for an isolated experiment;
remove only that project's resources.

| Engine | Default endpoint | Account | Port variable |
|---|---|---|---|
| MySQL | 127.0.0.1:33061 | root | MYSQL_PORT |
| PostgreSQL | 127.0.0.1:55432 | fg_test, database postgres | POSTGRES_PORT |
| TiDB | 127.0.0.1:33062 | root | TIDB_PORT |
| MongoDB | 127.0.0.1:27027 | root, auth database admin | MONGO_PORT |

An optional ignored `test/local/.env` can configure Compose, but test commands
also need matching shell values. Never commit passwords or print DSNs in a
report. A reference-versus-reference smoke run validates the fixture and harness;
it does not prove proxy behavior. Protocol and write-path changes need their
specific native cases.
