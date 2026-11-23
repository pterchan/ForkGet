# 可丢弃的原生测试引擎

[English](README.md) · 简体中文

本地 Compose 测试环境包含 MySQL 8.0.43、PostgreSQL 16.14、TiDB 8.5.8 和 MongoDB 7.0.48，用于运行合成测试数据。TiDB 的单进程测试环境无法验证并发外键完整性，参阅[已知限制](../../doc/limitations.zh-CN.md)。

复用数据卷时，请继续使用同一个 Shell 会话和其中生成的密码。

```sh
export FG_TEST_MYSQL_ROOT_PASSWORD="$(openssl rand -hex 24)"
export FG_TEST_POSTGRES_PASSWORD="$(openssl rand -hex 24)"
export FG_TEST_TIDB_ROOT_PASSWORD="$(openssl rand -hex 24)"
export FG_TEST_MONGO_ROOT_PASSWORD="$(openssl rand -hex 24)"
make local-up
make diff-test TAG=smoke
make local-down
```

`local-down` 停止测试环境并保留数据卷。`local-reset` 删除其数据卷，并使用全新的数据启动。请勿在需要保留的数据上执行重置。进行隔离实验时，请选择单独的 Compose 项目和未占用的端口，并仅清理该项目的资源。

| 引擎 | 默认端点 | 账号 | 端口变量 |
|---|---|---|---|
| MySQL | 127.0.0.1:33061 | root | MYSQL_PORT |
| PostgreSQL | 127.0.0.1:55432 | fg_test，数据库 postgres | POSTGRES_PORT |
| TiDB | 127.0.0.1:33062 | root | TIDB_PORT |
| MongoDB | 127.0.0.1:27027 | root，认证数据库 admin | MONGO_PORT |

可使用 Git 忽略的可选文件 `test/local/.env` 配置 Compose。执行测试命令的 Shell 也需要设置相同的值。请勿提交密码或在报告中输出 DSN。原生基准端之间的冒烟测试验证测试环境和测试工具。验证代理行为需要专门的用例，协议和写入路径的变更需要运行各自对应的原生用例。
