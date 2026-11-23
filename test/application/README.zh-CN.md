# SQLAlchemy 业务场景测试

[English](README.md) · 简体中文

该测试限定在一组明确的业务行为内，使用 SQLAlchemy 2.1.8 及标准的 PyMySQL 1.1.1 或 psycopg 3.2.9，分别在原生源数据库和 Forkget 上运行同一套模型和业务代码。TiDB 使用标准 MySQL 方言。测试保留初始化、反射、自动生成键、批量操作、乐观版本检查和自动刷新行为。

```sh
python3 -m venv .venv-application
.venv-application/bin/pip install -r test/application/requirements.txt
FG_GATE_BUILD_REVISION="$(git rev-parse HEAD)" cargo build --locked --workspace
.venv-application/bin/python test/application/run.py --engine mysql \
  --report-dir target/application-acceptance
```

测试环境会创建可丢弃、启用 TLS 的原生数据库和元数据库，建立实际的源 schema，并生成原生快照包。导入快照包后，它使用受限的运行时角色启动控制服务和代理。Docker 及固定版本的原生转储和恢复客户端必须在 PATH 上可用。请使用新的报告路径。严禁将生产库用作源数据库或目标数据库。

五张相互关联的表分别表示客户、产品、订单、订单明细和付款。流程检查现有数据行、自动生成的 BIGINT 键、唯一业务键、五个外键、十进制定点数、布尔值、日期、微秒精度的时间戳，以及用于乐观并发控制的订单版本。流程通过常规 ORM 刷新操作写入 1,001 个订单明细对象。PostgreSQL 的正常批处理路径会跨越分页边界，分为 1,000 条和 1 条两批，同时保留自动生成键的行为。

默认直接写入行数额度必须拒绝这次大批量刷新，并在独立审核人批准临时分支额度前回滚所有表上的变更。随后通过标准 ORM 验证已提交的数据行、约束和重连行为。对受支持的 JSON EXPLAIN，测试验证其将原生执行计划映射到逻辑字段，并拒绝 ANALYZE 和写入计划。

最后一阶段导出保留类型的净变更，准备重放目标，为该目标取得单独审核批准的额度，再应用重放作业。测试对比原生数据库、代理和重放目标三者的带类型状态、数据关系和实际键值。后续分配的键必须与重放写入的键互不冲突。任意 SQL、DDL 或目录查询仍受当前测试配置的准入范围限制。

使用 `--engine postgresql` 或 `--engine tidb` 可选择其他引擎，`all` 按顺序运行所有引擎。`--native-preflight` 仅检查源端 ORM 和捕获的前置条件，无需启动代理和控制服务。TiDB 的串行业务测试通过后，[并发外键阻塞项](../../doc/limitations.zh-CN.md)仍然存在。

报告包含带类型的合成数据行、生成的 ID、可安全记录的语句大小、脱敏后的计划、结果工件和清理结果。使用自行改造的模型时，请将生成的报告视为应用数据。凭据和私钥只能存放在测试环境的临时私有状态目录中。
