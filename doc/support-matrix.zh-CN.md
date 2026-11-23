# 支持范围

[English](support-matrix.md) · 简体中文

下表列出 **Forkget v0.1.1** 的发布支持范围。生产和托管环境的验收以该候选版本的实际验证结果为准。请使用 `forkget capabilities` 和分支状态查看实际部署的限制。

| 引擎基线 | 支持的协议与存储 | 边界 |
|---|---|---|
| MySQL 8.0.43 | 原生协议，共享只读基线和可写原生副本 | 一个逻辑数据库，须验证 TLS |
| PostgreSQL 16.14 | 原生协议，共享只读基线和可写原生副本 | 一个逻辑模式，须验证 TLS |
| MongoDB 7.0.48 | OP_MSG、文档增量与原生副本 | 单个直连端点，每个分支使用独立连接池，单机写入无原子性保证 |

由于并发外键完整性问题尚未解决，TiDB 不在 v0.1.1 的发布支持范围内。参阅[已知限制](limitations.zh-CN.md)。

## SQL 应用范围

导入支持整数主键和复合主键、生成的 BIGINT 键、精确小数、文本、二进制值、布尔值、日期、微秒精度的时间类型、已声明的索引、唯一约束和 CHECK 约束，以及同一模式内无环的外键。原生检查会比较具体定义，遇到不支持的细节时不会将其静默剔除。视图、触发器、例程、扩展、跨模式依赖和循环外键均超出导入范围。即使某类对象列在此处，准入检查仍可能拒绝某个具体的原生定义。

代表性应用配置为 SQLAlchemy 2.1.8 搭配常规的 PyMySQL 1.1.1 或 psycopg 3.2.9。该配置保留常规初始化、逻辑反射、生成键、批量刷写、乐观锁、事务回滚和重连行为。具体的查询集合见[业务用例范围](../test/application/README.zh-CN.md)。该范围不承诺支持任意 ORM 或系统目录查询。

客户端 DDL 和迁移、加锁读、SERIALIZABLE 和任意 INSERT SELECT 均超出代理的 SQL 支持范围。JSON EXPLAIN 只接受受支持的 SELECT，并拒绝 ANALYZE 和写入计划。计划会将支持的执行操作映射到逻辑对象角色，并移除物理名称和原生引擎的不透明表达式。

## 写入与恢复

新建分支默认为只读。可写 SQL 分支使用原生副本，预配和空间成本可见。预算按事务计算直接涉及的行数，并设置单表上限和小表最低额度。经独立审查的临时授权与显式启用的一次性语句审批各有独立的流程。

系统在可能发生变更之前持久化操作意图。SQL 提交在业务事务内写入私有提交见证，并在即将提交时重新执行提交检查。系统等待结果交付。交付失败时，已知成功结果仍会保留，受保护的写入则会暂停。重试交付不会重执行业务 DML。原生响应丢失及无法查明的结果会保持未知状态。请参阅[审计交付与存储恢复](audit-recovery.zh-CN.md)。

MongoDB 接受静止的源库副本，或包含 BSON 和索引元数据的一致性原生备份。持续接收写入的单机实例无法保证整库一致性。副本集、SRV、Atlas 配置以及 SQL 式多文档事务均超出支持范围。每个分支使用独立的直连连接池，并禁用可重试写入。部分生效的操作仍记录为部分完成，未知结果仍记录为未知。

## 资源上限

| 资源 | 上限或规则 |
|---|---|
| 新建分支的访问权限 | 默认为只读，暂存分支始终只读 |
| SQL 文本 / 词法单元 / 绑定参数 | 1 MiB / 65,536 / 16,384 |
| 单条语句的插入行数 | 1,024 |
| 世代 | 两个物理世代，保留的引用可能阻塞刷新 |
| 原生副本 | 十六个槽位，保留的阻塞项始终可见 |
| 租约 | 单次租约最长 24 小时，总生命周期最长七天 |
| 默认小表最低额度 | 十条直接涉及的行，受事务上限约束 |
| 临时授权 | 仅限一个分支，默认 15 分钟，最长一小时且不得超过分支到期时间 |
| 完整导出 | 默认总量 1 GiB，每条记录 64 MiB，结果流须完整，否则导出失败 |

FG 拒绝响应包含稳定的原因以及可安全用于处理问题的详细信息。各项限制见[已知限制](limitations.zh-CN.md)，保留结果的步骤见[应用工作流程](workflow.zh-CN.md)。

## 源码能力清单

[机器可读清单](../test/support-matrix.json)记录源码文件和已声明的用例 ID 之间的对应关系。`make matrix` 检查源码清单与下表是否一致。运行原生测试和进行发布验收各有独立步骤。表中的 TiDB 条目记录 v0.1.1 支持范围之外的源码能力。

| 能力 ID | 当前状态 | 引擎 |
| --- | --- | --- |
| `relation.mysql` | 已实现（仅源码清单） | mysql |
| `relation.postgres` | 已实现（仅源码清单） | postgresql |
| `relation.tidb` | 已实现（仅源码清单） | tidb |
| `relation.mongodb` | 已实现（仅源码清单） | mongodb |
| `metadata.validation` | 已实现（仅源码清单） | mysql, postgresql |
| `sql.parser` | 已实现（仅源码清单） | mysql, postgresql |
| `protocol.mysql` | 已计划（发布边界） | mysql |
| `protocol.postgres` | 已计划（发布边界） | postgresql |
| `protocol.tidb` | 已实现（仅源码清单） | tidb |
| `protocol.mongodb` | 已实现（仅源码清单） | mongodb |
| `write.insert_explicit` | 已实现（仅源码清单） | mysql, postgresql, mongodb |
| `write.update_delete` | 已实现（仅源码清单） | mysql, postgresql, mongodb |
| `write.generated_ids` | 已实现（仅源码清单） | mysql, postgresql |
| `write.transactions` | 已实现（仅源码清单） | mysql, postgresql |
| `lifecycle.branch` | 已计划（发布边界） | mysql, postgresql |
| `lifecycle.local_dev` | 已实现（仅源码清单） | mysql, postgresql |
| `lifecycle.local_ttl` | 已实现（仅源码清单） | mysql, postgresql |
| `lifecycle.refresh` | 已实现（仅源码清单） | mysql, postgresql |
| `policy.dryrun` | 已实现（仅源码清单） | mysql, postgresql |
| `integration.rowdiff` | 已实现（仅源码清单） | mysql, postgresql |
| `integration.github_app` | 已实现（仅源码清单） | mysql, postgresql |
| `integration.ci` | 已实现（仅源码清单） | mysql, postgresql |
| `integration.row_replay` | 已实现（仅源码清单） | mysql, postgresql |
| `verification.local_smoke` | 已实现（仅源码清单） | mysql, postgresql, tidb |
| `verification.gate_tools` | 已实现（仅源码清单） | mysql, postgresql, tidb |
| `deployment.managed_transport` | 已实现（仅源码清单） | mysql, postgresql, tidb, mongodb |
| `sql.ddl` | 已计划（发布边界） | mysql, postgresql |
| `sql.locking_serializable` | 已计划（发布边界） | mysql, postgresql |
| `sql.bulk_input` | 已计划（发布边界） | mysql, postgresql |
| `branch.access_layout` | 已实现（仅源码清单） | mysql, postgresql, tidb, mongodb |
| `snapshot.mysql` | 已实现（仅源码清单） | mysql |
| `snapshot.postgres` | 已实现（仅源码清单） | postgresql |
| `snapshot.tidb` | 已实现（仅源码清单） | tidb |
| `snapshot.mongodb` | 已实现（仅源码清单） | mongodb |
| `application.sqlalchemy` | 已实现（仅源码清单） | mysql, postgresql, tidb |
| `policy.scoped_budgets` | 已实现（仅源码清单） | mysql, postgresql, tidb, mongodb |
| `artifact.v2` | 已实现（仅源码清单） | mysql, postgresql, tidb, mongodb |
| `lifecycle.recovery` | 已实现（仅源码清单） | mysql, postgresql, tidb, mongodb |
| `diagnostics.capabilities` | 已实现（仅源码清单） | mysql, postgresql, tidb, mongodb |
| `storage.preflight` | 已实现（仅源码清单） | mysql, postgresql, tidb, mongodb |
