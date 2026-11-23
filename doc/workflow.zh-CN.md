# 从源库快照到保存结果

[English](workflow.md) · 简体中文

按照[安装指南](install.zh-CN.md)，捕获并导入受支持的源库模式。将源库备份凭据与服务凭据分开。运行应用前，请查阅[支持的对象和查询](support-matrix.zh-CN.md)。

## 创建和连接分支

在私有环境中设置 `FG_OWNER_TOKEN` 并使用环回地址 `FG_CONTROL_URL`，也可通过已配置的部署运维容器运行这些命令。

```sh
forkget capabilities
forkget fork order-review --write --class agent --ttl-seconds 3600
forkget status --id 42
forkget policy effective --id 42
```

将 `42` 替换为创建命令返回的不可变分支 ID。分支以异步方式创建，请等待分支进入活动状态后再连接。省略 `--write` 会创建只读分支。SQL 写入使用原生副本，预配时间和所需空间取决于快照大小。请以实际访问权限和存储布局为准。旧版模式标签不足以确定权限。

使用前端数据库账号和已验证的 TLS 连接，将分支名称作为数据库名。数据库密码应独立设置，切勿使用所有者 API 令牌。对受支持的 SQLAlchemy 配置，请保留常规初始化、反射和生成键行为。MongoDB 的每个分支需要独立的直连客户端连接池。请参阅[连接示例](connecting.zh-CN.md)。

## 遵守策略限制

默认 Agent 策略在直接影响行数的硬性限制内自动放行操作。预算只在单个原生事务内累计，整个 Agent 任务的用量不在该预算范围内。单表限额和小表最低额度仍受事务上限约束。原生级联操作可能执行超出直接计数的额外工作。

发生拒绝时，系统会回滚受保护的 SQL 操作。独立且获得授权的审查人可以批准临时提高特定分支的预算。被拒绝后请开启新事务。授权不会恢复已中止的事务，也不会延长分支租约。一次性语句审批须通过单独的策略显式启用。请参阅[预算命令](cli.zh-CN.md#budgets-and-independent-review)。

审计交付暂时不可用时，仍可能返回原生操作成功结果。随后，代理会暂停受保护的新写入，直至交付或恢复完成。原生确认丢失时，结果仍为未知。切勿仅为修复审计事件而重放业务 DML，请检查[审计状态与恢复](audit-recovery.zh-CN.md)。

## 检查与保存

```sh
forkget diff --id 42 --output diff.json
forkget export --id 42 --output result.ndjson
```

差异输出与控制台的差异下载用于检查。带版本的完整结果工件包含带类型的净变更、目录、来源信息和生成键信息。SQL 导出使用一个原生读快照。MongoDB 捕获会排空现有分支会话，随后须使用新的连接池。结果流成功完成后才会发布文件。完整导出的默认总量上限为 1 GiB，每条记录上限为 64 MiB。超限会导致导出失败，源分支会继续保留。

结果文件含有应用数据。即使审计元数据省略了语句参数或文档值，也应按敏感数据保护结果文件。请在源分支和原始基线仍处于保留状态时保存。结果文件不能作为完整的部署备份。

<a name="stage-and-replay"></a>

## 暂存与回放

```sh
forkget replay --engine postgresql --input result.ndjson --check
forkget replay --engine postgresql --input result.ndjson --name reviewed-replay --stage-only
```

请选择与结果包匹配的引擎。预检会在创建目标前校验结果包和保留的原始基线。回放无法合并到更新的世代。暂存会返回作业 ID 和目标分支 ID，业务事务此时尚未启动。目标分支保持独占，直至校验成功。

源分支的授权不会传递到回放目标。目标的常规策略额度不足时，请先为目标获取经独立审查的授权，再使用返回的作业 ID 执行以下命令。

```sh
forkget replay --engine postgresql --apply-job 12
forkget replay --engine postgresql --verify-job 12
```

校验会精确比较带类型的变更。生成的 ID 会在内部保留，分配器状态也会推进。执行结果不确定时，必须先校验再考虑重新执行。系统不会自动重复执行。MongoDB 回放仍受非原子性以及结果可能部分完成或未知的限制。

## 结束或保留分支

```sh
forkget drop --id 42
forkget status --id 42
```

确认清理已完成。如需更多时间，请使用当前租约版本在到期前续租。单次租约最长 24 小时，总生命周期最长七天。续租无法恢复已过期、正在删除或已删除的分支。发生容量冲突时，系统会指出保留的阻塞项，失败任务的分支仍予以保留。请参阅[保留与恢复](recovery.zh-CN.md)。
