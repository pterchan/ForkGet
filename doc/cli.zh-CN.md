# 所有者与运维命令

[English](cli.md) · 简体中文

`forkget` 是供所有者使用的 CLI。请通过私密配置设置 `FG_OWNER_TOKEN`，并用 `FG_CONTROL_URL` 指定监听在回环地址上的控制服务 HTTP 地址，默认为 `http://127.0.0.1:8081`。远程所有者通过 SSH 隧道连接。命令成功时输出 JSON，遇到 FG 拒绝时输出带类型的错误，并以非零状态退出。

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

请使用返回的不可变 ID 和租约版本替换示例值。分支名称长度为 3–63 个字符，只能包含小写字母、数字和连字符，且必须以字母开头。创建分支是异步操作。`--write` 指定访问权限，返回的布局描述存储方式。暂存分支始终只读。`drop` 会立即执行，并在清理分支专属资源前先排空会话。删除后仍可列出所保留的生命周期记录。名称被复用时，请检查分支状态。

<a name="budgets-and-independent-review"></a>

## 预算与独立审核

默认的 Agent 策略允许操作在每个事务的硬性行数限制内自动执行。对于需要审核的较大任务，可以申请仅适用于该分支的临时授权。

```sh
forkget budget request --id 42 --max-transaction-rows 2000 \
  --table-limit-bps 10000 --small-table-floor 2000 \
  --for-seconds 900 --reason 'Reviewed application experiment'
```

使用单独获得授权的审核者身份进行审核。

```sh
forkget budget inbox --state pending
forkget budget approve --id 42 --request-id 7
forkget budget deny --id 42 --request-id 8
forkget budget revoke --id 42 --grant-id 3
```

提交申请本身不会授予权限。审核者必须对该所有者拥有独立的策略管理权限。授权最长一小时，且不能超过分支有效期，默认有效期为 15 分钟。已回滚的事务无法通过授权恢复。撤销、到期和策略更新都会使生效的上下文失效，包括受保护的提交。操作被拒绝后，请启动新事务。

显式启用的语句审批是独立于临时授权的流程。

```sh
forkget approval list --id 42
forkget approval approve --id 42 --approval-id 9
forkget approval deny --id 42 --approval-id 10
forkget audit --help
```

使用 `forkget policy get agent` 检查类别策略。更新共享的类别策略需要管理权限和预期版本，参阅 `forkget policy set --help`。直接影响的行数在同一个原生事务内累计，系统不会对整个 Agent 任务跨事务累计用量。

## 运维工作流

运维人员分别配置源备份账号、服务后端管理员、运行时账号和元数据迁移账号，并使用 `fg-control` 检查、捕获和导入实际快照。

```sh
fg-control snapshot inspect --source-env FG_SOURCE_DSN \
  --schema commerce --name commerce-v1 --output plan.json
fg-control snapshot capture --source-env FG_SOURCE_DSN \
  --schema commerce --name commerce-v1 --output commerce-bundle
fg-control snapshot import --input commerce-bundle
fg-control doctor
fg-control status --json
```

输出路径必须尚不存在。请通过运维人员的私密环境提供源 DSN 和 CA。任务中断后，检查快照状态。如需重试清理，仅用 `snapshot retry-cleanup` 清理该任务的专属资源。参阅[安装](install.zh-CN.md)、[备份账号](source-backup-roles.zh-CN.md)以及[恢复](recovery.zh-CN.md)指南，了解角色和保留范围。

使用 `forkget github list` 列出 GitHub 绑定。重建过期环境需要显式操作，并会检查预期的旧分支 ID，参阅 `forkget github recreate --help`。重复的 webhook 不会为环境续期。CLI 不会自动将实验变更合并回生产源数据库。

## 审计管理

协议升级要求控制服务和代理的二进制文件匹配、原生服务的旧会话已全部退出，并提前完成仅涉及见证存储的准备工作。恢复流量之前，请检查 `forkget status --id 42`、`fg-control status --json` 和 `fg-control doctor` 的结果。`fg-control audit prepare`、`audit reconcile`、`audit invalidate-storage` 以及显式确认未知结果各自影响不同的安全条件。请遵循[完整运维流程](audit-recovery.zh-CN.md)。收到无法确认结果的响应时，请勿重建私有存储或重试业务写入。
