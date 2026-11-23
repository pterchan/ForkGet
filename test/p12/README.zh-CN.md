# 原生审计与恢复测试

[English](README.md) · 简体中文

这些测试环境覆盖持久化意图、原生 SQL 提交见证、如实记录 MongoDB 操作结果、审计投递故障和清理边界。测试会创建归其所有的可丢弃数据库。请勿将测试指向用户数据或生产数据。

在私有虚拟环境中安装 Python 依赖，并使用测试环境要求的源码标识构建二进制文件。

```sh
python3 -m venv .venv
.venv/bin/pip install -r test/p10/requirements.txt
FG_GATE_BUILD_REVISION="$(git rev-parse HEAD)" cargo build --locked --release --workspace
.venv/bin/python test/p12/test_mongo_audit.py -v
.venv/bin/python test/p12/test_witness_storage.py -v
```

独立测试覆盖消息分帧、TLS 就绪、部分发送、ACK 关联、选择私有恢复目标和安全诊断。原生执行须另行验证。原生测试还需要 Docker、PATH 上可用的原生客户端和工具，以及空闲的回环端口。

```sh
.venv/bin/python test/p12/sql_audit.py --engine mysql --report-dir target/audit-sql
.venv/bin/python test/p12/mongo_audit.py --report-dir target/audit-mongo
.venv/bin/python test/p12/witness_storage.py --engine mysql --report-dir target/audit-storage
```

每次运行都应使用新的报告路径，并保留失败记录。按顺序测试各 SQL 引擎，以减少本地多套服务同时运行造成的资源争用。报告成功必须同时确认清理完成。源码和二进制文件的标识检查必须保持启用。

SQL 测试覆盖原生错误、保存点、提交响应丢失、结果投递背压和私有协议边界。见证测试覆盖存储格式错误、最小权限授权、触发器和 DDL 的可见性、清理中断、恢复后失效处理和显式替换。MongoDB 测试覆盖有序和无序操作的部分响应、ACK 丢失导致结果未知、延迟投递、捕获和排空切点，以及单向拒绝写入，并保留这些情况下的实际结果。测试期间不重放业务变更。

实际升级时，请遵循[运维恢复流程](../../doc/audit-recovery.zh-CN.md)。这些故障测试及其计时用于诊断。托管环境中的性能需另行验证，TiDB 的[并发外键限制](../../doc/limitations.zh-CN.md)仍然存在。
