# 隔离协议检查

[English](README.md) · 简体中文

在仓库根目录运行以下命令，需要 Docker Compose、OpenSSL 和 Python 3。

```sh
FG_PROTOCOL_REPORT_ROOT="$PWD/target/protocol" make protocol-test ENGINE=all
```

选择 `mysql`、`postgresql`、`tidb` 或 `mongodb` 可仅测试一个引擎。测试运行程序会构建固定版本的驱动镜像，创建可丢弃的原生服务，并在回环地址上启动隔离的前端测试环境。它会生成临时凭据和证书，并删除自己创建的容器和数据卷。

[drivers.json](drivers.json) 定义固定的客户端版本和必测用例。SQL 检查涵盖验证服务端身份的 TLS、身份认证、获准执行的查询、预处理语句执行和事务行为。底层协议检查覆盖消息分帧、错误码、句柄归属、PostgreSQL portal 暂停、取消和 COPY 输出。MongoDB 测试使用范围明确受限的独立回环前端，完整的分支行为需要专门测试。

前端测试身份为 `p1_user`，测试分支为 `p1-fixture`。它们的密钥由测试运行程序在执行时生成。SQL 服务角色可以读取种子数据关系，也可以向单独的回滚见证对象插入数据。产品行为参阅[支持矩阵](../../doc/support-matrix.zh-CN.md)，行为边界参阅[已知限制](../../doc/limitations.zh-CN.md)。

## 协议规范与许可证

Rust 编解码器和认证交互遵循公开的协议规范。独立的驱动程序在各自的测试容器中运行。`make license-audit` 检查测试环境的 Rust 依赖。

| 范围 | 主要规范 |
|---|---|
| MySQL 数据包、能力、命令和结果 | [经典客户端/服务端协议](https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_PROTOCOL.html) |
| MySQL caching SHA-2 认证 | [认证交互](https://dev.mysql.com/doc/dev/mysql-server/8.0.46/page_caching_sha2_authentication_exchanges.html) |
| PostgreSQL 消息分帧、会话和取消 | [消息格式](https://www.postgresql.org/docs/16/protocol-message-formats.html)、[消息流程](https://www.postgresql.org/docs/16/protocol-flow.html) |
| PostgreSQL SCRAM 和 TLS | [PostgreSQL SASL](https://www.postgresql.org/docs/16/sasl-authentication.html)、[RFC 5802](https://www.rfc-editor.org/rfc/rfc5802)、[RFC 7677](https://www.rfc-editor.org/rfc/rfc7677) |

TLS 通过 rustls/tokio-rustls 实现，并使用 ring 加密提供程序。哈希、HMAC、PBKDF2、常量时间比较和系统随机数由现有 Rust 库提供。重新分发依赖或镜像时，请保留要求附带的许可证声明。

日志和版本摘要写入 `FG_PROTOCOL_REPORT_ROOT`。协议测试通过仅覆盖其固定的准入范围。完整的产品生命周期、任意客户端的兼容性和生产发布资格均需单独验证。
