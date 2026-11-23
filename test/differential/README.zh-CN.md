# 差分测试工具

[English](README.md) · 简体中文

`fg-diff` 执行选定的测试语料，并比较列名和类型、NULL、值、重复项出现的次数、受影响行数，以及稳定的错误类别。SQL 测试使用相互独立的原生数据库或 schema。MongoDB 命令测试比较规范化的原生命令响应。

## 本地自检

按[本地环境指南](../local/README.zh-CN.md)配置四个可丢弃测试引擎的密码，然后运行以下命令。

```sh
make local-up
make diff-test TAG=smoke
```

此命令以 `reference-vs-reference` 模式运行全部四个引擎，验证比较器能确认等价的原生执行结果一致。代理行为和支持矩阵中的能力级别需要各自的验证证据。

如需直接运行一个引擎的比较，设置其基准端和待测端的 URL 环境变量，并选择一个语料标签。以下以 MySQL 为例。

```sh
export FG_DIFF_MYSQL_REF_URL="$MYSQL_TEST_DSN"
export FG_DIFF_MYSQL_CAND_URL="$MYSQL_TEST_DSN"
cargo run --locked -p fg-diff -- run --engine mysql --tag smoke \
  --report-root target/differential
```

CLI 的引擎参数可取 `mysql`、`postgres`、`tidb` 和 `mongodb`。TiDB 使用 `mysql://` 连接 URL。请勿在 Shell 历史或报告中保存凭据。缺少端点、标签未知或未选中任何用例时，命令会失败。退出码 0 表示成功，1 表示结果不一致，2 表示用法错误或传输故障。

## 基准端与只读分支的比较

`fg-diff run --mode reference-vs-proxy` 将预先填充数据的 SQL 基准表与实际的只读分支进行比较。除特定引擎通常使用的基准端和待测端 URL 变量外，还需提供 `FG_DIFF_REF_CA` 和 `FG_DIFF_PROXY_CA`。两个连接都会验证服务端身份。此模式支持比较数据行，也支持验证仅待测端拒绝的情况，并精确检查 FG 错误码、SQLSTATE 和 MySQL errno。此模式拒绝含有写入操作的语料步骤或 MongoDB 代理会话。

`make p2-test ENGINE=mysql` 运行隔离的分支测试，使用独立的原生结果作为对照，并检查预处理语句的元数据。`make p2-mongo-test` 单独测试 MongoDB 分支的实际行为。串行测试通过后，[TiDB 并发外键限制](../../doc/limitations.zh-CN.md)仍然存在。

## 测试语料与比较边界

JSON 用例数组位于 `corpus/`，可确定性复现的原生测试环境定义位于 `fixtures/`。用例 ID 全局唯一。SQL 步骤声明 `rows`、`affected`、`error` 或受支持的代理拒绝预期。MongoDB 步骤声明命令。按全序比较时，必须显式指定完整的排序规则。多重集比较会保留重复项的计数。

测试工具精确比较值，浮点值也要求精确匹配。客户端收到的空结果集可能缺少原生列元数据。最终状态必须通过显式的 SELECT 步骤检查。MySQL 的受影响行数取决于 SQLx 的 `CLIENT_FOUND_ROWS` 设置，统计的是匹配行数。解读结果时应考虑上述边界。

报告包含观测结果、版本和源码标识，连接 URL 会被省略。使用 `--report-root` 将生成的输出保存在版本控制忽略的目录或仓库外部。用户提供的测试数据和原生诊断信息可能含有实际数据，请在共享前检查报告。
