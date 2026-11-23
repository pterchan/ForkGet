# 贡献指南

[English](CONTRIBUTING.md) · 简体中文

请通过 [Issue 和 Pull Request](https://github.com/pterchan/ForkGet) 提交可复现的问题和范围明确的改动。报告应包含引擎和客户端版本、涉及的受支持功能、最小化的合成 schema 和 FG 错误类别。请移除凭据和应用数据。请通过私下渠道处理潜在漏洞的细节。

代码、注释和公开技术文档使用英文。保留法律要求的署名和有用的技术说明。改动应遵守明确列出的[受支持子集](doc/support-matrix.zh-CN.md)。正确性和如实报告失败优先于增加功能或改善基准测试结果。

## 构建与检查

使用 `rust-toolchain.toml` 指定的 Rust 工具链和已提交的锁文件。

```sh
cargo build --locked --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --locked --workspace
```

原生测试需要可丢弃的数据库、Docker，以及固定版本的原生客户端和工具。请勿对含有需要保留的数据的数据库运行这些测试。参阅[测试引擎](test/local/README.zh-CN.md)、[审计故障测试](test/p12/README.zh-CN.md)和 [SQLAlchemy 测试配置](test/application/README.zh-CN.md)。默认跳过的原生测试必须显式配置各自所需的测试环境。默认单元测试通过时，这些原生测试仍未执行。

Console 使用 Node.js 24.19.0 和已提交的 npm 锁文件。

```sh
cd apps/console
npm ci
npm run check
npm test
npm run build
```

协议、策略、写入、清理和恢复方面的变更都需要有针对性的测试，覆盖各自的失败边界。保留原生响应、取消和回滚行为，并保留结果未知的状态以及清理证据。请勿为了让测试通过而关闭真实的 ORM 行为或缩减工作负载。

性能检查会记录带版本的验收策略。当前策略以实际观测到的本地基线为依据。调整验收标准本身既不会提升速度，也无法提供托管环境的实测数据。历史运行应保留其当时采用的策略和实际结果。
