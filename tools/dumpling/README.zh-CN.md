# 使用私有配置的原生 Dumpling 启动器

[English](README.md) · 简体中文

`fg-dumpling-run` 引入 PingCAP 未经修改的 Dumpling 实现，固定在 TiDB v8.5.8 的提交 `8b857efa20363d50a8fa2ea7dd9809a85a61b115`。它为原生快照配置仅含数据的 SQL 导出，无需在进程命令行中暴露源数据库密码。导出格式和源数据库的读写均由原生 Dumpling 负责。

使用 Go 1.25.12 运行 `sh tools/dumpling/build.sh /absolute/output/fg-dumpling-run` 构建。脚本会将指定版本的上游源码下载到用户缓存中，并在该模块内构建，保留其 `replace` 指令和已提交的 `go.sum`。请将可执行文件安装到运维环境的 PATH 上。`fg-control snapshot capture` 生成私有配置，配置格式仅供内部使用。`--version` 输出启动器版本和固定的上游提交版本。

原生输出和诊断文件包含用户数据。上层捕获任务在私有目录中创建并保留这些文件，请勿发布捕获数据或原生诊断日志。原生 Dumpling CLI 通过命令行参数接收密码，因此经身份验证的捕获流程必须使用此启动器。

上游源码为 [PingCAP Dumpling](https://github.com/pingcap/tidb/tree/8b857efa20363d50a8fa2ea7dd9809a85a61b115/dumpling)，采用 Apache-2.0 许可证。依赖版本和校验和来自该固定版本的上游源码。
