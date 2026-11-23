# Forkget Console

[English](README.md) · 简体中文

这是由控制服务提供的 **Forkget 0.1.1** 静态 Console。
日常用法见 [Console 指南](../../doc/console.zh-CN.md)，随包部署方式见
[安装指南](../../doc/install.zh-CN.md)。运行时提供静态文件无需启动 Vite 或 Node.js 进程。

前端开发使用 Node.js 24.19.0 和已提交的 npm 锁文件。

```sh
npm ci
npm run dev
```

打开 <http://127.0.0.1:4193/>。`FG_CONSOLE_CONTROL_URL` 默认为
`http://127.0.0.1:8081`，接受回环 HTTP 源。开发代理只转发受支持的公开 API 路径。
远程操作控制服务时使用 SSH 隧道。

```sh
npm run check
npm test
npm run build
npx playwright install chromium
npm run test:browser
```

静态输出位于 `build/`。在启动独立控制服务前设置 `FG_CONSOLE_DIR`，省略该配置
会禁用静态文件服务。请将资产设为只读，目录中只放静态资产，凭据、采集包和 source map
请另行存放。预览服务用于本地审阅，部署由控制服务提供静态文件。

令牌只保存在内存中。演示模式需要显式开启，实时请求失败时保留真实错误。
界面分别显示访问权限、存储布局、租约、策略和审计交付健康状态。下载的差异用于查看，
完整回放需导出结果工件。内置九种语言的翻译，JSON 处理精确保留整数。

常规浏览器检查会跳过两项可选的实机夹具用例。实机夹具会创建、修改和删除分支，
因此只能使用可丢弃的原生数据库。只有实际执行通过的实机用例才能验证相应后端流程。
修改协议或写入流程时，请遵循[贡献指南](../../CONTRIBUTING.zh-CN.md)。
