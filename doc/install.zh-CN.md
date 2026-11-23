# 本地安装与运行

[English](install.md) · 简体中文

在 [GitHub Releases](https://github.com/pterchan/ForkGet/releases) 中选择一个标签。选定工作负载前，请查看对应版本的[引擎支持范围](support-matrix.zh-CN.md)和[已知限制](limitations.zh-CN.md)。请使用可丢弃的非生产数据评估预发行版。

在本地评估尚未发布的候选版本时，请使用提供的候选源码，并按下文的 Compose 步骤构建。跳过克隆和检出标签的步骤，在提供的工作区根目录运行 `sh deploy/prepare.sh`。若使用已发布的标签，请阅读该标签对应的文档。

## 下载发行版

使用同一标签下的源代码归档、二进制归档、控制台归档和依赖声明。下载该标签对应的 `SHA256SUMS`，并在解压归档前于下载目录运行以下命令。

```sh
sha256sum --check SHA256SUMS
```

确认每个已下载的归档文件均出现在校验列表中，且结果为 `OK`。保留 MIT `LICENSE` 以及随附的依赖声明。运行二进制文件之前，请在发行页面核对源代码和构建修订版本。

发布的 Linux 二进制文件面向 x86_64 架构。控制服务要求 glibc 2.39，代理和 CLI 要求 glibc 2.34。要使用打包的控制台，请解压其独立归档，并在启动 `fg-control serve` 之前将 `FG_CONSOLE_DIR` 设为归档中的 `build` 目录。请查看所选标签的发行资源，确认是否提供容器镜像。

## 使用下载的二进制文件运行 PostgreSQL 部署

将解压后的 `bin` 目录添加到 `PATH`。从同版本的源代码归档取得部署 SQL 和证书生成脚本。在运维主机上安装 OpenSSL、Linux util-linux（`setpriv`）和 PostgreSQL 客户端工具。此版本源代码的快照命令要求 PostgreSQL 16.15 的 `pg_dump` 和 `pg_restore`。捕获前请核对工具版本。

运行 `sh deploy/prepare.sh` 生成前端 TLS 文件和账号配置。配置[原生服务后端账号](../deploy/README.zh-CN.md)、独立的元数据 PostgreSQL 实例，以及独立的[源备份账号](source-backup-roles.zh-CN.md#postgresql-16)。源数据库与服务数据库应使用相同的 UTF-8 libc 区域设置。PostgreSQL 导入还需要有权创建暂存数据库的原生管理员。为元数据迁移账号授予 DDL 权限，并为 `fg_meta_runtime` 登录角色授予连接专用元数据库的 CONNECT 权限。

将机密放入相应进程的私密配置中。启动服务前设置主机路径和回环地址。

| 进程 | 设置 |
| --- | --- |
| 元数据迁移 | 迁移账号的 `FG_META_MIGRATION_DSN`。运行 `fg-control migrate` 后，以元数据管理员身份应用 `deploy/runtime-grants.sql`。 |
| 快照运维 | `FG_META_DSN` 和 `FG_META_MIGRATION_DSN`、[部署指南](../deploy/README.zh-CN.md#private-configuration)中的四个原生 DSN，以及 `FG_BACKEND_CA`、`FG_SOURCE_CA`、`FG_SOURCE_DSN` 和 `FG_STATE_DIR`。导入时将 `FG_META_DSN` 设为迁移账号的 DSN。 |
| 控制服务 | 受限权限的 `FG_META_DSN`，以及 `FG_BACKEND_GC_DSN`、`FG_BRANCH_ADMIN_DSN`、`FG_BACKEND_CA`、`FG_CONTROL_ACCOUNTS`、`FG_INTERNAL_TOKEN` 和与运维环境共用的私密目录 `FG_STATE_DIR`，该目录须使用绝对路径。设置 `FG_CONTROL_LISTEN=127.0.0.1:8081`、`FG_PROXY_CONTROL_URL=http://127.0.0.1:8082`，并按需设置 `FG_CONSOLE_DIR`。 |
| 代理 | 受限权限的 `FG_BACKEND_DSN`，以及 `FG_BACKEND_CA`、`FG_FRONTEND_ACCOUNTS`、`FG_TLS_CERT`、`FG_TLS_KEY` 和与控制服务相同的 `FG_INTERNAL_TOKEN`。设置 `FG_CONTROL_URL=http://127.0.0.1:8081`、`FG_PROXY_CONTROL_LISTEN=127.0.0.1:8082`，并为 `FG_LISTEN_PG` 指定空闲的回环地址和端口。 |
| 所有者 CLI | `FG_CONTROL_URL=http://127.0.0.1:8081` 和 `FG_OWNER_TOKEN`。 |

在控制服务、代理和运维环境中配置匹配的角色名 `FG_BACKEND_SERVICE_USER=fg_service`、`FG_BACKEND_GC_USER=fg_gc` 及 `FG_BRANCH_ADMIN_USER=fg_branch_admin`。专用原生管理员和源备份账号的凭据仅用于运维环境。TLS 路径必须指向主机上对应的 CA、证书和密钥文件。

运维环境配置好后，检查、捕获并导入一个符合准入要求的源模式。请使用私密工作区下尚不存在的目录。

```sh
fg-control snapshot inspect --source-env FG_SOURCE_DSN --schema commerce \
  --name commerce-v1 --output /private/commerce-inspection.json
fg-control snapshot capture --source-env FG_SOURCE_DSN --schema commerce \
  --name commerce-v1 --output /private/commerce
FG_META_DSN="$FG_META_MIGRATION_DSN" fg-control snapshot import --input /private/commerce
```

在各自的环境中启动 `fg-control serve` 和 `fg-proxy`。[两项就绪检查](#wait-for-readiness)均返回 HTTP 204 后，在包含控制服务及代理配置的临时环境中运行 `fg-control doctor`。该临时环境不得包含源数据库、原生管理员或元数据迁移凭据。在所有者环境中运行 `forkget capabilities`。用 `forkget fork first-task` 创建工作区，等待其进入活动状态，然后按照[原生连接示例](connecting.zh-CN.md)连接。

## 使用 Compose 从源代码构建

本 Compose 指南使用 Linux x86_64，并需要 Docker Engine 及其 Compose 插件、OpenSSL、POSIX shell、curl 和 GNU timeout。Windows 用户可在 WSL 中使用 Linux Docker Engine 运行。此部署使用主机网络与回环监听器，启动前请确认所需端口可用。

解压校验通过的源代码归档。如果使用克隆方式，请检出相同的发行标签。运行以下命令前，将 `RELEASE_TAG` 设为所选标签。

```sh
git clone https://github.com/pterchan/ForkGet.git
cd ForkGet
git checkout --detach "${RELEASE_TAG:?Set RELEASE_TAG to the selected GitHub release tag}"
sh deploy/prepare.sh
```

准备步骤会创建私密配置以及适用于 localhost 和 127.0.0.1 的前端 CA 和证书，并保留已有部署文件。请勿将私钥和 `deploy/operator.env` 纳入版本控制。

## 配置专用服务后端

Compose 模板配置一个 SQL 引擎和元数据 PostgreSQL。原生服务数据库需要单独准备。按照[部署指南](../deploy/README.zh-CN.md)准备一个专用的 PostgreSQL 或 MySQL 后端，并分别创建原生服务账号、垃圾回收账号和分支管理员账号。源数据库是独立输入，请勿将生产源数据库设置为服务后端。服务数据库应在同一台 Linux 主机上运行，使用服务端证书覆盖的回环主机名或 IP，并使用与代理前端不同的端口。源数据库可使用单独的远程端点及其 CA。

替换 `deploy/operator.env` 中的每个占位值。四个原生 DSN 均需指向同一个服务后端端点，并使用正确的默认数据库及各自的账号。将该后端的 CA 复制到配置的后端 CA 路径。源数据库使用不同的 CA 时，请单独配置。请勿输出展开后的 Compose 配置，也不要发布环境文件或捕获结果。

从解压的发行版归档构建时，将 `FG_BUILD_REVISION` 设为发行页面上的完整修订版本标识。若从发行版或候选版本的 Git 工作区构建，则运行 `export FG_BUILD_REVISION="$(git rev-parse HEAD)"`。

```sh
sh deploy/run.sh initialize
```

初始化构建镜像、启动元数据服务、应用迁移，并为元数据运行时账号授予受限权限。构建产物包含控制台和原生导入工具。运行时无需在主机上运行 Node.js 服务器。Ubuntu 提供 PostgreSQL 客户端及 MySQL Shell 软件包。捕获前先核对镜像中的工具版本。PostgreSQL 使用 `sh deploy/run.sh operator pg_dump --version` 和 `sh deploy/run.sh operator pg_restore --version`，MySQL 使用 `sh deploy/run.sh operator mysqlsh --version`。快照操作分别要求 PostgreSQL 工具 16.15 和 MySQL Shell 8.0.36。若镜像中的 PostgreSQL 工具版本不同，可按上文直接运行二进制文件的步骤部署，并使用本机安装的匹配版本工具。捕获 MySQL 数据前，请确认运维镜像中的 MySQL Shell 版本符合要求。

## 捕获并导入一个应用模式

通过私密方式加载独立源备份账号的 `FG_SOURCE_DSN`。请使用 `postgresql://` 或 `mysql://` 等原生 DSN 协议方案。`postgresql+psycopg://` 是 ORM 使用的方案。运行捕获前设置源 CA。

```sh
docker compose --env-file deploy/operator.env -f deploy/compose.yaml run --rm \
  -e FG_SOURCE_DSN operator fg-control snapshot capture \
  --source-env FG_SOURCE_DSN --schema commerce --name commerce-v1 --output /work/commerce
sh deploy/run.sh operator fg-control snapshot import --input /work/commerce
```

将 `commerce` 替换为实际的源模式。输出路径必须尚不存在。预检会在激活前拒绝不受支持的对象。MySQL 使用固定版本的 MySQL Shell 执行转储，PostgreSQL 使用原生转储和还原进行暂存。凭据及可见性要求参见[源备份角色](source-backup-roles.zh-CN.md)。

本 Compose 指南涵盖 MySQL 和 PostgreSQL。MongoDB 使用独立的原生捕获流程，需要停写后制作的副本或一致性备份。

## 启动 Compose 服务

```sh
sh deploy/run.sh up
```

<a name="wait-for-readiness"></a>

## 等待服务就绪

Compose 部署与直接运行二进制文件使用相同的回环端点。

```sh
timeout 30 sh -c '
  while :; do
    control=$(curl --silent --output /dev/null --write-out "%{http_code}" --connect-timeout 1 --max-time 1 http://127.0.0.1:8081/health/ready || :)
    proxy=$(curl --silent --output /dev/null --write-out "%{http_code}" --connect-timeout 1 --max-time 1 http://127.0.0.1:8082/healthz || :)
    if [ "$control" = 204 ] && [ "$proxy" = 204 ]; then exit 0; fi
    sleep 1
  done
' || { echo 'Forkget did not become ready within 30 seconds.' >&2; exit 1; }
```

如果在限定时间内未能就绪，请停止后续操作。诊断命令会检查运行中代理的实际审计投递状况。请在两个服务均就绪后运行该命令。

## 连接 Compose 部署

```sh
sh deploy/run.sh operator fg-control doctor
sh deploy/run.sh operator forkget capabilities
sh deploy/run.sh operator forkget fork first-task
```

将 `<id>` 替换为返回的分支 ID，运行 `sh deploy/run.sh operator forkget status --id <id>`，轮询直至分支进入活动状态。可按照[原生连接示例](connecting.zh-CN.md)连接，或在 <http://127.0.0.1:8081/> 打开[控制台](console.zh-CN.md)。

新建分支默认为只读。需要可写分支时，请显式创建。

```sh
sh deploy/run.sh operator forkget fork write-task --write
```

`sh deploy/run.sh down` 会停止此项目并保留其卷。请对元数据、原生服务数据以及捕获和结果存储进行一致性备份。移除 Compose 卷会销毁保留的数据。变更现有部署前，请参阅[审计升级与还原流程](audit-recovery.zh-CN.md)。
