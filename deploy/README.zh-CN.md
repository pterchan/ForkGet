# 本地 SQL 部署

[English](README.md) · 简体中文

使用所选版本配套的部署模板。评估预发布版本时，请使用专用的可丢弃数据。选择引擎前，请阅读发布页面和[已知限制](../doc/limitations.zh-CN.md)。

此 Compose 模板启动控制服务、代理和元数据 PostgreSQL，并连接到一个单独配置的 SQL 服务后端。请使用 Linux，或在 WSL 中运行的 Linux Docker Engine。采用宿主机网络时，元数据使用 15432 端口，控制和排空接口分别使用 8081 和 8082 端口，所选 SQL 前端使用 3306 或 5432 端口。请先确认这些端口可用。

按[安装步骤](../doc/install.zh-CN.md)完成捕获、导入和启动，并在限定时间内检查服务是否就绪。两个服务均返回 HTTP 204 后，运行 `doctor`。控制和排空接口应只绑定回环地址，远程控制通过 SSH 隧道进行。

<a name="private-configuration"></a>

## 私有配置

`sh deploy/prepare.sh` 会创建 `operator.env` 和前端 TLS 材料，且会拒绝覆盖现有配置。请替换每一处占位值。原生服务数据库和源应用数据库必须彼此独立。

| 设置 | 账号或用途 |
|---|---|
| `FG_BACKEND_ADMIN_DSN` | 临时导入或管理命令使用的原生管理员账号 |
| `FG_BACKEND_DSN` | 代理使用的受限原生服务账号 |
| `FG_BACKEND_GC_DSN` | 受限原生垃圾回收账号 |
| `FG_BRANCH_ADMIN_DSN` | 用于创建分支资源和验证资源状态的专用管理员账号 |
| `FG_META_DSN` | 受限元数据运行时账号 |
| `FG_META_MIGRATION_DSN` | 独立的元数据迁移账号 |
| `FG_BACKEND_CA_HOST` | 服务后端 CA 文件在宿主机上的路径 |
| `FG_SOURCE_CA_HOST` | 源端 CA 文件在宿主机上的路径，可以与服务后端 CA 不同 |
| `FG_OWNER_TOKEN` | 操作容器使用的所有者 API 凭据 |
| `FG_REVIEWER_TOKEN` | 独立审核人的凭据，严禁以所有者身份代替 |

前端密码、API 令牌和原生凭据应彼此独立。密码中的保留字符在 DSN 中必须进行 URL 编码。请勿打印 `docker compose config` 的输出，也不要把设置、密钥或捕获数据复制到诊断资料中。标准运维命令仅向临时容器提供管理凭据。

在 `deploy/operator.env` 中设置 `FG_NATIVE_FREE_BYTES`，可将原生后端当前的可用空间估计值（以字节为单位）传给控制服务和快照操作程序。留空或省略时，系统继续使用估计值判断原生后端容量。设置为数字零表示无可用字节，系统会拒绝需要空间的分配请求。

## PostgreSQL 服务账号

在新建专用服务数据库的管理员会话中，私下设置 `FG_NATIVE_SERVICE_PASSWORD`、`FG_NATIVE_GC_PASSWORD` 和 `FG_NATIVE_BRANCH_PASSWORD`。配置 psql 的标准连接与 TLS 环境后，运行以下命令。

```sh
psql -X -v ON_ERROR_STOP=1 -f deploy/postgresql-roles.sql
```

脚本会创建 `fg_service`、`fg_gc` 和 `fg_branch_admin`。它会在该服务数据库上向分支管理员授予 `CREATE` 权限。导入时会按登记信息应用各世代对应的授权。四个后端 DSN 都指向同一服务数据库。请勿在源生产数据库上执行这些步骤。

## MySQL 服务账号

使用固定版本的 MySQL 8.0 配置。通过完成身份验证的 TLS 连接，以原生管理员身份执行设置。请妥善保管系统返回的随机密码。

```sql
SET GLOBAL partial_revokes = ON;
CREATE DATABASE fgwrite CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
CREATE USER 'fg_service'@'%'
  IDENTIFIED WITH caching_sha2_password BY RANDOM PASSWORD REQUIRE SSL;
CREATE USER 'fg_gc'@'%'
  IDENTIFIED WITH caching_sha2_password BY RANDOM PASSWORD REQUIRE SSL;
CREATE USER 'fg_branch_admin'@'%'
  IDENTIFIED WITH caching_sha2_password BY RANDOM PASSWORD REQUIRE SSL;
GRANT CREATE, DROP, ALTER, INDEX, REFERENCES, SELECT, INSERT, UPDATE, DELETE, TRIGGER
  ON fgwrite.* TO 'fg_branch_admin'@'%' WITH GRANT OPTION;
```

重启后也应保持部分撤销功能启用，并将强制角色列表留空。在此专用服务后端启用 `local_infile`，供 MySQL Shell 加载数据。此设置关闭时，导入会被拒绝。请勿向服务账号或垃圾回收账号授予全局权限或可继承的角色。导入世代时会精确应用为这两个账号登记的对象级授权。

服务和垃圾回收账号的 DSN 使用 `/forkget_delta`。分支管理员使用 `/fgwrite`。垃圾回收账号无法以 `/fgwrite` 作为初始数据库。原生管理员应使用其有权访问的数据库。MySQL 限定作用范围的 `TRIGGER` 权限使分支管理员能够验证私有提交见证对象上没有触发器。请勿向服务或垃圾回收账号授予此权限。旧部署也需要在分支管理员已拥有的分支命名空间上授予此权限。

## 生命周期与数据保留

`initialize` 执行构建和迁移，`up` 启动服务，`down` 保留元数据卷、状态卷和工作卷。工作卷包含捕获数据及导出的用户数据，并使用 Linux 文件系统权限控制访问。删除卷会销毁其中保留的状态。请将这些卷和原生服务数据一并保护。

运行所有者命令时，`sh deploy/run.sh operator forkget ...` 使用已配置的所有者令牌。独立审核人必须使用其单独的凭据批准请求。失败或到期的分支不会为释放空间而自动移除。请检查该分支不可变的 ID、保留期限和清理状态。

协调升级协议或恢复存储时，重建镜像后还需执行其他步骤。请遵循[审计恢复](../doc/audit-recovery.zh-CN.md)流程，包括暂停服务活动、完成仅涉及提交见证的准备工作，并在启动新进程前将恢复前的存储实例标识作废。
