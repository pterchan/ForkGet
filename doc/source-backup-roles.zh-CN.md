# 源备份账号

[English](source-backup-roles.md) · 简体中文

为 `FG_SOURCE_DSN` 使用独立的源账号。`FG_BACKEND_ADMIN_DSN` 使用的账号、服务账号和垃圾回收账号也必须相互独立。源账号负责捕获应用的逻辑模式，目标管理员负责创建并验证 Forkget 的私有世代。源账号可以使用非管理员账号，也支持具备所需可见性且经合法授权的管理员账号。

以下配置是**经过测试的最低权限配置**。每种部署实际所需的最小授权集合可能不同。验收使用 MySQL 8.0.43 搭配 MySQL Shell **8.0.36**，以及 PostgreSQL **16.14** 搭配 `pg_dump`/`pg_restore` **16.15**。原生工具版本、角色激活设置或系统目录的加固权限有变化时，请重新验证配置。MongoDB 使用独立的原生导入流程，其备份角色配置**未在本次验收中验证**。

## MySQL 8.0

请在私密的管理员会话中运行以下命令。将 `shop` 替换为要完整捕获的源模式，将 `capture-host` 替换为发起捕获连接的主机。使用常规的机密管理机制保存生成的密码，请勿将返回的密码保存在测试报告或命令会话记录中。

```sql
CREATE USER 'fg_source_backup'@'capture-host'
    IDENTIFIED BY RANDOM PASSWORD REQUIRE SSL;

GRANT SELECT, SHOW VIEW, TRIGGER, EVENT
    ON shop.* TO 'fg_source_backup'@'capture-host';
GRANT RELOAD, BACKUP_ADMIN, SHOW_ROUTINE
    ON *.* TO 'fg_source_backup'@'capture-host';

-- Tested with activate_all_roles_on_login = OFF:
GRANT SELECT ON mysql.default_roles
    TO 'fg_source_backup'@'capture-host';
```

源 DSN 的数据库部分必须指定 `shop`，或另一个备份账号有权使用的数据库。如果服务后端管理员连接的是其他数据库，请勿复制其 DSN 的数据库部分。

| 权限 | 用途 |
| --- | --- |
| 整个模式的 `SELECT` | 读取每张表，避免遗漏在 `information_schema` 中不可见的表。 |
| `SHOW VIEW` | 供原生转储读取元数据。视图本身仍不受支持，遇到视图时会拒绝。 |
| `TRIGGER`、`EVENT` | 让预检能够发现不受支持的触发器和计划事件。 |
| `SHOW_ROUTINE` | 让预检发现其他账号创建的例程，并据此拒绝。 |
| `BACKUP_ADMIN` | 允许获取捕获时使用的源端 DDL 备份锁。 |
| `RELOAD` | 允许 MySQL Shell 在建立一致性快照时短暂获取全局读锁。 |
| `mysql.default_roles` 上的 `SELECT` | 允许固定版本的 MySQL Shell 检查默认角色元数据，无需读取身份验证表。 |

此账号没有应用数据的 `INSERT`、`UPDATE` 或 `DELETE` 权限。MySQL 原生 `TRIGGER` 和 `EVENT` 权限也允许执行相应的 DDL，全局备份权限允许执行备份和刷新操作，因此这个账号**并非全面只读**。Forkget 使用该账号进行检查和一致性备份，不会对源数据执行 DML。请根据这些原生权限控制凭据的使用范围和有效期。

请勿使用 `SELECT ON mysql.*` 或 `SELECT ON *.*` 代替范围有限的角色元数据授权。已验证的配置无法读取 `mysql.user`。MySQL Shell 当前手册说明，`activate_all_roles_on_login=ON` 时需要访问 `mysql.role_edges`。本配置的验收范围未涵盖这种角色激活方式。对系统额外加固或变更角色配置后，必须使用固定版本的工具重新验证。

MySQL 预检通过当前账号的规范化 `SHOW GRANTS` 输出验证直接授权的覆盖范围。授权须覆盖全局或目标模式，并计入相关的部分撤销。仅有表级授权或未展开的角色授予，无法证明整个源模式和不受支持的对象均可见。对于此类源数据库，预检会以 `mysql_source_*_visibility_unproven` 或 `mysql_source_schema_select_coverage_unproven` 为由明确拒绝。请按上述配置直接授予权限。空的元数据查询结果无法证明模式为空。全局管理员权限也可通过检查，只要对象可见性符合要求，账号名无需与示例一致。

这些要求依据 Oracle 关于[转储工具权限](https://dev.mysql.com/doc/mysql-shell/8.0/en/mysql-shell-utilities-dump-instance-schema.html)、[备份锁](https://dev.mysql.com/doc/refman/8.0/en/lock-instance-for-backup.html)、[触发器可见性](https://dev.mysql.com/doc/refman/8.0/en/information-schema-triggers-table.html)和[例程可见性](https://dev.mysql.com/doc/refman/8.0/en/information-schema-routines-table.html)的文档。Oracle 的 MySQL Shell 文档可能重定向至更新版本的手册。此配置以固定版本原生工具的验收结果为准。

<a name="postgresql-16"></a>

## PostgreSQL 16

以管理员或相关对象所有者的身份，在 `psql` 中运行以下命令。将 `appdb` 和 `shop` 替换为源数据库和源模式。`\password` 会提示输入源账号密码，使其无需出现在命令参数中。

```sql
CREATE ROLE fg_source_backup LOGIN
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
\password fg_source_backup

GRANT CONNECT ON DATABASE appdb TO fg_source_backup;
GRANT USAGE ON SCHEMA shop TO fg_source_backup;
GRANT SELECT ON ALL TABLES IN SCHEMA shop TO fg_source_backup;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA shop TO fg_source_backup;
```

表上的 `SELECT` 允许原生转储读取数据和执行 `COPY TO`。序列上的 `SELECT` 可保留 serial 或 identity 列的序列状态，无需授予 `nextval` 或 `setval`。此配置无需表所有权，也无需源数据 DML、模式 `CREATE`、超级用户或绕过 RLS 的权限。该配置假定 PostgreSQL 系统目录维持通常的公开可见性，且可正常访问内置函数。准入检查拒绝 RLS 和不受支持的源端例程。

上述授权覆盖已有对象。如果应用所有者在下次捕获前添加了表或序列，请再次应用授权，或为**实际创建这些对象的每个角色**配置默认权限。

```sql
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA shop
    GRANT SELECT ON TABLES TO fg_source_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA shop
    GRANT SELECT ON SEQUENCES TO fg_source_backup;
```

参阅 PostgreSQL 关于[权限](https://www.postgresql.org/docs/16/ddl-priv.html)、[模式访问](https://www.postgresql.org/docs/16/ddl-schemas.html)和[一致性原生转储](https://www.postgresql.org/docs/16/app-pgdump.html)的文档。

## 捕获、导入与验收

通过运维环境或机密管理机制提供 `FG_SOURCE_DSN`，对密码中的保留字符进行 URL 编码。将 `FG_SOURCE_CA` 指向源 CA 文件。源数据库使用非回环地址时，必须验证 TLS。保留指向目标端的服务后端和元数据管理员配置。

```sh
fg-control snapshot inspect --source-env FG_SOURCE_DSN \
  --schema shop --name application-backup --output plan.json
fg-control snapshot capture --source-env FG_SOURCE_DSN \
  --schema shop --name application-backup --output application-bundle
fg-control snapshot import --input application-bundle
```

输出路径必须尚不存在。通过私有文件或环境变量向原生工具提供源凭据，避免将密码作为命令参数传递。导入使用目标管理员账号。源备份账号无权访问导入后的私有世代。
