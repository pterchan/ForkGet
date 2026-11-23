# 连接应用

[English](connecting.md) · 简体中文

对于 SQL，前端连接的数据库字段用于选择分支名称。对于 MongoDB，首次指定数据库名称的分支数据命令会将连接绑定到该分支。

使用运维人员签发的前端账号，用户名须与 API 所有者一致，并使用前端 CA 和主机名验证 TLS。前端密码与所有者 API 令牌及各类原生后端凭据彼此独立。即使底层数据库支持某些 SQL 语句或命令，只要超出 Forkget 的支持范围，就会被拒绝。

| 监听器 | 默认地址 |
| --- | --- |
| MySQL | `127.0.0.1:3306` |
| PostgreSQL | `127.0.0.1:5432` |
| MongoDB | `127.0.0.1:28017` |

如果端口已被本机服务占用，请更改端口。将示例账号、分支和 CA 路径替换为实际部署值。CLI 示例会提示输入密码。请勿将机密粘贴到 shell 命令或报告中。使用本地 Compose 部署时，从仓库根目录运行命令，CA 路径为 `deploy/private/frontend-ca.pem`。请私下从 `deploy/operator.env` 的 `FG_FRONTEND_ACCOUNTS` 获取对应前端账号的密码。

```sh
mysql --host 127.0.0.1 --port 3306 --user owner --database first-task \
  --ssl-ca frontend-ca.pem --ssl-mode=VERIFY_IDENTITY -p

psql "host=127.0.0.1 port=5432 dbname=first-task user=owner \
  sslmode=verify-full sslrootcert=frontend-ca.pem"
```

## SQLAlchemy

代表性应用配置使用 SQLAlchemy **2.1.8**，搭配标准的 PyMySQL **1.1.1** 或 psycopg **3.2.9**。保留正常的方言初始化、反射、批量插入及生成键行为。要让符合准入要求的应用通过 Forkget 运行，请修改连接及 TLS 设置。通过运维流程创建或导入模式，客户端迁移 DDL 超出允许的应用操作范围。

```python
import os
from sqlalchemy import URL, create_engine

url = URL.create(
    "postgresql+psycopg", username="owner",
    password=os.environ["FRONTEND_PASSWORD"], host="127.0.0.1",
    port=5432, database="write-task",
)
engine = create_engine(url, connect_args={
    "sslmode": "verify-full", "sslrootcert": "frontend-ca.pem",
})
```

对于 MySQL，请使用 `mysql+pymysql`、端口 3306 和连接参数 `{"ssl": {"ca": "frontend-ca.pem", "check_hostname": True}}`。遇到准入错误时，请保留验证与生成键功能。修改应用前，请查看[支持的功能子集](support-matrix.zh-CN.md)及返回的 FG 拒绝原因。

## MongoDB 连接池与分支绑定

只要完整排序后的结果集在 BSON 响应 16 MiB 的限制内，MongoDB `distinct` 就会返回该结果集。如果结果集过大，代理返回 `FG-2002`，请缩小查询范围。

每个分支都应创建独立客户端。代理会在收到首条分支数据命令时绑定该连接。为某个分支建立的连接池仅供该分支使用，即使切换客户端的默认数据库也不能复用。请显式使用直连端点，并禁用可重试写入。

```python
import os
from pymongo import MongoClient

with MongoClient(
    host="127.0.0.1", port=28017, username="owner",
    password=os.environ["FRONTEND_PASSWORD"], authSource="admin",
    directConnection=True, retryWrites=False,
    tls=True, tlsCAFile="frontend-ca.pem",
) as client:
    order = client["first-task"].orders.find_one()
```

`first-task` 默认只读，只有创建时显式指定可写才允许写入。尝试写入默认创建的分支时，会在原生数据发生变更前返回 FG-5001。分支到期、删除或连接发生不可恢复的中断后，请关闭并重新创建该分支的连接池，避免无提示地切换到其他分支。此部署支持的 MongoDB 功能子集不保证多文档操作具备 SQL 事务语义，也不保证支持副本集或 SRV 发现。
