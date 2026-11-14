# Connect an application

For SQL, the frontend database field selects the branch name. MongoDB binds
the connection when its first branch data command names that database.
Use an operator-issued
frontend account whose username matches the API owner, and verify TLS using
the frontend CA and hostname. Frontend passwords are distinct from owner API
tokens and every native backend credential. Unsupported SQL or commands are
refused even when the underlying database supports them.

| Listener | Default |
| --- | --- |
| MySQL / TiDB | `127.0.0.1:3306` |
| PostgreSQL | `127.0.0.1:5432` |
| MongoDB | `127.0.0.1:28017` |

Change ports if local services already use them. Replace example account,
branch and CA paths with your actual deployment values. CLI examples prompt
for the password; do not paste a secret into a shell command or report.

```sh
mysql --host 127.0.0.1 --port 3306 --user owner --database first-task \
  --ssl-ca frontend-ca.pem --ssl-mode=VERIFY_IDENTITY -p

psql "host=127.0.0.1 port=5432 dbname=first-task user=owner \
  sslmode=verify-full sslrootcert=frontend-ca.pem"
```

The same MySQL frontend example applies to a TiDB deployment. TiDB serving
configuration uses a `tidb://` backend DSN and requires CHECK enforcement and
native metadata locking. Its unresolved concurrent-FK path can commit an orphan;
Forkget does not reliably refuse it. See the [correctness limitation](limitations.md).

## SQLAlchemy

The representative application profile uses SQLAlchemy **2.1.8**, with ordinary
PyMySQL **1.1.1** or psycopg **3.2.9**. Keep normal dialect initialization,
reflection, bulk insertion and generated-key behavior enabled. Change the
connection and TLS settings to run an admitted application through Forkget.
Create/import the schema with the operator workflow; client migration DDL is
not an admitted application operation.

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

For MySQL, use `mysql+pymysql`, port 3306, and connect arguments
`{"ssl": {"ca": "frontend-ca.pem", "check_hostname": True}}`. Do not turn off verification or generated-key
features to work around an admission error. Check the [supported subset](support-matrix.md)
and the returned FG reason before changing the application.

## MongoDB pool ownership

Create an independent client for every branch, not one client whose default
database is repeatedly switched. The proxy binds the connection to the first
branch data command. A pool created for one branch must never be reused for
another branch. Explicitly use a direct endpoint and disable retryable writes.

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

`first-task` is read-only unless created explicitly writable. A default-branch
write returns FG-5001 before native mutation. Close and recreate that branch's
pool after an expiry/drop or unrecoverable connection loss; do not silently
switch it to a different branch. MongoDB multi-document SQL transaction
semantics and replica/SRV discovery are not promised by this deployment subset.
