# Local SQL deployment

This Compose template runs control, proxy and metadata PostgreSQL against one
separately configured SQL serving backend. Use Linux or a WSL Linux Docker
Engine. Host networking keeps metadata on 15432, control/drain on 8081/8082,
and the selected SQL frontend on 3306 or 5432. Check these ports first.

Follow the [installation walkthrough](../doc/install.md) for capture, import,
startup and a bounded readiness check. Run doctor after both services report
HTTP 204. Keep control and drain on loopback; remote control uses an SSH tunnel.

## Private configuration

`sh deploy/prepare.sh` creates `operator.env` and frontend TLS material, and
refuses to overwrite existing settings. Replace every placeholder. The native
serving database and the source application database must be separate.

| Setting | Account or purpose |
|---|---|
| `FG_BACKEND_ADMIN_DSN` | Native administrator used by transient import/administration commands |
| `FG_BACKEND_DSN` | Restricted native service account used by the proxy |
| `FG_BACKEND_GC_DSN` | Restricted native collector account |
| `FG_BRANCH_ADMIN_DSN` | Dedicated branch provisioning/attestation administrator |
| `FG_META_DSN` | Restricted metadata runtime account |
| `FG_META_MIGRATION_DSN` | Separate metadata migration account |
| `FG_BACKEND_CA_HOST` | Host path to serving-backend CA |
| `FG_SOURCE_CA_HOST` | Host path to source CA; may differ from serving CA |
| `FG_OWNER_TOKEN` | Owner API credential used by the operator container |
| `FG_REVIEWER_TOKEN` | Independent reviewer credential; never substitute the owner's identity |

Keep frontend passwords, API tokens and native credentials separate. URL-encode
reserved password characters in DSNs. Do not print `docker compose config` or
copy settings, keys or captures into diagnostics. The standard operator commands
supply administration credentials only to transient containers.

## PostgreSQL serving accounts

In an administrator session for a new dedicated serving database, privately set
`FG_NATIVE_SERVICE_PASSWORD`, `FG_NATIVE_GC_PASSWORD` and
`FG_NATIVE_BRANCH_PASSWORD`. Configure psql's standard connection/TLS environment,
then run:

```sh
psql -X -v ON_ERROR_STOP=1 -f deploy/postgresql-roles.sql
```

The script creates `fg_service`, `fg_gc` and `fg_branch_admin`. It grants the
branch administrator CREATE on that serving database; import installs the
registered generation-specific grants. All four backend DSNs use the same
serving database. Do not apply this recipe to the source production database.

## MySQL serving accounts

Use the pinned MySQL 8.0 profile. Run setup as the native administrator over
verified TLS. Store the returned generated passwords privately:

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

Keep partial revokes enabled across restarts and mandatory roles empty. Enable
`local_infile` on this dedicated serving backend for MySQL Shell's data loader;
import refuses a disabled setting. Do not grant global access or inherited
roles to service/collector accounts. Generation import installs their exact
registered object grants.

The service and collector DSNs use `/forkget_delta`; the branch administrator
uses `/fgwrite`. The collector cannot use `/fgwrite` as its initial database.
The native administrator uses a database accessible to it. MySQL's scoped
TRIGGER privilege lets the branch administrator attest that private witnesses
have no triggers. Do not add that privilege to service or collector accounts.
Legacy deployments also need it on their already-owned branch namespaces.

TiDB does not support the MySQL TRIGGER or partial-revokes recipe. Its separate
native profile requires CHECK enforcement and metadata locking. Its unresolved
concurrent foreign-key failure remains a [correctness limitation](../doc/limitations.md).

## Lifecycle and retained data

`initialize` builds and migrates; `up` starts services; `down` retains the
metadata, state and work volumes. The work volume contains captures and exported
user data with Linux filesystem permissions. Deleting volumes destroys that
retained state. Protect them together with native serving data.

For owner commands, `sh deploy/run.sh operator forkget ...` uses the configured
owner token. An independent reviewer must supply its separate credential for
approval. A failed or expired branch is not automatically evicted to free space.
Inspect its immutable ID, retention deadline and cleanup state.

Coordinated protocol upgrades and storage restore need additional steps beyond
rebuilding the image. Follow [audit recovery](../doc/audit-recovery.md), including
service quiescence, witness-only preparation and invalidating a restored storage
incarnation before starting new processes.
