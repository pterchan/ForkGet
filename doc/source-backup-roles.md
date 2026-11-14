# Source backup accounts

Use an independent source account for `FG_SOURCE_DSN`. Keep
`FG_BACKEND_ADMIN_DSN`, the serving account and the collector account separate.
The source account captures the application's logical schema; the target
administrator creates and verifies Forkget's private generations. The product
does not require an administrator as its source account, and a legitimate
administrator with the required visibility remains supported.

The recipes below are the minimum **tested profiles**, not a proof of the
smallest possible grant set for every configuration. Acceptance uses MySQL
8.0.43 with MySQL Shell **8.0.36**, and PostgreSQL **16.14** with
`pg_dump`/`pg_restore` **16.15**. Requalify the recipe when changing native tool
versions, role activation settings or hardened system-catalog permissions.
TiDB and MongoDB have separate native import workflows; their backup-role
profiles are **not verified by this acceptance**.

## MySQL 8.0

Run the following in a private administrator session. Replace `shop` and
`capture-host` with the complete source schema and the host from which capture
connects. Store the generated password through your normal secret mechanism;
do not save the returned password in test reports or command transcripts.

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

The source DSN's database component must be `shop`, or another database the
backup account can use. It must not be copied from the serving administrator's
DSN when that account connects to a different database.

| Privilege | Purpose |
| --- | --- |
| Schema-wide `SELECT` | Read every table and avoid silently omitting tables hidden from `information_schema`. |
| `SHOW VIEW` | Native dump metadata access; views themselves remain unsupported and are refused. |
| `TRIGGER`, `EVENT` | Make unsupported triggers and scheduled events visible to preflight. |
| `SHOW_ROUTINE` | Reveal routines created by other accounts so preflight can refuse them. |
| `BACKUP_ADMIN` | Permit the source DDL backup lock used by capture. |
| `RELOAD` | Permit MySQL Shell's brief global read lock while establishing a consistent snapshot. |
| `SELECT` on `mysql.default_roles` | Let the pinned Shell inspect default role metadata without reading the authentication table. |

This account has no application `INSERT`, `UPDATE` or `DELETE` grant. It is
**not a blanket read-only account**: native MySQL `TRIGGER` and `EVENT` privileges
also permit corresponding DDL, and the global backup privileges permit backup
and flush operations. Forkget uses the account for inspection and consistent
backup, and does not issue source data DML. Scope and lifetime of the credential
should reflect those native capabilities.

Do not replace the narrow role-metadata grant with `SELECT ON mysql.*` or
`SELECT ON *.*`. The verified profile cannot read `mysql.user`. MySQL Shell's
current manual describes `mysql.role_edges` access when
`activate_all_roles_on_login=ON`; that alternate role-activation profile is not
part of the acceptance for this recipe. Additional system hardening or role
configuration must be qualified with the pinned tool.

MySQL preflight proves direct global or exact-schema coverage from the current
account's canonical `SHOW GRANTS`, including relevant partial revocations. A
table-only grant or an unexpanded role assignment does not prove that the
whole source schema and unsupported objects are visible. Such a source is
explicitly refused with a `mysql_source_*_visibility_unproven` or
`mysql_source_schema_select_coverage_unproven` reason. Apply the direct grant
recipe instead of treating an empty metadata query as evidence of an empty
schema. Global administrator grants are accepted; this is a visibility check,
not a restriction to the example account name.

These requirements follow Oracle's documentation for
[dump utility privileges](https://dev.mysql.com/doc/mysql-shell/8.0/en/mysql-shell-utilities-dump-instance-schema.html),
[backup locks](https://dev.mysql.com/doc/refman/8.0/en/lock-instance-for-backup.html),
[trigger visibility](https://dev.mysql.com/doc/refman/8.0/en/information-schema-triggers-table.html)
and [routine visibility](https://dev.mysql.com/doc/refman/8.0/en/information-schema-routines-table.html).
Oracle may redirect its Shell documentation to a newer manual; the pinned
native acceptance, rather than that redirect, establishes this tested profile.

## PostgreSQL 16

Run this in `psql` as an administrator or the relevant object owner. Replace
`appdb` and `shop` with the source database and schema. `\password` prompts for
the source secret without placing it in command arguments.

```sql
CREATE ROLE fg_source_backup LOGIN
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
\password fg_source_backup

GRANT CONNECT ON DATABASE appdb TO fg_source_backup;
GRANT USAGE ON SCHEMA shop TO fg_source_backup;
GRANT SELECT ON ALL TABLES IN SCHEMA shop TO fg_source_backup;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA shop TO fg_source_backup;
```

Table `SELECT` permits the native dump's reads and `COPY TO`. Sequence `SELECT`
preserves serial/identity sequence state without granting `nextval` or `setval`.
No table ownership, source data DML, schema `CREATE`, superuser or RLS-bypass
grant is needed. The profile assumes PostgreSQL's normal public system-catalog
visibility and built-in function access; RLS and unsupported source routines
are refused by admission.

These grants cover existing objects. If application owners add tables or
sequences before the next capture, repeat the grants, or configure defaults
for **each role that actually creates those objects**:

```sql
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA shop
    GRANT SELECT ON TABLES TO fg_source_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA shop
    GRANT SELECT ON SEQUENCES TO fg_source_backup;
```

See PostgreSQL's documentation for
[privileges](https://www.postgresql.org/docs/16/ddl-priv.html),
[schema access](https://www.postgresql.org/docs/16/ddl-schemas.html)
and [consistent native dumps](https://www.postgresql.org/docs/16/app-pgdump.html).

## Capture, import and acceptance

Supply `FG_SOURCE_DSN` through the operator environment or secret mechanism,
with reserved password characters URL-encoded. Set `FG_SOURCE_CA` to the
source CA file; non-loopback sources require verified TLS. Keep the serving
and metadata administrator settings configured for the destination.

```sh
fg-control snapshot inspect --source-env FG_SOURCE_DSN \
  --schema shop --name application-backup --output plan.json
fg-control snapshot capture --source-env FG_SOURCE_DSN \
  --schema shop --name application-backup --output application-bundle
fg-control snapshot import --input application-bundle
```

Output paths must not already exist. Source credentials reach native tools
through private files or environment variables, not password arguments.
Import uses the destination administrator. The source backup account does not
gain access to the imported private generation.
