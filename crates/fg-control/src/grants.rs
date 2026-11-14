use std::borrow::Cow;

use fg_meta::{BootstrapGeneration, NativeCatalog};
use fg_protocol_common::{CatalogEntry, MYSQL_WRITE_SCHEMA, TXN_WITNESS_TABLE, WriteTarget};
use sqlx::{Executor, MySqlConnection, PgConnection, Row};
use thiserror::Error;

use crate::{
    ControlError, mongo,
    native::{Engine, Native},
    seed::DELTA_SCHEMA,
    verify,
};

const READ: &str = "SELECT";
const COLLECT: &str = "SELECT, DELETE";
pub(crate) const BRANCH_ACCESS: &str = "SELECT, INSERT, UPDATE, DELETE";
const MYSQL_BRANCH_ADMIN: &str =
    "SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, REFERENCES, INDEX, ALTER, TRIGGER";
const TIDB_BRANCH_ADMIN: &str =
    "SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, REFERENCES, INDEX, ALTER";
const MYSQL_MIN_WRITE_PATCH: u32 = 30;
const LEGACY_MYSQL_BASES: &str = r"`fg\_g%`.*";
const LEGACY_MYSQL_BRANCHES: &str = r"`fg\_b%`.*";
const PRIVILEGES: ControlError =
    ControlError::Seed("native role privileges differ from the registered catalog");

#[derive(Debug, Error)]
#[error(
    "native role privileges differ from the registered catalog: role {role}: {detail}; verify the role settings for this backend and the deployment grant recipe"
)]
pub(crate) struct GrantError {
    role: String,
    detail: String,
}

fn role_failure(role: &NativeRole, detail: impl Into<String>) -> ControlError {
    let error = GrantError {
        role: role.user.clone(),
        detail: detail.into(),
    };
    tracing::error!(component = "grants", role = %error.role, detail = %error.detail,
        "native role verification failed");
    error.into()
}

fn missing_role(role: &NativeRole) -> ControlError {
    role_failure(role, "role does not exist on the configured native backend")
}

// SHOW GRANTS can contain account and authentication details. Only expose the
// privilege and object portion, with a bounded identifier alphabet.
fn grant_summary(grant: &str) -> String {
    let Some((rights, scope)) = grant
        .strip_prefix("GRANT ")
        .and_then(|grant| grant.split_once(" ON "))
        .and_then(|(rights, rest)| rest.split_once(" TO ").map(|(scope, _)| (rights, scope)))
    else {
        return "unsupported grant form".to_owned();
    };
    if !rights
        .bytes()
        .all(|byte| byte.is_ascii_uppercase() || matches!(byte, b' ' | b','))
        || !scope.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'*' | b'`' | b'%' | b'\\')
        })
    {
        return "unsupported grant form".to_owned();
    }
    let delegation = if grant.ends_with(" WITH GRANT OPTION") {
        " (grantable)"
    } else {
        ""
    };
    format!("{rights} on {scope}{delegation}")
}

fn grant_difference(role: &NativeRole, missing: &[String], unexpected: &[String]) -> ControlError {
    let missing = missing
        .iter()
        .map(|grant| grant_summary(grant))
        .collect::<Vec<_>>();
    let unexpected = unexpected
        .iter()
        .map(|grant| grant_summary(grant))
        .collect::<Vec<_>>();
    role_failure(
        role,
        format!("missing privileges {missing:?}; unexpected privileges {unexpected:?}"),
    )
}

pub(crate) struct NativeRoles {
    pub(crate) service: NativeRole,
    pub(crate) collector: NativeRole,
    pub(crate) branch_admin: Option<NativeRole>,
}

pub(crate) struct NativeRole {
    user: String,
    pub(crate) account: String,
}

impl NativeRoles {
    pub(crate) fn new(
        engine: Engine,
        service: &str,
        collector: &str,
        branch_admin: Option<&str>,
    ) -> Result<Self, ControlError> {
        if service == collector
            || branch_admin.is_some_and(|user| user == service || user == collector)
        {
            return Err(ControlError::Config(
                "native service, GC, and branch administrator roles must differ",
            ));
        }
        Ok(Self {
            service: NativeRole::new(engine, service)?,
            collector: NativeRole::new(engine, collector)?,
            branch_admin: branch_admin
                .map(|user| NativeRole::new(engine, user))
                .transpose()?,
        })
    }
}

impl NativeRole {
    fn new(engine: Engine, user: &str) -> Result<Self, ControlError> {
        if user.is_empty()
            || user.len() > 32
            || !user
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(ControlError::Config(
                "native role must be an ASCII account name",
            ));
        }
        let account = match engine {
            Engine::MySql | Engine::TiDB => format!("'{user}'@'%'"),
            Engine::Postgres => engine.quote(user),
            // The role name equals the account name on mongod.
            Engine::MongoDb => user.to_owned(),
        };
        Ok(Self {
            user: user.to_owned(),
            account,
        })
    }

    /// How `SHOW GRANTS` renders this account. MySQL 8.0 backticks the user
    /// and host; TiDB wraps both in single quotes.
    fn mysql_display(&self, engine: Engine) -> String {
        match engine {
            Engine::TiDB => format!("'{}'@'{}'", self.user, "%"),
            _ => format!(
                "{}@{}",
                Engine::MySql.quote(&self.user),
                Engine::MySql.quote("%")
            ),
        }
    }
}

struct TableGrant {
    rights: &'static str,
    relation: String,
}

fn table_grants(engine: Engine, tables: &[CatalogEntry], collector: bool) -> Vec<TableGrant> {
    let mut result = Vec::new();
    for table in tables {
        if !collector {
            result.push(TableGrant {
                rights: READ,
                relation: engine.relation(&table.base_schema, &table.base_table),
            });
        }
        result.push(TableGrant {
            rights: if collector { COLLECT } else { READ },
            relation: engine.relation(&table.delta_schema, &table.delta_table),
        });
    }
    result
}

pub(crate) async fn grant_table(
    native: &mut Native,
    table: &CatalogEntry,
    roles: &NativeRoles,
) -> Result<(), ControlError> {
    // MongoDB grants live in crate::mongo::build; this loop is SQL-only.
    for (role, collector) in [(&roles.service, false), (&roles.collector, true)] {
        for grant in table_grants(native.engine(), std::slice::from_ref(table), collector) {
            native
                .execute(&format!(
                    "GRANT {} ON {} TO {}",
                    grant.rights, grant.relation, role.account
                ))
                .await?;
        }
    }
    if let Some(role) = &roles.branch_admin {
        let base = native
            .engine()
            .relation(&table.base_schema, &table.base_table);
        native
            .execute(&format!("GRANT SELECT ON {base} TO {}", role.account))
            .await?;
    }
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Scope {
    Base,
    Delta,
    Branch,
    Witness,
}

struct Expected<'a> {
    schema: &'a str,
    table: Cow<'a, str>,
    scope: Scope,
    required: bool,
}

impl Expected<'_> {
    fn rights(&self, collector: bool) -> Option<&'static str> {
        match (self.scope, collector) {
            (Scope::Base | Scope::Delta, false) => Some(READ),
            (Scope::Delta, true) => Some(COLLECT),
            (Scope::Branch, false) => Some(BRANCH_ACCESS),
            (Scope::Witness, false) => Some("INSERT"),
            (Scope::Witness, true) => Some(COLLECT),
            _ => None,
        }
    }
}

fn expected_relations<'a>(
    catalog: &'a NativeCatalog,
    incoming: Option<&'a BootstrapGeneration>,
) -> Result<Vec<Expected<'a>>, ControlError> {
    let mut expected = Vec::new();
    for generation in catalog.generations.iter().chain(incoming) {
        for table in &generation.tables {
            expected.extend([
                Expected {
                    schema: &table.base_schema,
                    table: Cow::Borrowed(&table.base_table),
                    scope: Scope::Base,
                    required: true,
                },
                Expected {
                    schema: &table.delta_schema,
                    table: Cow::Borrowed(&table.delta_table),
                    scope: Scope::Delta,
                    required: true,
                },
            ]);
        }
    }
    for branch in &catalog.branches {
        let generation = catalog
            .generations
            .iter()
            .find(|item| item.id == branch.generation_id)
            .ok_or(PRIVILEGES)?;
        for table in &generation.tables {
            expected.push(expected_branch_table(
                &branch.target,
                table,
                branch.grants_required,
            ));
        }
        expected.push(expected_witness(&branch.target, branch.audit_witness_ready));
    }
    Ok(expected)
}

fn expected_witness(target: &WriteTarget, required: bool) -> Expected<'_> {
    Expected {
        schema: target.schema(),
        table: Cow::Owned(target.table(TXN_WITNESS_TABLE)),
        scope: Scope::Witness,
        required,
    }
}

fn expected_branch_table<'a>(
    target: &'a WriteTarget,
    table: &CatalogEntry,
    required: bool,
) -> Expected<'a> {
    Expected {
        schema: target.schema(),
        table: Cow::Owned(target.table(&table.logical_table)),
        scope: Scope::Branch,
        required,
    }
}

pub(crate) async fn verify(
    native: &mut Native,
    roles: &NativeRoles,
    catalog: &NativeCatalog,
    incoming: Option<&BootstrapGeneration>,
) -> Result<(), ControlError> {
    if let Native::Mongo(client) = native {
        // Canary verification: users exist and hold their deployment role
        // once anything is registered.
        let registered = incoming.is_some() || !catalog.generations.is_empty();
        return mongo::verify(client, roles, registered).await;
    }
    verify_branch_admin(
        native,
        roles,
        catalog,
        incoming,
        BranchAdminCheck::Generation,
    )
    .await?;
    let expected = expected_relations(catalog, incoming)?;
    match native {
        // Handled by the canary above.
        Native::Mongo(_) => Ok(()),
        Native::MySql(connection) => {
            verify_mysql(connection, Engine::MySql, roles, &expected).await
        }
        Native::TiDB(connection) => verify_mysql(connection, Engine::TiDB, roles, &expected).await,
        Native::Postgres(connection) => {
            for (role, collector) in [(&roles.service, false), (&roles.collector, true)] {
                verify_postgres_role(connection, role).await?;
                verify_postgres_tables(connection, role, &expected, collector, None).await?;
                for generation in catalog.generations.iter().chain(incoming) {
                    verify_postgres_schema(connection, role, &generation.schema, !collector)
                        .await?;
                }
                if !catalog.generations.is_empty() || incoming.is_some() {
                    verify_postgres_schema(connection, role, DELTA_SCHEMA, true).await?;
                }
                for branch in catalog
                    .branches
                    .iter()
                    .filter(|branch| branch.grants_required)
                {
                    verify_postgres_schema(
                        connection,
                        role,
                        branch.target.schema(),
                        !collector || branch.audit_witness_ready,
                    )
                    .await?;
                }
            }
            Ok(())
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum BranchAdminCheck {
    Generation,
    Startup { active_generation: Option<i64> },
}

impl BranchAdminCheck {
    fn requires_generation(self, id: i64) -> bool {
        match self {
            Self::Generation => true,
            // An interrupted retirement can already have revoked native grants.
            Self::Startup { active_generation } => active_generation == Some(id),
        }
    }
}

pub(crate) async fn verify_branch_admin(
    native: &mut Native,
    roles: &NativeRoles,
    catalog: &NativeCatalog,
    incoming: Option<&BootstrapGeneration>,
    check: BranchAdminCheck,
) -> Result<(), ControlError> {
    if matches!(native, Native::Mongo(_)) {
        // MongoDB uses its configured deployment administrator instead.
        return Ok(());
    }
    let Some(role) = &roles.branch_admin else {
        return Ok(());
    };
    if native.engine() != Engine::Postgres
        && !verify::has_schema(native, MYSQL_WRITE_SCHEMA).await?
    {
        return Err(ControlError::Config(
            "operator must create the fgwrite database",
        ));
    }
    match native {
        // MongoDB deployments return Ok before this point.
        Native::Mongo(_) => Ok(()),
        Native::MySql(connection) => {
            verify_mysql_branch_admin(connection, Engine::MySql, role, catalog, incoming, check)
                .await
        }
        Native::TiDB(connection) => {
            verify_mysql_branch_admin(connection, Engine::TiDB, role, catalog, incoming, check)
                .await
        }
        Native::Postgres(connection) => {
            verify_postgres_branch_admin(connection, role, catalog, incoming, check).await
        }
    }
}

fn supports_mysql_write_version(version: &str) -> bool {
    let Some(patch) = version.strip_prefix("8.0.") else {
        return false;
    };
    patch
        .split(|character: char| !character.is_ascii_digit())
        .next()
        .and_then(|patch| patch.parse::<u32>().ok())
        .is_some_and(|patch| patch >= MYSQL_MIN_WRITE_PATCH)
}

fn supports_tidb_write_version(version: &str) -> bool {
    // TiDB reports `8.0.11-TiDB-v8.5.<patch>`; writable branches require the
    // v8.5 LTS line or later.
    let Some(rest) = version.split_once("-TiDB-v").map(|(_, rest)| rest) else {
        return false;
    };
    let mut digits = rest.split(|character: char| !character.is_ascii_digit());
    let major: u32 = digits
        .next()
        .and_then(|part| part.parse().ok())
        .unwrap_or(0);
    let minor: u32 = digits
        .next()
        .and_then(|part| part.parse().ok())
        .unwrap_or(0);
    major > 8 || (major == 8 && minor >= 5)
}

/// Trigger absence is evidence only when the attesting connection can see
/// triggers on this registered witness. Collector SELECT is insufficient.
pub(crate) async fn verify_witness_visibility(
    native: &mut Native,
    target: &WriteTarget,
) -> Result<(), ControlError> {
    let connection = match native {
        Native::MySql(connection) => connection,
        Native::TiDB(connection) => {
            let version: String = sqlx::query_scalar("SELECT VERSION()")
                .fetch_one(&mut *connection)
                .await?;
            if !supports_tidb_write_version(&version) {
                return Err(ControlError::Config(
                    "TiDB witness attestation requires a genuine TiDB v8.5 LTS or later backend",
                ));
            }
            let metadata_lock: i64 =
                sqlx::query_scalar("SELECT CAST(@@GLOBAL.tidb_enable_metadata_lock AS SIGNED)")
                    .fetch_one(&mut *connection)
                    .await?;
            if metadata_lock != 1 {
                return Err(ControlError::Config(
                    "TiDB witness attestation requires tidb_enable_metadata_lock=ON; enable metadata locking before preparation or recovery",
                ));
            }
            return Ok(());
        }
        Native::Postgres(_) => return Ok(()),
        Native::Mongo(_) => {
            return Err(ControlError::Config(
                "Native transaction witnesses require a SQL backend",
            ));
        }
    };
    let partial_revokes: i64 =
        sqlx::query_scalar("SELECT CAST(@@GLOBAL.partial_revokes AS SIGNED)")
            .fetch_one(&mut *connection)
            .await?;
    let observed = read_mysql_grants(connection, "SHOW GRANTS").await?;
    if !has_witness_trigger_grant(&observed, target, partial_revokes == 0) {
        return Err(ControlError::Config(
            "MySQL witness attestation requires current scoped TRIGGER visibility for the branch administrator",
        ));
    }
    Ok(())
}

fn has_witness_trigger_grant(
    observed: &[String],
    target: &WriteTarget,
    permits_legacy: bool,
) -> bool {
    let schema = format!("{}.*", Engine::MySql.quote(target.schema()));
    let relation = Engine::MySql.relation(target.schema(), &target.table(TXN_WITNESS_TABLE));
    let legacy = permits_legacy
        && target.prefix().is_none()
        && target.schema() == format!("fg_b{}", target.branch_id());
    observed.iter().any(|line| {
        let Some(key) = grant_key(line) else {
            return false;
        };
        let mut parts = key.split('|');
        let (Some(rights), Some(scope), Some(_account), Some(_grantable)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return false;
        };
        parts.next().is_none()
            && rights.split(',').any(|right| right == "TRIGGER")
            && (scope == schema || scope == relation || (legacy && scope == LEGACY_MYSQL_BRANCHES))
    })
}

async fn verify_mysql_branch_admin(
    connection: &mut MySqlConnection,
    engine: Engine,
    role: &NativeRole,
    catalog: &NativeCatalog,
    incoming: Option<&BootstrapGeneration>,
    check: BranchAdminCheck,
) -> Result<(), ControlError> {
    let version: String = sqlx::query_scalar("SELECT VERSION()")
        .fetch_one(&mut *connection)
        .await?;
    match engine {
        Engine::TiDB => {
            if !supports_tidb_write_version(&version) {
                return Err(ControlError::Config(
                    "TiDB writable branches require TiDB v8.5 LTS or later",
                ));
            }
        }
        _ => {
            if !supports_mysql_write_version(&version) {
                return Err(ControlError::Config(
                    "MySQL writable branches require MySQL 8.0.30 or later in the 8.0 series",
                ));
            }
        }
    }
    // TiDB has neither partial_revokes nor mandatory_roles; wildcard
    // grants are always permitted, matching MySQL with partial_revokes off.
    let permits_legacy = if engine == Engine::TiDB {
        true
    } else {
        let (partial_revokes, mandatory): (i64, Vec<u8>) = sqlx::query_as(
            "SELECT CAST(@@GLOBAL.partial_revokes AS SIGNED), @@GLOBAL.mandatory_roles",
        )
        .fetch_one(&mut *connection)
        .await?;
        if !mandatory.is_empty() {
            return Err(role_failure(role, "MySQL mandatory_roles must be empty"));
        }
        partial_revokes == 0
    };
    let observed = if matches!(check, BranchAdminCheck::Startup { .. }) {
        let account: String = sqlx::query_scalar("SELECT CURRENT_USER()")
            .fetch_one(&mut *connection)
            .await?;
        if account != format!("{}@%", role.user) {
            return Err(role_failure(
                role,
                "connected MySQL account must match the configured role at host %",
            ));
        }
        read_mysql_grants(connection, "SHOW GRANTS").await?
    } else {
        mysql_grant_lines(connection, role).await?
    };
    let expected = catalog
        .generations
        .iter()
        .chain(incoming)
        .flat_map(|generation| {
            let required = check.requires_generation(generation.id);
            generation
                .tables
                .iter()
                .map(move |table| (base_read_grant(Engine::MySql, table), required))
        });
    let has_legacy_branches = catalog
        .branches
        .iter()
        .any(|branch| branch.target.prefix().is_none());
    check_mysql_admin_grants(
        &observed,
        role,
        engine,
        expected,
        permits_legacy,
        has_legacy_branches,
    )
}

fn check_mysql_admin_grants(
    observed: &[String],
    role: &NativeRole,
    engine: Engine,
    bases: impl Iterator<Item = (TableGrant, bool)>,
    permits_legacy: bool,
    has_legacy_branches: bool,
) -> Result<(), ControlError> {
    let account = role.mysql_display(engine);
    // MySQL hides trigger definitions without TRIGGER on their table. Only
    // the existing scoped branch administrator may attest witness storage;
    // service and collector privileges remain unchanged. TiDB has no triggers.
    let required = if engine == Engine::MySql {
        MYSQL_BRANCH_ADMIN
    } else {
        TIDB_BRANCH_ADMIN
    };
    let admin_rights = rights_set(required);
    let scoped = |line: &str, scope: &str| {
        grant_key(line)
            .is_some_and(|key| key == format!("{}|{scope}|{account}|true", admin_rights.join(",")))
    };
    let bases = bases
        .map(|(grant, required)| (grant_key(&mysql_grant_line(&grant, &account)), required))
        .collect::<Vec<_>>();
    let shared = format!("{}.*", Engine::MySql.quote(MYSQL_WRITE_SCHEMA));
    let usage = grant_key(&format!("GRANT USAGE ON *.* TO {account}"));
    let legacy_base = grant_key(&format!(
        "GRANT SELECT ON {LEGACY_MYSQL_BASES} TO {account}"
    ));
    let shared_admin = grant_key(&format!(
        "GRANT {required} ON {shared} TO {account} WITH GRANT OPTION"
    ));
    let legacy_branch = grant_key(&format!(
        "GRANT {required} ON {LEGACY_MYSQL_BRANCHES} TO {account} WITH GRANT OPTION"
    ));
    let mut missing = Vec::new();
    for (grant, required) in &bases {
        if *required && !observed.iter().any(|line| grant_key(line) == *grant) {
            missing.push(format!(
                "GRANT {} ON {} TO {account}",
                grant.as_ref().map_or(String::new(), |key| {
                    key.split('|').next().unwrap_or_default().to_owned()
                }),
                grant
                    .as_ref()
                    .and_then(|key| key.split('|').nth(1))
                    .unwrap_or_default(),
            ));
        }
    }
    if !observed.iter().any(|line| grant_key(line) == shared_admin) {
        missing.push(format!(
            "GRANT {required} ON {shared} TO {account} WITH GRANT OPTION"
        ));
    }
    if has_legacy_branches
        && !observed
            .iter()
            .any(|line| permits_legacy && grant_key(line) == legacy_branch)
    {
        missing.push(format!(
            "GRANT {required} ON {LEGACY_MYSQL_BRANCHES} TO {account} WITH GRANT OPTION"
        ));
    }
    let unexpected = observed
        .iter()
        .filter(|line| {
            let key = grant_key(line);
            !(key == usage
                || bases.iter().any(|(base, _)| *base == key)
                || scoped(line, &shared)
                || (permits_legacy && key == legacy_base)
                || (permits_legacy && key == legacy_branch))
        })
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() || !unexpected.is_empty() {
        return Err(grant_difference(role, &missing, &unexpected));
    }
    Ok(())
}

fn base_read_grant(engine: Engine, table: &CatalogEntry) -> TableGrant {
    TableGrant {
        rights: READ,
        relation: engine.relation(&table.base_schema, &table.base_table),
    }
}

async fn verify_postgres_branch_admin(
    connection: &mut PgConnection,
    role: &NativeRole,
    catalog: &NativeCatalog,
    incoming: Option<&BootstrapGeneration>,
    check: BranchAdminCheck,
) -> Result<(), ControlError> {
    let restricted: Option<bool> = sqlx::query_scalar(
        "SELECT r.rolcanlogin AND NOT (
            r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls
            OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member = r.oid)
            OR pg_catalog.has_database_privilege(r.oid, current_database()::text, 'CREATE WITH GRANT OPTION'))
            AND pg_catalog.has_database_privilege(r.oid, current_database()::text, 'CREATE')
         FROM pg_catalog.pg_roles r WHERE r.rolname = $1",
    )
    .bind(&role.user)
    .fetch_optional(&mut *connection)
    .await?;
    if restricted.is_none() {
        return Err(missing_role(role));
    }
    if restricted != Some(true) {
        return Err(role_failure(
            role,
            "requires LOGIN and database CREATE without delegation, elevated attributes or role memberships",
        ));
    }
    for generation in catalog.generations.iter().chain(incoming) {
        let required = check.requires_generation(generation.id);
        let expected = generation
            .tables
            .iter()
            .map(|table| Expected {
                schema: &table.base_schema,
                table: Cow::Borrowed(&table.base_table),
                scope: Scope::Base,
                required,
            })
            .collect::<Vec<_>>();
        if required {
            verify_postgres_schema(connection, role, &generation.schema, true).await?;
        }
        let can_create: Option<bool> = sqlx::query_scalar(
            "SELECT pg_catalog.has_schema_privilege($1::name, pg_catalog.to_regnamespace($2)::oid, 'CREATE')",
        ).bind(&role.user).bind(&generation.schema).fetch_one(&mut *connection).await?;
        if can_create == Some(true) {
            return Err(role_failure(
                role,
                format!(
                    "unexpected CREATE privilege on schema {}",
                    generation.schema
                ),
            ));
        }
        verify_postgres_tables(connection, role, &expected, false, Some(&generation.schema))
            .await?;
    }
    Ok(())
}

pub(crate) async fn verify_postgres_branch(
    connection: &mut PgConnection,
    roles: &NativeRoles,
    target: &WriteTarget,
    tables: &[CatalogEntry],
) -> Result<(), ControlError> {
    let mut expected = tables
        .iter()
        .map(|table| expected_branch_table(target, table, true))
        .collect::<Vec<_>>();
    expected.push(expected_witness(target, true));
    for (role, collector) in [(&roles.service, false), (&roles.collector, true)] {
        verify_postgres_schema(connection, role, target.schema(), true).await?;
        verify_postgres_tables(
            connection,
            role,
            &expected,
            collector,
            Some(target.schema()),
        )
        .await?;
    }
    Ok(())
}

async fn verify_mysql(
    connection: &mut MySqlConnection,
    engine: Engine,
    roles: &NativeRoles,
    tables: &[Expected<'_>],
) -> Result<(), ControlError> {
    // SHOW GRANTS FOR omits mandatory roles and differently matched accounts.
    // TiDB does not implement mandatory_roles.
    let mandatory = if engine == Engine::TiDB {
        Vec::new()
    } else {
        sqlx::query_scalar::<_, Vec<u8>>("SELECT @@GLOBAL.mandatory_roles")
            .fetch_one(&mut *connection)
            .await?
    };
    let accounts: Vec<(Vec<u8>, Vec<u8>)> =
        sqlx::query_as("SELECT User, Host FROM mysql.user WHERE User IN (?, ?, '')")
            .bind(&roles.service.user)
            .bind(&roles.collector.user)
            .fetch_all(&mut *connection)
            .await?;
    if !mandatory.is_empty() {
        return Err(role_failure(
            &roles.service,
            "MySQL mandatory_roles must be empty",
        ));
    }
    for role in [&roles.service, &roles.collector] {
        if !accounts
            .iter()
            .any(|(user, _)| user == role.user.as_bytes())
        {
            return Err(missing_role(role));
        }
    }
    if accounts.len() != 2
        || ![&roles.service, &roles.collector].iter().all(|role| {
            accounts
                .iter()
                .any(|(user, host)| user == role.user.as_bytes() && host == b"%")
        })
    {
        return Err(role_failure(
            &roles.service,
            "service and GC roles must each have exactly one MySQL account at host %, with no anonymous account",
        ));
    }
    for (role, collector) in [(&roles.service, false), (&roles.collector, true)] {
        let display = role.mysql_display(engine);
        let mut required = vec![format!("GRANT USAGE ON *.* TO {display}")];
        let mut optional = Vec::new();
        for table in tables {
            if let Some(rights) = table.rights(collector) {
                let grant = TableGrant {
                    rights,
                    relation: Engine::MySql.relation(table.schema, &table.table),
                };
                let grant = mysql_grant_line(&grant, &display);
                if table.required {
                    required.push(grant);
                } else {
                    optional.push(grant);
                }
            }
        }
        let observed = mysql_grant_lines(connection, role).await?;
        let required_keys = required
            .iter()
            .map(|line| grant_key(line))
            .collect::<Vec<_>>();
        let optional_keys = optional
            .iter()
            .map(|line| grant_key(line))
            .collect::<Vec<_>>();
        let missing = required
            .iter()
            .zip(&required_keys)
            .filter(|(_grant, key)| !observed.iter().any(|line| grant_key(line) == **key))
            .map(|(grant, _)| grant.clone())
            .collect::<Vec<_>>();
        let unexpected = observed
            .iter()
            .filter(|line| {
                let key = grant_key(line);
                !required_keys.contains(&key) && !optional_keys.contains(&key)
            })
            .cloned()
            .collect::<Vec<_>>();
        if !missing.is_empty() || !unexpected.is_empty() {
            return Err(grant_difference(role, &missing, &unexpected));
        }
    }
    Ok(())
}

async fn mysql_grant_lines(
    connection: &mut MySqlConnection,
    role: &NativeRole,
) -> Result<Vec<String>, ControlError> {
    read_mysql_grants(connection, &format!("SHOW GRANTS FOR {}", role.account))
        .await
        .map_err(|error| match error {
            ControlError::Native(sqlx::Error::Database(ref database))
                if database
                    .try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>()
                    .is_some_and(|error| error.number() == 1141) =>
            {
                missing_role(role)
            }
            _ => error,
        })
}

async fn read_mysql_grants(
    connection: &mut MySqlConnection,
    statement: &str,
) -> Result<Vec<String>, ControlError> {
    let rows = connection.fetch_all(statement).await?;
    rows.iter()
        .map(|row| row.try_get_unchecked(0).map_err(Into::into))
        .collect()
}

fn mysql_grant_line(grant: &TableGrant, display: &str) -> String {
    format!("GRANT {} ON {} TO {display}", grant.rights, grant.relation)
}

/// Normalize a SHOW GRANTS line for engine-independent comparison: MySQL 8.0
/// renders rights as "SELECT, DELETE" while TiDB renders "SELECT,DELETE", and
/// the two quote accounts differently. The key keeps the sorted rights set,
/// scope, grantee and delegation flag.
fn grant_key(line: &str) -> Option<String> {
    let (rights, rest) = line.strip_prefix("GRANT ")?.split_once(" ON ")?;
    let (scope, grantee) = rest.split_once(" TO ")?;
    let grantable = grantee.ends_with(" WITH GRANT OPTION");
    let grantee = grantee
        .strip_suffix(" WITH GRANT OPTION")
        .unwrap_or(grantee);
    let mut rights = rights.split(',').map(str::trim).collect::<Vec<_>>();
    rights.sort_unstable();
    Some(format!(
        "{}|{scope}|{grantee}|{grantable}",
        rights.join(",")
    ))
}

/// The sorted rights of a rights constant such as `MYSQL_BRANCH_ADMIN`.
fn rights_set(rights: &str) -> Vec<&str> {
    let mut rights = rights.split(", ").collect::<Vec<_>>();
    rights.sort_unstable();
    rights
}

pub(crate) async fn revoke_partial(
    native: &mut Native,
    roles: &NativeRoles,
    tables: &[CatalogEntry],
) -> Result<(), ControlError> {
    let engine = native.engine();
    let (Native::MySql(connection) | Native::TiDB(connection)) = native else {
        return Ok(());
    };
    // MySQL-family engines retain table privileges after DROP. Remove only
    // exact grants created for this generation, preserving operator grants.
    for (role, collector) in [(&roles.service, false), (&roles.collector, true)] {
        let observed = mysql_grant_lines(connection, role).await?;
        for grant in table_grants(engine, tables, collector) {
            revoke_exact_mysql_grant(connection, engine, role, &observed, grant).await?;
        }
    }
    if let Some(role) = &roles.branch_admin {
        let observed = mysql_grant_lines(connection, role).await?;
        for table in tables {
            revoke_exact_mysql_grant(
                connection,
                engine,
                role,
                &observed,
                base_read_grant(engine, table),
            )
            .await?;
        }
    }
    Ok(())
}

async fn revoke_exact_mysql_grant(
    connection: &mut MySqlConnection,
    engine: Engine,
    role: &NativeRole,
    observed: &[String],
    grant: TableGrant,
) -> Result<(), ControlError> {
    let expected = mysql_grant_line(&grant, &role.mysql_display(engine));
    if observed
        .iter()
        .any(|line| grant_key(line) == grant_key(&expected))
    {
        let statement = format!(
            "REVOKE {} ON {} FROM {}",
            grant.rights, grant.relation, role.account
        );
        connection.execute(statement.as_str()).await?;
    }
    Ok(())
}

async fn verify_postgres_role(
    connection: &mut PgConnection,
    role: &NativeRole,
) -> Result<(), ControlError> {
    let restricted: Option<bool> = sqlx::query_scalar(
        "SELECT r.rolcanlogin AND NOT (
            r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls
            OR pg_catalog.has_database_privilege(r.oid, current_database()::text, 'CREATE')
            OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member = r.oid)
            OR EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n
                       WHERE pg_catalog.has_schema_privilege(r.oid, n.oid, 'CREATE')))
         FROM pg_catalog.pg_roles r WHERE r.rolname = $1",
    )
    .bind(&role.user)
    .fetch_optional(connection)
    .await?;
    if restricted.is_none() {
        return Err(missing_role(role));
    }
    if restricted != Some(true) {
        return Err(role_failure(
            role,
            "requires LOGIN without elevated attributes, role memberships or CREATE privileges",
        ));
    }
    Ok(())
}

async fn verify_postgres_schema(
    connection: &mut PgConnection,
    role: &NativeRole,
    schema: &str,
    expected_usage: bool,
) -> Result<(), ControlError> {
    let (usage, delegable): (bool, bool) = sqlx::query_as(
        "SELECT pg_catalog.has_schema_privilege($1::name, $2::text, 'USAGE'),
                pg_catalog.has_schema_privilege($1::name, $2::text, 'USAGE WITH GRANT OPTION')",
    )
    .bind(&role.user)
    .bind(schema)
    .fetch_one(connection)
    .await?;
    if usage != expected_usage || delegable {
        return Err(role_failure(
            role,
            format!(
                "schema {schema}: expected USAGE={expected_usage} without delegation; actual USAGE={usage}, grantable={delegable}"
            ),
        ));
    }
    Ok(())
}

async fn verify_postgres_tables(
    connection: &mut PgConnection,
    role: &NativeRole,
    tables: &[Expected<'_>],
    collector: bool,
    schema_filter: Option<&str>,
) -> Result<(), ControlError> {
    type Observed = (
        String,
        String,
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
    );
    let observed: Vec<Observed> = sqlx::query_as(
        "SELECT n.nspname::text, c.relname::text,
                pg_catalog.has_table_privilege($1::name, c.oid, 'SELECT'),
                pg_catalog.has_table_privilege($1::name, c.oid, 'INSERT'),
                pg_catalog.has_table_privilege($1::name, c.oid, 'UPDATE'),
                pg_catalog.has_table_privilege($1::name, c.oid, 'DELETE'),
                pg_catalog.has_any_column_privilege($1::name, c.oid, 'SELECT'),
                pg_catalog.has_any_column_privilege($1::name, c.oid, 'INSERT'),
                pg_catalog.has_any_column_privilege($1::name, c.oid, 'UPDATE'),
                pg_catalog.has_any_column_privilege($1::name, c.oid,
                    'REFERENCES, SELECT WITH GRANT OPTION, INSERT WITH GRANT OPTION, UPDATE WITH GRANT OPTION')
                OR pg_catalog.has_table_privilege($1::name, c.oid,
                    'TRUNCATE, TRIGGER, DELETE WITH GRANT OPTION')
         FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f') AND n.nspname <> 'information_schema'
           AND left(n.nspname::text, 3) <> 'pg_' AND ($2::name IS NULL OR n.nspname = $2)",
    )
    .bind(&role.user)
    .bind(schema_filter)
    .fetch_all(connection)
    .await?;
    let mut found = 0;
    for (schema, table, read, insert, update, delete, part_read, part_insert, part_update, extra) in
        observed
    {
        let target = tables
            .iter()
            .find(|entry| entry.schema == schema && entry.table == table);
        let rights = target.and_then(|entry| entry.rights(collector));
        let actual = (read, insert, update, delete);
        if extra || (read, insert, update) != (part_read, part_insert, part_update) {
            return Err(role_failure(
                role,
                format!(
                    "relation {schema}.{table}: unexpected column, delegated or additional table privileges"
                ),
            ));
        }
        if target.is_some_and(|entry| !entry.required) && actual == (false, false, false, false) {
            continue;
        }
        let contains =
            |right| rights.is_some_and(|rights| rights.split(", ").any(|value| value == right));
        let expected = (
            contains("SELECT"),
            contains("INSERT"),
            contains("UPDATE"),
            contains("DELETE"),
        );
        if actual != expected {
            return Err(role_failure(
                role,
                format!(
                    "relation {schema}.{table}: expected (SELECT, INSERT, UPDATE, DELETE)={expected:?}; actual={actual:?}"
                ),
            ));
        }
        found += usize::from(rights.is_some() && target.is_some_and(|entry| entry.required));
    }
    if found
        != tables
            .iter()
            .filter(|entry| entry.required && entry.rights(collector).is_some())
            .count()
    {
        return Err(role_failure(
            role,
            "required catalog relations are missing or inaccessible; reapply the registered table grants",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        MYSQL_BRANCH_ADMIN, NativeRole, TIDB_BRANCH_ADMIN, check_mysql_admin_grants, grant_summary,
        has_witness_trigger_grant, supports_mysql_write_version, supports_tidb_write_version,
    };
    use crate::native::Engine;

    #[test]
    fn writable_cleanup_requires_mysql_8_0_30() {
        assert!(supports_mysql_write_version("8.0.30"));
        assert!(supports_mysql_write_version("8.0.43-google"));
        for version in ["8.0.29", "8.0.", "5.7.44", "8.4.6", "10.11.6-MariaDB"] {
            assert!(!supports_mysql_write_version(version));
        }
    }

    #[test]
    fn tidb_visibility_exemption_requires_a_real_supported_tidb_version() {
        assert!(supports_tidb_write_version("8.0.11-TiDB-v8.5.8"));
        for version in ["8.0.43", "8.0.43-google", "8.0.11-TiDB-v8.4.0", "TiDB", ""] {
            assert!(!supports_tidb_write_version(version));
        }
    }

    #[test]
    fn grant_diagnostics_exclude_accounts_and_authentication() {
        let grant = "GRANT SELECT ON `fg_g1`.`orders` TO `private-user`@`secret-host` IDENTIFIED BY 'secret-value'";
        assert_eq!(grant_summary(grant), "SELECT on `fg_g1`.`orders`");
        assert_eq!(
            grant_summary("GRANT `private-user`@`secret-host` TO `service`@`%`"),
            "unsupported grant form"
        );
        assert_eq!(
            grant_summary("GRANT SELECT ON `private\nvalue`.* TO `service`@`%`"),
            "unsupported grant form"
        );
    }

    #[test]
    fn mysql_admin_reports_missing_and_unexpected_scoped_privileges()
    -> Result<(), crate::ControlError> {
        let role = NativeRole::new(Engine::MySql, "forkget_branch")?;
        let observed = vec![
            "GRANT USAGE ON `forkget_delta`.* TO `forkget_branch`@`%` WITH GRANT OPTION".to_owned(),
        ];
        let error = check_mysql_admin_grants(
            &observed,
            &role,
            Engine::MySql,
            std::iter::empty(),
            false,
            false,
        )
        .err()
        .ok_or(crate::ControlError::Seed("expected a grant mismatch"))?;
        let message = error.to_string();
        assert!(message.contains("role forkget_branch"));
        assert!(message.contains("missing privileges"));
        assert!(message.contains("fgwrite"));
        assert!(message.contains("unexpected privileges"));
        assert!(message.contains("forkget_delta"));
        assert!(message.contains("grantable"));
        assert!(!message.contains(" TO "));
        Ok(())
    }

    #[test]
    fn only_mysql_scoped_administrators_require_trigger_visibility()
    -> Result<(), crate::ControlError> {
        for engine in [Engine::MySql, Engine::TiDB] {
            let role = NativeRole::new(engine, "branch_admin")?;
            let account = role.mysql_display(engine);
            let rights = if engine == Engine::MySql {
                MYSQL_BRANCH_ADMIN
            } else {
                TIDB_BRANCH_ADMIN
            };
            let grant = format!("GRANT {rights} ON `fgwrite`.* TO {account} WITH GRANT OPTION");
            check_mysql_admin_grants(&[grant], &role, engine, std::iter::empty(), false, false)?;
            let wrong = if engine == Engine::MySql {
                TIDB_BRANCH_ADMIN
            } else {
                MYSQL_BRANCH_ADMIN
            };
            let grant = format!("GRANT {wrong} ON `fgwrite`.* TO {account} WITH GRANT OPTION");
            assert!(
                check_mysql_admin_grants(&[grant], &role, engine, std::iter::empty(), false, false)
                    .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn trigger_visibility_is_rechecked_on_the_registered_scope() -> Result<(), crate::ControlError>
    {
        let target = fg_protocol_common::WriteTarget::new("mysql", 7, "fgwrite")
            .ok_or(crate::ControlError::Seed("test target"))?;
        for scope in ["`fgwrite`.*", "`fgwrite`.`fg_b7__fg_txn_witness`"] {
            assert!(has_witness_trigger_grant(
                &[format!("GRANT TRIGGER ON {scope} TO `admin`@`%`")],
                &target,
                false
            ));
        }
        for grant in [
            "GRANT SELECT, DELETE ON `fgwrite`.`fg_b7__fg_txn_witness` TO `gc`@`%`",
            "GRANT TRIGGER ON *.* TO `admin`@`%`",
            "GRANT TRIGGER ON `fgwrite`.`fg_b8__fg_txn_witness` TO `admin`@`%`",
            "GRANT TRIGGER ON `unrelated`.* TO `admin`@`%`",
            "GRANT `admin_role`@`%` TO `admin`@`%`",
        ] {
            assert!(!has_witness_trigger_grant(&[grant.into()], &target, false));
        }
        let legacy = fg_protocol_common::WriteTarget::new("mysql", 7, "fg_b7")
            .ok_or(crate::ControlError::Seed("legacy test target"))?;
        let grant = r"GRANT TRIGGER ON `fg\_b%`.* TO `admin`@`%`".to_owned();
        assert!(has_witness_trigger_grant(
            std::slice::from_ref(&grant),
            &legacy,
            true
        ));
        assert!(!has_witness_trigger_grant(&[grant], &legacy, false));
        Ok(())
    }
}
