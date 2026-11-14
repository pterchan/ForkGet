use fg_meta::Metadata;
use fg_protocol_common::{
    NativeWitnessBinding, TXN_WITNESS_FORMAT, TXN_WITNESS_TABLE, WriteTarget,
    valid_witness_identity,
};
use ring::rand::{SecureRandom, SystemRandom};
use thiserror::Error;

use super::Admin;
use crate::{
    ControlError,
    grants::NativeRoles,
    native::{Engine, Native, NativeOptions},
    verify,
};

const WITNESS_COLUMNS: [&str; 7] = [
    "format_version",
    "deployment_id",
    "branch_id",
    "generation_id",
    "storage_incarnation",
    "attempt_id",
    "native_session",
];

#[cfg(test)]
mod tests;

#[derive(Debug, Error)]
pub(crate) enum WitnessError {
    #[error(
        "Audit witness identity is invalid; keep this branch read-only and inspect its storage preparation"
    )]
    Identity,
    #[error(
        "Audit witness is missing or has an incompatible shape; do not recreate recovery evidence"
    )]
    Shape,
    #[error(
        "Audit witness column types, nullability or defaults are incompatible; keep storage for operator inspection"
    )]
    Columns,
    #[error(
        "Audit witness storage must be a permanent transactional table without triggers or foreign keys"
    )]
    Storage,
    #[error("Audit witness primary key is incompatible; keep storage for operator inspection")]
    PrimaryKey,
    #[error(
        "Audit witness identity constraint is incompatible; keep storage for operator inspection"
    )]
    Constraint,
    #[error(
        "Audit recovery is pending; preserve native storage and reconcile audit attempts before cleanup"
    )]
    Pending,
    #[error("Native session quiescence is unconfirmed; preserve the attempt as unknown")]
    Quiescence,
    #[error("Could not generate the native storage incarnation")]
    Random,
}

impl WitnessError {
    pub(crate) const fn reason(&self) -> &'static str {
        match self {
            Self::Identity => "audit_storage_identity_mismatch",
            Self::Shape | Self::Columns | Self::Storage | Self::PrimaryKey | Self::Constraint => {
                "audit_storage_incompatible"
            }
            Self::Pending => "audit_recovery_pending",
            Self::Quiescence => "native_quiescence_unconfirmed",
            Self::Random => "native_storage_identity_unavailable",
        }
    }
}

impl Admin {
    pub(crate) async fn attest_witness(
        &self,
        target: &WriteTarget,
        identity: &NativeWitnessBinding,
    ) -> Result<Native, ControlError> {
        let mut native = self.connect().await?;
        native.execute("BEGIN").await?;
        if native.engine() == Engine::Postgres {
            let relation =
                Engine::Postgres.relation(target.schema(), &target.table(TXN_WITNESS_TABLE));
            native
                .execute(&format!(
                    "LOCK TABLE {relation} IN SHARE UPDATE EXCLUSIVE MODE"
                ))
                .await?;
        }
        // The header read holds the relation's metadata lock until this
        // dedicated connection closes. The caller keeps it across collector
        // reads/deletes, so concurrent DDL cannot invalidate the attestation.
        crate::grants::verify_witness_visibility(&mut native, target).await?;
        verify_identity(&mut native, target, identity).await?;
        Ok(native)
    }

    pub(super) async fn prepare_witness(
        &self,
        metadata: &Metadata,
        native: &mut Native,
        target: &WriteTarget,
    ) -> Result<(), ControlError> {
        if native.engine() == Engine::MongoDb {
            return Ok(());
        }
        let identity = self
            .prepare_witness_native(metadata, native, target)
            .await?;
        metadata
            .mark_audit_witness_ready(native.engine().name(), &identity)
            .await?;
        Ok(())
    }

    async fn prepare_witness_native(
        &self,
        metadata: &Metadata,
        native: &mut Native,
        target: &WriteTarget,
    ) -> Result<NativeWitnessBinding, ControlError> {
        let identity = metadata
            .plan_audit_witness(
                native.engine().name(),
                target.branch_id(),
                &new_incarnation()?,
            )
            .await?;
        let table = target.table(TXN_WITNESS_TABLE);
        if !verify::has_table(native, target.schema(), &table).await? {
            // A ready binding must never be recreated: an absent marker would
            // otherwise turn a missing or restored database into false rollback proof.
            if metadata
                .audit_witness_binding(native.engine().name(), target.branch_id())
                .await?
                .is_some()
            {
                return Err(WitnessError::Shape.into());
            }
            create(native, target, &identity).await?;
        }
        verify_identity(native, target, &identity).await?;
        grant(native, target, &self.roles).await?;
        Ok(identity)
    }

    /// The coordinated upgrade adds only the internal relation. It never calls
    /// provision_native, whose retry semantics deliberately rebuild a new copy.
    pub(crate) async fn prepare_existing_witnesses(
        &self,
        metadata: &Metadata,
    ) -> Result<(), ControlError> {
        let _guard = metadata.lock_bootstrap().await?;
        let catalog = metadata
            .native_catalog(self.options.engine().name())
            .await?;
        let mut native = self.connect().await?;
        verify::check_constraint_enforcement(&mut native).await?;
        for branch in catalog
            .branches
            .into_iter()
            .filter(|branch| branch.grants_required)
        {
            self.prepare_witness(metadata, &mut native, &branch.target)
                .await?;
        }
        Ok(())
    }

    pub(crate) async fn replace_untrusted_witness(
        &self,
        metadata: &Metadata,
        request: Replacement<'_>,
    ) -> Result<(), ControlError> {
        let _guard = metadata.lock_bootstrap().await?;
        let engine = self.options.engine().name();
        if !metadata
            .audit_storage_replacement_allowed(engine, request.branch_id)
            .await?
        {
            return Err(WitnessError::Pending.into());
        }
        let catalog = metadata.native_catalog(engine).await?;
        let target = catalog
            .branches
            .iter()
            .find(|branch| branch.target.branch_id() == request.branch_id)
            .map(|branch| &branch.target)
            .ok_or(WitnessError::Identity)?;
        let identity = metadata
            .plan_audit_witness_replacement(engine, request.branch_id, &new_incarnation()?)
            .await?;
        let mut native = self.connect().await?;
        remove(&mut native, target, &self.roles).await?;
        create(&mut native, target, &identity).await?;
        verify_identity(&mut native, target, &identity).await?;
        grant(&mut native, target, &self.roles).await?;
        metadata
            .mark_audit_witness_replacement_ready_by(engine, &identity, request.operator)
            .await?;
        Ok(())
    }
}

pub(crate) struct Replacement<'a> {
    pub(crate) branch_id: i64,
    pub(crate) operator: &'a str,
}

fn new_incarnation() -> Result<String, WitnessError> {
    let mut bytes = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| WitnessError::Random)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

async fn create(
    native: &mut Native,
    target: &WriteTarget,
    identity: &NativeWitnessBinding,
) -> Result<(), ControlError> {
    validate_identity(target, identity)?;
    let engine = native.engine();
    let relation = engine.relation(target.schema(), &target.table(TXN_WITNESS_TABLE));
    let storage = if matches!(engine, Engine::MySql | Engine::TiDB) {
        " ENGINE=InnoDB DEFAULT CHARACTER SET ascii COLLATE ascii_bin"
    } else {
        ""
    };
    native
        .execute(&format!(
            "CREATE TABLE {relation} (
            format_version SMALLINT NOT NULL,
            deployment_id VARCHAR(64) NOT NULL,
            branch_id BIGINT NOT NULL,
            generation_id BIGINT NOT NULL,
            storage_incarnation CHAR(32) NOT NULL,
            attempt_id VARCHAR(96) NOT NULL PRIMARY KEY,
            native_session VARCHAR(128) NOT NULL,
            CHECK (format_version = {version} AND deployment_id = '{deployment}'
                AND branch_id = {branch} AND generation_id = {generation}
                AND storage_incarnation = '{incarnation}')
        ){storage}",
            version = identity.format_version,
            deployment = identity.deployment_id,
            branch = identity.branch_id,
            generation = identity.generation_id,
            incarnation = identity.storage_incarnation,
        ))
        .await?;
    native.execute(&format!(
        "INSERT INTO {relation} ({columns}) VALUES ({version}, '{deployment}', {branch}, {generation}, '{incarnation}', '', '')",
        columns = WITNESS_COLUMNS.join(", "),
        version = identity.format_version, deployment = identity.deployment_id,
        branch = identity.branch_id, generation = identity.generation_id,
        incarnation = identity.storage_incarnation,
    )).await
}

fn validate_identity(
    target: &WriteTarget,
    identity: &NativeWitnessBinding,
) -> Result<(), WitnessError> {
    if identity.format_version != TXN_WITNESS_FORMAT
        || identity.branch_id != target.branch_id()
        || identity.generation_id <= 0
        || !valid_witness_identity(&identity.deployment_id, &identity.storage_incarnation)
    {
        return Err(WitnessError::Identity);
    }
    Ok(())
}

pub(crate) async fn verify_identity(
    native: &mut Native,
    target: &WriteTarget,
    identity: &NativeWitnessBinding,
) -> Result<(), ControlError> {
    validate_identity(target, identity)?;
    let engine = native.engine();
    let relation = engine.relation(target.schema(), &target.table(TXN_WITNESS_TABLE));
    let projection = witness_projection(engine);
    let sql = format!("SELECT {projection} FROM {relation} WHERE attempt_id = ''");
    type Header = (i16, String, i64, i64, String, String);
    let header: Option<Header> = match native {
        Native::MySql(connection) | Native::TiDB(connection) => {
            sqlx::query_as(&sql).fetch_optional(connection).await?
        }
        Native::Postgres(connection) => sqlx::query_as(&sql).fetch_optional(connection).await?,
        Native::Mongo(_) => return Err(WitnessError::Identity.into()),
    };
    let expected = (
        i16::try_from(identity.format_version).map_err(|_| WitnessError::Identity)?,
        identity.deployment_id.clone(),
        identity.branch_id,
        identity.generation_id,
        identity.storage_incarnation.clone(),
        String::new(),
    );
    if header.as_ref() != Some(&expected) {
        return Err(WitnessError::Identity.into());
    }
    verify_shape(native, target).await?;
    verify_constraints(native, target, identity).await
}

fn witness_projection(engine: Engine) -> &'static str {
    match engine {
        Engine::Postgres => {
            "format_version, deployment_id, branch_id, generation_id, storage_incarnation, native_session"
        }
        _ => {
            "format_version, CONVERT(deployment_id USING utf8mb4) COLLATE utf8mb4_unicode_ci, branch_id, generation_id, CONVERT(storage_incarnation USING utf8mb4) COLLATE utf8mb4_unicode_ci, CONVERT(native_session USING utf8mb4) COLLATE utf8mb4_unicode_ci"
        }
    }
}

async fn verify_shape(native: &mut Native, target: &WriteTarget) -> Result<(), ControlError> {
    let table = target.table(TXN_WITNESS_TABLE);
    type Column = (String, String, String, i64, i64);
    let columns: Vec<Column> = match native {
        Native::MySql(connection) | Native::TiDB(connection) => sqlx::query_as(
            "SELECT CONVERT(column_name USING utf8mb4), CONVERT(data_type USING utf8mb4), CONVERT(is_nullable USING utf8mb4), CAST(COALESCE(character_maximum_length,-1) AS SIGNED), CAST((column_default IS NOT NULL OR extra<>'' OR column_type LIKE '%unsigned%') AS SIGNED) FROM information_schema.columns WHERE table_schema = ? AND table_name = ? ORDER BY ordinal_position",
        ).bind(target.schema()).bind(&table).fetch_all(connection).await?,
        Native::Postgres(connection) => sqlx::query_as(
            "SELECT column_name::text, data_type::text, is_nullable::text, COALESCE(character_maximum_length,-1)::bigint, CASE WHEN column_default IS NOT NULL OR is_identity<>'NO' OR is_generated<>'NEVER' THEN 1 ELSE 0 END::bigint FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2 ORDER BY ordinal_position",
        ).bind(target.schema()).bind(&table).fetch_all(connection).await?,
        Native::Mongo(_) => return Err(WitnessError::Shape.into()),
    };
    if columns.len() != WITNESS_COLUMNS.len()
        || !columns.iter().zip(WITNESS_COLUMNS).enumerate().all(
            |(index, ((name, kind, nullable, length, extra), expected))| {
                let type_matches = match index {
                    0 => kind == "smallint" && *length == -1,
                    2 | 3 => kind == "bigint" && *length == -1,
                    4 => matches!(kind.as_str(), "char" | "character") && *length == 32,
                    1 | 5 | 6 => {
                        matches!(kind.as_str(), "varchar" | "character varying")
                            && *length == [0, 64, 0, 0, 0, 96, 128][index]
                    }
                    _ => false,
                };
                name == expected && nullable == "NO" && *extra == 0 && type_matches
            },
        )
    {
        return Err(WitnessError::Columns.into());
    }
    Ok(())
}

async fn verify_constraints(
    native: &mut Native,
    target: &WriteTarget,
    identity: &NativeWitnessBinding,
) -> Result<(), ControlError> {
    let engine = native.engine();
    let (primary, checks, transactional, checks_enforced) = match native {
        Native::MySql(connection) | Native::TiDB(connection) => {
            let primary: Vec<String> = sqlx::query_scalar("SELECT CONVERT(column_name USING utf8mb4) FROM information_schema.statistics WHERE table_schema=? AND table_name=? AND index_name='PRIMARY' ORDER BY seq_in_index")
                .bind(target.schema()).bind(target.table(TXN_WITNESS_TABLE)).fetch_all(&mut *connection).await?;
            let checks: Vec<String> = crate::native::mysql_table_checks(
                connection,
                engine,
                target.schema(),
                &target.table(TXN_WITNESS_TABLE),
            )
            .await?
            .into_iter()
            .map(|check| check.expression)
            .collect();
            let safe: i64 = sqlx::query_scalar("SELECT CAST(COUNT(*)=1 AS SIGNED) FROM information_schema.tables t WHERE t.table_schema=? AND t.table_name=? AND t.table_type='BASE TABLE' AND t.engine='InnoDB' AND NOT EXISTS(SELECT 1 FROM information_schema.triggers r WHERE r.event_object_schema=t.table_schema AND r.event_object_table=t.table_name) AND NOT EXISTS(SELECT 1 FROM information_schema.table_constraints c WHERE c.table_schema=t.table_schema AND c.table_name=t.table_name AND c.constraint_type='FOREIGN KEY')")
                .bind(target.schema()).bind(target.table(TXN_WITNESS_TABLE)).fetch_one(&mut *connection).await?;
            (primary, checks, safe == 1, true)
        }
        Native::Postgres(connection) => {
            let primary: Vec<String> = sqlx::query_scalar("SELECT a.attname::text FROM pg_catalog.pg_constraint c JOIN pg_catalog.pg_class r ON r.oid=c.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=r.relnamespace JOIN LATERAL unnest(c.conkey) WITH ORDINALITY k(attnum,ord) ON TRUE JOIN pg_catalog.pg_attribute a ON a.attrelid=r.oid AND a.attnum=k.attnum WHERE n.nspname=$1 AND r.relname=$2 AND c.contype='p' AND NOT c.condeferrable AND c.convalidated ORDER BY k.ord")
                .bind(target.schema()).bind(target.table(TXN_WITNESS_TABLE)).fetch_all(&mut *connection).await?;
            let checks: Vec<(String, bool)> = sqlx::query_as("SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid)::text, c.convalidated FROM pg_catalog.pg_constraint c JOIN pg_catalog.pg_class r ON r.oid=c.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname=$1 AND r.relname=$2 AND c.contype='c'")
                .bind(target.schema()).bind(target.table(TXN_WITNESS_TABLE)).fetch_all(&mut *connection).await?;
            let safe: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_class r JOIN pg_catalog.pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname=$1 AND r.relname=$2 AND r.relkind='r' AND r.relpersistence='p' AND NOT r.relispartition AND NOT r.relrowsecurity AND NOT r.relforcerowsecurity AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid=r.oid) AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_rewrite w WHERE w.ev_class=r.oid) AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_inherits h WHERE h.inhrelid=r.oid OR h.inhparent=r.oid) AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint c WHERE c.conrelid=r.oid AND c.contype='f'))")
                .bind(target.schema()).bind(target.table(TXN_WITNESS_TABLE)).fetch_one(&mut *connection).await?;
            let enforced = checks.iter().all(|(_, validated)| *validated);
            (
                primary,
                checks
                    .into_iter()
                    .map(|(expression, _)| expression)
                    .collect(),
                safe,
                enforced,
            )
        }
        Native::Mongo(_) => return Err(WitnessError::Shape.into()),
    };
    let expected = format!(
        "format_version={}ANDdeployment_id='{}'ANDbranch_id={}ANDgeneration_id={}ANDstorage_incarnation='{}'",
        identity.format_version,
        identity.deployment_id,
        identity.branch_id,
        identity.generation_id,
        identity.storage_incarnation
    );
    if !transactional {
        return Err(WitnessError::Storage.into());
    }
    if primary != ["attempt_id"] {
        return Err(WitnessError::PrimaryKey.into());
    }
    if !checks_enforced
        || checks.len() != 1
        || normalize_check(&checks[0]) != normalize_check(&expected)
    {
        return Err(WitnessError::Constraint.into());
    }
    Ok(())
}

fn normalize_check(value: &str) -> String {
    let value = value.to_ascii_lowercase();
    let value = value
        .replace("::character varying", "")
        .replace("::text", "")
        .replace("::bpchar", "")
        .replace("::bigint", "")
        .replace("::smallint", "")
        .replace("_utf8mb4", "")
        .replace("_ascii", "");
    value
        .chars()
        .filter(|character| {
            !character.is_ascii_whitespace() && !matches!(character, '(' | ')' | '`' | '"')
        })
        .collect()
}

async fn grant(
    native: &mut Native,
    target: &WriteTarget,
    roles: &NativeRoles,
) -> Result<(), ControlError> {
    let engine = native.engine();
    if engine == Engine::Postgres {
        native
            .execute(&format!(
                "GRANT USAGE ON SCHEMA {} TO {}",
                engine.quote(target.schema()),
                roles.collector.account
            ))
            .await?;
    }
    let relation = engine.relation(target.schema(), &target.table(TXN_WITNESS_TABLE));
    for (role, rights) in [
        (&roles.service, "INSERT"),
        (&roles.collector, "SELECT, DELETE"),
    ] {
        native
            .execute(&format!("GRANT {rights} ON {relation} TO {}", role.account))
            .await?;
    }
    Ok(())
}

pub(crate) async fn remove(
    native: &mut Native,
    target: &WriteTarget,
    roles: &NativeRoles,
) -> Result<(), ControlError> {
    let engine = native.engine();
    if engine == Engine::MongoDb {
        return Ok(());
    }
    let relation = engine.relation(target.schema(), &target.table(TXN_WITNESS_TABLE));
    if matches!(engine, Engine::MySql | Engine::TiDB) {
        for role in [&roles.service, &roles.collector] {
            if engine == Engine::TiDB {
                super::revoke_existing(native, &relation, &role.account).await?;
            } else {
                native
                    .execute(&format!(
                        "REVOKE IF EXISTS SELECT, INSERT, DELETE ON {relation} FROM {}",
                        role.account
                    ))
                    .await?;
            }
        }
    }
    native
        .execute(&format!("DROP TABLE IF EXISTS {relation}"))
        .await?;
    if engine == Engine::Postgres && verify::has_schema(native, target.schema()).await? {
        native
            .execute(&format!(
                "REVOKE USAGE ON SCHEMA {} FROM {}",
                engine.quote(target.schema()),
                roles.collector.account
            ))
            .await?;
    }
    Ok(())
}

pub(crate) struct WitnessProbe<'a> {
    pub(crate) target: &'a WriteTarget,
    pub(crate) identity: &'a NativeWitnessBinding,
    pub(crate) attempt: &'a fg_protocol_common::AuditAttemptContext,
}

pub(crate) async fn contains(
    native: &mut Native,
    probe: WitnessProbe<'_>,
) -> Result<bool, ControlError> {
    verify_identity(native, probe.target, probe.identity).await?;
    let relation = native.engine().relation(
        probe.target.schema(),
        &probe.target.table(TXN_WITNESS_TABLE),
    );
    let marker = if native.engine() == Engine::Postgres {
        "$1"
    } else {
        "?"
    };
    let projection = witness_projection(native.engine());
    let sql = format!("SELECT {projection} FROM {relation} WHERE attempt_id = {marker}");
    type Row = (i16, String, i64, i64, String, String);
    let row: Option<Row> = match native {
        Native::MySql(connection) | Native::TiDB(connection) => {
            sqlx::query_as(&sql)
                .bind(&probe.attempt.attempt_id)
                .fetch_optional(connection)
                .await?
        }
        Native::Postgres(connection) => {
            sqlx::query_as(&sql)
                .bind(&probe.attempt.attempt_id)
                .fetch_optional(connection)
                .await?
        }
        Native::Mongo(_) => return Err(WitnessError::Identity.into()),
    };
    let Some(row) = row else { return Ok(false) };
    let expected = (
        i16::try_from(probe.identity.format_version).map_err(|_| WitnessError::Identity)?,
        probe.identity.deployment_id.clone(),
        probe.identity.branch_id,
        probe.identity.generation_id,
        probe.identity.storage_incarnation.clone(),
        probe.attempt.native_session_id.to_string(),
    );
    if row != expected {
        return Err(WitnessError::Identity.into());
    }
    Ok(true)
}

pub(crate) struct WitnessCollection<'a> {
    pub(crate) metadata: &'a Metadata,
    pub(crate) options: &'a NativeOptions,
    pub(crate) admin: &'a Admin,
    pub(crate) target: &'a WriteTarget,
}

pub(crate) async fn collect_completed(
    request: WitnessCollection<'_>,
) -> Result<usize, ControlError> {
    let collection_started =
        tracing::enabled!(target: "fg_control::audit_cleanup", tracing::Level::DEBUG)
            .then(std::time::Instant::now);
    let WitnessCollection {
        metadata,
        options,
        admin,
        target,
    } = request;
    let engine = options.engine();
    if engine == Engine::MongoDb {
        return Ok(0);
    }
    let ids = metadata
        .completed_sql_audit_attempts(engine.name(), target.branch_id(), 256)
        .await?;
    if ids.is_empty() {
        return Ok(0);
    }
    let identity = metadata
        .audit_witness_binding(engine.name(), target.branch_id())
        .await?
        .ok_or(WitnessError::Identity)?;
    // This connection belongs to this operation. Error/cancellation closes it,
    // rolling back any uncommitted deletion and releasing its own DDL locks.
    let mut native = options.connect().await?;
    begin_collection(&mut native, target).await?;
    let attestation = admin.attest_witness(target, &identity).await?;
    verify_identity(&mut native, target, &identity).await?;
    let started = collection_started.map(|_| std::time::Instant::now());
    delete_completed(&mut native, target, &ids).await?;
    let native_delete_ms = started.map(|clock| clock.elapsed().as_secs_f64() * 1_000.0);
    let commit_started = started.map(|_| std::time::Instant::now());
    native.execute("COMMIT").await?;
    let native_commit_ms = commit_started.map(|clock| clock.elapsed().as_secs_f64() * 1_000.0);
    drop(attestation);
    let mark_started = started.map(|_| std::time::Instant::now());
    metadata.mark_witness_collected(engine.name(), &ids).await?;
    if let (
        Some(native_delete_ms),
        Some(native_commit_ms),
        Some(mark_started),
        Some(collection_started),
    ) = (
        native_delete_ms,
        native_commit_ms,
        mark_started,
        collection_started,
    ) {
        tracing::debug!(target:"fg_control::audit_cleanup",engine=engine.name(),
            acknowledged_attempts=ids.len(),native_delete_ms,native_commit_ms,
            metadata_mark_ms=mark_started.elapsed().as_secs_f64()*1_000.0,
            collection_total_ms=collection_started.elapsed().as_secs_f64()*1_000.0,
            "Completed witness cleanup batch");
    }
    Ok(ids.len())
}

async fn begin_collection(native: &mut Native, target: &WriteTarget) -> Result<(), ControlError> {
    let engine = native.engine();
    let relation = engine.relation(target.schema(), &target.table(TXN_WITNESS_TABLE));
    native.execute("BEGIN").await?;
    let lock = match engine {
        Engine::Postgres => format!("LOCK TABLE ONLY {relation} IN ROW EXCLUSIVE MODE"),
        Engine::MySql => {
            format!("SELECT attempt_id FROM {relation} WHERE attempt_id='' FOR UPDATE")
        }
        // TiDB's transactional read pins MDL without a pessimistic header lock.
        // The native KILL regression left that row lock blocking fresh collectors.
        Engine::TiDB => format!("SELECT attempt_id FROM {relation} WHERE attempt_id=''"),
        Engine::MongoDb => return Err(WitnessError::Identity.into()),
    };
    // Pin metadata before attestation, independently of the admin connection.
    // MySQL needs its write-compatible MDL before a queued DDL blocks upgrades.
    native.execute(&lock).await
}

async fn delete_completed(
    native: &mut Native,
    target: &WriteTarget,
    ids: &[String],
) -> Result<(), ControlError> {
    let engine = native.engine();
    let relation = engine.relation(target.schema(), &target.table(TXN_WITNESS_TABLE));
    match native {
        Native::MySql(connection) | Native::TiDB(connection) => {
            let mut query = sqlx::QueryBuilder::<sqlx::MySql>::new(format!(
                "DELETE FROM {relation} WHERE attempt_id <> '' AND attempt_id IN ("
            ));
            let mut list = query.separated(", ");
            for id in ids {
                list.push_bind(id);
            }
            list.push_unseparated(")");
            query.build().execute(connection).await?;
        }
        Native::Postgres(connection) => {
            sqlx::query(&format!(
                "DELETE FROM {relation} WHERE attempt_id <> '' AND attempt_id = ANY($1)"
            ))
            .bind(ids)
            .execute(connection)
            .await?;
        }
        Native::Mongo(_) => return Err(WitnessError::Identity.into()),
    }
    Ok(())
}
