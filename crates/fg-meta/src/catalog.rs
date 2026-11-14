use fg_protocol_common::{
    BranchAccess, BranchBinding, BranchClass, BranchLayout, CatalogColumn, CatalogEntry,
    ReadStrategy, ReplayOrigin, WriteTarget,
};
use sqlx::{FromRow, PgConnection};
use std::collections::BTreeMap;

use crate::{MetaError, Metadata};

pub const DEFAULT_SCHEMA: &str = "app";
pub(crate) const DELTA_SCHEMA: &str = "forkget_delta";
const GENERATION_SWITCH_LOCK: i64 = 0x4647_0000_0000_0002;
const LIVE_GENERATION_LIMIT: i64 = 2;

pub struct SeedTable {
    pub name: &'static str,
    pub columns: &'static [SeedColumn],
    pub generated_key: Option<&'static str>,
    pub baseline_rows: i64,
}

pub struct RefreshGeneration<'a> {
    pub engine: &'a str,
    pub snapshot: &'a str,
    pub tables: &'a [SeedTable],
    pub cooldown_seconds: u32,
}

pub struct SeedColumn {
    pub name: &'static str,
    pub type_name: &'static str,
    pub collation: Option<&'static str>,
    pub nullable: bool,
    pub primary_key_ordinal: Option<u16>,
}

pub struct BootstrapGeneration {
    pub id: i64,
    pub engine: String,
    pub schema: String,
    pub native_claimed: bool,
    pub tables: Vec<CatalogEntry>,
}

pub struct NativeCatalog {
    pub generations: Vec<BootstrapGeneration>,
    pub branches: Vec<NativeBranch>,
}

pub struct NativeBranch {
    pub target: WriteTarget,
    pub generation_id: i64,
    pub grants_required: bool,
    pub audit_witness_ready: bool,
}

#[derive(FromRow)]
struct Generation {
    id: i64,
    engine: String,
    schema_name: String,
    native_claimed: bool,
}

#[derive(FromRow)]
struct RegisteredTable {
    id: i64,
    logical_schema: String,
    logical_table: String,
    base_schema: String,
    base_table: String,
    delta_schema: String,
    delta_table: String,
    generated_key: Option<String>,
    baseline_rows: i64,
}

#[derive(FromRow)]
struct RegisteredColumn {
    table_id: i64,
    ordinal: i32,
    name: String,
    data_type: String,
    is_nullable: bool,
    key_ordinal: Option<i32>,
}

impl Metadata {
    pub async fn has_active_generation(&self, engine: &str) -> Result<bool, MetaError> {
        Ok(self.active_generation_id(engine).await?.is_some())
    }

    pub async fn active_generation_id(&self, engine: &str) -> Result<Option<i64>, MetaError> {
        sqlx::query_scalar("SELECT id FROM generation WHERE engine = $1 AND status = 'active'")
            .bind(engine)
            .fetch_optional(&self.pool)
            .await
            .map_err(Into::into)
    }

    pub async fn importing_generation(&self) -> Result<Option<BootstrapGeneration>, MetaError> {
        let mut connection = self.pool.acquire().await?;
        let generation = sqlx::query_as::<_, Generation>(
            "SELECT id, engine, schema_name, native_claimed FROM generation WHERE status = 'importing'",
        )
        .fetch_optional(&mut *connection)
        .await?;
        match generation {
            Some(generation) => load_generation(&mut connection, generation).await.map(Some),
            None => Ok(None),
        }
    }

    pub async fn allocate_generation(
        &self,
        engine: &str,
        tables: &[SeedTable],
    ) -> Result<BootstrapGeneration, MetaError> {
        let mut transaction = self.pool.begin().await?;
        let active: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM generation WHERE status = 'active')")
                .fetch_one(&mut *transaction)
                .await?;
        if active {
            return Err(MetaError::AlreadyBootstrapped);
        }
        let generation = register_generation(&mut transaction, engine, "v1", tables).await?;
        transaction.commit().await?;
        Ok(generation)
    }

    pub async fn allocate_refresh(
        &self,
        request: RefreshGeneration<'_>,
    ) -> Result<BootstrapGeneration, MetaError> {
        let mut transaction = self.pool.begin().await?;
        let active_engine: Option<String> =
            sqlx::query_scalar("SELECT engine FROM generation WHERE status = 'active'")
                .fetch_optional(&mut *transaction)
                .await?;
        if active_engine.as_deref() != Some(request.engine) {
            return Err(MetaError::NoGeneration);
        }
        let live: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM generation WHERE status IN ('importing', 'active', 'retiring')
               OR (status = 'failed' AND native_claimed)",
        )
        .fetch_one(&mut *transaction)
        .await?;
        if live >= LIVE_GENERATION_LIMIT {
            return Err(MetaError::GenerationRetention);
        }
        let recent_refresh: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM refresh_job WHERE status = 'succeeded'
             AND finished_at > clock_timestamp() - $1::bigint * INTERVAL '1 second')",
        )
        .bind(i64::from(request.cooldown_seconds))
        .fetch_one(&mut *transaction)
        .await?;
        if recent_refresh {
            return Err(MetaError::RefreshCooldown {
                seconds: request.cooldown_seconds,
            });
        }
        let generation = register_generation(
            &mut transaction,
            request.engine,
            request.snapshot,
            request.tables,
        )
        .await?;
        sqlx::query(
            "INSERT INTO refresh_job (target_generation_id, status) VALUES ($1, 'pending')",
        )
        .bind(generation.id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(generation)
    }

    pub async fn fail_generation(&self, id: i64) -> Result<(), MetaError> {
        let mut transaction = self.pool.begin().await?;
        let failed = sqlx::query(
            "UPDATE generation SET status = 'failed', native_claimed = FALSE
             WHERE id = $1 AND status = 'importing'",
        )
        .bind(id)
        .execute(&mut *transaction)
        .await?;
        if failed.rows_affected() == 1 {
            sqlx::query(
                "UPDATE refresh_job SET status = 'failed', finished_at = now()
                 WHERE target_generation_id = $1 AND status IN ('pending', 'running')",
            )
            .bind(id)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn claim_generation(&self, id: i64) -> Result<(), MetaError> {
        let mut transaction = self.pool.begin().await?;
        let result = sqlx::query(
            "UPDATE generation SET native_claimed = TRUE
             WHERE id = $1 AND status = 'importing' AND NOT native_claimed",
        )
        .bind(id)
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() != 1 {
            return Err(MetaError::NoGeneration);
        }
        sqlx::query(
            "UPDATE refresh_job SET status = 'running', started_at = now()
             WHERE target_generation_id = $1 AND status = 'pending'",
        )
        .bind(id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn activate_generation(&self, id: i64) -> Result<(), MetaError> {
        let mut transaction = self.pool.begin().await?;
        lock_generation_switch(&mut transaction).await?;
        let result = sqlx::query(
            "UPDATE generation SET status = 'active', activated_at = now()
             WHERE id = $1 AND status = 'importing' AND native_claimed",
        )
        .bind(id)
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() != 1 {
            return Err(MetaError::NoGeneration);
        }
        sqlx::query(
            "INSERT INTO audit_event (actor, event_type, payload) VALUES ('bootstrap', 'generation_active', jsonb_build_object('generation_id', $1::bigint))",
        )
        .bind(id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn switch_generation(&self, id: i64, engine: &str) -> Result<(), MetaError> {
        let mut transaction = self.pool.begin().await?;
        lock_generation_switch(&mut transaction).await?;
        let previous: i64 = sqlx::query_scalar(
            "UPDATE generation SET status = 'retiring'
             WHERE status = 'active' AND engine = $1 RETURNING id",
        )
        .bind(engine)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(MetaError::NoGeneration)?;
        let updated = sqlx::query(
            "UPDATE generation SET status = 'active', activated_at = clock_timestamp()
             WHERE id = $1 AND engine = $2 AND status = 'importing' AND native_claimed",
        )
        .bind(id)
        .bind(engine)
        .execute(&mut *transaction)
        .await?;
        let job = sqlx::query(
            "UPDATE refresh_job SET status = 'succeeded', finished_at = clock_timestamp()
             WHERE target_generation_id = $1 AND status = 'running'",
        )
        .bind(id)
        .execute(&mut *transaction)
        .await?;
        if updated.rows_affected() != 1 || job.rows_affected() != 1 {
            return Err(MetaError::InvalidGeneration);
        }
        sqlx::query(
            "INSERT INTO audit_event (actor, event_type, payload)
             VALUES ('refresh', 'generation_switched',
                 jsonb_build_object('generation_id', $1::bigint, 'previous_generation_id', $2::bigint))",
        ).bind(id).bind(previous).execute(&mut *transaction).await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn retirement_candidate(
        &self,
        id: i64,
        engine: &str,
    ) -> Result<Option<BootstrapGeneration>, MetaError> {
        let mut connection = self.pool.begin().await?;
        lock_generation_switch(&mut connection).await?;
        let (generation, status, pinned) = load_retirement(&mut connection, id, engine).await?;
        if status == "retired" {
            return Ok(None);
        }
        if status != "retiring" || !generation.native_claimed {
            return Err(MetaError::InvalidGeneration);
        }
        if pinned {
            return Err(MetaError::GenerationPinned);
        }
        sqlx::query("UPDATE generation SET reclaim_started_at=COALESCE(reclaim_started_at,clock_timestamp()) WHERE id=$1")
            .bind(id).execute(&mut *connection).await?;
        let candidate = load_generation(&mut connection, generation).await?;
        connection.commit().await?;
        Ok(Some(candidate))
    }

    pub async fn complete_retirement(&self, id: i64) -> Result<(), MetaError> {
        let mut transaction = self.pool.begin().await?;
        let result = sqlx::query(
            "UPDATE generation g SET status = 'retired', retired_at = now()
             WHERE g.id = $1 AND g.status = 'retiring'
               AND NOT EXISTS (SELECT 1 FROM branch b WHERE b.generation_id = g.id AND b.status <> 'dropped')
               AND NOT EXISTS (SELECT 1 FROM audit_attempt a WHERE a.generation_id=g.id AND forkget_audit_pending(a))",
        ).bind(id).execute(&mut *transaction).await?;
        if result.rows_affected() != 1 {
            return Err(MetaError::InvalidGeneration);
        }
        sqlx::query(
            "INSERT INTO audit_event (actor, event_type, payload)
             VALUES ('refresh', 'generation_retired', jsonb_build_object('generation_id', $1::bigint))",
        ).bind(id).execute(&mut *transaction).await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn native_catalog(&self, engine: &str) -> Result<NativeCatalog, MetaError> {
        let mut connection = self.pool.acquire().await?;
        let registered = sqlx::query_as::<_, Generation>(
            "SELECT id, engine, schema_name, native_claimed FROM generation
             WHERE engine = $1 AND status IN ('active', 'retiring') ORDER BY id",
        )
        .bind(engine)
        .fetch_all(&mut *connection)
        .await?;
        let mut generations = Vec::with_capacity(registered.len());
        for entry in registered {
            generations.push(load_generation(&mut connection, entry).await?);
        }
        let materialized = sqlx::query_as::<_, (i64, i64, bool, bool, bool)>(
            "SELECT b.id, b.generation_id, b.status = 'active', b.uses_mysql_shared_schema, b.audit_witness_ready
             FROM branch b
             JOIN generation g ON b.generation_id = g.id
             WHERE g.engine = $1 AND g.status IN ('active', 'retiring')
               AND b.layout = 'native_copy' AND b.native_claimed AND b.status <> 'dropped'",
        )
        .bind(engine)
        .fetch_all(&mut *connection)
        .await?;
        let branches = materialized
            .into_iter()
            .map(
                |(id, generation_id, grants_required, shared, audit_witness_ready)| {
                    Ok(NativeBranch {
                        target: write_target(engine, id, shared)?,
                        generation_id,
                        grants_required,
                        audit_witness_ready,
                    })
                },
            )
            .collect::<Result<Vec<_>, MetaError>>()?;
        Ok(NativeCatalog {
            generations,
            branches,
        })
    }

    pub async fn generation_tables(
        &self,
        id: i64,
        engine: &str,
    ) -> Result<Vec<CatalogEntry>, MetaError> {
        let mut connection = self.pool.acquire().await?;
        let ready: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM generation WHERE id = $1 AND engine = $2
             AND status IN ('active', 'retiring'))",
        )
        .bind(id)
        .bind(engine)
        .fetch_one(&mut *connection)
        .await?;
        if !ready {
            return Err(MetaError::NoGeneration);
        }
        load_tables(&mut connection, id).await
    }

    pub async fn resolve(&self, principal: &str, name: &str) -> Result<BranchBinding, MetaError> {
        self.resolve_branch(principal, Some(name), None, None).await
    }

    pub async fn resolve_by_id(
        &self,
        principal: &str,
        id: i64,
    ) -> Result<BranchBinding, MetaError> {
        self.resolve_branch(principal, None, Some(id), None).await
    }

    pub(crate) async fn resolve_for_replay(
        &self,
        principal: &str,
        id: i64,
        job: i64,
    ) -> Result<BranchBinding, MetaError> {
        self.resolve_branch(principal, None, Some(id), Some(job))
            .await
    }

    async fn resolve_branch(
        &self,
        principal: &str,
        name: Option<&str>,
        id: Option<i64>,
        replay_job: Option<i64>,
    ) -> Result<BranchBinding, MetaError> {
        let mut transaction = self.pool.begin().await?;
        let (
            id,
            generation_id,
            engine,
            layout,
            name,
            class,
            snapshot,
            shared,
            expires_at,
            access,
            read_strategy,
            audit_witness_ready,
        ) = sqlx::query_as::<
            _,
            (
                i64,
                i64,
                String,
                String,
                String,
                String,
                String,
                bool,
                i64,
                String,
                String,
                bool,
            ),
        >(
            "SELECT b.id, b.generation_id, g.engine, b.layout, b.name, b.class, g.snapshot,
                        b.uses_mysql_shared_schema,
                        floor(extract(epoch FROM b.expires_at))::bigint, b.access, b.read_strategy, b.audit_witness_ready
             FROM branch b JOIN generation g ON g.id = b.generation_id
             WHERE b.created_by = $1 AND (b.name = $2 OR b.id = $3)
               AND b.status = 'active' AND b.expires_at > clock_timestamp()
               AND (NOT b.capture_active OR $2::text IS NULL)
               AND g.status IN ('active', 'retiring')
               AND (NOT EXISTS (SELECT 1 FROM replay_job j WHERE j.branch_id = b.id AND j.state <> 'verified')
                 OR EXISTS (SELECT 1 FROM replay_job j WHERE j.branch_id = b.id AND j.id = $4 AND j.principal = $1 AND j.state IN ('running','verifying')))",
        )
        .bind(principal)
        .bind(name)
        .bind(id)
        .bind(replay_job)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(MetaError::BranchUnavailable)?;
        let tables = load_tables(&mut transaction, generation_id).await?;
        let deployment_id = replay_deployment_id(&mut transaction).await?;
        let access = BranchAccess::parse(&access).ok_or(MetaError::InvalidCatalog)?;
        let layout = BranchLayout::parse(&layout).ok_or(MetaError::InvalidCatalog)?;
        let read_strategy = ReadStrategy::parse(&read_strategy).ok_or(MetaError::InvalidCatalog)?;
        let snapshot_manifest =
            crate::snapshot::load_manifest(&mut transaction, generation_id).await?;
        let write_schema = (layout == BranchLayout::NativeCopy)
            .then(|| write_target(&engine, id, shared).map(|target| target.schema().to_owned()))
            .transpose()?;
        transaction.commit().await?;
        Ok(BranchBinding {
            id,
            generation_id,
            engine,
            name,
            class: parse_branch_class(&class)?,
            access,
            layout,
            read_strategy,
            audit_witness_ready,
            // The proxy enforces the fork-time TTL locally on every command.
            expires_at,
            default_schema: snapshot_manifest.as_ref().map_or_else(
                || DEFAULT_SCHEMA.to_owned(),
                |manifest| manifest.logical_schema.clone(),
            ),
            tables,
            write_schema,
            snapshot_manifest,
            replay_origin: Some(ReplayOrigin {
                deployment_id,
                generation_id,
                snapshot,
            }),
        })
    }
}

fn write_target(engine: &str, id: i64, shared: bool) -> Result<WriteTarget, MetaError> {
    // Only MySQL-family engines use the shared fgwrite namespace.
    if shared && !matches!(engine, "mysql" | "tidb") {
        return Err(MetaError::InvalidCatalog);
    }
    Ok(WriteTarget::for_branch(id, shared))
}

pub(crate) async fn replay_deployment_id(
    connection: &mut PgConnection,
) -> Result<String, MetaError> {
    sqlx::query_scalar("SELECT id::text FROM replay_deployment WHERE singleton")
        .fetch_one(connection)
        .await
        .map_err(Into::into)
}

pub(crate) fn parse_branch_class(value: &str) -> Result<BranchClass, MetaError> {
    match value {
        "dev" => Ok(BranchClass::Dev),
        "ci" => Ok(BranchClass::Ci),
        "agent" => Ok(BranchClass::Agent),
        "staging" => Ok(BranchClass::Staging),
        _ => Err(MetaError::InvalidCatalog),
    }
}

pub(crate) async fn lock_generation_pin(connection: &mut PgConnection) -> Result<(), MetaError> {
    sqlx::query("SELECT pg_advisory_xact_lock_shared($1)")
        .bind(GENERATION_SWITCH_LOCK)
        .execute(connection)
        .await?;
    Ok(())
}

async fn lock_generation_switch(connection: &mut PgConnection) -> Result<(), MetaError> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(GENERATION_SWITCH_LOCK)
        .execute(connection)
        .await?;
    Ok(())
}

async fn load_retirement(
    connection: &mut PgConnection,
    id: i64,
    engine: &str,
) -> Result<(Generation, String, bool), MetaError> {
    let (schema_name, native_claimed, status, pinned) =
        sqlx::query_as::<_, (String, bool, String, bool)>(
            "SELECT g.schema_name, g.native_claimed, g.status, EXISTS (
             SELECT 1 FROM branch b WHERE b.generation_id = g.id AND b.status <> 'dropped') OR EXISTS (
             SELECT 1 FROM audit_attempt a WHERE a.generation_id=g.id AND forkget_audit_pending(a))
         FROM generation g WHERE g.id = $1 AND g.engine = $2",
        )
        .bind(id)
        .bind(engine)
        .fetch_optional(connection)
        .await?
        .ok_or(MetaError::InvalidGeneration)?;
    Ok((
        Generation {
            id,
            engine: engine.to_owned(),
            schema_name,
            native_claimed,
        },
        status,
        pinned,
    ))
}

async fn register_generation(
    connection: &mut PgConnection,
    engine: &str,
    snapshot: &str,
    tables: &[SeedTable],
) -> Result<BootstrapGeneration, MetaError> {
    let generation = sqlx::query_as::<_, Generation>(
        "INSERT INTO generation (engine, status, snapshot) VALUES ($1, 'importing', $2)
         RETURNING id, engine, schema_name, native_claimed",
    )
    .bind(engine)
    .bind(snapshot)
    .fetch_one(&mut *connection)
    .await?;
    // MongoDB delta collections share the generation database so branch
    // reads merge base and delta with same-database aggregation stages
    // rather than cross-database joins; SQL engines share forkget_delta.
    let delta_schema = if engine == "mongodb" {
        generation.schema_name.clone()
    } else {
        DELTA_SCHEMA.to_owned()
    };
    for table in tables {
        register_table(connection, generation.id, &delta_schema, table).await?;
    }
    load_generation(connection, generation).await
}

async fn register_table(
    connection: &mut PgConnection,
    generation_id: i64,
    delta_schema: &str,
    table: &SeedTable,
) -> Result<(), MetaError> {
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO catalog_table (generation_id, logical_schema, logical_table, base_table, delta_schema, generated_key, baseline_rows) VALUES ($1, $2, $3, $3, $4, $5, $6) RETURNING id",
    )
    .bind(generation_id)
    .bind(DEFAULT_SCHEMA)
    .bind(table.name)
    .bind(delta_schema)
    .bind(table.generated_key)
    .bind(table.baseline_rows)
    .fetch_one(&mut *connection)
    .await?;
    for (offset, column) in table.columns.iter().enumerate() {
        let ordinal = i32::try_from(offset + 1).map_err(|_| MetaError::InvalidCatalog)?;
        sqlx::query(
            "INSERT INTO catalog_column (table_id, ordinal, name, data_type, collation_name, is_nullable, key_ordinal) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(id)
        .bind(ordinal)
        .bind(column.name)
        .bind(column.type_name)
        .bind(column.collation)
        .bind(column.nullable)
        .bind(column.primary_key_ordinal.map(i32::from))
        .execute(&mut *connection)
        .await?;
    }
    Ok(())
}

async fn load_generation(
    connection: &mut PgConnection,
    generation: Generation,
) -> Result<BootstrapGeneration, MetaError> {
    Ok(BootstrapGeneration {
        id: generation.id,
        engine: generation.engine,
        schema: generation.schema_name,
        native_claimed: generation.native_claimed,
        tables: load_tables(connection, generation.id).await?,
    })
}

pub(crate) async fn load_tables(
    connection: &mut PgConnection,
    generation_id: i64,
) -> Result<Vec<CatalogEntry>, MetaError> {
    let rows = sqlx::query_as::<_, RegisteredTable>(
        "SELECT id, logical_schema, logical_table, base_schema, base_table, delta_schema, delta_table, generated_key, baseline_rows FROM catalog_table WHERE generation_id = $1 ORDER BY id",
    )
    .bind(generation_id)
    .fetch_all(&mut *connection)
    .await?;
    if rows.is_empty() {
        return Err(MetaError::InvalidCatalog);
    }
    let columns = sqlx::query_as::<_, RegisteredColumn>(
        "SELECT c.table_id,c.ordinal,c.name,c.data_type,c.is_nullable,c.key_ordinal FROM catalog_column c JOIN catalog_table t ON t.id=c.table_id WHERE t.generation_id=$1 ORDER BY c.table_id,c.ordinal",
    ).bind(generation_id).fetch_all(connection).await?;
    let mut grouped = group_columns(columns);
    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        let columns = validate_columns(grouped.remove(&row.id).unwrap_or_default())?;
        if let Some(key) = &row.generated_key
            && !is_generated_key(&columns, key)
        {
            return Err(MetaError::InvalidCatalog);
        }
        entries.push(CatalogEntry {
            id: row.id,
            logical_schema: row.logical_schema,
            logical_table: row.logical_table,
            base_schema: row.base_schema,
            base_table: row.base_table,
            delta_schema: row.delta_schema,
            delta_table: row.delta_table,
            columns,
            generated_key: row.generated_key,
            baseline_rows: row.baseline_rows,
        });
    }
    if !grouped.is_empty() {
        return Err(MetaError::InvalidCatalog);
    }
    Ok(entries)
}

fn group_columns(rows: Vec<RegisteredColumn>) -> BTreeMap<i64, Vec<RegisteredColumn>> {
    let mut grouped: BTreeMap<i64, Vec<RegisteredColumn>> = BTreeMap::new();
    for row in rows {
        grouped.entry(row.table_id).or_default().push(row);
    }
    grouped
}

fn is_generated_key(columns: &[CatalogColumn], key: &str) -> bool {
    let mut primary = columns
        .iter()
        .filter(|column| column.primary_key_ordinal.is_some());
    primary.next().is_some_and(|column| {
        column.name == key && column.type_name == "bigint" && !column.nullable
    }) && primary.next().is_none()
}

fn validate_columns(rows: Vec<RegisteredColumn>) -> Result<Vec<CatalogColumn>, MetaError> {
    // MongoDB tables register no columns: the document `_id` is the natural
    // key, so document catalogs legitimately have no registered SQL columns.
    let mut key_ordinals: Vec<i32> = rows.iter().filter_map(|row| row.key_ordinal).collect();
    key_ordinals.sort_unstable();
    if !key_ordinals.is_empty() && !contiguous(key_ordinals.into_iter()) {
        return Err(MetaError::InvalidCatalog);
    }
    if !contiguous(rows.iter().map(|row| row.ordinal)) {
        return Err(MetaError::InvalidCatalog);
    }
    rows.into_iter()
        .map(|row| {
            let key = row.key_ordinal.map(u16::try_from).transpose();
            Ok(CatalogColumn {
                name: row.name,
                type_name: row.data_type,
                nullable: row.is_nullable,
                primary_key_ordinal: key.map_err(|_| MetaError::InvalidCatalog)?,
            })
        })
        .collect()
}

fn contiguous(values: impl Iterator<Item = i32>) -> bool {
    values
        .enumerate()
        .all(|(offset, value)| usize::try_from(value).is_ok_and(|ordinal| ordinal == offset + 1))
}

#[cfg(test)]
mod tests;
