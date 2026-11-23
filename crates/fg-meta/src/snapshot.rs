//! User snapshot registration shares the existing immutable-generation catalog.

use fg_protocol_common::{CatalogEntry, SnapshotManifest};
use serde::Serialize;
use sqlx::{FromRow, PgConnection};

use crate::{BootstrapGeneration, MetaError, Metadata};

#[derive(FromRow, Serialize)]
pub struct SnapshotJob {
    pub id: i64,
    pub generation_id: Option<i64>,
    pub snapshot_name: String,
    pub engine: String,
    pub phase: String,
    pub failure_reason: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub storage_preflight: serde_json::Value,
}

impl Metadata {
    pub async fn record_snapshot_storage_preflight(
        &self,
        generation: i64,
        value: &serde_json::Value,
    ) -> Result<(), MetaError> {
        sqlx::query("UPDATE snapshot_job SET storage_preflight=$2::jsonb,updated_at=clock_timestamp() WHERE generation_id=$1")
            .bind(generation).bind(value.to_string()).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn record_branch_storage_preflight(
        &self,
        branch: i64,
        value: &serde_json::Value,
    ) -> Result<(), MetaError> {
        sqlx::query("UPDATE branch SET storage_preflight=$2::jsonb WHERE id=$1")
            .bind(branch)
            .bind(value.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn snapshot_generation_status(&self, generation: i64) -> Result<String, MetaError> {
        sqlx::query_scalar(
            "SELECT status FROM generation WHERE id=$1 AND snapshot_manifest IS NOT NULL",
        )
        .bind(generation)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(MetaError::InvalidGeneration)
    }

    pub async fn snapshot_native_claimed(&self, generation: i64) -> Result<bool, MetaError> {
        sqlx::query_scalar(
            "SELECT native_claimed FROM generation WHERE id=$1 AND snapshot_manifest IS NOT NULL",
        )
        .bind(generation)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(MetaError::InvalidGeneration)
    }

    pub async fn snapshot_registered_tables(
        &self,
        generation: i64,
        engine: &str,
    ) -> Result<Vec<CatalogEntry>, MetaError> {
        let mut connection = self.pool.acquire().await?;
        let owned:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM generation WHERE id=$1 AND engine=$2 AND snapshot_manifest IS NOT NULL)")
            .bind(generation).bind(engine).fetch_one(&mut*connection).await?;
        if !owned {
            return Err(MetaError::InvalidGeneration);
        }
        crate::catalog::load_tables(&mut connection, generation).await
    }

    pub async fn snapshot_manifest(
        &self,
        generation: i64,
    ) -> Result<Option<SnapshotManifest>, MetaError> {
        let mut connection = self.pool.acquire().await?;
        load_manifest(&mut connection, generation).await
    }

    pub async fn allocate_snapshot(
        &self,
        manifest: &SnapshotManifest,
        cooldown: u32,
    ) -> Result<BootstrapGeneration, MetaError> {
        let order = manifest.validate().map_err(|_| MetaError::InvalidCatalog)?;
        let mut tx = self.pool.begin().await?;
        crate::catalog::lock_generation_pin(&mut tx).await?;
        let live: i64 = sqlx::query_scalar("SELECT count(*) FROM generation WHERE status IN ('importing','active','retiring') OR (status='failed' AND native_claimed)")
            .fetch_one(&mut *tx).await?;
        if live >= crate::catalog::LIVE_GENERATION_LIMIT {
            return Err(MetaError::GenerationRetention);
        }
        let wrong_engine: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM generation WHERE status='active' AND engine <> $1)",
        )
        .bind(&manifest.engine)
        .fetch_one(&mut *tx)
        .await?;
        if wrong_engine {
            return Err(MetaError::InvalidGeneration);
        }
        let recent: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM refresh_job WHERE status='succeeded' AND finished_at > clock_timestamp()-$1::bigint*INTERVAL '1 second')")
            .bind(i64::from(cooldown)).fetch_one(&mut *tx).await?;
        if recent {
            return Err(MetaError::RefreshCooldown { seconds: cooldown });
        }
        let json = serde_json::to_string(manifest).map_err(|_| MetaError::InvalidCatalog)?;
        let id: i64 = sqlx::query_scalar("INSERT INTO generation(engine,status,snapshot,snapshot_manifest) VALUES($1,'importing',$2,$3::jsonb) RETURNING id")
            .bind(&manifest.engine).bind(&manifest.name).bind(json).fetch_one(&mut *tx).await?;
        if let Some(document) = &manifest.document {
            for collection in &document.collections {
                let definition =
                    serde_json::to_string(collection).map_err(|_| MetaError::InvalidCatalog)?;
                sqlx::query("INSERT INTO catalog_table(generation_id,logical_schema,logical_table,base_table,delta_schema,baseline_rows,definition) VALUES($1,$2,$3,$3,$4,$5,$6::jsonb)")
                    .bind(id).bind(&manifest.logical_schema).bind(&collection.name)
                    .bind(format!("fg_g{id}")).bind(collection.rows).bind(definition)
                    .execute(&mut *tx).await?;
            }
        }
        for index in order {
            let table = &manifest.tables[index];
            let generated = table.generated_key.as_deref();
            let definition = serde_json::to_string(table).map_err(|_| MetaError::InvalidCatalog)?;
            let table_id: i64 = sqlx::query_scalar("INSERT INTO catalog_table(generation_id,logical_schema,logical_table,base_table,generated_key,baseline_rows,definition) VALUES($1,$2,$3,$3,$4,$5,$6::jsonb) RETURNING id")
                .bind(id).bind(&manifest.logical_schema).bind(&table.name).bind(generated).bind(table.rows).bind(definition)
                .fetch_one(&mut *tx).await?;
            for (ordinal, column) in table.columns.iter().enumerate() {
                let key = table
                    .primary_key
                    .iter()
                    .position(|name| name == &column.name)
                    .map(|key| key as i32 + 1);
                sqlx::query("INSERT INTO catalog_column(table_id,ordinal,name,data_type,collation_name,is_nullable,key_ordinal) VALUES($1,$2,$3,$4,$5,$6,$7)")
                    .bind(table_id).bind(ordinal as i32 + 1).bind(&column.name).bind(column.sql_type.native_name(&manifest.engine))
                    .bind(&column.collation).bind(column.nullable).bind(key).execute(&mut *tx).await?;
            }
        }
        sqlx::query("INSERT INTO snapshot_job(generation_id,snapshot_name,engine,phase) VALUES($1,$2,$3,'allocated')")
            .bind(id).bind(&manifest.name).bind(&manifest.engine).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO refresh_job(target_generation_id,status) VALUES($1,'pending')")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        let tables = crate::catalog::load_tables(&mut tx, id).await?;
        tx.commit().await?;
        Ok(BootstrapGeneration {
            id,
            engine: manifest.engine.clone(),
            schema: format!("fg_g{id}"),
            native_claimed: false,
            tables,
        })
    }

    pub async fn snapshot_phase(
        &self,
        generation: i64,
        phase: &str,
        reason: Option<&str>,
    ) -> Result<(), MetaError> {
        if !matches!(
            phase,
            "allocated"
                | "staging"
                | "loading"
                | "verifying"
                | "active"
                | "cleanup_pending"
                | "failed"
        ) {
            return Err(MetaError::InvalidCatalog);
        }
        sqlx::query("UPDATE snapshot_job SET phase=$2,failure_reason=$3,updated_at=clock_timestamp() WHERE generation_id=$1")
            .bind(generation).bind(phase).bind(reason).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn snapshot_jobs(&self) -> Result<Vec<SnapshotJob>, MetaError> {
        sqlx::query_as("SELECT id,generation_id,snapshot_name,engine,phase,failure_reason,floor(extract(epoch FROM created_at))::bigint AS created_at,floor(extract(epoch FROM updated_at))::bigint AS updated_at,storage_preflight FROM snapshot_job ORDER BY id DESC LIMIT 100")
            .fetch_all(&self.pool).await.map_err(Into::into)
    }

    pub async fn snapshot_job(&self, id: i64) -> Result<Option<SnapshotJob>, MetaError> {
        sqlx::query_as("SELECT id,generation_id,snapshot_name,engine,phase,failure_reason,floor(extract(epoch FROM created_at))::bigint AS created_at,floor(extract(epoch FROM updated_at))::bigint AS updated_at,storage_preflight FROM snapshot_job WHERE id=$1")
            .bind(id).fetch_optional(&self.pool).await.map_err(Into::into)
    }

    pub async fn finish_snapshot(&self, generation: i64, engine: &str) -> Result<(), MetaError> {
        if self.active_generation_id(engine).await?.is_some() {
            self.switch_generation(generation, engine).await?;
        } else {
            self.activate_generation(generation).await?;
            sqlx::query("UPDATE refresh_job SET status='succeeded',finished_at=clock_timestamp() WHERE target_generation_id=$1 AND status='running'")
                .bind(generation).execute(&self.pool).await?;
        }
        self.snapshot_phase(generation, "active", None).await
    }
}

pub(crate) async fn load_manifest(
    connection: &mut PgConnection,
    generation: i64,
) -> Result<Option<SnapshotManifest>, MetaError> {
    let json: Option<String> =
        sqlx::query_scalar("SELECT snapshot_manifest::text FROM generation WHERE id=$1")
            .bind(generation)
            .fetch_optional(connection)
            .await?
            .flatten();
    json.map(|value| serde_json::from_str(&value).map_err(|_| MetaError::InvalidCatalog))
        .transpose()
}
