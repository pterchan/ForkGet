use fg_protocol_common::{ArtifactHeader, BranchClass, GENERATED_ID_MAX, GENERATED_ID_START};
use serde::Serialize;
use sqlx::{FromRow, PgConnection};

use crate::{Branch, BranchMode, ForkBranch, MetaError, Metadata};

#[derive(FromRow, Serialize)]
pub struct ReplayJob {
    pub id: i64,
    pub branch_id: i64,
    pub principal: String,
    pub generation_id: i64,
    pub state: String,
    pub failure_code: Option<String>,
}

#[derive(Serialize)]
pub struct ReplayStart {
    pub job: ReplayJob,
    pub branch: Branch,
}

impl Metadata {
    pub async fn replay_preflight(&self, header: &ArtifactHeader) -> Result<(), MetaError> {
        let mut tx = self.pool.begin().await?;
        crate::catalog::lock_generation_pin(&mut tx).await?;
        preflight(&mut tx, header).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn start_replay(
        &self,
        principal: &str,
        name: &str,
        header: &ArtifactHeader,
    ) -> Result<ReplayStart, MetaError> {
        let mut tx = self.pool.begin().await?;
        crate::catalog::lock_generation_pin(&mut tx).await?;
        preflight(&mut tx, header).await?;
        let branch = crate::lifecycle::fork_in(
            &mut tx,
            &ForkBranch {
                engine: &header.engine,
                principal,
                name,
                ttl_seconds: crate::lifecycle::MAX_TTL_SECONDS,
                mode: BranchMode::NativeWrite,
                class: BranchClass::Dev,
                expected_generation: Some(&header.origin),
            },
            principal,
        )
        .await?;
        let job = sqlx::query_as("INSERT INTO replay_job (branch_id, principal, generation_id) VALUES ($1, $2, $3) RETURNING id, branch_id, principal, generation_id, state, failure_code")
            .bind(branch.id).bind(principal).bind(branch.generation_id).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        Ok(ReplayStart { job, branch })
    }

    pub async fn replay_job(&self, principal: &str, job: i64) -> Result<ReplayJob, MetaError> {
        sqlx::query_as("SELECT id, branch_id, principal, generation_id, state, failure_code FROM replay_job WHERE id = $1 AND principal = $2")
            .bind(job).bind(principal).fetch_optional(&self.pool).await?.ok_or(MetaError::BranchUnavailable)
    }

    pub async fn claim_replay(
        &self,
        principal: &str,
        job: i64,
        native_id: u32,
        verify_only: bool,
    ) -> Result<fg_protocol_common::BranchBinding, MetaError> {
        if native_id == 0 {
            return Err(MetaError::InvalidPolicy);
        }
        let branch: i64 = sqlx::query_scalar(
            "UPDATE replay_job SET state = CASE WHEN $4 THEN 'verifying' ELSE 'running' END,
                 native_session_id = $3, session_id = NULL, updated_at = clock_timestamp()
             WHERE id = $1 AND principal = $2
               AND (($4 AND state IN ('unknown','failed')) OR (NOT $4 AND state = 'staged'))
             RETURNING branch_id",
        )
        .bind(job)
        .bind(principal)
        .bind(i64::from(native_id))
        .bind(verify_only)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(MetaError::BranchUnavailable)?;
        self.resolve_for_replay(principal, branch, job).await
    }

    pub async fn bind_replay_session(
        &self,
        principal: &str,
        job: i64,
        native_id: u32,
        session_id: &str,
    ) -> Result<(), MetaError> {
        let changed = sqlx::query("UPDATE replay_job SET session_id = $4 WHERE id = $1 AND principal = $2 AND native_session_id = $3 AND session_id IS NULL AND state IN ('running','verifying')")
            .bind(job).bind(principal).bind(i64::from(native_id)).bind(session_id).execute(&self.pool).await?;
        if changed.rows_affected() != 1 {
            return Err(MetaError::BranchUnavailable);
        }
        Ok(())
    }

    pub async fn validate_replay_session(
        &self,
        principal: &str,
        job: i64,
        native_id: u32,
        session: &str,
    ) -> Result<(), MetaError> {
        let valid: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM replay_job j JOIN branch b ON b.id=j.branch_id WHERE j.id=$1 AND j.principal=$2 AND j.native_session_id=$3 AND j.session_id=$4 AND j.state='running' AND b.status='active' AND b.expires_at>clock_timestamp())")
            .bind(job).bind(principal).bind(i64::from(native_id)).bind(session).fetch_one(&self.pool).await?;
        if !valid {
            return Err(MetaError::BranchUnavailable);
        }
        Ok(())
    }

    pub async fn uncertain_replay(
        &self,
        principal: &str,
        job: i64,
        native_id: u32,
        session: &str,
    ) -> Result<(), MetaError> {
        let changed = sqlx::query("UPDATE replay_job SET state='unknown',updated_at=clock_timestamp() WHERE id=$1 AND principal=$2 AND native_session_id=$3 AND session_id=$4 AND state='running'")
            .bind(job).bind(principal).bind(i64::from(native_id)).bind(session).execute(&self.pool).await?;
        if changed.rows_affected() != 1 {
            return Err(MetaError::BranchUnavailable);
        }
        Ok(())
    }

    pub async fn recover_replays_on_start(&self) -> Result<(), MetaError> {
        sqlx::query("UPDATE replay_job SET state='unknown',failure_code='control_restarted',updated_at=clock_timestamp() WHERE state IN ('running','verifying')").execute(&self.pool).await?;
        Ok(())
    }

    pub async fn replay_cleanup_jobs(&self, engine: &str) -> Result<Vec<i64>, MetaError> {
        sqlx::query_scalar("SELECT j.id FROM replay_job j JOIN branch b ON b.id=j.branch_id JOIN generation g ON g.id=j.generation_id WHERE g.engine=$1 AND NOT j.artifact_cleaned AND (b.status='dropped' OR j.state='verified') ORDER BY j.id LIMIT 100")
            .bind(engine).fetch_all(&self.pool).await.map_err(Into::into)
    }

    pub async fn replay_artifact_cleaned(&self, job: i64) -> Result<(), MetaError> {
        sqlx::query("UPDATE replay_job SET artifact_cleaned=TRUE WHERE id=$1 AND (state='verified' OR EXISTS (SELECT 1 FROM branch WHERE id=replay_job.branch_id AND status='dropped'))")
            .bind(job).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn advance_replay_ids(
        &self,
        principal: &str,
        job: i64,
        session: &str,
        table: i64,
        highest: i64,
    ) -> Result<(), MetaError> {
        if !(GENERATED_ID_START..=GENERATED_ID_MAX).contains(&highest) {
            return Err(MetaError::InvalidAllocation);
        }
        let mut tx = self.pool.begin().await?;
        let branch: i64 = sqlx::query_scalar(
            "SELECT j.branch_id FROM replay_job j JOIN branch b ON b.id = j.branch_id
             JOIN catalog_table c ON c.generation_id = j.generation_id
             WHERE j.id = $1 AND j.principal = $2 AND j.session_id = $3 AND j.state = 'running'
               AND c.id = $4 AND c.generated_key IS NOT NULL AND b.status = 'active'
               AND b.expires_at > clock_timestamp() FOR SHARE OF b",
        )
        .bind(job)
        .bind(principal)
        .bind(session)
        .bind(table)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(MetaError::BranchUnavailable)?;
        sqlx::query("INSERT INTO generated_id_cursor (branch_id, table_id, next_id) VALUES ($1, $2, $3) ON CONFLICT (branch_id,table_id) DO UPDATE SET next_id = GREATEST(generated_id_cursor.next_id, EXCLUDED.next_id)")
            .bind(branch).bind(table).bind(highest + 1).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn finish_replay(
        &self,
        principal: &str,
        job: i64,
        state: &str,
        code: Option<&str>,
    ) -> Result<ReplayJob, MetaError> {
        if !matches!(state, "verified" | "failed" | "unknown") {
            return Err(MetaError::InvalidPolicy);
        }
        let result = sqlx::query_as("UPDATE replay_job SET state = $3, failure_code = $4, updated_at = clock_timestamp() WHERE id = $1 AND principal = $2 AND state <> 'verified' RETURNING id, branch_id, principal, generation_id, state, failure_code")
            .bind(job).bind(principal).bind(state).bind(code).fetch_optional(&self.pool).await?;
        match result {
            Some(job) => Ok(job),
            None => self.replay_job(principal, job).await,
        }
    }
}

async fn preflight(
    connection: &mut PgConnection,
    header: &ArtifactHeader,
) -> Result<(), MetaError> {
    header.validate().map_err(|_| MetaError::InvalidCatalog)?;
    header
        .require_replay_source()
        .map_err(|_| MetaError::WriteUnavailable)?;
    let available: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM generation WHERE id = $1 AND engine = $2 AND snapshot = $3 AND status IN ('active','retiring') AND reclaim_started_at IS NULL)")
        .bind(header.origin.generation_id).bind(&header.engine).bind(&header.origin.snapshot).fetch_one(&mut *connection).await?;
    if !available
        || crate::catalog::replay_deployment_id(connection).await? != header.origin.deployment_id
    {
        return Err(MetaError::ReplayMismatch);
    }
    let tables = crate::catalog::load_tables(connection, header.origin.generation_id).await?;
    if tables.len() != header.tables.len()
        || tables.iter().zip(&header.tables).any(|(actual, given)| {
            actual.id != given.id
                || actual.logical_schema != given.schema
                || actual.logical_table != given.table
                || actual.generated_key != given.generated_key
                || actual.columns != given.columns
        })
    {
        return Err(MetaError::InvalidCatalog);
    }
    let manifest = crate::snapshot::load_manifest(connection, header.origin.generation_id).await?;
    if manifest != header.manifest {
        return Err(MetaError::InvalidCatalog);
    }
    Ok(())
}
