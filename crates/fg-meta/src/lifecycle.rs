use fg_protocol_common::{BranchAccess, BranchClass, BranchLayout, ReadStrategy, ReplayOrigin};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgConnection};

use crate::{MetaError, Metadata};

pub const MAX_TTL_SECONDS: u32 = 24 * 60 * 60;
const WRITE_CAPACITY: i64 = 16;
const WRITE_CAPACITY_LOCK: i64 = 0x4647_0000_0000_0003;
const EXPIRY_BATCH_SIZE: i64 = 64;

const RETURNED_BRANCH: &str = "id, name, class, generation_id, created_by, floor(extract(epoch FROM expires_at))::bigint AS expires_at, status, mode, access, layout, read_strategy";
const LIFECYCLE_BRANCH: &str =
    "b.id, b.generation_id, g.snapshot, b.native_claimed, b.layout = 'native_copy' AS is_native,
     b.uses_mysql_shared_schema";

#[derive(FromRow, Serialize)]
pub struct Branch {
    pub id: i64,
    pub name: String,
    pub class: String,
    pub generation_id: i64,
    pub created_by: String,
    pub expires_at: i64,
    pub status: String,
    pub mode: String,
    pub access: String,
    pub layout: String,
    pub read_strategy: String,
}

#[derive(Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum BranchMode {
    #[default]
    ReadOnly,
    NativeWrite,
}

impl BranchMode {
    pub const fn access(self) -> BranchAccess {
        match self {
            Self::ReadOnly => BranchAccess::ReadOnly,
            Self::NativeWrite => BranchAccess::ReadWrite,
        }
    }

    pub const fn layout(self) -> BranchLayout {
        match self {
            Self::ReadOnly => BranchLayout::SparseDelta,
            Self::NativeWrite => BranchLayout::NativeCopy,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::NativeWrite => "native_write",
        }
    }

    const fn initial_status(self) -> &'static str {
        match self {
            Self::ReadOnly => "active",
            Self::NativeWrite => "provisioning",
        }
    }
}

#[derive(FromRow)]
pub struct LifecycleBranch {
    pub id: i64,
    pub generation_id: i64,
    pub snapshot: String,
    pub native_claimed: bool,
    pub is_native: bool,
    pub uses_mysql_shared_schema: bool,
}

pub struct ForkBranch<'a> {
    pub engine: &'a str,
    pub principal: &'a str,
    pub name: &'a str,
    pub ttl_seconds: u32,
    pub mode: BranchMode,
    pub class: BranchClass,
    pub expected_generation: Option<&'a ReplayOrigin>,
}

impl Metadata {
    pub async fn fork(&self, request: ForkBranch<'_>) -> Result<Branch, MetaError> {
        let mut transaction = self.pool.begin().await?;
        let branch = fork_in(&mut transaction, &request, request.principal).await?;
        transaction.commit().await?;
        Ok(branch)
    }

    pub async fn list(&self, principal: &str) -> Result<Vec<Branch>, MetaError> {
        let statement =
            format!("SELECT {RETURNED_BRANCH} FROM branch WHERE created_by = $1 ORDER BY id");
        sqlx::query_as(&statement)
            .bind(principal)
            .fetch_all(&self.pool)
            .await
            .map_err(Into::into)
    }

    pub async fn detail(&self, principal: &str, id: i64) -> Result<Branch, MetaError> {
        let statement =
            format!("SELECT {RETURNED_BRANCH} FROM branch WHERE id = $1 AND created_by = $2");
        sqlx::query_as(&statement)
            .bind(id)
            .bind(principal)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(MetaError::BranchUnavailable)
    }

    pub async fn is_active(
        &self,
        principal: &str,
        id: i64,
        engine: &str,
    ) -> Result<bool, MetaError> {
        sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM branch b JOIN generation g ON g.id = b.generation_id
             WHERE b.id = $1 AND b.created_by = $2 AND b.status = 'active'
             AND b.expires_at > clock_timestamp() AND g.engine = $3
             AND g.status IN ('active', 'retiring'))",
        )
        .bind(id)
        .bind(principal)
        .bind(engine)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn begin_drop(&self, principal: &str, id: i64) -> Result<Branch, MetaError> {
        let mut transaction = self.pool.begin().await?;
        let branch = begin_drop_in(&mut transaction, principal, id, principal).await?;
        transaction.commit().await?;
        Ok(branch)
    }

    pub async fn dropping_branches(&self, engine: &str) -> Result<Vec<LifecycleBranch>, MetaError> {
        let statement = format!(
            "SELECT {LIFECYCLE_BRANCH} FROM branch b JOIN generation g ON g.id = b.generation_id
             WHERE b.status = 'dropping' AND g.engine = $1 ORDER BY b.id"
        );
        sqlx::query_as(&statement)
            .bind(engine)
            .fetch_all(&self.pool)
            .await
            .map_err(Into::into)
    }

    pub async fn provisioning_branches(&self, engine: &str) -> Result<Vec<i64>, MetaError> {
        sqlx::query_scalar(
            "SELECT b.id FROM branch b JOIN generation g ON g.id = b.generation_id
             WHERE b.status = 'provisioning' AND b.expires_at > clock_timestamp()
             AND g.engine = $1 ORDER BY b.id",
        )
        .bind(engine)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn provisioning_branch(
        &self,
        id: i64,
        engine: &str,
    ) -> Result<Option<LifecycleBranch>, MetaError> {
        let statement = format!(
            "SELECT {LIFECYCLE_BRANCH} FROM branch b JOIN generation g ON g.id = b.generation_id
             WHERE b.id = $1 AND g.engine = $2 AND b.status = 'provisioning'
             AND b.expires_at > clock_timestamp()"
        );
        sqlx::query_as(&statement)
            .bind(id)
            .bind(engine)
            .fetch_optional(&self.pool)
            .await
            .map_err(Into::into)
    }

    pub async fn claim_branch(&self, id: i64) -> Result<bool, MetaError> {
        let updated = sqlx::query(
            "UPDATE branch SET native_claimed = TRUE WHERE id = $1 AND status = 'provisioning'
             AND NOT native_claimed AND expires_at > clock_timestamp()",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(updated.rows_affected() == 1)
    }

    pub async fn activate_branch(&self, id: i64) -> Result<(), MetaError> {
        let mut transaction = self.pool.begin().await?;
        let principal: Option<String> = sqlx::query_scalar(
            "UPDATE branch SET status = 'active' WHERE id = $1 AND status = 'provisioning'
             AND native_claimed AND expires_at > clock_timestamp() RETURNING created_by",
        )
        .bind(id)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(principal) = principal {
            audit(&mut transaction, &principal, id, "branch_active").await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn reject_branch(&self, id: i64) -> Result<(), MetaError> {
        sqlx::query(
            "WITH refused AS (
                UPDATE branch SET status = 'dropping' WHERE id = $1 AND status = 'provisioning'
                RETURNING id
             )
             INSERT INTO audit_event (actor, branch_id, event_type, payload)
             SELECT 'system:provision', id, 'branch_dropping',
                    '{\"reason\":\"provisioning\"}'::jsonb FROM refused",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn expire_branches(&self, engine: &str) -> Result<bool, MetaError> {
        let mut tx = self.pool.begin().await?;
        let ids: Vec<i64> = sqlx::query_scalar(
            "WITH batch AS (
                SELECT b.id FROM branch b JOIN generation g ON g.id = b.generation_id
                WHERE b.status IN ('provisioning', 'active') AND b.expires_at <= statement_timestamp()
                AND g.engine = $1 ORDER BY b.expires_at, b.id LIMIT $2 FOR UPDATE OF b SKIP LOCKED
             ), expired AS (
                UPDATE branch b SET status = 'dropping' FROM batch
                WHERE b.id = batch.id RETURNING b.id
             )
             INSERT INTO audit_event (actor, branch_id, event_type, payload)
             SELECT 'system:ttl', id, 'branch_dropping', '{\"reason\":\"ttl\"}'::jsonb FROM expired
             RETURNING branch_id",
        )
        .bind(engine)
        .bind(EXPIRY_BATCH_SIZE)
        .fetch_all(&mut *tx)
        .await?;
        if !ids.is_empty() {
            crate::approvals::invalidate_branches(&mut tx, &ids).await?;
        }
        tx.commit().await?;
        Ok(ids.len() as i64 == EXPIRY_BATCH_SIZE)
    }

    pub async fn complete_drop(&self, id: i64) -> Result<(), MetaError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SELECT id FROM branch WHERE id=$1 FOR UPDATE")
            .bind(id)
            .execute(&mut *transaction)
            .await?;
        let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM audit_attempt a WHERE branch_id=$1 AND forkget_audit_pending(a))")
            .bind(id).fetch_one(&mut *transaction).await?;
        if blocked {
            return Err(MetaError::AuditPending);
        }
        let principal: Option<String> = sqlx::query_scalar(
            "UPDATE branch SET status = 'dropped' WHERE id = $1 AND status = 'dropping' RETURNING created_by",
        )
        .bind(id)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(principal) = principal {
            audit(&mut transaction, &principal, id, "branch_dropped").await?;
        }
        transaction.commit().await?;
        Ok(())
    }
}

pub(crate) async fn fork_in(
    connection: &mut PgConnection,
    request: &ForkBranch<'_>,
    actor: &str,
) -> Result<Branch, MetaError> {
    crate::catalog::lock_generation_pin(connection).await?;
    let (generation, snapshot, has_manifest): (i64, String, bool) = sqlx::query_as(
        "SELECT id, snapshot, snapshot_manifest IS NOT NULL FROM generation
         WHERE engine = $1 AND reclaim_started_at IS NULL
           AND (($2::bigint IS NULL AND status='active')
             OR (id=$2 AND status IN ('active','retiring')))",
    )
    .bind(request.engine)
    .bind(
        request
            .expected_generation
            .map(|origin| origin.generation_id),
    )
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(if request.expected_generation.is_some() {
        MetaError::ReplayMismatch
    } else {
        MetaError::NoGeneration
    })?;
    if let Some(expected) = request.expected_generation {
        let deployment = crate::catalog::replay_deployment_id(connection).await?;
        if expected.deployment_id != deployment
            || expected.generation_id != generation
            || expected.snapshot != snapshot
        {
            return Err(MetaError::ReplayMismatch);
        }
    }
    if request.mode.layout() == BranchLayout::NativeCopy {
        if request.class == BranchClass::Staging {
            return Err(MetaError::WriteUnavailable);
        }
        if !matches!(snapshot.as_str(), "v2" | "v3")
            && fg_protocol_common::gate_order_count(&snapshot).is_none()
            && !has_manifest
        {
            return Err(MetaError::WriteUnavailable);
        }
        reserve_write_capacity(connection).await?;
    }
    let statement = format!(
        "INSERT INTO branch (name, class, generation_id, created_by, created_at, expires_at, status,
                             mode, uses_mysql_shared_schema, access, layout, read_strategy)
         VALUES ($1, $2, $3, $4, statement_timestamp(),
                 statement_timestamp() + make_interval(secs => $5), $6, $7, $8, $9, $10, $11)
         RETURNING {RETURNED_BRANCH}"
    );
    let branch = sqlx::query_as::<_, Branch>(&statement)
        .bind(request.name)
        .bind(request.class.as_str())
        .bind(generation)
        .bind(request.principal)
        .bind(f64::from(request.ttl_seconds))
        .bind(request.mode.initial_status())
        .bind(request.mode.name())
        .bind(
            matches!(request.engine, "mysql" | "tidb")
                && request.mode.layout() == BranchLayout::NativeCopy,
        )
        .bind(request.mode.access().as_str())
        .bind(request.mode.layout().as_str())
        .bind(new_read_strategy(request.engine, request.mode).as_str())
        .fetch_one(&mut *connection)
        .await
        .map_err(branch_write_error)?;
    audit(connection, actor, branch.id, "branch_forked").await?;
    Ok(branch)
}

pub(crate) async fn begin_drop_in(
    connection: &mut PgConnection,
    principal: &str,
    id: i64,
    actor: &str,
) -> Result<Branch, MetaError> {
    let statement = format!(
        "SELECT {RETURNED_BRANCH} FROM branch WHERE id = $1 AND created_by = $2 FOR UPDATE"
    );
    let mut branch: Branch = sqlx::query_as(&statement)
        .bind(id)
        .bind(principal)
        .fetch_optional(&mut *connection)
        .await?
        .ok_or(MetaError::BranchUnavailable)?;
    if matches!(branch.status.as_str(), "provisioning" | "active") {
        sqlx::query("UPDATE branch SET status = 'dropping' WHERE id = $1")
            .bind(id)
            .execute(&mut *connection)
            .await?;
        audit(connection, actor, id, "branch_dropping").await?;
        crate::approvals::invalidate_branches(connection, &[id]).await?;
        branch.status = "dropping".to_owned();
    }
    Ok(branch)
}

async fn reserve_write_capacity(connection: &mut PgConnection) -> Result<(), MetaError> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(WRITE_CAPACITY_LOCK)
        .execute(&mut *connection)
        .await?;
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM branch WHERE layout = 'native_copy' AND status <> 'dropped'",
    )
    .fetch_one(connection)
    .await?;
    if live >= WRITE_CAPACITY {
        return Err(MetaError::WriteCapacity);
    }
    Ok(())
}

async fn audit(
    connection: &mut PgConnection,
    principal: &str,
    branch: i64,
    event: &str,
) -> Result<(), MetaError> {
    sqlx::query(
        "INSERT INTO audit_event (actor, branch_id, event_type, payload) VALUES ($1, $2, $3, '{}'::jsonb)",
    )
    .bind(principal)
    .bind(branch)
    .bind(event)
    .execute(connection)
    .await?;
    Ok(())
}

fn branch_write_error(error: sqlx::Error) -> MetaError {
    if error
        .as_database_error()
        .is_some_and(|database| database.constraint() == Some("live_branch_name"))
    {
        MetaError::BranchConflict
    } else {
        MetaError::Database(error)
    }
}

fn new_read_strategy(engine: &str, mode: BranchMode) -> ReadStrategy {
    if mode == BranchMode::ReadOnly && matches!(engine, "mysql" | "postgresql" | "tidb") {
        ReadStrategy::BaseOnly
    } else {
        ReadStrategy::Merge
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_new_immutable_sql_read_branches_bypass_delta() {
        for engine in ["mysql", "postgresql", "tidb", "mongodb"] {
            assert_eq!(BranchMode::ReadOnly.access(), BranchAccess::ReadOnly);
            assert_eq!(BranchMode::ReadOnly.layout(), BranchLayout::SparseDelta);
            assert_eq!(BranchMode::NativeWrite.access(), BranchAccess::ReadWrite);
            assert_eq!(BranchMode::NativeWrite.layout(), BranchLayout::NativeCopy);
            assert_eq!(
                new_read_strategy(engine, BranchMode::NativeWrite),
                ReadStrategy::Merge
            );
            assert_eq!(
                new_read_strategy(engine, BranchMode::ReadOnly),
                if engine == "mongodb" {
                    ReadStrategy::Merge
                } else {
                    ReadStrategy::BaseOnly
                }
            );
        }
    }
}
