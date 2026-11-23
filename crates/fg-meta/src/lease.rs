//! Finite renewable leases and lifecycle diagnostics use metadata time.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;

use crate::{MetaError, Metadata};

/// A dedicated connection owns the export lock; cancellation cannot return a
/// session-level advisory lock to the metadata connection pool.
pub struct CaptureGuard {
    _connection: sqlx::PgConnection,
    version: i64,
}

pub const MAX_BRANCH_LIFETIME_SECONDS: i64 = 7 * 24 * 60 * 60;
const MAX_LEASE_SECONDS: u32 = 24 * 60 * 60;

#[derive(Clone, Copy, Debug, Deserialize, FromRow, Serialize)]
pub struct BranchLease {
    pub expires_at: i64,
    pub lease_version: i64,
}

impl Metadata {
    pub async fn begin_capture(
        &self,
        engine: &str,
        id: i64,
        principal: &str,
    ) -> Result<CaptureGuard, MetaError> {
        use sqlx::ConnectOptions as _;
        let mut connection = self.pool.connect_options().connect().await?;
        let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
            .bind(id ^ 0x4647_1000_0000_0000_i64)
            .fetch_one(&mut connection)
            .await?;
        if !acquired {
            return Err(MetaError::BranchUnavailable);
        }
        let version=sqlx::query_scalar("UPDATE branch b SET capture_active=TRUE,capture_version=capture_version+1 FROM generation g WHERE b.id=$1 AND b.created_by=$2 AND b.generation_id=g.id AND g.engine=$3 AND b.status='active' AND b.expires_at>clock_timestamp() RETURNING b.capture_version")
            .bind(id).bind(principal).bind(engine).fetch_optional(&self.pool).await?
            .ok_or(MetaError::BranchUnavailable)?;
        Ok(CaptureGuard {
            _connection: connection,
            version,
        })
    }

    pub async fn finish_capture(&self, id: i64, guard: CaptureGuard) -> Result<(), MetaError> {
        sqlx::query("UPDATE branch SET capture_active=FALSE WHERE id=$1 AND capture_version=$2")
            .bind(id)
            .bind(guard.version)
            .execute(&self.pool)
            .await?;
        drop(guard);
        Ok(())
    }
    pub async fn lifecycle_progress(
        &self,
        id: i64,
        phase: &str,
        reason: Option<&str>,
    ) -> Result<(), MetaError> {
        if !matches!(
            phase,
            "preflight"
                | "copying"
                | "validating"
                | "granting"
                | "removing"
                | "provision_retry"
                | "cleanup_retry"
        ) {
            return Err(MetaError::InvalidCatalog);
        }
        sqlx::query("UPDATE branch SET lifecycle_phase=CASE WHEN status='dropping' AND $2='provision_retry' THEN 'cleanup_retry' ELSE $2 END,lifecycle_reason=$3,lifecycle_updated_at=clock_timestamp() WHERE id=$1 AND status IN ('provisioning','dropping')")
            .bind(id).bind(phase).bind(reason).execute(&self.pool).await?;
        Ok(())
    }
    pub async fn branch_lease(
        &self,
        engine: &str,
        id: i64,
        principal: &str,
    ) -> Result<BranchLease, MetaError> {
        sqlx::query_as("SELECT floor(extract(epoch FROM b.expires_at))::bigint AS expires_at,b.lease_version FROM branch b JOIN generation g ON g.id=b.generation_id WHERE b.id=$1 AND b.created_by=$2 AND g.engine=$3 AND b.status='active' AND b.expires_at>clock_timestamp() AND g.status IN ('active','retiring') AND g.reclaim_started_at IS NULL")
            .bind(id).bind(principal).bind(engine).fetch_optional(&self.pool).await?
            .ok_or(MetaError::BranchUnavailable)
    }

    pub async fn renew_branch(
        &self,
        engine: &str,
        id: i64,
        principal: &str,
        seconds: u32,
        expected: i64,
    ) -> Result<BranchLease, MetaError> {
        if !(1..=MAX_LEASE_SECONDS).contains(&seconds) || expected <= 0 {
            return Err(MetaError::InvalidLease);
        }
        let mut tx = self.pool.begin().await?;
        let current: Option<(i64, bool)> = sqlx::query_as("SELECT b.lease_version,b.status IN ('active','provisioning') AND b.expires_at>clock_timestamp() FROM branch b JOIN generation g ON g.id=b.generation_id WHERE b.id=$1 AND b.created_by=$2 AND g.engine=$3 FOR UPDATE OF b")
            .bind(id).bind(principal).bind(engine).fetch_optional(&mut *tx).await?;
        let (version, active) = current.ok_or(MetaError::BranchUnavailable)?;
        if !active {
            return Err(MetaError::BranchUnavailable);
        }
        if version != expected {
            return Err(MetaError::LeaseConflict);
        }
        // The FOR UPDATE above has finished waiting and this transaction
        // owns the tuple lock. Recheck the deadline here: the SELECT's
        // projected boolean may have been evaluated before its lock wait.
        let renewed: Option<BranchLease> = sqlx::query_as("UPDATE branch SET expires_at=LEAST(clock_timestamp()+make_interval(secs=>$2),created_at+INTERVAL '7 days'),lease_renewed_at=clock_timestamp(),lease_version=lease_version+1 WHERE id=$1 AND lease_version=$3 AND status IN ('active','provisioning') AND expires_at>clock_timestamp() AND LEAST(clock_timestamp()+make_interval(secs=>$2),created_at+INTERVAL '7 days')>expires_at RETURNING floor(extract(epoch FROM expires_at))::bigint AS expires_at,lease_version")
            .bind(id).bind(f64::from(seconds))
            .bind(expected)
            .fetch_optional(&mut *tx).await?;
        let lease = renewed.ok_or(MetaError::InvalidLease)?;
        sqlx::query("INSERT INTO audit_event(actor,branch_id,event_type,payload) VALUES($1,$2,'branch_renewed',jsonb_build_object('lease_version',$3::bigint,'expires_at',$4::bigint))")
            .bind(principal).bind(id).bind(lease.lease_version).bind(lease.expires_at)
            .execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(lease)
    }

    pub async fn branch_status(
        &self,
        engine: &str,
        id: i64,
        principal: &str,
    ) -> Result<Value, MetaError> {
        let json: Option<String> = sqlx::query_scalar("SELECT jsonb_build_object('id',b.id,'name',b.name,'class',b.class,'generation_id',b.generation_id,'snapshot',g.snapshot,'status',b.status,'access',b.access,'layout',b.layout,'read_strategy',b.read_strategy,'expires_at',floor(extract(epoch FROM b.expires_at))::bigint,'lease_version',b.lease_version,'retain_until_max',floor(extract(epoch FROM b.created_at+INTERVAL '7 days'))::bigint,'expired',b.expires_at<=clock_timestamp())::text FROM branch b JOIN generation g ON g.id=b.generation_id WHERE b.id=$1 AND b.created_by=$2 AND g.engine=$3")
            .bind(id).bind(principal).bind(engine).fetch_optional(&self.pool).await?;
        let mut result: Value = serde_json::from_str(&json.ok_or(MetaError::BranchUnavailable)?)
            .map_err(|_| MetaError::InvalidCatalog)?;
        let diagnostics:String=sqlx::query_scalar("SELECT jsonb_build_object('lifecycle_phase',b.lifecycle_phase,'reason',b.lifecycle_reason,'phase_updated_at',floor(extract(epoch FROM b.lifecycle_updated_at))::bigint,'snapshot_rows',(SELECT COALESCE(sum(baseline_rows),0) FROM catalog_table WHERE generation_id=b.generation_id),'snapshot_objects',(SELECT count(*) FROM catalog_table WHERE generation_id=b.generation_id),'export_in_progress',b.capture_active,'export_recovery','retry export after an interrupted capture; running exports remain exclusive','replay',(SELECT jsonb_build_object('id',j.id,'state',j.state) FROM replay_job j WHERE j.branch_id=b.id))::text FROM branch b WHERE b.id=$1")
            .bind(id).fetch_one(&self.pool).await?;
        if let (Some(target), Value::Object(fields)) = (
            result.as_object_mut(),
            serde_json::from_str::<Value>(&diagnostics).map_err(|_| MetaError::InvalidCatalog)?,
        ) {
            target.extend(fields);
        }
        let storage: String =
            sqlx::query_scalar("SELECT storage_preflight::text FROM branch WHERE id=$1")
                .bind(id)
                .fetch_one(&self.pool)
                .await?;
        result["storage_preflight"] =
            serde_json::from_str(&storage).map_err(|_| MetaError::InvalidCatalog)?;
        result["audit"] = self.branch_audit_status(engine, id).await?;
        Ok(result)
    }

    pub async fn deployment_status(&self, engine: &str) -> Result<Value, MetaError> {
        let generations: Vec<String> = sqlx::query_scalar("SELECT jsonb_build_object('id',g.id,'snapshot',g.snapshot,'status',g.status,'reclaim_started',g.reclaim_started_at IS NOT NULL,'blockers',COALESCE((SELECT jsonb_agg(jsonb_build_object('branch_id',b.id,'name',b.name,'owner',b.created_by,'status',b.status,'layout',b.layout,'expires_at',floor(extract(epoch FROM b.expires_at))::bigint)) FROM branch b WHERE b.generation_id=g.id AND b.status<>'dropped'),'[]'::jsonb))::text FROM generation g WHERE g.engine=$1 AND (g.status IN ('importing','active','retiring') OR (g.status='failed' AND g.native_claimed)) ORDER BY g.id")
            .bind(engine).fetch_all(&self.pool).await?;
        let generations = generations
            .iter()
            .map(|value| {
                serde_json::from_str::<Value>(value).map_err(|_| MetaError::InvalidCatalog)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let slots: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM branch WHERE layout='native_copy' AND status<>'dropped'",
        )
        .fetch_one(&self.pool)
        .await?;
        let blockers:Vec<String>=sqlx::query_scalar("SELECT jsonb_build_object('branch_id',id,'owner',created_by,'name',name,'status',status,'phase',lifecycle_phase,'reason',lifecycle_reason,'expires_at',floor(extract(epoch FROM expires_at))::bigint,'storage_preflight',storage_preflight)::text FROM branch WHERE layout='native_copy' AND status<>'dropped' ORDER BY id")
            .fetch_all(&self.pool).await?;
        let blockers = blockers
            .iter()
            .map(|value| {
                serde_json::from_str::<Value>(value).map_err(|_| MetaError::InvalidCatalog)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let audit = self.deployment_audit_status(engine).await?;
        Ok(
            serde_json::json!({"engine":engine,"generations":generations,"generation_limit":crate::catalog::LIVE_GENERATION_LIMIT,"native_slots_used":slots,"native_slots_limit":crate::lifecycle::WRITE_CAPACITY,"native_copy_blockers":blockers,"audit":audit,"max_branch_lifetime_seconds":MAX_BRANCH_LIFETIME_SECONDS}),
        )
    }
}
