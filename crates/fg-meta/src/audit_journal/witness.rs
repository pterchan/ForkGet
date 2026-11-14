use super::lock_branch;
use crate::write_observation::{WriteObservation, WritePhase};
use crate::{MetaError, Metadata};
use fg_protocol_common::{AUDIT_WITNESS_VERSION, NativeWitnessBinding};
use serde_json::json;
use sqlx::PgConnection;

struct WitnessPlan<'a> {
    engine: &'a str,
    branch: i64,
    incarnation: &'a str,
    replacement: bool,
}

struct WitnessPreparation<'a> {
    engine: &'a str,
    binding: &'a NativeWitnessBinding,
    operator: &'a str,
    replacement: bool,
}

impl Metadata {
    /// Persist the irreversible end of native evidence before any physical
    /// deletion, so interrupted cleanup can resume without recreating proof.
    pub async fn begin_audit_storage_reclaim(
        &self,
        engine: &str,
        branch: i64,
    ) -> Result<(), MetaError> {
        let mut tx = self.pool.begin().await?;
        lock_branch(&mut tx, branch, true).await?;
        let eligible: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM branch b JOIN generation g ON g.id=b.generation_id
            WHERE b.id=$1 AND g.engine=$2 AND b.status='dropping')",
        )
        .bind(branch)
        .bind(engine)
        .fetch_one(&mut *tx)
        .await?;
        if !eligible {
            return Err(MetaError::BranchUnavailable);
        }
        let pending:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM audit_attempt a WHERE branch_id=$1 AND forkget_audit_pending(a))")
            .bind(branch)
.fetch_one(&mut *tx).await?;
        if pending {
            return Err(MetaError::AuditPending);
        }
        sqlx::query("UPDATE branch SET audit_storage_reclaim_started=TRUE,audit_witness_ready=FALSE WHERE id=$1")
            .bind(branch)
.execute(&mut *tx).await?;
        sqlx::query(
            "UPDATE audit_attempt SET sealed=TRUE,storage_history_trusted=FALSE WHERE branch_id=$1",
        )
        .bind(branch)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Rebuilding an owned, never-admitted provisioning copy cannot erase
    /// transaction evidence. Active or previously attempted branches refuse.
    pub async fn reset_provisioning_audit_witness(
        &self,
        engine: &str,
        branch: i64,
    ) -> Result<bool, MetaError> {
        let mut tx = self.pool.begin().await?;
        let found: Option<i64> = sqlx::query_scalar("SELECT id FROM branch WHERE id=$1 FOR UPDATE")
            .bind(branch)
            .fetch_optional(&mut *tx)
            .await?;
        if found.is_none() {
            return Ok(false);
        }
        let changed = sqlx::query(
            "UPDATE branch b SET audit_witness_ready=FALSE FROM generation g
            WHERE b.id=$1 AND g.id=b.generation_id AND g.engine=$2 AND b.status='provisioning'
            AND b.native_claimed AND b.layout='native_copy'
            AND NOT b.audit_storage_reclaim_started
            AND NOT EXISTS(SELECT 1 FROM audit_attempt a WHERE a.branch_id=b.id)",
        )
        .bind(branch)
        .bind(engine)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(changed.rows_affected() == 1)
    }

    pub async fn plan_audit_witness(
        &self,
        engine: &str,
        branch: i64,
        incarnation: &str,
    ) -> Result<NativeWitnessBinding, MetaError> {
        self.plan_witness(WitnessPlan {
            engine,
            branch,
            incarnation,
            replacement: false,
        })
        .await
    }

    pub async fn plan_audit_witness_replacement(
        &self,
        engine: &str,
        branch: i64,
        incarnation: &str,
    ) -> Result<NativeWitnessBinding, MetaError> {
        self.plan_witness(WitnessPlan {
            engine,
            branch,
            incarnation,
            replacement: true,
        })
        .await
    }

    async fn plan_witness(&self, plan: WitnessPlan<'_>) -> Result<NativeWitnessBinding, MetaError> {
        let WitnessPlan {
            engine,
            branch,
            incarnation,
            replacement,
        } = plan;
        if !matches!(engine, "mysql" | "postgresql" | "tidb")
            || incarnation.len() != 32
            || !incarnation
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(MetaError::InvalidPolicy);
        }
        let mut tx = self.pool.begin().await?;
        lock_branch(&mut tx, branch, true).await?;
        let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM audit_attempt WHERE branch_id=$1 AND NOT storage_history_trusted
            AND (outcome IS NULL OR (outcome='unknown' AND resolution IS NULL AND retention_ack_event_id IS NULL)))")
            .bind(branch)
.fetch_one(&mut *tx).await?;
        if blocked {
            return Err(MetaError::AuditPending);
        }
        let changed = sqlx::query(
            "UPDATE branch b SET audit_witness_version=1,
            audit_witness_incarnation=COALESCE(audit_witness_incarnation,$3)
            FROM generation g WHERE b.id=$1 AND g.id=b.generation_id AND g.engine=$2
            AND b.layout='native_copy' AND b.access='read_write' AND b.native_claimed
            AND NOT b.audit_storage_reclaim_started
            AND b.audit_storage_invalidated=$4 AND (NOT $4 OR NOT b.audit_witness_ready)
            AND (NOT $4 OR NOT EXISTS(SELECT 1 FROM audit_attempt a WHERE a.branch_id=b.id AND forkget_audit_pending(a)))
            AND b.status IN ('active','provisioning') AND g.status IN ('active','retiring')",
        )
        .bind(branch)
        .bind(engine)
        .bind(incarnation)
        .bind(replacement)
        .execute(&mut *tx)
        .await?;
        if changed.rows_affected() != 1 {
            return Err(MetaError::BranchUnavailable);
        }
        let binding = witness_binding(&mut tx, engine, branch, false)
            .await?
            .ok_or(MetaError::InvalidCatalog)?;
        tx.commit().await?;
        Ok(binding)
    }

    pub async fn mark_audit_witness_ready(
        &self,
        engine: &str,
        binding: &NativeWitnessBinding,
    ) -> Result<(), MetaError> {
        self.mark_audit_witness_ready_by(engine, binding, "system:audit-preparation")
            .await
    }

    pub async fn mark_audit_witness_ready_by(
        &self,
        engine: &str,
        binding: &NativeWitnessBinding,
        operator: &str,
    ) -> Result<(), MetaError> {
        self.mark_witness_prepared(WitnessPreparation {
            engine,
            binding,
            operator,
            replacement: false,
        })
        .await
    }

    pub async fn mark_audit_witness_replacement_ready_by(
        &self,
        engine: &str,
        binding: &NativeWitnessBinding,
        operator: &str,
    ) -> Result<(), MetaError> {
        self.mark_witness_prepared(WitnessPreparation {
            engine,
            binding,
            operator,
            replacement: true,
        })
        .await
    }

    async fn mark_witness_prepared(
        &self,
        preparation: WitnessPreparation<'_>,
    ) -> Result<(), MetaError> {
        let WitnessPreparation {
            engine,
            binding,
            operator,
            replacement,
        } = preparation;
        if operator.is_empty() || operator.len() > 128 {
            return Err(MetaError::InvalidPolicy);
        }
        let mut tx = self.pool.begin().await?;
        lock_branch(&mut tx, binding.branch_id, true).await?;
        if witness_binding(&mut tx, engine, binding.branch_id, false)
            .await?
            .as_ref()
            != Some(binding)
        {
            return Err(MetaError::AuditConflict);
        }
        let (invalidated, ready): (bool, bool) = sqlx::query_as(
            "SELECT audit_storage_invalidated,audit_witness_ready FROM branch WHERE id=$1",
        )
        .bind(binding.branch_id)
        .fetch_one(&mut *tx)
        .await?;
        if invalidated != replacement {
            let repeated:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM audit_event WHERE branch_id=$1 AND event_type='audit_witness_prepared' AND payload->>'storage_incarnation'=$2 AND payload->>'replacement'='true')")
                .bind(binding.branch_id)
.bind(&binding.storage_incarnation)
.fetch_one(&mut *tx).await?;
            if !replacement || !ready || invalidated || !repeated {
                return Err(MetaError::AuditConflict);
            }
            tx.commit().await?;
            return Ok(());
        }
        if replacement {
            let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM audit_attempt a WHERE branch_id=$1 AND forkget_audit_pending(a))")
                .bind(binding.branch_id)
.fetch_one(&mut *tx).await?;
            if blocked {
                return Err(MetaError::AuditPending);
            }
        }
        let changed=sqlx::query("UPDATE branch SET audit_witness_ready=TRUE,audit_storage_invalidated=FALSE WHERE id=$1 AND NOT audit_witness_ready")
            .bind(binding.branch_id)
.execute(&mut *tx).await?;
        if changed.rows_affected() == 1 {
            sqlx::query("INSERT INTO audit_event(actor,branch_id,event_type,payload) VALUES($1,$2,'audit_witness_prepared',$3)")
                .bind(operator)
.bind(binding.branch_id)
.bind(json!({"generation_id":binding.generation_id,"storage_incarnation":binding.storage_incarnation,"replacement":replacement}))
                .execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn audit_storage_replacement_allowed(
        &self,
        engine: &str,
        branch: i64,
    ) -> Result<bool, MetaError> {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM branch b JOIN generation g ON g.id=b.generation_id
            WHERE b.id=$1 AND g.engine=$2 AND b.audit_storage_invalidated AND NOT b.audit_witness_ready AND NOT b.audit_storage_reclaim_started
            AND NOT EXISTS(SELECT 1 FROM audit_attempt a WHERE a.branch_id=b.id AND (a.outcome IS NULL OR
                (a.mode='sql_transaction' AND a.outcome='unknown' AND a.resolution IS NULL AND a.retention_ack_event_id IS NULL))))")
            .bind(branch)
.bind(engine)
.fetch_one(&self.pool).await.map_err(Into::into)
    }

    pub async fn audit_witness_binding(
        &self,
        engine: &str,
        branch: i64,
    ) -> Result<Option<NativeWitnessBinding>, MetaError> {
        let mut connection = self.pool.acquire().await?;
        witness_binding(&mut connection, engine, branch, true).await
    }
}

pub(super) async fn witness_binding(
    connection: &mut PgConnection,
    engine: &str,
    branch: i64,
    ready: bool,
) -> Result<Option<NativeWitnessBinding>, MetaError> {
    witness_binding_observed(
        connection,
        WitnessLookup {
            engine,
            branch,
            ready,
        },
        &WriteObservation::disabled(),
    )
    .await
}

pub(super) struct WitnessLookup<'a> {
    pub engine: &'a str,
    pub branch: i64,
    pub ready: bool,
}

pub(super) async fn witness_binding_observed(
    connection: &mut PgConnection,
    lookup: WitnessLookup<'_>,
    observation: &WriteObservation,
) -> Result<Option<NativeWitnessBinding>, MetaError> {
    let WitnessLookup {
        engine,
        branch,
        ready,
    } = lookup;
    let row: Option<(i64, String)> = observation
        .run(
            WritePhase::Witness,
            sqlx::query_as(
                "SELECT b.generation_id,b.audit_witness_incarnation
        FROM branch b JOIN generation g ON g.id=b.generation_id WHERE b.id=$1 AND g.engine=$2
        AND b.audit_witness_version=1 AND NOT b.audit_storage_reclaim_started AND (NOT $3 OR b.audit_witness_ready)",
            )
                .bind(branch)
                .bind(engine)
                .bind(ready)
                .fetch_optional(&mut *connection),
        ).await?;
    match row {
        Some((generation_id, storage_incarnation)) => Ok(Some(NativeWitnessBinding {
            format_version: AUDIT_WITNESS_VERSION,
            deployment_id: observation
                .run(
                    WritePhase::Witness,
                    crate::catalog::replay_deployment_id(connection),
                )
                .await?,
            branch_id: branch,
            generation_id,
            storage_incarnation,
        })),
        None => Ok(None),
    }
}
