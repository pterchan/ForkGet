use super::{
    AttemptRow, AuditRecoveryAttempt, AuditRecoveryEvidence, complete_mongo_step, load_attempt,
    lock_branch, store_outcome,
};
use crate::{MetaError, Metadata};
use fg_protocol_common::{
    AuditMode, AuditedOutcomeRequest, MongoObservationState, NativeWitnessBinding, OutcomeAck,
    TransactionOutcome,
};
use serde_json::json;
use sqlx::PgConnection;

impl Metadata {
    /// Rotate a bounded background scan after a present or unavailable native
    /// observer result. This neither seals nor authorizes a live transaction.
    pub async fn note_audit_recovery_deferred(
        &self,
        engine: &str,
        id: &str,
    ) -> Result<(), MetaError> {
        sqlx::query("UPDATE audit_attempt a SET updated_at=clock_timestamp() WHERE attempt_id=$1 AND engine=$2
            AND outcome IS NULL AND NOT sealed AND EXISTS(SELECT 1 FROM policy_proxy_epoch e WHERE e.epoch=split_part(a.session_id,':',1))")
            .bind(id).bind(engine).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn pending_audit_attempts(
        &self,
        engine: &str,
    ) -> Result<Vec<AuditRecoveryAttempt>, MetaError> {
        let rows:Vec<AttemptRow>=sqlx::query_as("SELECT a.*,EXISTS(SELECT 1 FROM policy_proxy_epoch e WHERE e.epoch=split_part(a.session_id,':',1)) AS is_current_epoch FROM audit_attempt a WHERE engine=$1
            AND forkget_audit_pending(a) ORDER BY updated_at,attempt_id LIMIT 256")
            .bind(engine).fetch_all(&self.pool).await?;
        rows.iter().map(AttemptRow::recovery).collect()
    }

    pub async fn pending_branch_audit_attempts(
        &self,
        engine: &str,
        branch: i64,
    ) -> Result<Vec<AuditRecoveryAttempt>, MetaError> {
        let rows:Vec<AttemptRow>=sqlx::query_as("SELECT a.*,EXISTS(SELECT 1 FROM policy_proxy_epoch e WHERE e.epoch=split_part(a.session_id,':',1)) AS is_current_epoch
            FROM audit_attempt a WHERE engine=$1 AND branch_id=$2 AND forkget_audit_pending(a) ORDER BY updated_at,attempt_id LIMIT 256")
            .bind(engine).bind(branch).fetch_all(&self.pool).await?;
        rows.iter().map(AttemptRow::recovery).collect()
    }

    pub async fn seal_audit_attempt(
        &self,
        engine: &str,
        id: &str,
    ) -> Result<AuditRecoveryAttempt, MetaError> {
        let row:AttemptRow=sqlx::query_as("UPDATE audit_attempt SET sealed=TRUE,updated_at=clock_timestamp()
            WHERE attempt_id=$1 AND engine=$2 RETURNING audit_attempt.*,EXISTS(SELECT 1 FROM policy_proxy_epoch e WHERE e.epoch=split_part(audit_attempt.session_id,':',1)) AS is_current_epoch")
            .bind(id).bind(engine).fetch_optional(&self.pool).await?.ok_or(MetaError::BranchUnavailable)?;
        row.recovery()
    }

    /// Known SQL evidence is accepted only from the controller after its native
    /// quiescence and storage-history barrier, never from an HTTP request.
    pub async fn resolve_audit_attempt(
        &self,
        engine: &str,
        id: &str,
        evidence: AuditRecoveryEvidence,
    ) -> Result<OutcomeAck, MetaError> {
        let mut tx = self.pool.begin().await?;
        let row = lock_recovery_attempt(&mut tx, engine, id).await?;
        if row.engine != engine || !row.sealed {
            return Err(MetaError::AuditConflict);
        }
        sqlx::query("UPDATE audit_attempt SET quiescence_confirmed=TRUE,updated_at=clock_timestamp() WHERE attempt_id=$1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        let outcome = match evidence {
            AuditRecoveryEvidence::SqlCommitted(binding) => {
                verify_evidence(&row, &binding)?;
                TransactionOutcome::Committed
            }
            AuditRecoveryEvidence::SqlRolledBack(binding) => {
                verify_evidence(&row, &binding)?;
                TransactionOutcome::RolledBack
            }
            AuditRecoveryEvidence::Unknown => TransactionOutcome::Unknown,
        };
        let ack = if let Some(original) = row.ack()? {
            if outcome == TransactionOutcome::Unknown || original.outcome == outcome {
                original
            } else if original.outcome == TransactionOutcome::Unknown {
                append_resolution(&mut tx, &row, outcome).await?
            } else {
                return Err(MetaError::AuditConflict);
            }
        } else {
            let context = row.recovery()?.context;
            let mongo = (context.mode == AuditMode::MongoCommand).then(|| {
                fg_protocol_common::MongoWriteObservation {
                    state: MongoObservationState::Unknown,
                    ..Default::default()
                }
            });
            if row.armed_step > 0
                && let Some(observation) = &mongo
            {
                complete_mongo_step(&mut tx, &row, observation).await?;
            }
            let payload = serde_json::to_value(AuditedOutcomeRequest {
                attempt: context,
                outcome,
                armed_step: u32::try_from(row.armed_step).map_err(|_| MetaError::InvalidCatalog)?,
                mongo,
            })
            .map_err(|_| MetaError::InvalidCatalog)?;
            store_outcome(&mut tx, &row, outcome, &payload).await?
        };
        tx.commit().await?;
        Ok(ack)
    }

    pub async fn audit_cleanup_ready(&self, engine: &str, branch: i64) -> Result<bool, MetaError> {
        sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM audit_attempt a WHERE engine=$1 AND branch_id=$2 AND forkget_audit_pending(a))")
            .bind(engine).bind(branch).fetch_one(&self.pool).await.map_err(Into::into)
    }

    pub async fn completed_sql_audit_attempts(
        &self,
        engine: &str,
        branch: i64,
        limit: u32,
    ) -> Result<Vec<String>, MetaError> {
        sqlx::query_scalar("SELECT attempt_id FROM audit_attempt WHERE engine=$1 AND branch_id=$2 AND mode='sql_transaction'
            AND NOT witness_collected AND outcome IS NOT NULL AND (outcome<>'unknown' OR resolution IS NOT NULL)
            ORDER BY created_at LIMIT $3")
            .bind(engine).bind(branch).bind(i64::from(limit.min(256))).fetch_all(&self.pool).await.map_err(Into::into)
    }

    pub async fn mark_witness_collected(
        &self,
        engine: &str,
        attempts: &[String],
    ) -> Result<(), MetaError> {
        sqlx::query("UPDATE audit_attempt SET witness_collected=TRUE WHERE engine=$1 AND attempt_id=ANY($2)
            AND mode='sql_transaction' AND outcome IS NOT NULL AND (outcome<>'unknown' OR resolution IS NOT NULL)")
            .bind(engine).bind(attempts).execute(&self.pool).await?;
        Ok(())
    }

    /// The local operator command establishes native quiescence first.
    pub async fn acknowledge_audit_unknown(
        &self,
        engine: &str,
        id: &str,
        operator: &str,
    ) -> Result<(), MetaError> {
        if operator.is_empty() || operator.len() > 128 {
            return Err(MetaError::InvalidPolicy);
        }
        let mut tx = self.pool.begin().await?;
        let row = lock_recovery_attempt(&mut tx, engine, id).await?;
        if row.engine != engine
            || !row.sealed
            || !row.quiescence_confirmed
            || row.outcome.as_deref() != Some("unknown")
            || row.resolution.is_some()
        {
            return Err(MetaError::AuditConflict);
        }
        if row.retention_ack_event_id.is_none() {
            let payload = json!({"attempt_id":id,"generation_id":row.generation_id,"outcome":"unknown","reason":"operator_confirmed_unknown"});
            let event:i64=sqlx::query_scalar("INSERT INTO audit_event(actor,branch_id,event_type,payload) VALUES($1,$2,'policy_outcome_retention_ack',$3) RETURNING id")
                .bind(operator).bind(row.branch_id).bind(payload).fetch_one(&mut *tx).await?;
            sqlx::query("UPDATE audit_attempt SET retention_ack_event_id=$2,updated_at=clock_timestamp() WHERE attempt_id=$1")
                .bind(id).bind(event).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Restore transitions invalidate old absence proofs; the caller drains
    /// native sessions before entering this explicit local operator boundary.
    pub async fn invalidate_audit_storage(
        &self,
        engine: &str,
        branch: i64,
        operator: &str,
    ) -> Result<(), MetaError> {
        if operator.is_empty() || operator.len() > 128 {
            return Err(MetaError::InvalidPolicy);
        }
        let mut tx = self.begin_policy(true).await?;
        lock_branch(&mut tx, branch, true).await?;
        let changed=sqlx::query("UPDATE branch b SET audit_witness_ready=FALSE,audit_witness_version=0,audit_witness_incarnation=NULL,audit_storage_invalidated=TRUE
            FROM generation g WHERE b.id=$1 AND g.id=b.generation_id AND g.engine=$2 AND b.layout='native_copy' AND NOT b.audit_storage_reclaim_started")
            .bind(branch).bind(engine).execute(&mut *tx).await?;
        if changed.rows_affected() != 1 {
            return Err(MetaError::BranchUnavailable);
        }
        sqlx::query("UPDATE audit_attempt SET sealed=TRUE,storage_history_trusted=FALSE,updated_at=clock_timestamp() WHERE branch_id=$1")
            .bind(branch).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO audit_event(actor,branch_id,event_type,payload) VALUES($1,$2,'audit_storage_invalidated','{}')")
            .bind(operator).bind(branch).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
}

async fn lock_recovery_attempt(
    connection: &mut PgConnection,
    engine: &str,
    id: &str,
) -> Result<AttemptRow, MetaError> {
    let branch: i64 =
        sqlx::query_scalar("SELECT branch_id FROM audit_attempt WHERE attempt_id=$1 AND engine=$2")
            .bind(id)
            .bind(engine)
            .fetch_optional(&mut *connection)
            .await?
            .ok_or(MetaError::BranchUnavailable)?;
    // Outcomes and storage reclamation also lock branch before attempt. The
    // event's branch foreign key must never invert that order after a wait.
    lock_branch(connection, branch, false).await?;
    load_attempt(connection, id, true).await
}

fn verify_evidence(row: &AttemptRow, binding: &NativeWitnessBinding) -> Result<(), MetaError> {
    if row.mode != "sql_transaction"
        || !row.storage_history_trusted
        || row.witness()?.as_ref() != Some(binding)
    {
        return Err(MetaError::AuditConflict);
    }
    Ok(())
}

async fn append_resolution(
    connection: &mut PgConnection,
    row: &AttemptRow,
    outcome: TransactionOutcome,
) -> Result<OutcomeAck, MetaError> {
    if let Some(resolution) = &row.resolution {
        if resolution != outcome.as_str() {
            return Err(MetaError::AuditConflict);
        }
        let id: i64 =
            sqlx::query_scalar("SELECT resolution_event_id FROM audit_attempt WHERE attempt_id=$1")
                .bind(&row.attempt_id)
                .fetch_one(connection)
                .await?;
        return Ok(OutcomeAck {
            attempt_id: row.attempt_id.clone(),
            audit_event_id: id,
            outcome,
        });
    }
    let payload = json!({"attempt_id":row.attempt_id,"generation_id":row.generation_id,
        "session_id":row.session_id,"original_outcome":"unknown","outcome":outcome,"evidence":"native_witness"});
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO audit_event(actor,branch_id,event_type,payload)
        VALUES('system:audit-recovery',$1,'policy_outcome_resolved',$2) RETURNING id",
    )
    .bind(row.branch_id)
    .bind(payload)
    .fetch_one(&mut *connection)
    .await?;
    sqlx::query("UPDATE audit_attempt SET resolution=$2,resolution_event_id=$3,updated_at=clock_timestamp() WHERE attempt_id=$1")
        .bind(&row.attempt_id).bind(outcome.as_str()).bind(id).execute(connection).await?;
    Ok(OutcomeAck {
        attempt_id: row.attempt_id.clone(),
        audit_event_id: id,
        outcome,
    })
}
