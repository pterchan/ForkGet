use crate::write_observation::{WriteObservation, WriteOperation, WritePhase};
use fg_protocol_common::{
    AuditAttemptContext, AuditMode, AuditStatus, AuditedDecisionRequest, AuditedDecisionResponse,
    AuditedOutcomeRequest, MongoObservationState, MongoStepAck, MongoStepRequest,
    NativeWitnessBinding, OutcomeAck, TransactionOutcome, WriteFenceRequest, WriteFenceResponse,
};
use serde_json::{Value, json};
use sqlx::{Acquire, FromRow, PgConnection};

use crate::{MetaError, Metadata};

#[derive(Clone)]
pub struct AuditRecoveryAttempt {
    pub context: AuditAttemptContext,
    pub branch_id: i64,
    pub witness: Option<NativeWitnessBinding>,
    pub outcome: Option<TransactionOutcome>,
    pub sealed: bool,
    pub is_current_epoch: bool,
    pub storage_history_trusted: bool,
}

pub enum AuditRecoveryEvidence {
    SqlCommitted(NativeWitnessBinding),
    SqlRolledBack(NativeWitnessBinding),
    Unknown,
}

#[derive(Clone, FromRow)]
struct AttemptRow {
    attempt_id: String,
    branch_id: i64,
    generation_id: i64,
    engine: String,
    principal: String,
    session_id: String,
    native_session_id: i64,
    replay_job_id: Option<i64>,
    mode: String,
    witness: Option<Value>,
    policy_version: i64,
    effective_revision: i64,
    last_verdict: String,
    approval_id: Option<i64>,
    sealed: bool,
    outcome: Option<String>,
    outcome_event_id: Option<i64>,
    outcome_payload: Option<Value>,
    late_payload: Option<Value>,
    late_event_id: Option<i64>,
    resolution: Option<String>,
    resolution_event_id: Option<i64>,
    armed_step: i32,
    #[sqlx(default)]
    is_current_epoch: bool,
    storage_history_trusted: bool,
    retention_ack_event_id: Option<i64>,
    quiescence_confirmed: bool,
}

impl AttemptRow {
    fn recovery(&self) -> Result<AuditRecoveryAttempt, MetaError> {
        Ok(AuditRecoveryAttempt {
            context: AuditAttemptContext {
                attempt_id: self.attempt_id.clone(),
                principal: self.principal.clone(),
                session_id: self.session_id.clone(),
                native_session_id: u32::try_from(self.native_session_id)
                    .map_err(|_| MetaError::InvalidCatalog)?,
                generation_id: self.generation_id,
                replay_job_id: self.replay_job_id,
                mode: if self.mode == "sql_transaction" {
                    AuditMode::SqlTransaction
                } else {
                    AuditMode::MongoCommand
                },
            },
            branch_id: self.branch_id,
            witness: self.witness()?,
            outcome: self.outcome.as_deref().map(parse_outcome).transpose()?,
            sealed: self.sealed,
            is_current_epoch: self.is_current_epoch,
            storage_history_trusted: self.storage_history_trusted,
        })
    }
    fn matches(&self, engine: &str, branch: i64, context: &AuditAttemptContext) -> bool {
        context.is_valid()
            && self.attempt_id == context.attempt_id
            && self.branch_id == branch
            && self.generation_id == context.generation_id
            && self.engine == engine
            && self.principal == context.principal
            && self.session_id == context.session_id
            && self.native_session_id == i64::from(context.native_session_id)
            && self.replay_job_id == context.replay_job_id
            && self.mode == context.mode.as_str()
    }

    fn ack(&self) -> Result<Option<OutcomeAck>, MetaError> {
        self.outcome
            .as_deref()
            .map(|outcome| {
                Ok(OutcomeAck {
                    attempt_id: self.attempt_id.clone(),
                    audit_event_id: self.outcome_event_id.ok_or(MetaError::InvalidCatalog)?,
                    outcome: parse_outcome(outcome)?,
                })
            })
            .transpose()
    }

    fn witness(&self) -> Result<Option<NativeWitnessBinding>, MetaError> {
        self.witness
            .clone()
            .map(|value| serde_json::from_value(value).map_err(|_| MetaError::InvalidCatalog))
            .transpose()
    }

    fn resolution_ack(&self) -> Result<Option<OutcomeAck>, MetaError> {
        self.resolution
            .as_deref()
            .map(|outcome| {
                Ok(OutcomeAck {
                    attempt_id: self.attempt_id.clone(),
                    audit_event_id: self.resolution_event_id.ok_or(MetaError::InvalidCatalog)?,
                    outcome: parse_outcome(outcome)?,
                })
            })
            .transpose()
    }

    fn late_ack(&self) -> Result<Option<OutcomeAck>, MetaError> {
        let Some(payload) = self.late_payload.clone() else {
            return Ok(None);
        };
        let request: AuditedOutcomeRequest =
            serde_json::from_value(payload).map_err(|_| MetaError::InvalidCatalog)?;
        Ok(Some(OutcomeAck {
            attempt_id: self.attempt_id.clone(),
            audit_event_id: self.late_event_id.ok_or(MetaError::InvalidCatalog)?,
            outcome: request.outcome,
        }))
    }
}

mod recovery;
mod status;
mod witness;

use crate::authority::{AuthorityLookup, BranchAuthority, WriteAccess, load_authority};

impl Metadata {
    pub async fn record_audited_decision(
        &self,
        engine: &str,
        branch: i64,
        request: AuditedDecisionRequest,
    ) -> Result<AuditedDecisionResponse, MetaError> {
        let observation = WriteObservation::new(WriteOperation::Decision, engine);
        let result = record_audited_decision_observed(
            self,
            AuditWrite {
                engine,
                branch,
                request,
            },
            &observation,
        )
        .await;
        observation.finish(&result);
        result
    }

    pub async fn record_audited_outcome(
        &self,
        engine: &str,
        branch: i64,
        request: AuditedOutcomeRequest,
    ) -> Result<OutcomeAck, MetaError> {
        let observation = WriteObservation::new(WriteOperation::Outcome, engine);
        let result = record_audited_outcome_observed(
            self,
            AuditWrite {
                engine,
                branch,
                request,
            },
            &observation,
        )
        .await;
        observation.finish(&result);
        result
    }

    pub async fn audit_attempt_status(
        &self,
        engine: &str,
        branch: i64,
        context: &AuditAttemptContext,
    ) -> Result<AuditStatus, MetaError> {
        let mut connection = self.pool.acquire().await?;
        let row = load_attempt(&mut connection, &context.attempt_id, false).await?;
        if !row.matches(engine, branch, context) {
            return Err(MetaError::AuditConflict);
        }
        let resolved = row.outcome.as_deref().is_some_and(|outcome| {
            outcome != "unknown"
                || row.mode == "mongo_command"
                || row.resolution.is_some()
                || row.retention_ack_event_id.is_some()
        });
        Ok(AuditStatus {
            ack: row.ack()?,
            outcome: row
                .outcome_payload
                .clone()
                .map(serde_json::from_value)
                .transpose()
                .map_err(|_| MetaError::InvalidCatalog)?,
            resolution: row.resolution_ack()?,
            retention_ack_event_id: row.retention_ack_event_id,
            late_ack: row.late_ack()?,
            late_outcome: row
                .late_payload
                .clone()
                .map(serde_json::from_value)
                .transpose()
                .map_err(|_| MetaError::InvalidCatalog)?,
            resolved,
        })
    }

    pub async fn arm_mongo_step(
        &self,
        engine: &str,
        branch: i64,
        request: MongoStepRequest,
    ) -> Result<MongoStepAck, MetaError> {
        if request.attempt.mode != AuditMode::MongoCommand || engine != "mongodb" {
            return Err(MetaError::InvalidPolicy);
        }
        let mut tx = self.begin_policy(false).await?;
        lock_branch(&mut tx, branch, false).await?;
        let row = load_attempt(&mut tx, &request.attempt.attempt_id, true).await?;
        if !row.matches(engine, branch, &request.attempt) || row.sealed || row.outcome.is_some() {
            return Err(MetaError::AuditConflict);
        }
        let expected =
            i32::try_from(request.expected_step).map_err(|_| MetaError::InvalidPolicy)?;
        if (expected == 0) != request.previous.is_none() {
            return Err(MetaError::AuditConflict);
        }
        let authority = authorize_attempt(
            &mut tx,
            AuthorityLookup {
                engine,
                branch,
                principal: &request.attempt.principal,
                write: Some(WriteAccess {
                    context: &request.attempt,
                    table_id: None,
                    approval_id: row.approval_id,
                }),
            },
            &WriteObservation::disabled(),
        )
        .await?;
        validate_attempt_admission(&row, &authority)?;
        if row.armed_step == expected.checked_add(1).ok_or(MetaError::InvalidPolicy)? {
            if let Some(previous) = &request.previous {
                let saved: Option<Value> = sqlx::query_scalar(
                    "SELECT observation FROM audit_mongo_step WHERE attempt_id=$1 AND step=$2",
                )
                .bind(&row.attempt_id)
                .bind(expected)
                .fetch_one(&mut *tx)
                .await?;
                if saved
                    != Some(serde_json::to_value(previous).map_err(|_| MetaError::InvalidPolicy)?)
                {
                    return Err(MetaError::AuditConflict);
                }
            }
            tx.commit().await?;
            return Ok(MongoStepAck {
                attempt_id: row.attempt_id,
                armed_step: u32::try_from(row.armed_step).map_err(|_| MetaError::InvalidCatalog)?,
            });
        }
        if row.armed_step != expected {
            return Err(MetaError::AuditConflict);
        }
        if let Some(previous) = request.previous {
            if !matches!(previous.state, MongoObservationState::Acknowledged) {
                return Err(MetaError::AuditConflict);
            }
            complete_mongo_step(&mut tx, &row, &previous).await?;
        }
        let step = row
            .armed_step
            .checked_add(1)
            .ok_or(MetaError::InvalidPolicy)?;
        sqlx::query("INSERT INTO audit_mongo_step(attempt_id,step) VALUES($1,$2)")
            .bind(&row.attempt_id)
            .bind(step)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE audit_attempt SET armed_step=$2,updated_at=clock_timestamp() WHERE attempt_id=$1")
            .bind(&row.attempt_id)
.bind(step)
.execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(MongoStepAck {
            attempt_id: row.attempt_id,
            armed_step: u32::try_from(step).map_err(|_| MetaError::InvalidCatalog)?,
        })
    }

    pub async fn write_fence(
        &self,
        engine: &str,
        branch: i64,
        request: WriteFenceRequest,
    ) -> Result<WriteFenceResponse, MetaError> {
        let observation = WriteObservation::new(WriteOperation::Fence, engine);
        let result = write_fence_observed(
            self,
            AuditWrite {
                engine,
                branch,
                request,
            },
            &observation,
        )
        .await;
        observation.finish(&result);
        result
    }
}

struct AuditWrite<'a, T> {
    engine: &'a str,
    branch: i64,
    request: T,
}

async fn record_audited_decision_observed(
    metadata: &Metadata,
    write: AuditWrite<'_, AuditedDecisionRequest>,
    observation: &WriteObservation,
) -> Result<AuditedDecisionResponse, MetaError> {
    let AuditWrite {
        engine,
        branch,
        request,
    } = write;
    let context = &request.attempt;
    if !context.is_valid()
        || context.principal != request.decision.principal
        || context.session_id != request.decision.session_id
        || (context.mode == AuditMode::MongoCommand) != (engine == "mongodb")
    {
        return Err(MetaError::InvalidPolicy);
    }
    let mut connection = observation
        .run(WritePhase::PoolAcquire, metadata.pool.acquire())
        .await?;
    let mut tx = crate::policy::begin_policy_on(&mut connection, false, observation).await?;
    lock_branch_observed(&mut tx, branch, false, observation).await?;
    insert_intent(
        &mut tx,
        IntentRecord {
            engine,
            branch,
            request: &request,
        },
        observation,
    )
    .await?;
    let row = load_attempt_optional(&mut tx, &context.attempt_id, true, observation).await?;
    if let Some(row) = &row {
        if !row.matches(engine, branch, context) || row.sealed || row.outcome.is_some() {
            return Err(MetaError::AuditConflict);
        }
        if row.policy_version != request.decision.policy_version
            || row.effective_revision != request.decision.effective_revision
        {
            return Err(MetaError::PolicyConflict);
        }
    }
    // Every authority deadline is sampled only after the attempt lock wait.
    let authority = authorize_attempt(
        &mut tx,
        AuthorityLookup {
            engine,
            branch,
            principal: &context.principal,
            write: Some(WriteAccess {
                context,
                table_id: Some(request.decision.operation.table_id),
                approval_id: None,
            }),
        },
        observation,
    )
    .await?;
    authority.validate_policy(
        request.decision.policy_version,
        request.decision.effective_revision,
    )?;
    let witness = authority.witness()?;
    if context.mode == AuditMode::SqlTransaction && witness.is_none() {
        return Err(MetaError::AuditPending);
    }
    let row = row.ok_or(MetaError::AuditConflict)?;
    if row.witness()? != witness {
        return Err(MetaError::AuditConflict);
    }
    let policy = authority.policy()?;
    let scope = crate::approvals::DecisionScope {
        generation_id: authority.generation_id,
        class: policy.class.as_str().into(),
        approval_after_rows: policy
            .approval_after_rows
            .map(i64::try_from)
            .transpose()
            .map_err(|_| MetaError::InvalidCatalog)?,
    };
    let record = crate::approvals::DecisionRecord {
        observation,
        branch_id: branch,
        request: &request.decision,
        attempt_id: Some(&context.attempt_id),
    };
    let response = crate::approvals::record_authorized_decision(&mut tx, &record, &scope).await?;
    observation
        .run(WritePhase::TransactionCommit, tx.commit())
        .await?;
    Ok(AuditedDecisionResponse {
        attempt_id: context.attempt_id.clone(),
        approval_id: response.approval_id,
        witness,
    })
}

async fn record_audited_outcome_observed(
    metadata: &Metadata,
    write: AuditWrite<'_, AuditedOutcomeRequest>,
    observation: &WriteObservation,
) -> Result<OutcomeAck, MetaError> {
    let AuditWrite {
        engine,
        branch,
        request,
    } = write;
    let mut connection = observation
        .run(WritePhase::PoolAcquire, metadata.pool.acquire())
        .await?;
    let mut tx = observation
        .run(WritePhase::TransactionBegin, connection.begin())
        .await?;
    if !request.attempt.is_valid() {
        return Err(MetaError::InvalidPolicy);
    }
    // The journal's scope is immutable. Existing attempts may share the branch
    // lock; a missing intent still serializes exclusively with first admission.
    let identity: Option<(i64, String)> = observation
        .run(
            WritePhase::Intent,
            sqlx::query_as("SELECT branch_id,engine FROM audit_attempt WHERE attempt_id=$1")
                .bind(&request.attempt.attempt_id)
                .fetch_optional(&mut *tx),
        )
        .await?;
    if identity
        .as_ref()
        .is_some_and(|(stored_branch, stored_engine)| {
            *stored_branch != branch || stored_engine != engine
        })
    {
        return Err(MetaError::AuditConflict);
    }
    lock_branch_observed(&mut tx, branch, identity.is_none(), observation).await?;
    let exists = if identity.is_some() {
        true
    } else {
        observation
            .run(
                WritePhase::Intent,
                sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM audit_attempt WHERE attempt_id=$1)",
                )
                .bind(&request.attempt.attempt_id)
                .fetch_one(&mut *tx),
            )
            .await?
    };
    if !exists {
        // A definitely rolled-back native transaction may precede a lost
        // first-decision request. This terminal tombstone serializes with
        // admission and refuses any delayed decision for the same attempt.
        record_unadmitted_abort(
            &mut tx,
            UnadmittedAbort {
                engine,
                branch,
                request: &request,
            },
            observation,
        )
        .await?;
    }
    let row =
        load_attempt_observed(&mut tx, &request.attempt.attempt_id, true, observation).await?;
    if !row.matches(engine, branch, &request.attempt) {
        return Err(MetaError::AuditConflict);
    }
    validate_observation(&row, &request)?;
    let payload = serde_json::to_value(&request).map_err(|_| MetaError::InvalidPolicy)?;
    if let Some(ack) = row.ack()? {
        if row.outcome_payload.as_ref() != Some(&payload) {
            let late = record_late_mongo_observation(
                &mut tx,
                LateObservation {
                    row: &row,
                    request: &request,
                    payload: &payload,
                },
                observation,
            )
            .await?;
            observation
                .run(WritePhase::TransactionCommit, tx.commit())
                .await?;
            return Ok(late);
        }
        observation
            .run(WritePhase::TransactionCommit, tx.commit())
            .await?;
        return Ok(ack);
    }
    if row.sealed {
        return Err(MetaError::AuditConflict);
    }
    if request.attempt.mode == AuditMode::MongoCommand && row.armed_step > 0 {
        complete_mongo_step_observed(
            &mut tx,
            &row,
            request.mongo.as_ref().ok_or(MetaError::InvalidPolicy)?,
            observation,
        )
        .await?;
    }
    let ack = store_outcome_observed(
        &mut tx,
        OutcomeRecord {
            row: &row,
            outcome: request.outcome,
            payload: &payload,
        },
        observation,
    )
    .await?;
    observation
        .run(WritePhase::TransactionCommit, tx.commit())
        .await?;
    Ok(ack)
}

async fn write_fence_observed(
    metadata: &Metadata,
    write: AuditWrite<'_, WriteFenceRequest>,
    observation: &WriteObservation,
) -> Result<WriteFenceResponse, MetaError> {
    let AuditWrite {
        engine,
        branch,
        request,
    } = write;
    let mut connection = observation
        .run(WritePhase::PoolAcquire, metadata.pool.acquire())
        .await?;
    let mut tx = crate::policy::begin_policy_on(&mut connection, false, observation).await?;
    lock_branch_observed(&mut tx, branch, false, observation).await?;
    let row =
        load_attempt_observed(&mut tx, &request.attempt.attempt_id, true, observation).await?;
    if !row.matches(engine, branch, &request.attempt)
        || row.sealed
        || row.outcome.is_some()
        || row.witness()? != request.witness
    {
        return Err(MetaError::AuditConflict);
    }
    if row.policy_version != request.policy_version
        || row.effective_revision != request.effective_revision
    {
        return Err(MetaError::PolicyConflict);
    }
    let authority = authorize_attempt(
        &mut tx,
        AuthorityLookup {
            engine,
            branch,
            principal: &request.attempt.principal,
            write: Some(WriteAccess {
                context: &request.attempt,
                table_id: None,
                approval_id: row.approval_id,
            }),
        },
        observation,
    )
    .await?;
    validate_attempt_admission(&row, &authority)?;
    if row.mode == "sql_transaction" && authority.witness()? != request.witness {
        return Err(MetaError::AuditPending);
    }
    observation
        .run(WritePhase::TransactionCommit, tx.commit())
        .await?;
    Ok(WriteFenceResponse {
        branch_id: branch,
        engine: engine.to_owned(),
        context: request,
        expires_at: authority.expires_at,
        lease_version: authority.lease_version,
    })
}

async fn lock_branch(
    connection: &mut PgConnection,
    branch: i64,
    exclusive: bool,
) -> Result<(), MetaError> {
    lock_branch_observed(connection, branch, exclusive, &WriteObservation::disabled()).await
}

async fn lock_branch_observed(
    connection: &mut PgConnection,
    branch: i64,
    exclusive: bool,
    observation: &WriteObservation,
) -> Result<(), MetaError> {
    let query = if exclusive {
        "SELECT id FROM branch WHERE id=$1 FOR UPDATE"
    } else {
        "SELECT id FROM branch WHERE id=$1 FOR SHARE"
    };
    observation
        .run(
            WritePhase::BranchLock,
            sqlx::query_scalar::<_, i64>(query)
                .bind(branch)
                .fetch_optional(connection),
        )
        .await?
        .ok_or(MetaError::BranchUnavailable)?;
    Ok(())
}

struct IntentRecord<'a> {
    engine: &'a str,
    branch: i64,
    request: &'a AuditedDecisionRequest,
}

async fn insert_intent(
    connection: &mut PgConnection,
    record: IntentRecord<'_>,
    observation: &WriteObservation,
) -> Result<(), MetaError> {
    let IntentRecord {
        engine,
        branch,
        request,
    } = record;
    let context = &request.attempt;
    observation
        .run(
            WritePhase::Intent,
            sqlx::query("INSERT INTO audit_attempt(attempt_id,branch_id,generation_id,engine,principal,session_id,native_session_id,replay_job_id,mode,witness,policy_version,effective_revision,last_verdict)
        SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,
          CASE WHEN $9='sql_transaction' AND b.audit_witness_ready AND b.audit_witness_version=1
                    AND NOT b.audit_storage_reclaim_started THEN
            jsonb_build_object('format_version',b.audit_witness_version,'deployment_id',d.id::text,
              'branch_id',b.id,'generation_id',b.generation_id,'storage_incarnation',b.audit_witness_incarnation)
            ELSE NULL END,$10,$11,$12
        FROM branch b LEFT JOIN replay_deployment d ON d.singleton WHERE b.id=$2
          AND ($9='mongo_command' OR (b.audit_witness_ready AND b.audit_witness_version=1
               AND NOT b.audit_storage_reclaim_started))
        ON CONFLICT(attempt_id) DO NOTHING")
                .bind(&context.attempt_id)
                .bind(branch)
                .bind(context.generation_id)
                .bind(engine)
                .bind(&context.principal)
                .bind(&context.session_id)
                .bind(i64::from(context.native_session_id))
                .bind(context.replay_job_id)
                .bind(context.mode.as_str())
                .bind(request.decision.policy_version)
                .bind(request.decision.effective_revision)
                .bind(request.decision.verdict.as_str())
                .execute(connection),
        ).await?;
    Ok(())
}

async fn load_attempt(
    connection: &mut PgConnection,
    id: &str,
    locked: bool,
) -> Result<AttemptRow, MetaError> {
    load_attempt_observed(connection, id, locked, &WriteObservation::disabled()).await
}

async fn load_attempt_observed(
    connection: &mut PgConnection,
    id: &str,
    locked: bool,
    observation: &WriteObservation,
) -> Result<AttemptRow, MetaError> {
    load_attempt_optional(connection, id, locked, observation)
        .await?
        .ok_or(MetaError::BranchUnavailable)
}

async fn load_attempt_optional(
    connection: &mut PgConnection,
    id: &str,
    locked: bool,
    observation: &WriteObservation,
) -> Result<Option<AttemptRow>, MetaError> {
    let query = if locked {
        "SELECT * FROM audit_attempt WHERE attempt_id=$1 FOR UPDATE"
    } else {
        "SELECT * FROM audit_attempt WHERE attempt_id=$1"
    };
    observation
        .run(
            WritePhase::AttemptLock,
            sqlx::query_as(query).bind(id).fetch_optional(connection),
        )
        .await
        .map_err(Into::into)
}

async fn authorize_attempt(
    connection: &mut PgConnection,
    lookup: AuthorityLookup<'_>,
    observation: &WriteObservation,
) -> Result<BranchAuthority, MetaError> {
    let authority = load_authority(connection, lookup, observation).await?;
    authority.require_write()?;
    Ok(authority)
}

fn validate_attempt_admission(
    row: &AttemptRow,
    authority: &BranchAuthority,
) -> Result<(), MetaError> {
    authority.validate_policy(row.policy_version, row.effective_revision)?;
    if row.last_verdict != "allowed"
        && !(row.last_verdict == "await_approval" && authority.approval_consumed)
    {
        return Err(MetaError::PolicyConflict);
    }
    Ok(())
}

fn validate_observation(
    row: &AttemptRow,
    request: &AuditedOutcomeRequest,
) -> Result<(), MetaError> {
    match (&request.mongo, request.attempt.mode) {
        (None, AuditMode::SqlTransaction) if request.armed_step == 0 => Ok(()),
        (Some(observation), AuditMode::MongoCommand)
            if (i32::try_from(request.armed_step).ok() == Some(row.armed_step)
                || (matches!(
                    observation.state,
                    MongoObservationState::NotSent | MongoObservationState::Unknown
                ) && i32::try_from(request.armed_step).ok()
                    == row.armed_step.checked_add(1)))
                && observation.outcome(request.armed_step) == request.outcome =>
        {
            Ok(())
        }
        _ => Err(MetaError::InvalidPolicy),
    }
}

async fn complete_mongo_step(
    connection: &mut PgConnection,
    row: &AttemptRow,
    observation: &fg_protocol_common::MongoWriteObservation,
) -> Result<(), MetaError> {
    complete_mongo_step_observed(connection, row, observation, &WriteObservation::disabled()).await
}

async fn complete_mongo_step_observed(
    connection: &mut PgConnection,
    row: &AttemptRow,
    native_observation: &fg_protocol_common::MongoWriteObservation,
    observation: &WriteObservation,
) -> Result<(), MetaError> {
    let value = serde_json::to_value(native_observation).map_err(|_| MetaError::InvalidPolicy)?;
    let changed = observation
        .run(
            WritePhase::MongoStep,
            sqlx::query(
                "UPDATE audit_mongo_step SET observation=$3,completed_at=clock_timestamp()
        WHERE attempt_id=$1 AND step=$2 AND observation IS NULL",
            )
            .bind(&row.attempt_id)
            .bind(row.armed_step)
            .bind(value)
            .execute(connection),
        )
        .await?;
    if changed.rows_affected() != 1 {
        return Err(MetaError::AuditConflict);
    }
    Ok(())
}

async fn store_outcome(
    connection: &mut PgConnection,
    row: &AttemptRow,
    outcome: TransactionOutcome,
    payload: &Value,
) -> Result<OutcomeAck, MetaError> {
    store_outcome_observed(
        connection,
        OutcomeRecord {
            row,
            outcome,
            payload,
        },
        &WriteObservation::disabled(),
    )
    .await
}

struct OutcomeRecord<'a> {
    row: &'a AttemptRow,
    outcome: TransactionOutcome,
    payload: &'a Value,
}

async fn store_outcome_observed(
    connection: &mut PgConnection,
    record: OutcomeRecord<'_>,
    observation: &WriteObservation,
) -> Result<OutcomeAck, MetaError> {
    if record.row.mode == "sql_transaction" {
        return store_sql_outcome(connection, record, observation).await;
    }
    let OutcomeRecord {
        row,
        outcome,
        payload,
    } = record;
    let (steps,confirmed):(Value,i64)=observation
        .run(
            WritePhase::AuditEvent,
            sqlx::query_as("SELECT COALESCE(jsonb_agg(jsonb_build_object('step',step,'observation',observation) ORDER BY step),'[]'::jsonb),
        count(*) FILTER(WHERE observation->>'state' IN ('acknowledged','acknowledged_with_errors')) FROM audit_mongo_step WHERE attempt_id=$1")
                .bind(&row.attempt_id)
                .fetch_one(&mut *connection),
        ).await?;
    let event_payload = json!({"generation_id":row.generation_id,"session_id":row.session_id,
        "attempt_id":row.attempt_id,"outcome":outcome,"atomic":row.mode=="sql_transaction",
        "mongo":payload.get("mongo"),"confirmed_steps":confirmed,"mongo_steps":steps});
    let id:i64=observation
        .run(
            WritePhase::AuditEvent,
            sqlx::query_scalar("INSERT INTO audit_event(actor,branch_id,event_type,payload) VALUES($1,$2,'policy_outcome',$3) RETURNING id")
                .bind(&row.principal)
                .bind(row.branch_id)
                .bind(event_payload)
                .fetch_one(&mut *connection),
        ).await?;
    observation
        .run(
            WritePhase::AuditEvent,
            sqlx::query("UPDATE audit_attempt SET outcome=$2,outcome_event_id=$3,outcome_payload=$4,updated_at=clock_timestamp() WHERE attempt_id=$1")
                .bind(&row.attempt_id)
                .bind(outcome.as_str())
                .bind(id)
                .bind(payload)
                .execute(connection),
        ).await?;
    Ok(OutcomeAck {
        attempt_id: row.attempt_id.clone(),
        audit_event_id: id,
        outcome,
    })
}

async fn store_sql_outcome(
    connection: &mut PgConnection,
    record: OutcomeRecord<'_>,
    observation: &WriteObservation,
) -> Result<OutcomeAck, MetaError> {
    let OutcomeRecord {
        row,
        outcome,
        payload,
    } = record;
    let event_payload = json!({"generation_id":row.generation_id,"session_id":row.session_id,
        "attempt_id":row.attempt_id,"outcome":outcome,"atomic":true,
        "mongo":payload.get("mongo"),"confirmed_steps":0,"mongo_steps":[]});
    let id: i64 = observation
        .run(
            WritePhase::AuditEvent,
            sqlx::query_scalar(
                "WITH recorded AS (
           INSERT INTO audit_event(actor,branch_id,event_type,payload)
           VALUES($1,$2,'policy_outcome',$3) RETURNING id
         ) UPDATE audit_attempt SET outcome=$5,outcome_event_id=recorded.id,
             outcome_payload=$6,updated_at=clock_timestamp()
           FROM recorded WHERE attempt_id=$4 RETURNING outcome_event_id",
            )
            .bind(&row.principal)
            .bind(row.branch_id)
            .bind(event_payload)
            .bind(&row.attempt_id)
            .bind(outcome.as_str())
            .bind(payload)
            .fetch_one(connection),
        )
        .await?;
    Ok(OutcomeAck {
        attempt_id: row.attempt_id.clone(),
        audit_event_id: id,
        outcome,
    })
}

struct LateObservation<'a> {
    row: &'a AttemptRow,
    request: &'a AuditedOutcomeRequest,
    payload: &'a Value,
}

async fn record_late_mongo_observation(
    connection: &mut PgConnection,
    record: LateObservation<'_>,
    observation: &WriteObservation,
) -> Result<OutcomeAck, MetaError> {
    let LateObservation {
        row,
        request,
        payload,
    } = record;
    if row.mode != "mongo_command"
        || !row.sealed
        || !row.quiescence_confirmed
        || row.outcome.as_deref() != Some("unknown")
    {
        return Err(MetaError::AuditConflict);
    }
    if let Some(previous) = &row.late_payload {
        if previous != payload {
            return Err(MetaError::AuditConflict);
        }
        return row.late_ack()?.ok_or(MetaError::InvalidCatalog);
    }
    let event = json!({"attempt_id":row.attempt_id,"generation_id":row.generation_id,"session_id":row.session_id,
        "atomic":false,"original_outcome":"unknown","reported_outcome":request.outcome,"mongo":request.mongo,"armed_step":request.armed_step});
    let id:i64=observation
        .run(
            WritePhase::AuditEvent,
            sqlx::query_scalar("INSERT INTO audit_event(actor,branch_id,event_type,payload) VALUES($1,$2,'policy_outcome_late_observation',$3) RETURNING id")
                .bind(&row.principal)
                .bind(row.branch_id)
                .bind(event)
                .fetch_one(&mut *connection),
        ).await?;
    observation
        .run(
            WritePhase::AuditEvent,
            sqlx::query("UPDATE audit_attempt SET late_payload=$2,late_event_id=$3,updated_at=clock_timestamp() WHERE attempt_id=$1")
                .bind(&row.attempt_id)
                .bind(payload)
                .bind(id)
                .execute(connection),
        ).await?;
    Ok(OutcomeAck {
        attempt_id: row.attempt_id.clone(),
        audit_event_id: id,
        outcome: request.outcome,
    })
}

struct UnadmittedAbort<'a> {
    engine: &'a str,
    branch: i64,
    request: &'a AuditedOutcomeRequest,
}

async fn record_unadmitted_abort(
    connection: &mut PgConnection,
    abort: UnadmittedAbort<'_>,
    observation: &WriteObservation,
) -> Result<(), MetaError> {
    let UnadmittedAbort {
        engine,
        branch,
        request,
    } = abort;
    if request.outcome != TransactionOutcome::RolledBack
        || request.armed_step != 0
        || request
            .mongo
            .as_ref()
            .is_some_and(|observation| observation.state != MongoObservationState::NotSent)
        || (request.attempt.mode == AuditMode::MongoCommand) != (engine == "mongodb")
    {
        return Err(MetaError::AuditConflict);
    }
    let context = &request.attempt;
    let scope:Option<(i64,i64)>=observation
        .run(
            WritePhase::Intent,
            sqlx::query_as("SELECT p.version,forkget_budget_revision(b.id)
        FROM branch b JOIN generation g ON g.id=b.generation_id
        JOIN LATERAL(SELECT version FROM policy_version WHERE class=b.class ORDER BY version DESC LIMIT 1)p ON TRUE
        WHERE b.id=$1 AND b.created_by=$2 AND b.generation_id=$3 AND g.engine=$4")
                .bind(branch)
                .bind(&context.principal)
                .bind(context.generation_id)
                .bind(engine)
                .fetch_optional(&mut *connection),
        ).await?;
    let (version, revision) = scope.ok_or(MetaError::BranchUnavailable)?;
    let payload = serde_json::to_value(request).map_err(|_| MetaError::InvalidPolicy)?;
    let event = json!({"generation_id":context.generation_id,"session_id":context.session_id,"attempt_id":context.attempt_id,
        "outcome":"rolled_back","atomic":context.mode==AuditMode::SqlTransaction,"mongo":request.mongo,"admitted":false});
    let id:i64=observation
        .run(
            WritePhase::Intent,
            sqlx::query_scalar("INSERT INTO audit_event(actor,branch_id,event_type,payload) VALUES($1,$2,'policy_outcome',$3) RETURNING id")
                .bind(&context.principal)
                .bind(branch)
                .bind(event)
                .fetch_one(&mut *connection),
        ).await?;
    observation
        .run(
            WritePhase::Intent,
            sqlx::query("INSERT INTO audit_attempt(attempt_id,branch_id,generation_id,engine,principal,session_id,native_session_id,replay_job_id,mode,
        policy_version,effective_revision,last_verdict,outcome,outcome_event_id,outcome_payload,witness_collected)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'native_error','rolled_back',$12,$13,TRUE)")
                .bind(&context.attempt_id)
                .bind(branch)
                .bind(context.generation_id)
                .bind(engine)
                .bind(&context.principal)
                .bind(&context.session_id)
                .bind(i64::from(context.native_session_id))
                .bind(context.replay_job_id)
                .bind(context.mode.as_str())
                .bind(version)
                .bind(revision)
                .bind(id)
                .bind(payload)
                .execute(connection),
        ).await?;
    Ok(())
}

fn parse_outcome(outcome: &str) -> Result<TransactionOutcome, MetaError> {
    match outcome {
        "committed" => Ok(TransactionOutcome::Committed),
        "rolled_back" => Ok(TransactionOutcome::RolledBack),
        "unknown" => Ok(TransactionOutcome::Unknown),
        _ => Err(MetaError::InvalidCatalog),
    }
}

#[cfg(test)]
mod tests;
