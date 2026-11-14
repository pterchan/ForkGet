use fg_protocol_common::{
    ApprovalContext, ApprovalState, BranchClass, DecisionRequest, DecisionResponse, DecisionVerdict,
};
use serde::Serialize;
use sqlx::{FromRow, PgConnection};

use crate::write_observation::{WriteObservation, WritePhase};
use crate::{MetaError, Metadata};

const APPROVAL_SECONDS: i32 = 60;
const APPROVAL_LIST_LIMIT: i64 = 100;

#[derive(Clone, Copy)]
pub struct ApprovalKey {
    pub branch_id: i64,
    pub id: i64,
}

pub struct ApprovalReview<'a> {
    pub actor: &'a str,
    pub owners: &'a [String],
    pub approve: bool,
}

pub(crate) struct DecisionRecord<'a> {
    pub observation: &'a WriteObservation,
    pub branch_id: i64,
    pub request: &'a DecisionRequest,
    pub attempt_id: Option<&'a str>,
}

#[derive(FromRow, Serialize)]
pub struct ApprovalSummary {
    id: i64,
    policy_version: i64,
    table_id: i64,
    kind: String,
    rows: i64,
    state: String,
    expires_at: i64,
}

#[derive(FromRow)]
pub(crate) struct DecisionScope {
    pub generation_id: i64,
    pub class: String,
    pub approval_after_rows: Option<i64>,
}

#[derive(FromRow)]
struct ApprovalRow {
    state: String,
    is_expired: bool,
    is_current: bool,
}

enum ApprovalAccess<'a> {
    Session(&'a ApprovalContext),
    Reviewer(&'a ApprovalReview<'a>),
}

impl Metadata {
    #[cfg(test)]
    pub(crate) async fn record_decision(
        &self,
        engine: &str,
        branch_id: i64,
        request: DecisionRequest,
    ) -> Result<DecisionResponse, MetaError> {
        let mut tx = self.begin_policy(false).await?;
        let observation = WriteObservation::disabled();
        let record = DecisionRecord {
            observation: &observation,
            branch_id,
            request: &request,
            attempt_id: None,
        };
        let response = record_decision_in(&mut tx, engine, &record).await?;
        tx.commit().await?;
        Ok(response)
    }

    pub async fn approvals(
        &self,
        engine: &str,
        branch_id: i64,
        actor: &str,
        owners: &[String],
    ) -> Result<Vec<ApprovalSummary>, MetaError> {
        let authorized: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM branch b JOIN generation g ON g.id = b.generation_id
             WHERE b.id = $1 AND g.engine = $2 AND (b.created_by = $3 OR b.created_by = ANY($4)))",
        )
        .bind(branch_id)
        .bind(engine)
        .bind(actor)
        .bind(owners)
        .fetch_one(&self.pool)
        .await?;
        if !authorized {
            return Err(MetaError::BranchUnavailable);
        }
        sqlx::query_as(
            "SELECT id, policy_version, table_id, kind, rows,
                CASE WHEN state IN ('pending','approved') AND expires_at <= clock_timestamp()
                    THEN 'expired' ELSE state END AS state,
                floor(extract(epoch FROM expires_at))::bigint AS expires_at
             FROM policy_approval WHERE branch_id = $1
             ORDER BY (state IN ('pending','approved') AND expires_at > clock_timestamp()) DESC, id DESC
             LIMIT $2",
        )
.bind(branch_id)
.bind(APPROVAL_LIST_LIMIT).fetch_all(&self.pool).await.map_err(Into::into)
    }

    pub async fn review_approval(
        &self,
        engine: &str,
        key: ApprovalKey,
        review: ApprovalReview<'_>,
    ) -> Result<ApprovalState, MetaError> {
        let mut tx = self.begin_policy(false).await?;
        let row = approval_row(&mut tx, engine, key, ApprovalAccess::Reviewer(&review)).await?;
        let state = refresh_state(&mut tx, key, &row).await?;
        if state != "pending" {
            tx.commit().await?;
            return Err(MetaError::ApprovalConflict);
        }
        let (state, result) = if review.approve {
            ("approved", ApprovalState::Approved)
        } else {
            ("denied", ApprovalState::Denied)
        };
        let actual = transition(&mut tx, key, review.actor, state).await?;
        tx.commit().await?;
        if actual == state {
            Ok(result)
        } else {
            Err(MetaError::ApprovalConflict)
        }
    }

    pub async fn poll_approval(
        &self,
        engine: &str,
        key: ApprovalKey,
        context: ApprovalContext,
    ) -> Result<ApprovalState, MetaError> {
        let mut tx = self.begin_policy(false).await?;
        let row = approval_row(&mut tx, engine, key, ApprovalAccess::Session(&context)).await?;
        let state = match refresh_state(&mut tx, key, &row).await? {
            "pending" => ApprovalState::Pending,
            "approved" => match transition(&mut tx, key, &context.principal, "consumed")
                .await?
                .as_str()
            {
                "consumed" => ApprovalState::Approved,
                "expired" => ApprovalState::Expired,
                _ => return Err(MetaError::InvalidCatalog),
            },
            "denied" => ApprovalState::Denied,
            "expired" => ApprovalState::Expired,
            "invalidated" | "consumed" => ApprovalState::Invalidated,
            _ => return Err(MetaError::InvalidCatalog),
        };
        tx.commit().await?;
        Ok(state)
    }

    pub async fn invalidate_approval(
        &self,
        engine: &str,
        key: ApprovalKey,
        context: ApprovalContext,
    ) -> Result<(), MetaError> {
        let mut tx = self.begin_policy(false).await?;
        let row = approval_row(&mut tx, engine, key, ApprovalAccess::Session(&context)).await?;
        if matches!(
            refresh_state(&mut tx, key, &row).await?,
            "pending" | "approved"
        ) {
            transition(&mut tx, key, "system:approval", "invalidated").await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn invalidate_approvals_on_start(&self) -> Result<(), MetaError> {
        let mut tx = self.begin_policy(true).await?;
        invalidate(&mut tx, None, None, "control_restart").await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn register_proxy_epoch(&self, epoch: &str) -> Result<(), MetaError> {
        let mut tx = self.begin_policy(true).await?;
        let result = sqlx::query(
            "UPDATE policy_proxy_epoch SET epoch = $1 WHERE singleton AND epoch IS DISTINCT FROM $1",
        )
.bind(epoch)
.execute(&mut *tx).await?;
        if result.rows_affected() == 1 {
            invalidate(&mut tx, None, None, "proxy_restart").await?;
            // Proxy registration follows its native clean-start barrier.
            sqlx::query("UPDATE branch SET capture_active=FALSE WHERE capture_active")
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) async fn record_decision_in(
    connection: &mut PgConnection,
    engine: &str,
    record: &DecisionRecord<'_>,
) -> Result<DecisionResponse, MetaError> {
    let scope = decision_scope(connection, engine, record).await?;
    let effective = crate::policy::branch_policy(
        connection,
        engine,
        record.branch_id,
        &record.request.principal,
    )
    .await?;
    if effective.version != record.request.policy_version
        || effective.effective_revision != record.request.effective_revision
    {
        return Err(MetaError::PolicyConflict);
    }
    record_authorized_decision(connection, record, &scope).await
}

pub(crate) async fn record_authorized_decision(
    connection: &mut PgConnection,
    record: &DecisionRecord<'_>,
    scope: &DecisionScope,
) -> Result<DecisionResponse, MetaError> {
    let DecisionRecord {
        observation,
        branch_id,
        request,
        attempt_id,
        ..
    } = record;
    let branch_id = *branch_id;
    let rows = i64::try_from(request.rows).map_err(|_| MetaError::InvalidPolicy)?;
    let approval_id = if request.verdict == DecisionVerdict::AwaitApproval {
        if scope
            .approval_after_rows
            .is_none_or(|minimum| rows < minimum)
        {
            return Err(MetaError::PolicyConflict);
        }
        Some(
            create_approval(
                connection,
                ApprovalCreation {
                    branch_id,
                    request,
                    scope,
                    rows,
                },
                observation,
            )
            .await?,
        )
    } else {
        None
    };
    let (events,updated): (i64,i64) = observation
        .run(
            WritePhase::AuditEvent,
            sqlx::query_as(
                "WITH recorded AS (INSERT INTO audit_event(actor,branch_id,event_type,payload)
         VALUES($1,$2,'policy_decision',jsonb_strip_nulls(jsonb_build_object(
            'generation_id',$3::bigint,'policy_version',$4::bigint,'table_id',$5::bigint,
            'kind',$6::text,'rows',$7::bigint,'verdict',$8::text,'approval_id',$9::bigint,
            'session_id',$10::text,'effective_revision',$11::bigint,'attempt_id',$12::text))) RETURNING id),
         updated AS (UPDATE audit_attempt SET
            last_verdict=CASE WHEN $8='native_error' THEN last_verdict ELSE $8 END,
            approval_id=CASE WHEN $8='native_error' THEN approval_id ELSE $9 END,
            updated_at=clock_timestamp() WHERE attempt_id=$12 RETURNING attempt_id)
         SELECT (SELECT count(*) FROM recorded),(SELECT count(*) FROM updated)",
            )
            .bind(&request.principal)
            .bind(branch_id)
            .bind(scope.generation_id)
            .bind(request.policy_version)
            .bind(request.operation.table_id)
            .bind(request.operation.kind.as_str())
            .bind(rows)
            .bind(request.verdict.as_str())
            .bind(approval_id)
            .bind(&request.session_id)
            .bind(request.effective_revision)
            .bind(attempt_id)
            .fetch_one(connection),
        )
        .await?;
    if events != 1 || updated != i64::from(attempt_id.is_some()) {
        return Err(MetaError::AuditConflict);
    }
    Ok(DecisionResponse { approval_id })
}

#[cfg(test)]
async fn decision_scope(
    connection: &mut PgConnection,
    engine: &str,
    record: &DecisionRecord<'_>,
) -> Result<DecisionScope, MetaError> {
    let DecisionRecord {
        branch_id,
        request,
        observation,
        ..
    } = record;
    let branch_id = *branch_id;
    // Evaluate deadlines only after a lifecycle lock wait has completed.
    observation
        .run(
            WritePhase::BranchLock,
            sqlx::query_scalar::<_, i64>("SELECT id FROM branch WHERE id=$1 FOR SHARE")
                .bind(branch_id)
                .fetch_optional(&mut *connection),
        )
        .await?
        .ok_or(MetaError::BranchUnavailable)?;
    observation
        .run(
            WritePhase::FreshScope,
            sqlx::query_as(
                "SELECT b.generation_id, b.class, p.approval_after_rows
         FROM branch b JOIN generation g ON g.id = b.generation_id
         JOIN policy_version p ON p.class = b.class AND p.version = $5
         JOIN catalog_table c ON c.generation_id = g.id AND c.id = $6
         JOIN policy_proxy_epoch e ON e.epoch = split_part($4, ':', 1)
         WHERE b.id = $1 AND b.created_by = $2 AND g.engine = $3
            AND b.access = 'read_write'
            AND (NOT EXISTS (SELECT 1 FROM replay_job j WHERE j.branch_id=b.id AND j.state<>'verified')
                OR EXISTS (SELECT 1 FROM replay_job j WHERE j.branch_id=b.id AND j.session_id=$4 AND j.state='running'))
           AND b.status = 'active' AND b.expires_at > clock_timestamp()
           AND NOT b.capture_active AND g.reclaim_started_at IS NULL
           AND g.status IN ('active', 'retiring')",
            )
                .bind(branch_id)
                .bind(&request.principal)
                .bind(engine)
                .bind(&request.session_id)
                .bind(request.policy_version)
                .bind(request.operation.table_id)
                .fetch_optional(connection),
        ).await?
    .ok_or(MetaError::BranchUnavailable)
}

struct ApprovalCreation<'a> {
    branch_id: i64,
    request: &'a DecisionRequest,
    scope: &'a DecisionScope,
    rows: i64,
}

async fn create_approval(
    connection: &mut PgConnection,
    creation: ApprovalCreation<'_>,
    observation: &WriteObservation,
) -> Result<i64, MetaError> {
    let ApprovalCreation {
        branch_id,
        request,
        scope,
        rows,
    } = creation;
    expire_session_approvals(connection, &request.session_id, observation).await?;
    observation
        .run(
            WritePhase::Approval,
            sqlx::query_scalar(
                "INSERT INTO policy_approval (branch_id, generation_id, principal, session_id, class,
              policy_version, table_id, kind, rows, expires_at, effective_revision)
         SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9,
                 LEAST(b.expires_at, clock_timestamp() + make_interval(secs => $10)), $11
         FROM branch b WHERE b.id = $1 AND b.expires_at > clock_timestamp()
         RETURNING id",
            )
                .bind(branch_id)
                .bind(scope.generation_id)
                .bind(&request.principal)
                .bind(&request.session_id)
                .bind(&scope.class)
                .bind(request.policy_version)
                .bind(request.operation.table_id)
                .bind(request.operation.kind.as_str())
                .bind(rows)
                .bind(f64::from(APPROVAL_SECONDS))
                .bind(request.effective_revision)
                .fetch_optional(connection),
        ).await
    .map_err(|error| {
        if error.as_database_error().is_some_and(|database| {
            database.is_unique_violation()
                && database.constraint() == Some("one_live_invocation_approval")
        }) {
            MetaError::ApprovalConflict
        } else {
            MetaError::Database(error)
        }
    })?
    .ok_or(MetaError::BranchUnavailable)
}

async fn expire_session_approvals(
    connection: &mut PgConnection,
    session: &str,
    observation: &WriteObservation,
) -> Result<(), MetaError> {
    observation
        .run(
            WritePhase::Approval,
            sqlx::query(
                "WITH changed AS (
             UPDATE policy_approval SET state = 'expired' WHERE session_id = $1
               AND state IN ('pending','approved') AND expires_at <= clock_timestamp()
             RETURNING branch_id, id, generation_id, policy_version
         ) INSERT INTO audit_event (actor, branch_id, event_type, payload)
         SELECT 'system:approval', branch_id, 'approval_state', jsonb_build_object('approval_id', id,
             'generation_id', generation_id, 'policy_version', policy_version, 'state', 'expired')
         FROM changed",
            )
                .bind(session)
                .execute(connection),
        ).await?;
    Ok(())
}

async fn approval_row(
    connection: &mut PgConnection,
    engine: &str,
    key: ApprovalKey,
    access: ApprovalAccess<'_>,
) -> Result<ApprovalRow, MetaError> {
    // Keep branch lifecycle transitions ordered before locking an approval row.
    sqlx::query_scalar::<_, i64>("SELECT id FROM branch WHERE id = $1 FOR SHARE")
        .bind(key.branch_id)
        .fetch_optional(&mut *connection)
        .await?
        .ok_or(MetaError::BranchUnavailable)?;
    let (principal, session, reviewer, owners) = match access {
        ApprovalAccess::Session(context) => (
            Some(&context.principal),
            Some(&context.session_id),
            None,
            &[][..],
        ),
        ApprovalAccess::Reviewer(review) => (None, None, Some(review.actor), review.owners),
    };
    sqlx::query_as(
        "SELECT a.state, a.expires_at <= clock_timestamp() AS is_expired,
            (b.status = 'active' AND b.access = 'read_write' AND b.expires_at > clock_timestamp()
             AND g.status IN ('active','retiring') AND b.generation_id = a.generation_id
             AND b.created_by = a.principal AND b.class = a.class
             AND a.policy_version = (SELECT max(version) FROM policy_version WHERE class = b.class)
             AND a.effective_revision = forkget_budget_revision(b.id)
             AND EXISTS (SELECT 1 FROM policy_proxy_epoch WHERE epoch = split_part(a.session_id, ':', 1))) AS is_current
         FROM policy_approval a JOIN branch b ON b.id = a.branch_id
         JOIN generation g ON g.id = b.generation_id
         WHERE a.branch_id = $1 AND a.id = $2 AND g.engine = $3
           AND ((a.principal = $4 AND a.session_id = $5)
                OR (a.principal <> $6 AND a.principal = ANY($7))) FOR UPDATE OF a",
    )
.bind(key.branch_id)
.bind(key.id)
.bind(engine)
.bind(principal)
.bind(session)
        .bind(reviewer)
.bind(owners)
.fetch_optional(connection).await?
        .ok_or(MetaError::BranchUnavailable)
}

async fn refresh_state<'a>(
    connection: &mut PgConnection,
    key: ApprovalKey,
    row: &'a ApprovalRow,
) -> Result<&'a str, MetaError> {
    if !matches!(row.state.as_str(), "pending" | "approved") {
        return Ok(&row.state);
    }
    let state = if row.is_expired {
        "expired"
    } else if !row.is_current {
        "invalidated"
    } else {
        return Ok(&row.state);
    };
    transition(connection, key, "system:approval", state).await?;
    Ok(state)
}

async fn transition(
    connection: &mut PgConnection,
    key: ApprovalKey,
    actor: &str,
    state: &str,
) -> Result<String, MetaError> {
    let next = sqlx::query_scalar(
        "WITH changed AS (
             UPDATE policy_approval a SET state = CASE
                 WHEN $3 IN ('approved','denied','consumed') AND a.expires_at <= clock_timestamp()
                     THEN 'expired' ELSE $3 END
             WHERE branch_id = $1 AND id = $2
             RETURNING branch_id, id, generation_id, policy_version, state
         ), logged AS (
             INSERT INTO audit_event (actor, branch_id, event_type, payload)
             SELECT CASE WHEN state = 'expired' THEN 'system:approval' ELSE $4 END,
                 branch_id, 'approval_state', jsonb_build_object('approval_id', id,
                 'generation_id', generation_id, 'policy_version', policy_version, 'state', state)
             FROM changed
         ) SELECT state FROM changed",
    )
    .bind(key.branch_id)
    .bind(key.id)
    .bind(state)
    .bind(actor)
    .fetch_one(connection)
    .await?;
    Ok(next)
}

pub(crate) async fn invalidate_class(
    connection: &mut PgConnection,
    class: BranchClass,
    version: i64,
) -> Result<(), MetaError> {
    invalidate(connection, Some((class, version)), None, "policy_change").await
}

pub(crate) async fn invalidate_branches(
    connection: &mut PgConnection,
    ids: &[i64],
) -> Result<(), MetaError> {
    invalidate(connection, None, Some(ids), "branch_drop").await
}

pub(crate) async fn invalidate_budget(
    connection: &mut PgConnection,
    id: i64,
) -> Result<(), MetaError> {
    invalidate(connection, None, Some(&[id]), "budget_change").await
}

async fn invalidate(
    connection: &mut PgConnection,
    policy: Option<(BranchClass, i64)>,
    ids: Option<&[i64]>,
    reason: &str,
) -> Result<(), MetaError> {
    sqlx::query(
        "WITH changed AS (
             UPDATE policy_approval SET state = 'invalidated' WHERE state IN ('pending','approved')
               AND ($1::text IS NULL OR (class = $1 AND policy_version <> $2))
               AND ($3::bigint[] IS NULL OR branch_id = ANY($3))
             RETURNING branch_id, id, generation_id, policy_version
         ) INSERT INTO audit_event (actor, branch_id, event_type, payload)
         SELECT 'system:approval', branch_id, 'approval_state', jsonb_build_object('approval_id', id,
             'generation_id', generation_id, 'policy_version', policy_version,
             'state', 'invalidated', 'reason', $4::text) FROM changed",
    )
.bind(policy.map(|(class, _)| class.as_str()))
.bind(policy.map(|(_, version)| version))
        .bind(ids)
.bind(reason)
.execute(connection).await?;
    Ok(())
}
