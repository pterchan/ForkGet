use serde::Serialize;
use sqlx::{FromRow, types::JsonValue};

use crate::{MetaError, Metadata};

pub struct AuditFilter<'a> {
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub event_type: Option<&'a str>,
    pub after: i64,
    pub limit: u32,
}

#[derive(FromRow, Serialize)]
pub struct AuditEvent {
    id: i64,
    occurred_at: i64,
    actor: String,
    event_type: String,
    payload: JsonValue,
}

#[derive(Serialize)]
pub struct AuditPage {
    events: Vec<AuditEvent>,
    next_after: Option<i64>,
}

impl Metadata {
    pub async fn audit_page(
        &self,
        branch: i64,
        principal: &str,
        filter: AuditFilter<'_>,
    ) -> Result<AuditPage, MetaError> {
        self.detail(principal, branch).await?;
        let mut events = sqlx::query_as::<_, AuditEvent>(
            "SELECT e.id, floor(extract(epoch FROM e.occurred_at))::bigint AS occurred_at,
                 e.actor, e.event_type,
                 CASE e.event_type
                   WHEN 'policy_decision' THEN jsonb_strip_nulls(jsonb_build_object(
                     'generation_id', e.payload->'generation_id', 'policy_version', e.payload->'policy_version',
                     'table_id', e.payload->'table_id', 'kind', e.payload->'kind', 'rows', e.payload->'rows',
                     'verdict', e.payload->'verdict', 'approval_id', e.payload->'approval_id',
                     'session_id', e.payload->'session_id', 'effective_revision', e.payload->'effective_revision',
                     'attempt_id', e.payload->'attempt_id'))
                   WHEN 'policy_outcome' THEN jsonb_strip_nulls(jsonb_build_object(
                     'generation_id', e.payload->'generation_id', 'outcome', e.payload->'outcome',
                     'session_id', e.payload->'session_id','attempt_id',e.payload->'attempt_id',
                     'atomic',e.payload->'atomic','mongo',e.payload->'mongo',
                     'confirmed_steps',e.payload->'confirmed_steps','mongo_steps',e.payload->'mongo_steps',
                     'admitted',e.payload->'admitted'))
                   WHEN 'policy_outcome_resolved' THEN jsonb_build_object(
                     'attempt_id',e.payload->'attempt_id','generation_id',e.payload->'generation_id',
                     'session_id',e.payload->'session_id','original_outcome',e.payload->'original_outcome',
                     'outcome',e.payload->'outcome','evidence',e.payload->'evidence')
                   WHEN 'policy_outcome_retention_ack' THEN jsonb_build_object(
                     'attempt_id',e.payload->'attempt_id','generation_id',e.payload->'generation_id',
                     'outcome',e.payload->'outcome','reason',e.payload->'reason')
                   WHEN 'policy_outcome_late_observation' THEN jsonb_build_object(
                     'attempt_id',e.payload->'attempt_id','generation_id',e.payload->'generation_id',
                     'session_id',e.payload->'session_id','atomic',false,'original_outcome','unknown',
                     'reported_outcome',e.payload->'reported_outcome','mongo',e.payload->'mongo','armed_step',e.payload->'armed_step')
                   WHEN 'approval_state' THEN jsonb_strip_nulls(jsonb_build_object(
                     'approval_id', e.payload->'approval_id', 'generation_id', e.payload->'generation_id',
                     'policy_version', e.payload->'policy_version', 'state', e.payload->'state', 'reason', e.payload->'reason'))
                   WHEN 'branch_dropping' THEN jsonb_strip_nulls(jsonb_build_object('reason', e.payload->'reason'))
                   WHEN 'budget_requested' THEN jsonb_build_object('budget_id', e.payload->'budget_id')
                   WHEN 'budget_reviewed' THEN jsonb_build_object('budget_id', e.payload->'budget_id')
                   WHEN 'budget_granted' THEN jsonb_build_object('budget_id', e.payload->'budget_id')
                   WHEN 'budget_revoked' THEN jsonb_build_object('budget_id', e.payload->'budget_id')
                   ELSE '{}'::jsonb END AS payload
             FROM audit_event e JOIN branch b ON b.id = e.branch_id
             WHERE b.id = $1 AND b.created_by = $2 AND e.id > $3
               AND ($4::double precision IS NULL OR e.occurred_at >= to_timestamp($4))
               AND ($5::double precision IS NULL OR e.occurred_at < to_timestamp($5))
               AND ($6::text IS NULL OR e.event_type = $6)
             ORDER BY e.id LIMIT $7",
        )
        .bind(branch).bind(principal).bind(filter.after)
        .bind(filter.since.map(|seconds| seconds as f64)).bind(filter.until.map(|seconds| seconds as f64))
        .bind(filter.event_type).bind(i64::from(filter.limit) + 1).fetch_all(&self.pool).await?;
        let next_after = if events.len() > filter.limit as usize {
            events.pop();
            events.last().map(|event| event.id)
        } else {
            None
        };
        Ok(AuditPage { events, next_after })
    }
}
