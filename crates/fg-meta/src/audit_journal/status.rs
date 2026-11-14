use crate::{MetaError, Metadata};
use serde_json::Value;

impl Metadata {
    pub(crate) async fn branch_audit_status(
        &self,
        engine: &str,
        branch: i64,
    ) -> Result<Value, MetaError> {
        sqlx::query_scalar("SELECT jsonb_build_object(
            'witness_ready',b.audit_witness_ready,'storage_invalidated',b.audit_storage_invalidated,
            'requires_witness',b.layout='native_copy' AND g.engine<>'mongodb' AND b.status IN ('active','provisioning') AND NOT b.audit_storage_reclaim_started,
            'storage_reclaim_started',b.audit_storage_reclaim_started,
            'pending_delivery',count(a.attempt_id) FILTER(WHERE a.outcome IS NULL),
            'sql_unresolved_unknown',count(a.attempt_id) FILTER(WHERE a.mode='sql_transaction' AND a.outcome='unknown' AND a.resolution IS NULL AND a.retention_ack_event_id IS NULL),
            'mongo_unknown',count(a.attempt_id) FILTER(WHERE a.mode='mongo_command' AND a.outcome='unknown'),
            'mongo_partial',count(a.attempt_id) FILTER(WHERE a.mode='mongo_command' AND (a.outcome_payload->'mongo'->>'state'='acknowledged_with_errors' OR a.late_payload->'mongo'->>'state'='acknowledged_with_errors')),
            'oldest_pending_at',floor(extract(epoch FROM min(a.created_at) FILTER(WHERE forkget_audit_pending(a))))::bigint,
            'cleanup_blocked',COALESCE(bool_or(forkget_audit_pending(a)) FILTER(WHERE a.attempt_id IS NOT NULL),FALSE),
            'latest_mongo_observation',(SELECT jsonb_build_object('attempt_id',m.attempt_id,'outcome',m.outcome,'observation',m.outcome_payload->'mongo','late_reported_outcome',m.late_payload->'outcome','late_observation',m.late_payload->'mongo') FROM audit_attempt m WHERE m.branch_id=b.id AND m.mode='mongo_command' AND m.outcome IS NOT NULL ORDER BY m.updated_at DESC LIMIT 1))
            FROM branch b JOIN generation g ON g.id=b.generation_id LEFT JOIN audit_attempt a ON a.branch_id=b.id
            WHERE b.id=$1 AND g.engine=$2 GROUP BY b.id,g.engine")
            .bind(branch).bind(engine).fetch_optional(&self.pool).await?.ok_or(MetaError::BranchUnavailable)
    }

    pub async fn deployment_audit_status(&self, engine: &str) -> Result<Value, MetaError> {
        sqlx::query_scalar("SELECT jsonb_build_object(
            'pending_delivery',count(*) FILTER(WHERE outcome IS NULL),
            'sql_unresolved_unknown',count(*) FILTER(WHERE mode='sql_transaction' AND outcome='unknown' AND resolution IS NULL AND retention_ack_event_id IS NULL),
            'mongo_unknown',count(*) FILTER(WHERE mode='mongo_command' AND outcome='unknown'),
            'oldest_pending_at',floor(extract(epoch FROM min(created_at) FILTER(WHERE forkget_audit_pending(a))))::bigint)
            FROM audit_attempt a WHERE engine=$1")
            .bind(engine).fetch_one(&self.pool).await.map_err(Into::into)
    }
}
