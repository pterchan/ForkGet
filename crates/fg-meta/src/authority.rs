use fg_protocol_common::{AuditAttemptContext, AuditMode, NativeWitnessBinding, Policy};
use serde_json::Value;
use sqlx::{FromRow, PgConnection};

use crate::{
    MetaError,
    catalog::parse_branch_class,
    write_observation::{WriteObservation, WritePhase},
};

pub(crate) struct AuthorityLookup<'a> {
    pub engine: &'a str,
    pub branch: i64,
    pub principal: &'a str,
    pub write: Option<WriteAccess<'a>>,
}

pub(crate) struct WriteAccess<'a> {
    pub context: &'a AuditAttemptContext,
    pub table_id: Option<i64>,
    pub approval_id: Option<i64>,
}

#[derive(FromRow)]
pub(crate) struct BranchAuthority {
    pub generation_id: i64,
    class: String,
    policy_version: i64,
    max_transaction_rows: i64,
    table_limit_bps: Option<i32>,
    approval_after_rows: Option<i64>,
    small_table_floor: i64,
    effective_revision: i64,
    grant_expires_at: Option<i64>,
    pub expires_at: i64,
    pub lease_version: i64,
    write_scope_valid: bool,
    table_valid: bool,
    pub approval_consumed: bool,
    witness: Option<Value>,
}

impl BranchAuthority {
    pub(crate) fn require_write(&self) -> Result<(), MetaError> {
        if !self.write_scope_valid || !self.table_valid {
            return Err(MetaError::BranchUnavailable);
        }
        Ok(())
    }

    pub(crate) fn validate_policy(&self, version: i64, revision: i64) -> Result<(), MetaError> {
        if self.policy_version != version || self.effective_revision != revision {
            return Err(MetaError::PolicyConflict);
        }
        Ok(())
    }

    pub(crate) fn policy(&self) -> Result<Policy, MetaError> {
        Ok(Policy {
            class: parse_branch_class(&self.class)?,
            version: self.policy_version,
            max_transaction_rows: u64::try_from(self.max_transaction_rows)
                .map_err(|_| MetaError::InvalidCatalog)?,
            table_limit_bps: self
                .table_limit_bps
                .map(u16::try_from)
                .transpose()
                .map_err(|_| MetaError::InvalidCatalog)?,
            approval_after_rows: self
                .approval_after_rows
                .map(u64::try_from)
                .transpose()
                .map_err(|_| MetaError::InvalidCatalog)?,
            small_table_floor: u64::try_from(self.small_table_floor)
                .map_err(|_| MetaError::InvalidCatalog)?,
            effective_revision: self.effective_revision,
            grant_expires_at: self.grant_expires_at,
        })
    }

    pub(crate) fn witness(&self) -> Result<Option<NativeWitnessBinding>, MetaError> {
        self.witness
            .clone()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| MetaError::InvalidCatalog)
    }
}

/// Callers establish policy, branch and attempt locks before writer lookup.
/// The materialized clock is evaluated in this separate statement after waits.
/// Observer lookup deliberately preserves policy access for read-only branches.
pub(crate) async fn load_authority(
    connection: &mut PgConnection,
    lookup: AuthorityLookup<'_>,
    observation: &WriteObservation,
) -> Result<BranchAuthority, MetaError> {
    let access = lookup.write.as_ref();
    let context = access.map(|access| access.context);
    let phase = if access.is_some() {
        WritePhase::FreshScope
    } else {
        WritePhase::EffectivePolicy
    };
    observation
        .run(
            phase,
            sqlx::query_as(AUTHORITY_QUERY)
                .bind(lookup.branch)
                .bind(lookup.principal)
                .bind(lookup.engine)
                .bind(context.map(|context| context.session_id.as_str()))
                .bind(context.map(|context| context.generation_id))
                .bind(context.and_then(|context| context.replay_job_id))
                .bind(context.map(|context| i64::from(context.native_session_id)))
                .bind(access.and_then(|access| access.table_id))
                .bind(access.and_then(|access| access.approval_id))
                .bind(access.is_some())
                .bind(context.is_some_and(|context| context.mode == AuditMode::SqlTransaction))
                .fetch_optional(connection),
        )
        .await?
        .ok_or(MetaError::BranchUnavailable)
}

// The TRUE-only primary keys enforce singleton cardinality. Make that bound
// explicit before statistics exist: multiplying their default row estimates
// otherwise inflates correlated subplan costs enough to trigger per-write JIT.
const AUTHORITY_QUERY: &str = r#"
WITH authority_clock AS MATERIALIZED (SELECT clock_timestamp() AS observed_at)
SELECT b.generation_id,b.class,p.version AS policy_version,
       COALESCE(x.max_transaction_rows,p.max_transaction_rows) AS max_transaction_rows,
       CASE WHEN x.id IS NULL THEN p.table_limit_bps ELSE x.table_limit_bps END AS table_limit_bps,
       p.approval_after_rows,COALESCE(x.small_table_floor,p.small_table_floor) AS small_table_floor,
       COALESCE(r.revision,0)*2+CASE WHEN x.id IS NULL THEN 0 ELSE 1 END AS effective_revision,
       floor(extract(epoch FROM x.expires_at))::bigint AS grant_expires_at,
       floor(extract(epoch FROM b.expires_at))::bigint AS expires_at,b.lease_version,
       ($10 AND e.singleton IS NOT NULL AND b.access='read_write' AND b.class<>'staging'
         AND b.generation_id=$5 AND NOT b.capture_active
         AND g.reclaim_started_at IS NULL AND NOT b.audit_storage_reclaim_started
         AND (($6::bigint IS NULL AND NOT EXISTS(
                 SELECT 1 FROM replay_job j WHERE j.branch_id=b.id AND j.state<>'verified'))
           OR EXISTS(SELECT 1 FROM replay_job j WHERE j.id=$6 AND j.branch_id=b.id
                 AND j.principal=$2 AND j.state='running' AND j.session_id=$4
                 AND j.native_session_id=$7))) AS write_scope_valid,
       ($8::bigint IS NULL OR EXISTS(SELECT 1 FROM catalog_table c
            WHERE c.id=$8 AND c.generation_id=b.generation_id)) AS table_valid,
       EXISTS(SELECT 1 FROM policy_approval a WHERE a.id=$9 AND a.state='consumed') AS approval_consumed,
       CASE WHEN $11 AND b.audit_witness_ready AND b.audit_witness_version=1
                 AND NOT b.audit_storage_reclaim_started THEN
            jsonb_build_object('format_version',b.audit_witness_version,
                'deployment_id',d.id::text,'branch_id',b.id,'generation_id',b.generation_id,
                'storage_incarnation',b.audit_witness_incarnation)
            ELSE NULL END AS witness
FROM branch b JOIN generation g ON g.id=b.generation_id
CROSS JOIN authority_clock n
JOIN LATERAL(SELECT * FROM policy_version WHERE class=b.class ORDER BY version DESC LIMIT 1) p ON TRUE
LEFT JOIN branch_budget_revision r ON r.branch_id=b.id
LEFT JOIN LATERAL(SELECT singleton FROM policy_proxy_epoch WHERE singleton AND epoch=split_part($4,':',1) LIMIT 1) e ON TRUE
LEFT JOIN LATERAL(SELECT id FROM replay_deployment WHERE singleton LIMIT 1) d ON TRUE
LEFT JOIN LATERAL(
    SELECT x.id,x.max_transaction_rows,x.table_limit_bps,x.small_table_floor,x.expires_at
    FROM budget_grant x WHERE x.branch_id=b.id AND x.revoked_at IS NULL
      AND x.expires_at>n.observed_at AND x.expires_at<=b.expires_at
      AND x.generation_id=b.generation_id AND x.principal=b.created_by
      AND x.class=b.class AND x.policy_version=p.version
) x ON TRUE
WHERE b.id=$1 AND b.created_by=$2 AND g.engine=$3 AND b.status='active'
  AND b.expires_at>n.observed_at AND g.status IN ('active','retiring')
"#;
