use fg_protocol_common::CreateBudgetRequest;
use serde::Serialize;
use sqlx::{FromRow, PgConnection};

use crate::{MetaError, Metadata, approvals, policy::branch_policy};

const LIST_LIMIT: i64 = 100;
const REQUEST_LIFETIME: f64 = 900.0;

#[derive(FromRow, Serialize)]
pub struct BudgetRequestSummary {
    pub id: i64,
    pub branch_id: i64,
    pub principal: String,
    pub policy_version: i64,
    pub effective_revision: i64,
    pub max_transaction_rows: i64,
    pub table_limit_bps: Option<i32>,
    pub small_table_floor: i64,
    pub ttl_seconds: i32,
    pub reason: String,
    pub state: String,
    pub expires_at: i64,
    pub reviewed_by: Option<String>,
}

#[derive(FromRow, Serialize)]
pub struct BudgetGrantSummary {
    pub id: i64,
    pub request_id: i64,
    pub branch_id: i64,
    pub policy_version: i64,
    pub revision: i64,
    pub max_transaction_rows: i64,
    pub table_limit_bps: Option<i32>,
    pub small_table_floor: i64,
    pub approved_by: String,
    pub expires_at: i64,
    pub state: String,
}

pub struct BudgetReview<'a> {
    pub actor: &'a str,
    pub owners: &'a [String],
    pub approve: bool,
}

#[derive(FromRow)]
struct RequestRow {
    id: i64,
    principal: String,
    generation_id: i64,
    class: String,
    policy_version: i64,
    effective_revision: i64,
    max_transaction_rows: i64,
    table_limit_bps: Option<i32>,
    small_table_floor: i64,
    ttl_seconds: i32,
    state: String,
    expired: bool,
}

impl Metadata {
    pub async fn budget_inbox(
        &self,
        engine: &str,
        actor: &str,
        owners: &[String],
        after: i64,
    ) -> Result<Vec<BudgetRequestSummary>, MetaError> {
        sqlx::query_as(
            "SELECT r.id, r.branch_id, r.principal, r.policy_version, r.effective_revision,
                r.max_transaction_rows, r.table_limit_bps, r.small_table_floor, r.ttl_seconds, r.reason,
                r.state, floor(extract(epoch FROM r.expires_at))::bigint AS expires_at, r.reviewed_by
             FROM budget_request r JOIN branch b ON b.id = r.branch_id
             JOIN generation g ON g.id = b.generation_id
             WHERE g.engine = $1 AND (b.created_by = $2 OR b.created_by = ANY($3))
               AND r.id > $4 AND r.state = 'pending' AND r.expires_at > clock_timestamp()
               AND b.status = 'active' AND b.expires_at > clock_timestamp()
               AND r.policy_version = (SELECT max(version) FROM policy_version WHERE class = b.class)
               AND r.effective_revision = forkget_budget_revision(b.id)
             ORDER BY r.id LIMIT $5",
        )
.bind(engine)
.bind(actor)
.bind(owners)
.bind(after)
.bind(LIST_LIMIT)
            .fetch_all(&self.pool).await.map_err(Into::into)
    }

    pub async fn request_budget(
        &self,
        engine: &str,
        branch: i64,
        principal: &str,
        request: CreateBudgetRequest,
    ) -> Result<BudgetRequestSummary, MetaError> {
        validate_request(&request)?;
        let mut tx = self.begin_policy(true).await?;
        let policy = branch_policy(&mut tx, engine, branch, principal).await?;
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO budget_request (branch_id, generation_id, principal, class, policy_version,
                 effective_revision, max_transaction_rows, table_limit_bps, small_table_floor,
                 ttl_seconds, reason, expires_at)
             SELECT id, generation_id, created_by, class, $3, $4, $5, $6, $7, $8, $9,
                 LEAST(expires_at, clock_timestamp() + make_interval(secs => $10))
             FROM branch WHERE id = $1 AND created_by = $2 AND status = 'active'
                 AND access = 'read_write' AND class <> 'staging' AND expires_at > clock_timestamp()
             RETURNING budget_request.id",
        )
.bind(branch)
.bind(principal)
.bind(policy.version)
.bind(policy.effective_revision)
            .bind(request.max_transaction_rows as i64)
.bind(request.table_limit_bps.map(i32::from))
            .bind(request.small_table_floor as i64)
.bind(request.ttl_seconds as i32)
            .bind(request.reason.trim())
.bind(REQUEST_LIFETIME)
.fetch_optional(&mut *tx).await?
            .ok_or(MetaError::BranchUnavailable)?;
        audit(&mut tx, principal, branch, "budget_requested", id).await?;
        let result = request_summary(&mut tx, branch, id).await?;
        tx.commit().await?;
        Ok(result)
    }

    pub async fn budget_requests(
        &self,
        engine: &str,
        branch: i64,
        actor: &str,
        owners: &[String],
    ) -> Result<Vec<BudgetRequestSummary>, MetaError> {
        let mut connection = self.pool.acquire().await?;
        authorize_list(&mut connection, engine, branch, actor, owners).await?;
        sqlx::query_as(
            "SELECT id, branch_id, principal, policy_version, effective_revision,
                max_transaction_rows, table_limit_bps, small_table_floor, ttl_seconds, reason,
                CASE WHEN state = 'pending' AND expires_at <= clock_timestamp() THEN 'expired' ELSE state END AS state,
                floor(extract(epoch FROM expires_at))::bigint AS expires_at, reviewed_by
             FROM budget_request WHERE branch_id = $1 ORDER BY id DESC LIMIT $2",
        )
.bind(branch)
.bind(LIST_LIMIT).fetch_all(&mut *connection).await.map_err(Into::into)
    }

    pub async fn review_budget(
        &self,
        engine: &str,
        branch: i64,
        id: i64,
        review: BudgetReview<'_>,
    ) -> Result<BudgetRequestSummary, MetaError> {
        let mut tx = self.begin_policy(true).await?;
        let request = review_request(&mut tx, engine, branch, id, &review).await?;
        if request.state != "pending" {
            return Err(MetaError::ApprovalConflict);
        }
        let policy = branch_policy(&mut tx, engine, branch, &request.principal).await?;
        let state = if request.expired {
            "expired"
        } else if policy.version != request.policy_version
            || policy.effective_revision != request.effective_revision
        {
            "invalidated"
        } else if review.approve {
            "approved"
        } else {
            "denied"
        };
        if state == "approved" {
            create_grant(&mut tx, branch, &request, review.actor).await?;
        }
        sqlx::query("UPDATE budget_request SET state = $3, reviewed_by = $4 WHERE branch_id = $1 AND id = $2")
            .bind(branch)
.bind(id)
.bind(state)
.bind(review.actor)
.execute(&mut *tx).await?;
        audit(&mut tx, review.actor, branch, "budget_reviewed", id).await?;
        let result = request_summary(&mut tx, branch, id).await?;
        tx.commit().await?;
        Ok(result)
    }

    pub async fn budget_grants(
        &self,
        engine: &str,
        branch: i64,
        actor: &str,
        owners: &[String],
    ) -> Result<Vec<BudgetGrantSummary>, MetaError> {
        let mut connection = self.pool.acquire().await?;
        authorize_list(&mut connection, engine, branch, actor, owners).await?;
        sqlx::query_as(
            "SELECT x.id, x.request_id, x.branch_id, x.policy_version, x.revision,
                x.max_transaction_rows, x.table_limit_bps, x.small_table_floor, x.approved_by,
                floor(extract(epoch FROM LEAST(x.expires_at, b.expires_at)))::bigint AS expires_at,
                CASE WHEN x.revoked_at IS NOT NULL THEN 'revoked'
                     WHEN b.status <> 'active' OR b.expires_at <= clock_timestamp() OR x.expires_at <= clock_timestamp() THEN 'expired'
                     WHEN x.policy_version <> (SELECT max(version) FROM policy_version WHERE class = b.class) THEN 'invalidated'
                     ELSE 'active' END AS state
             FROM budget_grant x JOIN branch b ON b.id = x.branch_id
             WHERE x.branch_id = $1 ORDER BY x.id DESC LIMIT $2",
        )
.bind(branch)
.bind(LIST_LIMIT).fetch_all(&mut *connection).await.map_err(Into::into)
    }

    pub async fn revoke_budget(
        &self,
        engine: &str,
        branch: i64,
        id: i64,
        actor: &str,
        owners: &[String],
    ) -> Result<(), MetaError> {
        let mut tx = self.begin_policy(true).await?;
        authorize_list(&mut tx, engine, branch, actor, owners).await?;
        let changed = sqlx::query(
            "UPDATE budget_grant SET revoked_at = clock_timestamp(), revoked_by = $3
             WHERE branch_id = $1 AND id = $2 AND revoked_at IS NULL",
        )
        .bind(branch)
        .bind(id)
        .bind(actor)
        .execute(&mut *tx)
        .await?;
        if changed.rows_affected() != 1 {
            return Err(MetaError::ApprovalConflict);
        }
        advance_revision(&mut tx, branch).await?;
        approvals::invalidate_budget(&mut tx, branch).await?;
        audit(&mut tx, actor, branch, "budget_revoked", id).await?;
        tx.commit().await?;
        Ok(())
    }
}

async fn review_request(
    connection: &mut PgConnection,
    engine: &str,
    branch: i64,
    id: i64,
    review: &BudgetReview<'_>,
) -> Result<RequestRow, MetaError> {
    sqlx::query_as(
        "SELECT r.id, r.principal, r.generation_id, r.class, r.policy_version, r.effective_revision,
            r.max_transaction_rows, r.table_limit_bps, r.small_table_floor, r.ttl_seconds, r.state,
            r.expires_at <= clock_timestamp() AS expired
         FROM budget_request r JOIN branch b ON b.id = r.branch_id
         JOIN generation g ON g.id = b.generation_id
         WHERE r.branch_id = $1 AND r.id = $2 AND g.engine = $3
           AND r.principal <> $4 AND r.principal = ANY($5)
           AND r.principal = b.created_by AND r.generation_id = b.generation_id
           AND b.status = 'active' AND b.access = 'read_write'
           AND b.expires_at > clock_timestamp() AND g.status IN ('active','retiring')
         FOR UPDATE OF r, b",
    )
.bind(branch)
.bind(id)
.bind(engine)
.bind(review.actor)
.bind(review.owners)
        .fetch_optional(connection).await?.ok_or(MetaError::BranchUnavailable)
}

async fn create_grant(
    connection: &mut PgConnection,
    branch: i64,
    request: &RequestRow,
    actor: &str,
) -> Result<(), MetaError> {
    sqlx::query("UPDATE budget_grant SET revoked_at = clock_timestamp(), revoked_by = $2 WHERE branch_id = $1 AND revoked_at IS NULL")
        .bind(branch)
.bind(actor)
.execute(&mut *connection).await?;
    let revision = advance_revision(connection, branch).await?;
    sqlx::query(
        "INSERT INTO budget_grant (request_id, branch_id, generation_id, principal, class, policy_version,
             revision, max_transaction_rows, table_limit_bps, small_table_floor, approved_by, expires_at)
         SELECT $1, b.id, $3, $4, $5, $6, $7, $8, $9, $10, $11,
             LEAST(b.expires_at, clock_timestamp() + make_interval(secs => $12))
         FROM branch b WHERE b.id = $2 AND b.expires_at > clock_timestamp()",
    )
.bind(request.id)
.bind(branch)
.bind(request.generation_id)
.bind(&request.principal)
        .bind(&request.class)
.bind(request.policy_version)
.bind(revision)
        .bind(request.max_transaction_rows)
.bind(request.table_limit_bps)
.bind(request.small_table_floor)
        .bind(actor)
.bind(f64::from(request.ttl_seconds))
.execute(&mut *connection).await?;
    approvals::invalidate_budget(connection, branch).await?;
    audit(connection, actor, branch, "budget_granted", request.id).await
}

async fn advance_revision(connection: &mut PgConnection, branch: i64) -> Result<i64, MetaError> {
    sqlx::query_scalar(
        "INSERT INTO branch_budget_revision (branch_id, revision) VALUES ($1, 1)
         ON CONFLICT (branch_id) DO UPDATE SET revision = branch_budget_revision.revision + 1
         RETURNING revision",
    )
    .bind(branch)
    .fetch_one(connection)
    .await
    .map_err(Into::into)
}

async fn authorize_list(
    connection: &mut PgConnection,
    engine: &str,
    branch: i64,
    actor: &str,
    owners: &[String],
) -> Result<(), MetaError> {
    let allowed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM branch b JOIN generation g ON g.id = b.generation_id
         WHERE b.id = $1 AND g.engine = $2 AND (b.created_by = $3 OR b.created_by = ANY($4)))",
    )
    .bind(branch)
    .bind(engine)
    .bind(actor)
    .bind(owners)
    .fetch_one(connection)
    .await?;
    if !allowed {
        return Err(MetaError::BranchUnavailable);
    }
    Ok(())
}

async fn request_summary(
    connection: &mut PgConnection,
    branch: i64,
    id: i64,
) -> Result<BudgetRequestSummary, MetaError> {
    sqlx::query_as(
        "SELECT id, branch_id, principal, policy_version, effective_revision, max_transaction_rows,
            table_limit_bps, small_table_floor, ttl_seconds, reason, state,
            floor(extract(epoch FROM expires_at))::bigint AS expires_at, reviewed_by
         FROM budget_request WHERE branch_id = $1 AND id = $2",
    )
    .bind(branch)
    .bind(id)
    .fetch_one(connection)
    .await
    .map_err(Into::into)
}

async fn audit(
    connection: &mut PgConnection,
    actor: &str,
    branch: i64,
    event: &str,
    id: i64,
) -> Result<(), MetaError> {
    sqlx::query("INSERT INTO audit_event (actor, branch_id, event_type, payload) VALUES ($1, $2, $3, jsonb_build_object('budget_id', $4::bigint))")
        .bind(actor)
.bind(branch)
.bind(event)
.bind(id)
.execute(connection).await?;
    Ok(())
}

fn validate_request(request: &CreateBudgetRequest) -> Result<(), MetaError> {
    if request.max_transaction_rows > i64::MAX as u64
        || request.small_table_floor == 0
        || request.small_table_floor > i64::MAX as u64
        || !(1..=3600).contains(&request.ttl_seconds)
        || request
            .table_limit_bps
            .is_some_and(|bps| !(1..=10000).contains(&bps))
        || request.reason.trim().is_empty()
        || request.reason.chars().count() > 512
    {
        return Err(MetaError::InvalidPolicy);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fg_protocol_common::{
        BranchClass, DecisionRequest, DecisionVerdict, Policy, PolicyContext, WriteKind,
        WriteOperation,
    };
    use sqlx::{PgPool, postgres::PgConnectOptions};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn metadata(pool: PgPool) -> Metadata {
        Metadata {
            pool,
            options: PgConnectOptions::new(),
        }
    }

    fn request() -> CreateBudgetRequest {
        CreateBudgetRequest {
            max_transaction_rows: 20,
            table_limit_bps: Some(10000),
            small_table_floor: 20,
            ttl_seconds: 900,
            reason: "Run the order scenario".into(),
        }
    }

    async fn branch(pool: &PgPool) -> Result<(i64, i64), sqlx::Error> {
        let generation: i64 = sqlx::query_scalar("INSERT INTO generation (engine, status, native_claimed, activated_at, snapshot) VALUES ('postgresql', 'active', TRUE, now(), 'v2') RETURNING id")
            .fetch_one(pool).await?;
        let table: i64 = sqlx::query_scalar("INSERT INTO catalog_table (generation_id, logical_schema, logical_table, base_table, baseline_rows) VALUES ($1, 'app', 'orders', 'orders', 4) RETURNING id")
            .bind(generation)
.fetch_one(pool).await?;
        let branch: i64 = sqlx::query_scalar("INSERT INTO branch (name, class, generation_id, created_by, expires_at, status, mode, native_claimed) VALUES ('budget-one', 'agent', $1, 'alice', now() + INTERVAL '2 hours', 'active', 'native_write', TRUE) RETURNING id")
            .bind(generation)
.fetch_one(pool).await?;
        Ok((branch, table))
    }

    fn context(policy: Policy) -> PolicyContext {
        PolicyContext {
            principal: "alice".into(),
            policy_version: policy.version,
            effective_revision: policy.effective_revision,
        }
    }

    fn decision(policy: Policy, table: i64) -> DecisionRequest {
        DecisionRequest {
            principal: "alice".into(),
            session_id: format!("{}:1", "a".repeat(32)),
            policy_version: policy.version,
            effective_revision: policy.effective_revision,
            operation: WriteOperation {
                table_id: table,
                kind: WriteKind::Insert,
            },
            rows: 1,
            verdict: DecisionVerdict::Allowed,
        }
    }

    #[sqlx::test(migrations = "./migrations")]
    #[ignore = "requires DATABASE_URL for an isolated metadata PostgreSQL"]
    async fn grants_are_independent_scoped_and_authoritative(pool: PgPool) -> TestResult {
        let (branch, table) = branch(&pool).await?;
        let meta = metadata(pool.clone());
        meta.register_proxy_epoch(&"a".repeat(32)).await?;
        let baseline = meta
            .policy_for_branch("postgresql", branch, "alice")
            .await?;
        assert_eq!(baseline.small_table_floor, 10);
        assert!(baseline.approval_after_rows.is_none());
        meta.validate_policy_context("postgresql", branch, context(baseline))
            .await?;
        let mut foreign_owner = context(baseline);
        foreign_owner.principal = "stranger".into();
        assert!(matches!(
            meta.validate_policy_context("postgresql", branch, foreign_owner)
                .await,
            Err(MetaError::BranchUnavailable)
        ));
        assert!(matches!(
            meta.validate_policy_context("mysql", branch, context(baseline))
                .await,
            Err(MetaError::BranchUnavailable)
        ));
        let request = meta
            .request_budget("postgresql", branch, "alice", request())
            .await?;
        let owners = vec!["alice".to_owned()];
        assert!(
            meta.review_budget(
                "postgresql",
                branch,
                request.id,
                BudgetReview {
                    actor: "alice",
                    owners: &owners,
                    approve: true
                }
            )
            .await
            .is_err()
        );
        assert!(
            meta.review_budget(
                "postgresql",
                branch,
                request.id,
                BudgetReview {
                    actor: "eve",
                    owners: &[],
                    approve: true
                }
            )
            .await
            .is_err()
        );
        assert_eq!(
            meta.budget_inbox("postgresql", "reviewer", &owners, 0)
                .await?
                .len(),
            1
        );
        assert!(
            meta.budget_inbox("postgresql", "stranger", &[], 0)
                .await?
                .is_empty()
        );
        meta.review_budget(
            "postgresql",
            branch,
            request.id,
            BudgetReview {
                actor: "reviewer",
                owners: &owners,
                approve: true,
            },
        )
        .await?;
        let granted = meta
            .policy_for_branch("postgresql", branch, "alice")
            .await?;
        assert_eq!(granted.small_table_floor, 20);
        assert!(granted.grant_expires_at.is_some());
        meta.validate_policy_context("postgresql", branch, context(granted))
            .await?;
        assert!(matches!(
            meta.validate_policy_context("postgresql", branch, context(baseline))
                .await,
            Err(MetaError::PolicyConflict)
        ));
        assert!(matches!(
            meta.record_decision("postgresql", branch, decision(baseline, table))
                .await,
            Err(MetaError::PolicyConflict)
        ));
        meta.record_decision("postgresql", branch, decision(granted, table))
            .await?;
        let grant = meta
            .budget_grants("postgresql", branch, "alice", &[])
            .await?
            .remove(0);
        meta.revoke_budget("postgresql", branch, grant.id, "alice", &[])
            .await?;
        assert!(matches!(
            meta.validate_policy_context("postgresql", branch, context(granted))
                .await,
            Err(MetaError::PolicyConflict)
        ));
        assert!(matches!(
            meta.record_decision("postgresql", branch, decision(granted, table))
                .await,
            Err(MetaError::PolicyConflict)
        ));
        assert_eq!(
            meta.policy_for_branch("postgresql", branch, "alice")
                .await?
                .small_table_floor,
            10
        );
        Ok(())
    }

    #[sqlx::test(migrations = "./migrations")]
    #[ignore = "requires DATABASE_URL for an isolated metadata PostgreSQL"]
    async fn expiry_and_policy_change_remove_grants_without_sweeps(pool: PgPool) -> TestResult {
        let (branch, _) = branch(&pool).await?;
        let meta = metadata(pool.clone());
        let owners = vec!["alice".to_owned()];
        let pending = meta
            .request_budget("postgresql", branch, "alice", request())
            .await?;
        meta.review_budget(
            "postgresql",
            branch,
            pending.id,
            BudgetReview {
                actor: "reviewer",
                owners: &owners,
                approve: true,
            },
        )
        .await?;
        let granted = meta
            .policy_for_branch("postgresql", branch, "alice")
            .await?;
        sqlx::query("UPDATE budget_grant SET expires_at = clock_timestamp() - INTERVAL '1 second' WHERE branch_id = $1")
            .bind(branch)
.execute(&pool).await?;
        assert!(matches!(
            meta.validate_policy_context("postgresql", branch, context(granted))
                .await,
            Err(MetaError::PolicyConflict)
        ));
        let fresh = meta
            .policy_for_branch("postgresql", branch, "alice")
            .await?;
        assert!(fresh.grant_expires_at.is_none());
        assert_eq!(fresh.small_table_floor, 10);
        let pending = meta
            .request_budget("postgresql", branch, "alice", request())
            .await?;
        meta.update_policy(
            "reviewer",
            BranchClass::Agent,
            fg_protocol_common::UpdatePolicy {
                expected_version: fresh.version,
                max_transaction_rows: 100,
                table_limit_bps: Some(100),
                approval_after_rows: Some(1),
                small_table_floor: None,
            },
        )
        .await?;
        let reviewed = meta
            .review_budget(
                "postgresql",
                branch,
                pending.id,
                BudgetReview {
                    actor: "reviewer",
                    owners: &owners,
                    approve: true,
                },
            )
            .await?;
        assert_eq!(reviewed.state, "invalidated");
        assert_eq!(
            meta.policy_for_branch("postgresql", branch, "alice")
                .await?
                .approval_after_rows,
            Some(1)
        );
        Ok(())
    }

    #[sqlx::test(migrations = false)]
    #[ignore = "requires DATABASE_URL for an isolated metadata PostgreSQL"]
    async fn migration_preserves_custom_policies(pool: PgPool) -> TestResult {
        let migrations = sqlx::migrate!("./migrations");
        for migration in migrations.iter().filter(|item| item.version < 15) {
            sqlx::raw_sql(&migration.sql).execute(&pool).await?;
        }
        sqlx::query("UPDATE policy_version SET max_transaction_rows = 42 WHERE class = 'dev'")
            .execute(&pool)
            .await?;
        sqlx::query("INSERT INTO policy_version (class, version, max_transaction_rows, table_limit_bps, approval_after_rows) VALUES ('agent', 2, 50, 500, 2)")
.execute(&pool).await?;
        sqlx::raw_sql(include_str!("../migrations/0015_scoped_budgets.sql"))
            .execute(&pool)
            .await?;
        let meta = metadata(pool);
        let dev = meta.policy(BranchClass::Dev).await?;
        assert_eq!(
            (dev.version, dev.max_transaction_rows, dev.small_table_floor),
            (1, 42, 1)
        );
        let agent = meta.policy(BranchClass::Agent).await?;
        assert_eq!(
            (
                agent.version,
                agent.approval_after_rows,
                agent.small_table_floor
            ),
            (2, Some(2), 1)
        );
        assert_eq!(meta.policy(BranchClass::Ci).await?.small_table_floor, 10);
        Ok(())
    }

    #[sqlx::test(migrations = "./migrations")]
    #[ignore = "requires DATABASE_URL for an isolated metadata PostgreSQL"]
    async fn grant_expiry_is_bounded_and_invalidates_statement_approval(
        pool: PgPool,
    ) -> TestResult {
        let (branch, table) = branch(&pool).await?;
        let meta = metadata(pool.clone());
        meta.register_proxy_epoch(&"a".repeat(32)).await?;
        let baseline = meta.policy(BranchClass::Agent).await?;
        meta.update_policy(
            "reviewer",
            BranchClass::Agent,
            fg_protocol_common::UpdatePolicy {
                expected_version: baseline.version,
                max_transaction_rows: 100,
                table_limit_bps: Some(100),
                approval_after_rows: Some(1),
                small_table_floor: Some(1),
            },
        )
        .await?;
        sqlx::query("UPDATE branch SET expires_at = now() + INTERVAL '5 minutes' WHERE id = $1")
            .bind(branch)
            .execute(&pool)
            .await?;
        let owners = vec!["alice".to_owned()];
        let mut wanted = request();
        wanted.ttl_seconds = 3601;
        assert!(matches!(
            meta.request_budget("postgresql", branch, "alice", wanted.clone())
                .await,
            Err(MetaError::InvalidPolicy)
        ));
        wanted.ttl_seconds = 3600;
        let pending = meta
            .request_budget("postgresql", branch, "alice", wanted)
            .await?;
        meta.review_budget(
            "postgresql",
            branch,
            pending.id,
            BudgetReview {
                actor: "reviewer",
                owners: &owners,
                approve: true,
            },
        )
        .await?;
        let grant = meta
            .policy_for_branch("postgresql", branch, "alice")
            .await?;
        assert_eq!(grant.approval_after_rows, Some(1));
        let bounded: bool = sqlx::query_scalar("SELECT x.expires_at <= b.expires_at AND x.expires_at <= x.created_at + INTERVAL '1 hour' FROM budget_grant x JOIN branch b ON b.id = x.branch_id WHERE b.id = $1")
            .bind(branch)
.fetch_one(&pool).await?;
        assert!(bounded);
        let mut invocation = decision(grant, table);
        invocation.verdict = DecisionVerdict::AwaitApproval;
        let approval = meta
            .record_decision("postgresql", branch, invocation)
            .await?
            .approval_id
            .ok_or("approval missing")?;
        sqlx::query("UPDATE budget_grant SET expires_at = clock_timestamp() - INTERVAL '1 second' WHERE branch_id = $1")
            .bind(branch)
.execute(&pool).await?;
        assert_eq!(
            meta.poll_approval(
                "postgresql",
                crate::ApprovalKey {
                    branch_id: branch,
                    id: approval
                },
                fg_protocol_common::ApprovalContext {
                    principal: "alice".into(),
                    session_id: format!("{}:1", "a".repeat(32))
                }
            )
            .await?,
            fg_protocol_common::ApprovalState::Invalidated
        );
        Ok(())
    }
}
