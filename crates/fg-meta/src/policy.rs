use crate::write_observation::{WriteObservation, WritePhase};
use fg_protocol_common::{BranchClass, Policy, UpdatePolicy};
use sqlx::{Acquire, FromRow, PgConnection, Postgres, Transaction};

use crate::authority::{AuthorityLookup, load_authority};
use crate::{MetaError, Metadata, approvals, catalog::parse_branch_class};

const POLICY_LOCK: i64 = 0x4647_0000_0000_0004;

#[derive(FromRow)]
struct PolicyRow {
    class: String,
    version: i64,
    max_transaction_rows: i64,
    table_limit_bps: Option<i32>,
    approval_after_rows: Option<i64>,
    small_table_floor: i64,
}

impl TryFrom<PolicyRow> for Policy {
    type Error = MetaError;

    fn try_from(row: PolicyRow) -> Result<Self, MetaError> {
        Ok(Self {
            class: parse_branch_class(&row.class)?,
            version: row.version,
            max_transaction_rows: u64::try_from(row.max_transaction_rows)
                .map_err(|_| MetaError::InvalidCatalog)?,
            table_limit_bps: row
                .table_limit_bps
                .map(u16::try_from)
                .transpose()
                .map_err(|_| MetaError::InvalidCatalog)?,
            approval_after_rows: row
                .approval_after_rows
                .map(u64::try_from)
                .transpose()
                .map_err(|_| MetaError::InvalidCatalog)?,
            small_table_floor: u64::try_from(row.small_table_floor)
                .map_err(|_| MetaError::InvalidCatalog)?,
            effective_revision: 0,
            grant_expires_at: None,
        })
    }
}

impl Metadata {
    pub async fn policy(&self, class: BranchClass) -> Result<Policy, MetaError> {
        sqlx::query_as::<_, PolicyRow>(
            "SELECT class, version, max_transaction_rows, table_limit_bps, approval_after_rows, small_table_floor
             FROM policy_version WHERE class = $1 ORDER BY version DESC LIMIT 1",
        )
        .bind(class.as_str())
        .fetch_one(&self.pool)
        .await?
        .try_into()
    }

    pub async fn policy_for_branch(
        &self,
        engine: &str,
        id: i64,
        principal: &str,
    ) -> Result<Policy, MetaError> {
        let mut tx = self.begin_policy(false).await?;
        let policy = branch_policy(&mut tx, engine, id, principal).await?;
        tx.commit().await?;
        Ok(policy)
    }

    pub async fn validate_policy_context(
        &self,
        engine: &str,
        id: i64,
        context: fg_protocol_common::PolicyContext,
    ) -> Result<(), MetaError> {
        // Commit validation needs the authoritative identity, not grant limits.
        // Keep the shared policy lock and fresh metadata time while avoiding a
        // second round trip to fetch limits that are never used here.
        let mut tx = self.begin_policy(false).await?;
        let (version, revision): (i64, i64) = sqlx::query_as(
            "SELECT p.version, forkget_budget_revision(b.id)
             FROM branch b JOIN generation g ON g.id = b.generation_id
             JOIN LATERAL (SELECT version FROM policy_version WHERE class = b.class
                           ORDER BY version DESC LIMIT 1) p ON TRUE
             WHERE b.id = $1 AND b.created_by = $2 AND b.status = 'active'
               AND b.expires_at > clock_timestamp() AND g.engine = $3
               AND g.status IN ('active', 'retiring')",
        )
        .bind(id)
        .bind(&context.principal)
        .bind(engine)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(MetaError::BranchUnavailable)?;
        tx.commit().await?;
        if version != context.policy_version || revision != context.effective_revision {
            return Err(MetaError::PolicyConflict);
        }
        Ok(())
    }

    pub async fn update_policy(
        &self,
        actor: &str,
        class: BranchClass,
        request: UpdatePolicy,
    ) -> Result<Policy, MetaError> {
        validate_update(class, &request)?;
        let rows =
            i64::try_from(request.max_transaction_rows).map_err(|_| MetaError::InvalidPolicy)?;
        let approval = request
            .approval_after_rows
            .map(i64::try_from)
            .transpose()
            .map_err(|_| MetaError::InvalidPolicy)?;
        let floor = request
            .small_table_floor
            .map(i64::try_from)
            .transpose()
            .map_err(|_| MetaError::InvalidPolicy)?;
        let mut tx = self.begin_policy(true).await?;
        let policy = sqlx::query_as::<_, PolicyRow>(
            "INSERT INTO policy_version (class, version, max_transaction_rows, table_limit_bps, approval_after_rows, small_table_floor)
             SELECT $1, version + 1, $3, $4, $5, COALESCE($6, small_table_floor) FROM (
                 SELECT version, small_table_floor FROM policy_version WHERE class = $1 ORDER BY version DESC LIMIT 1
             ) current_version WHERE version = $2
             RETURNING class, version, max_transaction_rows, table_limit_bps, approval_after_rows, small_table_floor",
        )
        .bind(class.as_str())
.bind(request.expected_version)
.bind(rows)
        .bind(request.table_limit_bps.map(i32::from))
.bind(approval)
.bind(floor)
        .fetch_optional(&mut *tx).await?.ok_or(MetaError::PolicyConflict)?;
        approvals::invalidate_class(&mut tx, class, policy.version).await?;
        sqlx::query(
            "INSERT INTO audit_event (actor, event_type, payload) VALUES ($1, 'policy_updated',
             jsonb_build_object('class', $2::text, 'policy_version', $3::bigint))",
        )
        .bind(actor)
        .bind(class.as_str())
        .bind(policy.version)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        policy.try_into()
    }

    pub(crate) async fn begin_policy(
        &self,
        exclusive: bool,
    ) -> Result<Transaction<'_, Postgres>, MetaError> {
        let mut tx = self.pool.begin().await?;
        lock_policy(&mut tx, exclusive, &WriteObservation::disabled()).await?;
        Ok(tx)
    }
}

pub(crate) async fn begin_policy_on<'a>(
    connection: &'a mut PgConnection,
    exclusive: bool,
    observation: &WriteObservation,
) -> Result<Transaction<'a, Postgres>, MetaError> {
    let mut tx = observation
        .run(WritePhase::TransactionBegin, connection.begin())
        .await?;
    lock_policy(&mut tx, exclusive, observation).await?;
    Ok(tx)
}

async fn lock_policy(
    connection: &mut PgConnection,
    exclusive: bool,
    observation: &WriteObservation,
) -> Result<(), MetaError> {
    let lock = if exclusive {
        "SELECT pg_advisory_xact_lock($1)"
    } else {
        "SELECT pg_advisory_xact_lock_shared($1)"
    };
    observation
        .run(
            WritePhase::PolicyLock,
            sqlx::query(lock).bind(POLICY_LOCK).execute(connection),
        )
        .await?;
    Ok(())
}

pub(crate) async fn branch_policy(
    connection: &mut PgConnection,
    engine: &str,
    id: i64,
    principal: &str,
) -> Result<Policy, MetaError> {
    load_authority(
        connection,
        AuthorityLookup {
            engine,
            branch: id,
            principal,
            write: None,
        },
        &WriteObservation::disabled(),
    )
    .await?
    .policy()
}

fn validate_update(class: BranchClass, request: &UpdatePolicy) -> Result<(), MetaError> {
    if request.expected_version <= 0
        || request.expected_version == i64::MAX
        || request
            .small_table_floor
            .is_some_and(|floor| floor == 0 || floor > i64::MAX as u64)
        || request
            .table_limit_bps
            .is_some_and(|bps| !(1..=10_000).contains(&bps))
        || request
            .approval_after_rows
            .is_some_and(|rows| rows > request.max_transaction_rows)
    {
        return Err(MetaError::InvalidPolicy);
    }
    if class == BranchClass::Staging
        && (request.max_transaction_rows != 0
            || request.table_limit_bps.is_some()
            || request.approval_after_rows.is_some())
    {
        return Err(MetaError::InvalidPolicy);
    }
    Ok(())
}
