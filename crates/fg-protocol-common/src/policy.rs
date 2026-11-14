use std::{collections::HashMap, time::Duration};

use serde::{Deserialize, Serialize};
use tokio::time::{Instant, sleep, timeout_at};

use crate::{AuditAttempt, BranchSession, WireError};

const APPROVAL_WINDOW: Duration = Duration::from_secs(60);
const APPROVAL_POLL_INTERVAL: Duration = Duration::from_millis(150);
const BASIS_POINTS: u128 = 10_000;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BranchClass {
    #[default]
    Dev,
    Ci,
    Agent,
    Staging,
}

impl BranchClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Ci => "ci",
            Self::Agent => "agent",
            Self::Staging => "staging",
        }
    }

    pub const fn default_ttl_seconds(self) -> u32 {
        match self {
            Self::Dev | Self::Staging => 24 * 60 * 60,
            Self::Ci | Self::Agent => 2 * 60 * 60,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct Policy {
    pub class: BranchClass,
    pub version: i64,
    pub max_transaction_rows: u64,
    pub table_limit_bps: Option<u16>,
    pub approval_after_rows: Option<u64>,
    #[serde(default = "legacy_table_floor")]
    pub small_table_floor: u64,
    #[serde(default)]
    pub effective_revision: i64,
    #[serde(default)]
    pub grant_expires_at: Option<i64>,
}

const fn legacy_table_floor() -> u64 {
    1
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdatePolicy {
    pub expected_version: i64,
    pub max_transaction_rows: u64,
    pub table_limit_bps: Option<u16>,
    pub approval_after_rows: Option<u64>,
    #[serde(default)]
    pub small_table_floor: Option<u64>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyContext {
    pub principal: String,
    pub policy_version: i64,
    pub effective_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateBudgetRequest {
    pub max_transaction_rows: u64,
    pub table_limit_bps: Option<u16>,
    #[serde(default = "default_budget_floor")]
    pub small_table_floor: u64,
    #[serde(default = "default_budget_ttl")]
    pub ttl_seconds: u32,
    pub reason: String,
}

const fn default_budget_floor() -> u64 {
    10
}
const fn default_budget_ttl() -> u32 {
    900
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteKind {
    Insert,
    Update,
    Delete,
}

impl WriteKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Insert => "insert",
            Self::Update => "update",
            Self::Delete => "delete",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WriteOperation {
    pub table_id: i64,
    pub kind: WriteKind,
}

pub(crate) struct DecisionEvaluation {
    pub operation: WriteOperation,
    pub rows: u64,
    pub verdict: DecisionVerdict,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionVerdict {
    Allowed,
    Limit,
    NativeError,
    AwaitApproval,
}

impl DecisionVerdict {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Limit => "limit",
            Self::NativeError => "native_error",
            Self::AwaitApproval => "await_approval",
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct DecisionRequest {
    pub principal: String,
    pub session_id: String,
    pub policy_version: i64,
    #[serde(default)]
    pub effective_revision: i64,
    pub operation: WriteOperation,
    pub rows: u64,
    pub verdict: DecisionVerdict,
}

#[derive(Deserialize, Serialize)]
pub struct DecisionResponse {
    pub approval_id: Option<i64>,
}

#[derive(Deserialize, Serialize)]
pub struct ApprovalContext {
    pub principal: String,
    pub session_id: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    Pending,
    Approved,
    Denied,
    Expired,
    Invalidated,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionOutcome {
    Committed,
    RolledBack,
    Unknown,
}

impl TransactionOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::RolledBack => "rolled_back",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct OutcomeRequest {
    pub principal: String,
    pub session_id: String,
    pub outcome: TransactionOutcome,
}

#[derive(Deserialize, Serialize)]
pub struct ProxyEpoch {
    pub epoch: String,
    pub protocol_version: u32,
}

/// Work charged to one native transaction. Rolling back a savepoint preserves it.
#[derive(Default)]
pub struct TransactionBudget {
    total: u64,
    tables: HashMap<i64, u64>,
    context: Option<Policy>,
    attempt: Option<AuditAttempt>,
}

#[derive(Clone, Copy)]
enum AuthorizationBoundary {
    Statement,
    Commit,
}

struct BudgetEvaluation {
    operation: WriteOperation,
    rows: u64,
    boundary: AuthorizationBoundary,
}

impl TransactionBudget {
    pub fn reset(&mut self) {
        self.total = 0;
        self.tables.clear();
        self.context = None;
        self.attempt = None;
    }

    pub fn attempt(&self) -> Option<&AuditAttempt> {
        self.attempt.as_ref()
    }

    pub fn take_attempt(&mut self) -> Option<AuditAttempt> {
        self.attempt.take()
    }

    pub fn set_attempt(&mut self, attempt: AuditAttempt) {
        self.attempt = Some(attempt);
    }

    pub async fn native_error(
        &mut self,
        branch: &BranchSession,
        policy: &Policy,
        operation: WriteOperation,
    ) {
        if self.attempt.is_none() {
            match branch.new_write_attempt() {
                Ok(attempt) => self.attempt = Some(attempt),
                Err(_) => return,
            }
        }
        if let Some(attempt) = self.attempt.as_mut() {
            let _ = branch
                .audit_decision(
                    attempt,
                    policy,
                    DecisionEvaluation {
                        operation,
                        rows: 0,
                        verdict: DecisionVerdict::NativeError,
                    },
                )
                .await;
        }
    }

    /// A grant cannot outlive its authoritative policy context at commit.
    pub async fn validate_for_commit(&self, branch: &BranchSession) -> Result<(), WireError> {
        if let Some(policy) = &self.context {
            branch.validate_policy_context(policy).await?;
        }
        Ok(())
    }

    /// Recheck the exact admitted attempt immediately before the native commit.
    /// An error-only attempt retains observer lease semantics without claiming
    /// that any business write received a successful admission.
    pub async fn fence_for_commit(&self, branch: &BranchSession) -> Result<(), WireError> {
        if let Some(policy) = &self.context {
            branch
                .fresh_write_fence(self.attempt.as_ref().ok_or(WireError::Backend)?, policy)
                .await?;
        } else if self.attempt.is_some() {
            branch.fresh_authorize().await?;
        }
        Ok(())
    }

    pub async fn evaluate(
        &mut self,
        branch: &BranchSession,
        policy: &Policy,
        operation: WriteOperation,
        rows: u64,
    ) -> Result<(), WireError> {
        self.evaluate_at(
            branch,
            policy,
            BudgetEvaluation {
                operation,
                rows,
                boundary: AuthorizationBoundary::Statement,
            },
        )
        .await
    }

    /// Implicit SQL transactions defer standalone authority checks to their
    /// mandatory final commit fence. Every Execute still records a fresh
    /// audited decision; extended cycles remain uncommitted until final Sync.
    pub async fn evaluate_autocommit(
        &mut self,
        branch: &BranchSession,
        policy: &Policy,
        operation: WriteOperation,
        rows: u64,
    ) -> Result<(), WireError> {
        self.evaluate_at(
            branch,
            policy,
            BudgetEvaluation {
                operation,
                rows,
                boundary: AuthorizationBoundary::Commit,
            },
        )
        .await
    }

    async fn evaluate_at(
        &mut self,
        branch: &BranchSession,
        policy: &Policy,
        evaluation: BudgetEvaluation,
    ) -> Result<(), WireError> {
        let BudgetEvaluation {
            operation,
            rows,
            boundary,
        } = evaluation;
        self.require_transaction_context(policy)?;
        if self.attempt.is_none() {
            self.attempt = Some(branch.new_write_attempt()?);
        }
        let baseline = branch
            .binding()
            .tables
            .iter()
            .find(|table| table.id == operation.table_id)
            .and_then(|table| u64::try_from(table.baseline_rows).ok())
            .ok_or(WireError::Backend)?;
        let total = self.total.saturating_add(rows);
        let per_table = self
            .tables
            .get(&operation.table_id)
            .copied()
            .unwrap_or(0)
            .saturating_add(rows);
        // The write path may run on a backstop-cached policy copy. The
        // control plane audits every decision under the current class
        // version and refuses stale ones, so a refusal means the policy
        // moved since the cache was filled: refetch, re-evaluate and
        // decide once more under the version that will be audited.
        let mut context = *policy;
        let mut evaluation = evaluate_policy(policy, baseline, total, per_table, rows);
        let mut decision = branch
            .audit_decision(
                self.attempt.as_mut().ok_or(WireError::Backend)?,
                policy,
                DecisionEvaluation {
                    operation,
                    rows,
                    verdict: verdict_of(&evaluation),
                },
            )
            .await;
        if matches!(&decision, Err(WireError::Policy)) {
            let refreshed = branch.fresh_policy().await?;
            self.require_transaction_context(&refreshed)?;
            context = refreshed;
            evaluation = evaluate_policy(&refreshed, baseline, total, per_table, rows);
            decision = branch
                .audit_decision(
                    self.attempt.as_mut().ok_or(WireError::Backend)?,
                    &refreshed,
                    DecisionEvaluation {
                        operation,
                        rows,
                        verdict: verdict_of(&evaluation),
                    },
                )
                .await;
        }
        let approval = decision?;
        let verdict = match evaluation {
            Ok(verdict) => verdict,
            // The decision above recorded the audit row; limits and errors
            // surface afterwards and the guarded write rolls back.
            Err(error) => return Err(error),
        };
        if verdict == DecisionVerdict::AwaitApproval {
            let id = approval.ok_or(WireError::Backend)?;
            wait_for_approval(branch, id).await?;
            // Approval waits can outlast the backstop window, so the
            // comparison needs the current policy, not a cached copy.
            let fresh = branch.fresh_policy().await?;
            if fresh.version != context.version
                || fresh.effective_revision != context.effective_revision
            {
                return Err(WireError::Approval);
            }
        }
        if matches!(boundary, AuthorizationBoundary::Statement) {
            branch.fresh_authorize().await?;
            branch.validate_policy_context(&context).await?;
        }
        self.total = total;
        self.tables.insert(operation.table_id, per_table);
        self.context = Some(context);
        Ok(())
    }

    fn require_transaction_context(&self, policy: &Policy) -> Result<(), WireError> {
        // A later table must not replace the context that admitted earlier
        // work. Checking only the latest table could otherwise commit rows
        // admitted under a revoked grant or an older class policy. SQL rolls
        // the transaction back; standalone Mongo replay stops at admission.
        if self.context.is_some_and(|established| {
            established.version != policy.version
                || established.effective_revision != policy.effective_revision
        }) {
            return Err(WireError::Policy);
        }
        Ok(())
    }
}

fn verdict_of(evaluation: &Result<DecisionVerdict, WireError>) -> DecisionVerdict {
    match evaluation {
        Ok(verdict) => *verdict,
        Err(_) => DecisionVerdict::Limit,
    }
}

fn evaluate_policy(
    policy: &Policy,
    baseline: u64,
    total: u64,
    per_table: u64,
    rows: u64,
) -> Result<DecisionVerdict, WireError> {
    if total > policy.max_transaction_rows {
        return Err(WireError::TransactionRowLimit {
            rows: total,
            limit: policy.max_transaction_rows,
        });
    }
    if let Some(bps) = policy.table_limit_bps {
        let limit = (u128::from(baseline) * u128::from(bps) / BASIS_POINTS)
            .max(u128::from(policy.small_table_floor));
        if u128::from(per_table) > limit {
            return Err(WireError::TableRowLimit {
                rows: per_table,
                limit,
                baseline,
                bps,
            });
        }
    }
    if policy
        .approval_after_rows
        .is_some_and(|minimum| rows >= minimum)
    {
        Ok(DecisionVerdict::AwaitApproval)
    } else {
        Ok(DecisionVerdict::Allowed)
    }
}

async fn wait_for_approval(branch: &BranchSession, id: i64) -> Result<(), WireError> {
    let deadline = Instant::now() + APPROVAL_WINDOW;
    let mut pending = branch.pending_approval(id);
    let result = timeout_at(deadline, async {
        loop {
            match branch.poll_approval(id).await? {
                ApprovalState::Pending => sleep(APPROVAL_POLL_INTERVAL).await,
                ApprovalState::Approved => return Ok(()),
                ApprovalState::Denied | ApprovalState::Expired | ApprovalState::Invalidated => {
                    return Err(WireError::Approval);
                }
            }
        }
    })
    .await;
    match result {
        Ok(Ok(())) => {
            pending.complete();
            Ok(())
        }
        Ok(Err(error)) => Err(error),
        Err(_) => Err(WireError::Approval),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hard_limits_precede_approval_and_small_baselines_allow_one_row() {
        let policy = Policy {
            class: BranchClass::Agent,
            version: 1,
            max_transaction_rows: 2,
            table_limit_bps: Some(100),
            approval_after_rows: Some(1),
            small_table_floor: 1,
            effective_revision: 0,
            grant_expires_at: None,
        };
        assert_eq!(
            evaluate_policy(&policy, 3, 1, 1, 1),
            Ok(DecisionVerdict::AwaitApproval)
        );
        assert_eq!(
            evaluate_policy(&policy, 3, 2, 2, 1),
            Err(WireError::TableRowLimit {
                rows: 2,
                limit: 1,
                baseline: 3,
                bps: 100,
            })
        );
        assert_eq!(
            evaluate_policy(&policy, 1000, 3, 3, 1),
            Err(WireError::TransactionRowLimit { rows: 3, limit: 2 })
        );
        assert_eq!(
            evaluate_policy(&policy, 3, 1, 1, 0),
            Ok(DecisionVerdict::Allowed)
        );
    }

    #[test]
    fn reports_the_cumulative_budget_that_refused_the_write() {
        let policy = Policy {
            class: BranchClass::Dev,
            version: 1,
            max_transaction_rows: 10,
            table_limit_bps: Some(1000),
            approval_after_rows: None,
            small_table_floor: 1,
            effective_revision: 0,
            grant_expires_at: None,
        };
        assert_eq!(
            evaluate_policy(&policy, 4, 1, 1, 1),
            Ok(DecisionVerdict::Allowed)
        );
        let table_error = evaluate_policy(&policy, 4, 3, 2, 1);
        assert_eq!(
            table_error,
            Err(WireError::TableRowLimit {
                rows: 2,
                limit: 1,
                baseline: 4,
                bps: 1000,
            })
        );
        assert_eq!(
            evaluate_policy(&policy, 100, 10, 10, 1),
            Ok(DecisionVerdict::Allowed)
        );
        assert_eq!(
            evaluate_policy(&policy, 100, 11, 1, 1),
            Err(WireError::TransactionRowLimit {
                rows: 11,
                limit: 10,
            })
        );
    }

    #[test]
    fn automatic_small_table_floor_never_overrides_transaction_cap() {
        let policy = Policy {
            class: BranchClass::Agent,
            version: 2,
            max_transaction_rows: 8,
            table_limit_bps: Some(100),
            approval_after_rows: None,
            small_table_floor: 10,
            effective_revision: 0,
            grant_expires_at: None,
        };
        assert_eq!(
            evaluate_policy(&policy, 0, 8, 8, 8),
            Ok(DecisionVerdict::Allowed)
        );
        assert_eq!(
            evaluate_policy(&policy, 4, 9, 9, 1),
            Err(WireError::TransactionRowLimit { rows: 9, limit: 8 })
        );
        let opt_in = Policy {
            approval_after_rows: Some(2),
            ..policy
        };
        assert_eq!(
            evaluate_policy(&opt_in, 4, 2, 2, 2),
            Ok(DecisionVerdict::AwaitApproval)
        );
    }
}
