//! PostgreSQL metadata for the local branch lifecycle.

mod allocation;
mod approvals;
mod audit;
mod audit_journal;
mod authority;
mod budget;
mod catalog;
mod github;
mod lease;
mod lifecycle;
mod migrations;
mod policy;
mod replay;
mod snapshot;
mod write_observation;

use sqlx::{
    ConnectOptions, Connection, PgConnection, PgPool,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};
use std::{env, path::Path, str::FromStr};
use thiserror::Error;

pub use approvals::{ApprovalKey, ApprovalReview, ApprovalSummary};
pub use audit::{AuditEvent, AuditFilter, AuditPage};
pub use audit_journal::{AuditRecoveryAttempt, AuditRecoveryEvidence};
pub use budget::{BudgetGrantSummary, BudgetRequestSummary, BudgetReview};
pub use catalog::{
    BootstrapGeneration, NativeBranch, NativeCatalog, RefreshGeneration, SeedColumn, SeedTable,
};
pub use github::{
    GitHubBinding, GitHubFailure, GitHubObservation, GitHubRecreate, GitHubSignal, GitHubSource,
};
pub use lease::{BranchLease, CaptureGuard, MAX_BRANCH_LIFETIME_SECONDS};
pub use lifecycle::{Branch, BranchMode, ForkBranch, LifecycleBranch, MAX_TTL_SECONDS};
pub use replay::{ReplayJob, ReplayStart};
pub use snapshot::SnapshotJob;

const DEFAULT_POOL_LIMIT: u32 = 32;
const POOL_LIMIT_SETTING: &str = "FG_META_POOL_MAX";
// Generation import, retirement, and branch DDL share the native catalog.
const BOOTSTRAP_LOCK: i64 = 0x4647_0000_0000_0001;

#[derive(Debug, Error)]
pub enum MetaError {
    #[error("Invalid or missing setting: {0}")]
    Config(&'static str),
    #[error("Metadata is unavailable")]
    Database(#[from] sqlx::Error),
    #[error("Metadata migration failed")]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error("The requested branch is unavailable")]
    BranchUnavailable,
    #[error("A live branch already has this name")]
    BranchConflict,
    #[error("The lease version changed; refresh branch status before renewing")]
    LeaseConflict,
    #[error(
        "A renewal must extend a live lease by at most 24 hours, within seven days of creation"
    )]
    InvalidLease,
    #[error(
        "The active snapshot does not support writable branches; run fg-control refresh --snapshot v2 on this deployment before creating a writable branch"
    )]
    WriteUnavailable,
    #[error("The deployment already holds 16 writable branch slots")]
    WriteCapacity,
    #[error("The generated key range is exhausted")]
    IdsExhausted,
    #[error("The requested generated key count is outside the supported range")]
    InvalidAllocation,
    #[error("No generation is active for the configured engine")]
    NoGeneration,
    #[error("A generation is already active")]
    AlreadyBootstrapped,
    #[error("Another native catalog operation is running")]
    BootstrapBusy,
    #[error("Retire the previous generation after dropping its branches before refreshing again")]
    GenerationRetention,
    #[error(
        "Wait at least {seconds} seconds after the last successful refresh before refreshing again (FG_REFRESH_COOLDOWN_SECONDS)"
    )]
    RefreshCooldown { seconds: u32 },
    #[error("This generation still has branches awaiting cleanup")]
    GenerationPinned,
    #[error("The requested generation is not eligible for this operation")]
    InvalidGeneration,
    #[error("Replay requires the same deployment and active generation")]
    ReplayMismatch,
    #[error("The generation catalog is invalid")]
    InvalidCatalog,
    #[error("Invalid policy settings")]
    InvalidPolicy,
    #[error("The policy version changed")]
    PolicyConflict,
    #[error("The approval is no longer pending")]
    ApprovalConflict,
    #[error("The durable write attempt conflicts with an existing observation")]
    AuditConflict,
    #[error("Write audit recovery or witness preparation is required before writing")]
    AuditPending,
    #[error("This repository source or generated branch name is already bound")]
    GitHubBindingConflict,
}

#[derive(Clone)]
pub struct Metadata {
    pool: PgPool,
    options: PgConnectOptions,
}

impl Metadata {
    /// Opens the separate metadata database. A supplied CA enables verify-full.
    ///
    /// `FG_META_POOL_MAX` sizes the shared pool (default 32); the proxy's
    /// per-command control calls and every administrative endpoint queue on
    /// it, so a pool sized below the frontend session count amplifies tail
    /// latency under load.
    pub async fn connect(dsn: &str, ca: Option<&Path>) -> Result<Self, MetaError> {
        let mut options = PgConnectOptions::from_str(dsn)?.disable_statement_logging();
        if let Some(ca) = ca {
            options = options.ssl_mode(PgSslMode::VerifyFull).ssl_root_cert(ca);
        }
        let pool = PgPoolOptions::new()
            .max_connections(pool_limit()?)
            .connect_with(options.clone())
            .await?;
        Ok(Self { pool, options })
    }

    pub async fn migrate(&self) -> Result<(), MetaError> {
        migrations::run(&self.pool).await?;
        Ok(())
    }

    /// Hold this dedicated connection through native catalog operations.
    /// Its lifetime releases the session advisory lock even after cancellation.
    pub async fn lock_bootstrap(&self) -> Result<PgConnection, MetaError> {
        let mut connection = PgConnection::connect_with(&self.options).await?;
        let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
            .bind(BOOTSTRAP_LOCK)
            .fetch_one(&mut connection)
            .await?;
        if !acquired {
            return Err(MetaError::BootstrapBusy);
        }
        Ok(connection)
    }
}

/// Control and proxy each hold one pool against the shared metadata
/// PostgreSQL (100 connections by default), so a per-process limit above
/// 100 would exhaust the server when both processes scale up together.
fn pool_limit() -> Result<u32, MetaError> {
    pool_limit_from(env::var(POOL_LIMIT_SETTING).ok().as_deref())
}

fn pool_limit_from(value: Option<&str>) -> Result<u32, MetaError> {
    match value {
        Some(value) => value
            .parse::<u32>()
            .ok()
            .filter(|limit| (1..=100).contains(limit))
            .ok_or(MetaError::Config(POOL_LIMIT_SETTING)),
        None => Ok(DEFAULT_POOL_LIMIT),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_limit_defaults_and_rejects_unusable_values() {
        assert_eq!(pool_limit_from(None).ok(), Some(DEFAULT_POOL_LIMIT));
        for (value, expected) in [("1", 1), ("32", DEFAULT_POOL_LIMIT), ("100", 100)] {
            assert_eq!(pool_limit_from(Some(value)).ok(), Some(expected));
        }
        for invalid in ["0", "101", "-1", "1.5", "many"] {
            assert!(
                pool_limit_from(Some(invalid)).is_err(),
                "{invalid} must be refused"
            );
        }
    }
}
