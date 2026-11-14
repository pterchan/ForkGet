//! Native evidence is consumed only after a durable attempt seal and an
//! independently observed closed service connection.

use fg_meta::{AuditRecoveryAttempt, AuditRecoveryEvidence, Metadata};
use fg_protocol_common::{AuditMode, TransactionOutcome, loopback_client, loopback_http};
use reqwest::{Client, StatusCode, Url};
use serde::Serialize;
use std::{collections::HashSet, time::Duration};
use tokio::time::{Instant, timeout, timeout_at};

use crate::{
    ControlError,
    native::NativeOptions,
    writable::{WitnessError, audit},
};

const NATIVE_EVIDENCE_TIMEOUT: Duration = Duration::from_secs(5);
const RECOVERY_PASS_TIMEOUT: Duration = Duration::from_secs(20);

pub(crate) struct Recovery<'a> {
    pub(crate) metadata: &'a Metadata,
    pub(crate) native: &'a NativeOptions,
    pub(crate) client: &'a Client,
    pub(crate) proxy_url: &'a Url,
    pub(crate) token: &'a str,
    pub(crate) admin: Option<&'a crate::writable::Admin>,
}

#[derive(Default, Serialize)]
pub(crate) struct RecoveryReport {
    examined: usize,
    resolved: usize,
    retained_unknown: usize,
    active_skipped: usize,
    witnesses_collected: usize,
}

impl Recovery<'_> {
    pub(crate) async fn ensure_quiescent(&self) -> Result<(), ControlError> {
        self.proxy_status("internal/v1/native-sessions/quiescent")
            .await
    }

    pub(crate) async fn pass(
        &self,
        branch: Option<i64>,
        forced: bool,
    ) -> Result<RecoveryReport, ControlError> {
        let deadline = Instant::now() + RECOVERY_PASS_TIMEOUT;
        let engine = self.native.engine().name();
        let pending = match branch {
            Some(id) => {
                self.metadata
                    .pending_branch_audit_attempts(engine, id)
                    .await?
            }
            None => self.metadata.pending_audit_attempts(engine).await?,
        };
        let mut report = RecoveryReport::default();
        let mut drained = HashSet::new();
        for attempt in pending {
            if Instant::now() >= deadline {
                break;
            }
            report.examined += 1;
            if attempt.is_current_epoch
                && attempt.outcome.is_none()
                && !forced
                && !matches!(
                    timeout_at(
                        deadline,
                        self.proxy_status(&format!(
                            "internal/v1/native-sessions/{}/quiescent",
                            attempt.context.native_session_id
                        ))
                    )
                    .await,
                    Ok(Ok(()))
                )
            {
                self.metadata
                    .note_audit_recovery_deferred(engine, &attempt.context.attempt_id)
                    .await?;
                report.active_skipped += 1;
                continue;
            }
            if forced && drained.insert(attempt.branch_id) {
                self.proxy_status(&format!("internal/v1/branches/{}/drain", attempt.branch_id))
                    .await?;
            }
            match timeout_at(deadline, self.resolve(attempt)).await {
                Ok(Ok(TransactionOutcome::Committed | TransactionOutcome::RolledBack)) => {
                    report.resolved += 1
                }
                Ok(Ok(TransactionOutcome::Unknown)) => report.retained_unknown += 1,
                Ok(Err(_)) | Err(_) => {
                    report.retained_unknown += 1;
                    tracing::warn!(
                        component = "audit_recovery",
                        "Audit recovery could not verify a sealed attempt; native storage remains retained"
                    );
                }
            }
        }
        report.witnesses_collected = self.collect_until(branch, deadline).await?;
        Ok(report)
    }

    async fn resolve(
        &self,
        attempt: AuditRecoveryAttempt,
    ) -> Result<TransactionOutcome, ControlError> {
        let engine = self.native.engine().name();
        let attempt = self
            .metadata
            .seal_audit_attempt(engine, &attempt.context.attempt_id)
            .await?;
        if let Some(outcome @ (TransactionOutcome::Committed | TransactionOutcome::RolledBack)) =
            attempt.outcome
        {
            return Ok(outcome);
        }
        self.proxy_status(&format!(
            "internal/v1/native-sessions/{}/quiescent",
            attempt.context.native_session_id
        ))
        .await?;
        let evidence = timeout(NATIVE_EVIDENCE_TIMEOUT, self.evidence(&attempt)).await;
        let evidence = match evidence {
            Ok(Ok(evidence)) => evidence,
            Ok(Err(_)) | Err(_) => AuditRecoveryEvidence::Unknown,
        };
        let ack = self
            .metadata
            .resolve_audit_attempt(engine, &attempt.context.attempt_id, evidence)
            .await?;
        Ok(ack.outcome)
    }

    async fn evidence(
        &self,
        attempt: &AuditRecoveryAttempt,
    ) -> Result<AuditRecoveryEvidence, ControlError> {
        if attempt.context.mode == AuditMode::MongoCommand || !attempt.storage_history_trusted {
            return Ok(AuditRecoveryEvidence::Unknown);
        }
        let identity = self
            .metadata
            .audit_witness_binding(self.native.engine().name(), attempt.branch_id)
            .await?
            .ok_or(WitnessError::Identity)?;
        if attempt.witness.as_ref() != Some(&identity) {
            return Err(WitnessError::Identity.into());
        }
        let catalog = self
            .metadata
            .native_catalog(self.native.engine().name())
            .await?;
        let target = catalog
            .branches
            .iter()
            .find(|branch| branch.target.branch_id() == attempt.branch_id)
            .map(|branch| &branch.target)
            .ok_or(WitnessError::Identity)?;
        let admin = self.admin.ok_or(WitnessError::Identity)?;
        let mut attestation = admin.attest_witness(target, &identity).await?;
        let mut native = self.native.connect().await?;
        let exists = audit::contains(
            &mut native,
            audit::WitnessProbe {
                target,
                identity: &identity,
                attempt: &attempt.context,
            },
        )
        .await?;
        attestation.execute("SELECT 1").await?;
        Ok(if exists {
            AuditRecoveryEvidence::SqlCommitted(identity)
        } else {
            AuditRecoveryEvidence::SqlRolledBack(identity)
        })
    }

    async fn collect_until(
        &self,
        branch: Option<i64>,
        deadline: Instant,
    ) -> Result<usize, ControlError> {
        if self.native.engine() == crate::native::Engine::MongoDb {
            return Ok(0);
        }
        let catalog = self
            .metadata
            .native_catalog(self.native.engine().name())
            .await?;
        let mut count = 0;
        for entry in catalog.branches.into_iter().filter(|entry| {
            entry.audit_witness_ready && branch.is_none_or(|id| id == entry.target.branch_id())
        }) {
            if Instant::now() >= deadline {
                break;
            }
            let branch_deadline = deadline.min(Instant::now() + NATIVE_EVIDENCE_TIMEOUT);
            match timeout_at(branch_deadline, self.collect_branch(&entry.target)).await {
                Ok(Ok(collected)) => count += collected,
                Ok(Err(_)) | Err(_) => tracing::warn!(
                    component = "audit_recovery",
                    reason = "audit_witness_cleanup_pending",
                    "Acknowledged witness cleanup remains pending"
                ),
            }
        }
        Ok(count)
    }

    async fn collect_branch(
        &self,
        target: &fg_protocol_common::WriteTarget,
    ) -> Result<usize, ControlError> {
        audit::collect_completed(audit::WitnessCollection {
            metadata: self.metadata,
            options: self.native,
            admin: self.admin.ok_or(WitnessError::Identity)?,
            target,
        })
        .await
    }

    async fn proxy_status(&self, path: &str) -> Result<(), ControlError> {
        let url = self.proxy_url.join(path).map_err(|_| ControlError::Drain)?;
        let response = self
            .client
            .post(url)
            .bearer_auth(self.token)
            .send()
            .await
            .map_err(|_| ControlError::Drain)?;
        if response.status() != StatusCode::NO_CONTENT {
            return Err(WitnessError::Quiescence.into());
        }
        Ok(())
    }
}

pub(crate) async fn require_upgrade_quiescence(
    authoritative: &NativeOptions,
) -> Result<(), ControlError> {
    let managed = fg_protocol_common::ManagedBackend::load()
        .await
        .map_err(ControlError::Config)?;
    let observer = crate::native_options("FG_BACKEND_DSN", managed.as_ref())?;
    let (service, _) = crate::role_names(managed.is_some())?;
    if observer.username() != service || !observer.same_backend(authoritative) {
        return Err(ControlError::Config(
            "upgrade observation requires the configured service account on the authoritative backend",
        ));
    }
    tokio::time::timeout(
        Duration::from_secs(5),
        crate::native::require_service_quiescence(&observer),
    )
    .await
    .map_err(|_| ControlError::NativeTimeout)?
}

struct Operator {
    metadata: Metadata,
    native: NativeOptions,
    client: Client,
    proxy_url: Url,
    token: String,
    admin: Option<crate::writable::Admin>,
}

impl Operator {
    async fn load() -> Result<Self, ControlError> {
        let metadata = crate::metadata("FG_META_DSN", &crate::required("FG_META_DSN")?).await?;
        let managed = fg_protocol_common::ManagedBackend::load()
            .await
            .map_err(ControlError::Config)?;
        let native = crate::native_options("FG_BACKEND_GC_DSN", managed.as_ref())?;
        if native.username() != crate::setting("FG_BACKEND_GC_USER", crate::GC_USER) {
            return Err(ControlError::Config(
                "audit commands require the dedicated native GC account",
            ));
        }
        let (service, collector) = crate::role_names(managed.is_some())?;
        let admin = crate::branch_admin(&native, &service, &collector, managed.as_ref())?;
        Ok(Self {
            metadata,
            native,
            admin,
            client: loopback_client(Duration::from_secs(20)).map_err(|_| ControlError::Drain)?,
            proxy_url: loopback_http(&crate::setting("FG_PROXY_CONTROL_URL", crate::PROXY_URL))
                .ok_or(ControlError::Config("FG_PROXY_CONTROL_URL"))?,
            token: crate::required("FG_INTERNAL_TOKEN")?,
        })
    }

    fn recovery(&self) -> Recovery<'_> {
        Recovery {
            metadata: &self.metadata,
            native: &self.native,
            client: &self.client,
            proxy_url: &self.proxy_url,
            token: &self.token,
            admin: self.admin.as_ref(),
        }
    }
}

pub(crate) async fn reconcile_operator(branch: Option<i64>) -> Result<(), ControlError> {
    let operator = Operator::load().await?;
    let report = operator.recovery().pass(branch, branch.is_some()).await?;
    println!(
        "{}",
        serde_json::to_string(&report)
            .map_err(|_| ControlError::Config("audit report encoding"))?
    );
    Ok(())
}

pub(crate) async fn acknowledge_operator(attempt: &str, actor: &str) -> Result<(), ControlError> {
    let operator = Operator::load().await?;
    if operator.recovery().ensure_quiescent().await.is_err() {
        require_upgrade_quiescence(&operator.native).await?;
    }
    operator
        .metadata
        .acknowledge_audit_unknown(operator.native.engine().name(), attempt, actor)
        .await?;
    Ok(())
}

pub(crate) async fn invalidate_operator(branch: i64, actor: &str) -> Result<(), ControlError> {
    let operator = Operator::load().await?;
    if operator.native.engine() == crate::native::Engine::MongoDb {
        return Err(ControlError::Config(
            "storage incarnation invalidation requires a SQL witness branch",
        ));
    }
    operator
        .metadata
        .invalidate_audit_storage(operator.native.engine().name(), branch, actor)
        .await?;
    // Readiness is already false and old attempts are sealed before closing
    // sessions, so a concurrent client cannot obtain another commit fence.
    if operator
        .recovery()
        .proxy_status(&format!("internal/v1/branches/{branch}/drain"))
        .await
        .is_ok()
        && operator.recovery().pass(Some(branch), true).await.is_ok()
    {
        return Ok(());
    }
    // An offline restore must invalidate metadata before starting the new
    // controller. A fresh service-account observation provides the same
    // quiescence barrier without relying on an unavailable proxy process.
    require_upgrade_quiescence(&operator.native).await?;
    for attempt in operator
        .metadata
        .pending_branch_audit_attempts(operator.native.engine().name(), branch)
        .await?
    {
        if attempt.storage_history_trusted {
            return Err(WitnessError::Identity.into());
        }
        operator
            .metadata
            .resolve_audit_attempt(
                operator.native.engine().name(),
                &attempt.context.attempt_id,
                AuditRecoveryEvidence::Unknown,
            )
            .await?;
    }
    Ok(())
}
