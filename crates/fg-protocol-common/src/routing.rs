use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    future::Future,
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use reqwest::{Client, StatusCode, Url, redirect::Policy as RedirectPolicy};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::{
    sync::{OwnedRwLockReadGuard, RwLock, watch},
    time::{sleep, timeout},
};

use crate::{
    ApprovalContext, ApprovalState, AuditAttempt, AuditAttemptContext, AuditMode,
    AuditedDecisionRequest, AuditedDecisionResponse, AuditedOutcomeRequest,
    BRANCH_PROTOCOL_VERSION, BranchAccess, BranchClass, BranchLayout, DecisionRequest,
    DecisionVerdict, GENERATED_ID_MAX, GENERATED_ID_START, MAX_GENERATED_ROWS, MongoStepAck,
    MongoStepRequest, MongoWriteObservation, OutcomeAck, Policy, PolicyContext, ProxyEpoch,
    ReadStrategy, TransactionOutcome, WireError, WriteFenceRequest, WriteFenceResponse,
    WriteTarget,
};

mod audit_delivery;
use audit_delivery::PendingDelivery;
#[cfg(test)]
use audit_delivery::audit_status_confirms;
#[cfg(test)]
#[path = "routing/audit_delivery_tests.rs"]
mod audit_delivery_tests;
#[cfg(test)]
#[path = "routing/write_checks_tests.rs"]
mod write_checks_tests;

const CONTROL_TIMEOUT: Duration = Duration::from_secs(3);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(15);
const OBSERVE_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Deserialize, Serialize)]
pub struct BranchBinding {
    pub id: i64,
    pub generation_id: i64,
    pub engine: String,
    pub name: String,
    pub default_schema: String,
    #[serde(default)]
    pub class: BranchClass,
    pub access: BranchAccess,
    pub layout: BranchLayout,
    pub read_strategy: ReadStrategy,
    /// Initial authoritative branch lease deadline in epoch seconds.
    pub expires_at: i64,
    #[serde(default)]
    pub write_schema: Option<String>,
    #[serde(default)]
    pub replay_origin: Option<ReplayOrigin>,
    pub tables: Vec<CatalogEntry>,
    #[serde(default)]
    pub snapshot_manifest: Option<crate::SnapshotManifest>,
    #[serde(default)]
    pub audit_witness_ready: bool,
}

impl BranchBinding {
    pub fn can_write(&self) -> bool {
        self.access == BranchAccess::ReadWrite && self.class != BranchClass::Staging
    }

    /// Fail closed on impossible or incomplete permission/storage bindings.
    pub fn valid_storage_contract(&self) -> bool {
        if self.class == BranchClass::Staging && self.access != BranchAccess::ReadOnly {
            return false;
        }
        match self.layout {
            BranchLayout::NativeCopy => {
                self.write_schema.is_some() && self.read_strategy == ReadStrategy::Merge
            }
            BranchLayout::SparseDelta => {
                self.write_schema.is_none()
                    && (self.access == BranchAccess::ReadOnly || self.engine == "mongodb")
                    && (self.read_strategy == ReadStrategy::Merge
                        || (self.access == BranchAccess::ReadOnly
                            && matches!(self.engine.as_str(), "mysql" | "postgresql" | "tidb")))
            }
        }
    }

    pub fn require_write_access(&self) -> Result<(), WireError> {
        if !self.can_write() {
            return Err(WireError::ReadOnly);
        }
        if self.layout == BranchLayout::NativeCopy
            && self.engine != "mongodb"
            && !self.audit_witness_ready
        {
            return Err(WireError::AuditStorageUnprepared);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayOrigin {
    pub deployment_id: String,
    pub generation_id: i64,
    pub snapshot: String,
}

impl ReplayOrigin {
    pub fn is_valid(&self) -> bool {
        let mut parts = self.deployment_id.split('-');
        self.generation_id > 0
            && (matches!(self.snapshot.as_str(), "v1" | "v2" | "v3")
                || valid_branch_name(&self.snapshot))
            && [8, 4, 4, 4, 12].into_iter().all(|length| {
                parts.next().is_some_and(|part| {
                    part.len() == length
                        && part
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                })
            })
            && parts.next().is_none()
    }

    pub fn session_context(&self, branch_id: i64) -> String {
        format!("{}:{}:{branch_id}", self.deployment_id, self.generation_id)
    }
}

pub fn gate_order_count(snapshot: &str) -> Option<u32> {
    let count = snapshot.strip_prefix("gate-v2-")?;
    if count.starts_with('0') || !count.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    count
        .parse()
        .ok()
        .filter(|count| (1..=20_000_000).contains(count))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CatalogEntry {
    pub id: i64,
    #[serde(default)]
    pub baseline_rows: i64,
    pub logical_schema: String,
    pub logical_table: String,
    pub base_schema: String,
    pub base_table: String,
    pub delta_schema: String,
    pub delta_table: String,
    #[serde(default)]
    pub generated_key: Option<String>,
    pub columns: Vec<CatalogColumn>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CatalogColumn {
    pub name: String,
    pub type_name: String,
    pub nullable: bool,
    pub primary_key_ordinal: Option<u16>,
}

#[derive(Deserialize, Serialize)]
pub struct ResolveBranch {
    pub principal: String,
    pub branch: String,
}

#[derive(Deserialize, Serialize)]
pub struct CheckBranch {
    pub principal: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiffRequest {
    pub principal: String,
    pub expires_at: i64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BranchGrantCheck {
    pub write_schema: String,
    pub tables: Vec<String>,
}

#[derive(Deserialize, Serialize)]
pub struct AllocateIds {
    pub principal: String,
    pub table_id: i64,
    pub count: u16,
}

#[derive(Deserialize, Serialize)]
pub struct AllocatedIds {
    pub first: i64,
}

#[derive(Deserialize)]
pub struct FrontendAccount {
    pub user: String,
    pub password: String,
    pub expires_at: i64,
}

impl FrontendAccount {
    pub fn is_current(&self) -> bool {
        credential_current(self.expires_at)
    }
}

pub fn credential_current(expires_at: i64) -> bool {
    let Ok(expires_at) = u64::try_from(expires_at) else {
        return false;
    };
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .is_ok_and(|now| now.as_secs() < expires_at)
}

fn epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |now| now.as_millis() as u64)
}

pub fn valid_branch_name(name: &str) -> bool {
    (3..=63).contains(&name.len())
        && name.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        // "postgres"/"mysql" collide with deployment databases; "admin",
        // "local" and "config" are mongod-reserved databases.
        && !matches!(name, "postgres" | "mysql" | "admin" | "local" | "config")
}

pub fn bearer_matches(candidate: &str, expected: &str) -> bool {
    !expected.is_empty() && bool::from(candidate.as_bytes().ct_eq(expected.as_bytes()))
}

/// Accept only a literal loopback origin. Tokens stay on the host.
pub fn loopback_http(value: &str) -> Option<Url> {
    let url = Url::parse(value).ok()?;
    let host = url.host_str()?.trim_matches(['[', ']']);
    (url.scheme() == "http"
        && host.parse::<IpAddr>().is_ok_and(|host| host.is_loopback())
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none())
    .then_some(url)
}

pub fn loopback_client(request_timeout: Duration) -> Result<Client, reqwest::Error> {
    Client::builder()
        .no_proxy()
        .redirect(RedirectPolicy::none())
        .timeout(request_timeout)
        .build()
}

/// A single proxy's authenticated control client and native session registry.
#[derive(Clone)]
pub struct Router(Arc<RouterState>);

struct RouterState {
    url: Url,
    token: String,
    engine: String,
    epoch: String,
    next_session: AtomicU64,
    client: Client,
    admission: Arc<RwLock<()>>,
    sessions: Mutex<HashMap<u32, RegisteredSession>>,
    /// Set the moment any control-plane contact fails so cached hot-path
    /// decisions stop being served; a later successful contact clears it.
    degraded: AtomicBool,
    audit_pending: Mutex<HashMap<String, PendingDelivery>>,
    next_audit_retry: AtomicU64,
}

struct RegisteredSession {
    branch_id: i64,
    cancel: watch::Sender<bool>,
}

impl Router {
    pub fn new(url: Url, token: String, engine: &str) -> Result<Self, WireError> {
        if loopback_http(url.as_str()).is_none() || token.is_empty() {
            return Err(WireError::Backend);
        }
        Ok(Self(Arc::new(RouterState {
            url,
            token,
            engine: engine.to_owned(),
            epoch: format!("{:032x}", rand::random::<u128>()),
            next_session: AtomicU64::new(1),
            client: loopback_client(CONTROL_TIMEOUT).map_err(|_| WireError::Backend)?,
            admission: Arc::new(RwLock::new(())),
            sessions: Mutex::new(HashMap::new()),
            degraded: AtomicBool::new(false),
            audit_pending: Mutex::new(HashMap::new()),
            next_audit_retry: AtomicU64::new(1),
        })))
    }

    pub async fn control_ready(&self) -> bool {
        let Ok(url) = self.0.url.join("health/ready") else {
            return false;
        };
        self.0
            .client
            .get(url)
            .send()
            .await
            .is_ok_and(|response| response.status() == StatusCode::NO_CONTENT)
    }

    /// The deployment's native engine name.
    pub fn engine(&self) -> &str {
        &self.0.engine
    }

    pub fn protected_writes_paused(&self) -> Result<bool, WireError> {
        Ok(self
            .0
            .audit_pending
            .lock()
            .map_err(|_| WireError::Backend)?
            .values()
            .any(|delivery| delivery.retry_required))
    }

    pub async fn register_epoch(&self) -> Result<(), WireError> {
        let body = ProxyEpoch {
            epoch: self.0.epoch.clone(),
            protocol_version: BRANCH_PROTOCOL_VERSION,
        };
        self.post("internal/v1/proxy/start", &body).await?;
        Ok(())
    }

    pub async fn begin(
        &self,
        principal: &str,
        branch: &str,
        expires_at: i64,
    ) -> Result<PendingSession, WireError> {
        if !credential_current(expires_at) {
            return Err(WireError::Auth);
        }
        if !valid_branch_name(branch) {
            return Err(WireError::Branch);
        }
        let barrier = self.0.admission.clone().read_owned().await;
        if !credential_current(expires_at) {
            return Err(WireError::Auth);
        }
        let request = ResolveBranch {
            principal: principal.to_owned(),
            branch: branch.to_owned(),
        };
        let response = self.post("internal/v1/resolve", &request).await?;
        let binding: BranchBinding = response.json().await.map_err(|_| WireError::Backend)?;
        if !credential_current(expires_at) {
            return Err(WireError::Auth);
        }
        if binding.name != branch {
            return Err(WireError::Backend);
        }
        self.pending(binding, request.principal, expires_at, barrier)
    }

    pub async fn begin_id(
        &self,
        principal: &str,
        branch_id: i64,
        expires_at: i64,
    ) -> Result<PendingSession, WireError> {
        if !credential_current(expires_at) {
            return Err(WireError::Auth);
        }
        if branch_id <= 0 {
            return Err(WireError::Branch);
        }
        let barrier = self.0.admission.clone().read_owned().await;
        if !credential_current(expires_at) {
            return Err(WireError::Auth);
        }
        let body = CheckBranch {
            principal: principal.to_owned(),
        };
        let path = format!("internal/v1/branches/{branch_id}/resolve");
        let response = self.post(&path, &body).await?;
        let binding: BranchBinding = response.json().await.map_err(|_| WireError::Backend)?;
        if !credential_current(expires_at) {
            return Err(WireError::Auth);
        }
        if binding.id != branch_id {
            return Err(WireError::Backend);
        }
        self.pending(binding, body.principal, expires_at, barrier)
    }

    fn pending(
        &self,
        binding: BranchBinding,
        principal: String,
        expires_at: i64,
        barrier: OwnedRwLockReadGuard<()>,
    ) -> Result<PendingSession, WireError> {
        if binding.id <= 0
            || binding.generation_id <= 0
            || binding.engine != self.0.engine
            || binding.tables.is_empty()
            || !binding.valid_storage_contract()
            || binding.write_schema.as_ref().is_some_and(|schema| {
                WriteTarget::new(&binding.engine, binding.id, schema).is_none()
            })
        {
            return Err(WireError::Backend);
        }
        Ok(PendingSession {
            router: self.clone(),
            binding,
            principal,
            expires_at,
            replay_job_id: None,
            _barrier: barrier,
        })
    }

    pub async fn begin_replay(
        &self,
        permit: &crate::ReplayPermit,
        native_id: u32,
        verify_only: bool,
    ) -> Result<PendingSession, WireError> {
        if !credential_current(permit.credential_expires_at) || permit.job_id <= 0 {
            return Err(WireError::Auth);
        }
        let barrier = self.0.admission.clone().read_owned().await;
        let body = crate::ReplayResolve {
            principal: permit.owner.clone(),
            expires_at: permit.credential_expires_at,
            job_id: permit.job_id,
            native_session_id: native_id,
            verify_only,
        };
        let response = self
            .post(
                &format!("internal/v1/replays/{}/resolve", permit.job_id),
                &body,
            )
            .await?;
        let binding: BranchBinding = response.json().await.map_err(|_| WireError::Backend)?;
        if binding.id != permit.branch_id || binding.generation_id != permit.generation_id {
            return Err(WireError::Branch);
        }
        let mut pending = self.pending(
            binding,
            permit.owner.clone(),
            permit.credential_expires_at,
            barrier,
        )?;
        pending.replay_job_id = Some(permit.job_id);
        Ok(pending)
    }

    async fn post(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> Result<reqwest::Response, WireError> {
        let response = self.send(path, body).await?;
        match response.status() {
            StatusCode::OK | StatusCode::NO_CONTENT => Ok(response),
            StatusCode::NOT_FOUND => Err(WireError::Branch),
            _ => Err(WireError::Backend),
        }
    }

    async fn send(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> Result<reqwest::Response, WireError> {
        let url = self.0.url.join(path).map_err(|_| WireError::Backend)?;
        let result = self
            .0
            .client
            .post(url)
            .bearer_auth(&self.0.token)
            .json(body)
            .send()
            .await;
        match result {
            Ok(response) => {
                self.0.degraded.store(false, Ordering::Relaxed);
                Ok(response)
            }
            Err(_) => {
                self.0.degraded.store(true, Ordering::Relaxed);
                Err(WireError::Backend)
            }
        }
    }

    /// Account for new and closing native sockets before authorizing GC.
    pub async fn drain<F, Fut>(&self, branch_id: i64, observe: F) -> Result<(), WireError>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<Vec<u32>, WireError>>,
    {
        timeout(DRAIN_TIMEOUT, self.drain_with_barrier(branch_id, observe))
            .await
            .map_err(|_| WireError::Backend)?
    }

    async fn drain_with_barrier<F, Fut>(&self, branch_id: i64, observe: F) -> Result<(), WireError>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<Vec<u32>, WireError>>,
    {
        let _barrier = self.0.admission.write().await;
        for session in self
            .0
            .sessions
            .lock()
            .map_err(|_| WireError::Backend)?
            .values()
        {
            if session.branch_id == branch_id {
                session.cancel.send_replace(true);
            }
        }
        loop {
            if let Some(other_sessions) = self.other_sessions(branch_id)?
                && observe()
                    .await?
                    .iter()
                    .all(|id| other_sessions.contains(id))
            {
                return Ok(());
            }
            sleep(OBSERVE_INTERVAL).await;
        }
    }

    fn other_sessions(&self, branch_id: i64) -> Result<Option<HashSet<u32>>, WireError> {
        let sessions = self.0.sessions.lock().map_err(|_| WireError::Backend)?;
        if sessions
            .values()
            .any(|session| session.branch_id == branch_id)
        {
            return Ok(None);
        }
        Ok(Some(sessions.keys().copied().collect()))
    }
}

/// Holds admission through native authentication and session registration.
pub struct PendingSession {
    router: Router,
    binding: BranchBinding,
    principal: String,
    expires_at: i64,
    replay_job_id: Option<i64>,
    _barrier: OwnedRwLockReadGuard<()>,
}

impl PendingSession {
    pub fn binding(&self) -> &BranchBinding {
        &self.binding
    }

    pub fn activate(self, native_id: u32) -> Result<BranchSession, WireError> {
        if !credential_current(self.expires_at) {
            return Err(WireError::Auth);
        }
        let (cancel, receiver) = watch::channel(false);
        let serial = self
            .router
            .0
            .next_session
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |serial| {
                serial.checked_add(1)
            })
            .map_err(|_| WireError::Backend)?;
        let mut sessions = self
            .router
            .0
            .sessions
            .lock()
            .map_err(|_| WireError::Backend)?;
        let Entry::Vacant(entry) = sessions.entry(native_id) else {
            return Err(WireError::Backend);
        };
        entry.insert(RegisteredSession {
            branch_id: self.binding.id,
            cancel,
        });
        drop(sessions);
        let lease_deadline = self.binding.expires_at;
        Ok(BranchSession {
            router: self.router,
            binding: self.binding,
            principal: self.principal,
            expires_at: self.expires_at,
            native_id,
            serial,
            receiver,
            last_active_ms: AtomicU64::new(0),
            lease_deadline: AtomicI64::new(lease_deadline),
            lease_version: AtomicI64::new(0),
            policy_cache: Mutex::new(None),
            next_operation: AtomicU64::new(1),
            replay_job_id: self.replay_job_id,
        })
    }
}

pub struct BranchSession {
    router: Router,
    binding: BranchBinding,
    principal: String,
    expires_at: i64,
    native_id: u32,
    serial: u64,
    receiver: watch::Receiver<bool>,
    // Bounded read authorization and policy caches avoid redundant control
    // requests. Protected writes still require fresh checks. Epoch
    // milliseconds (0 = never checked) keep the session future Send.
    last_active_ms: AtomicU64,
    lease_deadline: AtomicI64,
    lease_version: AtomicI64,
    policy_cache: Mutex<Option<(Policy, Instant)>>,
    next_operation: AtomicU64,
    replay_job_id: Option<i64>,
}

/// Interval between control-plane re-verifications of cached hot-path state.
///
/// The per-command guarantee stays local: the cancel watch covers drops and
/// generation switches pushed through drain. A reached lease deadline forces
/// an authoritative refresh so a prior renewal also reaches existing sessions.
/// A failed refresh cannot extend service beyond the known lease deadline.
const BACKSTOP: Duration = Duration::from_secs(5);

#[derive(Deserialize)]
struct LeaseResponse {
    expires_at: i64,
    lease_version: i64,
}

impl BranchSession {
    pub fn binding(&self) -> &BranchBinding {
        &self.binding
    }

    pub fn new_write_attempt(&self) -> Result<AuditAttempt, WireError> {
        self.check_local()?;
        let operation = self
            .next_operation
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| WireError::Backend)?;
        let session_id = self.session_id();
        Ok(AuditAttempt::new(AuditAttemptContext {
            attempt_id: format!("{session_id}:{operation}"),
            principal: self.principal.clone(),
            session_id,
            native_session_id: self.native_id,
            generation_id: self.binding.generation_id,
            replay_job_id: self.replay_job_id,
            mode: if self.binding.engine == "mongodb" {
                AuditMode::MongoCommand
            } else {
                AuditMode::SqlTransaction
            },
        }))
    }

    async fn reconcile_audit_delivery(&self) -> Result<(), WireError> {
        self.router.retry_audit_deliveries().await?;
        if self.router.protected_writes_paused()? {
            return Err(WireError::Backend);
        }
        Ok(())
    }

    pub(crate) async fn audit_decision(
        &self,
        attempt: &mut AuditAttempt,
        policy: &Policy,
        evaluation: crate::policy::DecisionEvaluation,
    ) -> Result<Option<i64>, WireError> {
        let crate::policy::DecisionEvaluation {
            operation,
            rows,
            verdict,
        } = evaluation;
        self.check_local()?;
        self.reconcile_audit_delivery().await?;
        let request = AuditedDecisionRequest {
            attempt: attempt.context().clone(),
            decision: DecisionRequest {
                principal: self.principal.clone(),
                session_id: self.session_id(),
                policy_version: policy.version,
                effective_revision: policy.effective_revision,
                operation,
                rows,
                verdict,
            },
        };
        attempt.mark_intent_possible();
        let response = self
            .router
            .send(
                &format!("internal/v1/branches/{}/audit/decisions", self.binding.id),
                &request,
            )
            .await?;
        let response: AuditedDecisionResponse = match response.status() {
            StatusCode::OK => response.json().await.map_err(|_| WireError::Backend)?,
            StatusCode::CONFLICT if verdict == DecisionVerdict::AwaitApproval => {
                return Err(WireError::Approval);
            }
            StatusCode::CONFLICT => return Err(WireError::Policy),
            StatusCode::NOT_FOUND => return Err(WireError::Branch),
            _ => return Err(WireError::Backend),
        };
        let valid_witness = match attempt.context().mode {
            AuditMode::MongoCommand => response.witness.is_none(),
            AuditMode::SqlTransaction => response.witness.as_ref().is_some_and(|witness| {
                witness.format_version == crate::AUDIT_WITNESS_VERSION
                    && witness.branch_id == self.binding.id
                    && witness.generation_id == self.binding.generation_id
                    && crate::valid_witness_identity(
                        &witness.deployment_id,
                        &witness.storage_incarnation,
                    )
            }),
        };
        if !valid_witness {
            return Err(WireError::Backend);
        }
        self.check_local()?;
        attempt.accept_decision(response)
    }

    pub async fn audit_outcome(
        &self,
        attempt: &AuditAttempt,
        outcome: TransactionOutcome,
    ) -> Result<OutcomeAck, WireError> {
        if !attempt.intent_possible() {
            return Err(WireError::Backend);
        }
        self.deliver_audit_outcome(AuditedOutcomeRequest {
            attempt: attempt.context().clone(),
            outcome,
            armed_step: 0,
            mongo: None,
        })
        .await
    }

    async fn deliver_audit_outcome(
        &self,
        request: AuditedOutcomeRequest,
    ) -> Result<OutcomeAck, WireError> {
        self.router
            .deliver_audit_outcome(self.binding.id, request)
            .await
    }

    pub async fn arm_mongo_step(
        &self,
        attempt: &mut AuditAttempt,
        previous: Option<MongoWriteObservation>,
    ) -> Result<MongoStepAck, WireError> {
        self.check_local()?;
        self.reconcile_audit_delivery().await?;
        let request = MongoStepRequest {
            attempt: attempt.context().clone(),
            expected_step: attempt.confirmed_step(),
            previous,
        };
        attempt.mark_step_possible()?;
        let response = self
            .router
            .post(
                &format!("internal/v1/branches/{}/audit/mongo-step", self.binding.id),
                &request,
            )
            .await?;
        let ack = response.json().await.map_err(|_| WireError::Backend)?;
        attempt.accept_step(&ack)?;
        self.check_local()?;
        Ok(ack)
    }

    pub async fn finish_mongo_attempt(
        &self,
        attempt: &AuditAttempt,
        observation: MongoWriteObservation,
    ) -> Result<OutcomeAck, WireError> {
        if !attempt.intent_possible() {
            return Err(WireError::Backend);
        }
        self.deliver_audit_outcome(AuditedOutcomeRequest {
            attempt: attempt.context().clone(),
            outcome: observation.outcome(attempt.armed_step()),
            armed_step: attempt.armed_step(),
            mongo: Some(observation),
        })
        .await
    }

    pub async fn fresh_write_fence(
        &self,
        attempt: &AuditAttempt,
        policy: &Policy,
    ) -> Result<(), WireError> {
        self.check_local()?;
        self.reconcile_audit_delivery().await?;
        let request = WriteFenceRequest {
            attempt: attempt.context().clone(),
            policy_version: policy.version,
            effective_revision: policy.effective_revision,
            witness: attempt.witness().cloned(),
        };
        let response = self
            .router
            .send(
                &format!("internal/v1/branches/{}/write-fence", self.binding.id),
                &request,
            )
            .await?;
        let lease: WriteFenceResponse = match response.status() {
            StatusCode::OK => response.json().await.map_err(|_| WireError::Backend)?,
            StatusCode::CONFLICT => return Err(WireError::Policy),
            StatusCode::NOT_FOUND => return Err(WireError::Branch),
            _ => return Err(WireError::Backend),
        };
        if lease.branch_id != self.binding.id
            || lease.engine != self.binding.engine
            || lease.context != request
        {
            return Err(WireError::Backend);
        }
        if !credential_current(lease.expires_at) || lease.lease_version <= 0 {
            return Err(WireError::Branch);
        }
        self.check_local()?;
        self.lease_deadline
            .fetch_max(lease.expires_at, Ordering::Relaxed);
        self.lease_version
            .fetch_max(lease.lease_version, Ordering::Relaxed);
        self.last_active_ms.store(epoch_millis(), Ordering::Relaxed);
        Ok(())
    }

    pub fn session_id(&self) -> String {
        format!("{}:{}", self.router.0.epoch, self.serial)
    }

    pub async fn bind_replay(&self, job: i64) -> Result<(), WireError> {
        let body = crate::ReplaySession {
            principal: self.principal.clone(),
            session_id: self.session_id(),
            native_session_id: self.native_id,
        };
        self.router
            .post(&format!("internal/v1/replays/{job}/bind"), &body)
            .await?;
        Ok(())
    }

    pub async fn validate_replay(&self, job: i64) -> Result<(), WireError> {
        let body = crate::ReplaySession {
            principal: self.principal.clone(),
            session_id: self.session_id(),
            native_session_id: self.native_id,
        };
        self.router
            .post(&format!("internal/v1/replays/{job}/validate"), &body)
            .await?;
        Ok(())
    }

    pub async fn uncertain_replay(&self, job: i64) -> Result<(), WireError> {
        let body = crate::ReplaySession {
            principal: self.principal.clone(),
            session_id: self.session_id(),
            native_session_id: self.native_id,
        };
        self.router
            .post(&format!("internal/v1/replays/{job}/uncertain"), &body)
            .await?;
        Ok(())
    }

    pub async fn advance_replay_ids(
        &self,
        job: i64,
        table_id: i64,
        highest: i64,
    ) -> Result<(), WireError> {
        let body = crate::ReplayIds {
            session: crate::ReplaySession {
                principal: self.principal.clone(),
                session_id: self.session_id(),
                native_session_id: self.native_id,
            },
            table_id,
            highest,
        };
        self.router
            .post(&format!("internal/v1/replays/{job}/ids"), &body)
            .await?;
        Ok(())
    }

    fn approval_context(&self) -> ApprovalContext {
        ApprovalContext {
            principal: self.principal.clone(),
            session_id: self.session_id(),
        }
    }

    pub(crate) fn pending_approval(&self, id: i64) -> PendingApproval {
        PendingApproval {
            router: self.router.clone(),
            context: Some(self.approval_context()),
            path: format!(
                "internal/v1/branches/{}/approvals/{id}/invalidate",
                self.binding.id
            ),
        }
    }

    pub(crate) async fn poll_approval(&self, id: i64) -> Result<ApprovalState, WireError> {
        self.check_local()?;
        let path = format!(
            "internal/v1/branches/{}/approvals/{id}/poll",
            self.binding.id
        );
        let response = self.router.post(&path, &self.approval_context()).await?;
        let state = response.json().await.map_err(|_| WireError::Backend)?;
        self.check_local()?;
        Ok(state)
    }

    /// Verify the branch may still serve this command.
    ///
    /// Locally decided per command: cancel watch (drop/drain), credential
    /// expiry, and the branch TTL deadline. The control plane is consulted
    /// at most once per [`BACKSTOP`] to pick up state changes the local
    /// signals cannot observe — except while the router is degraded, when
    /// every command re-verifies (and fails closed on control loss).
    pub async fn authorize(&self) -> Result<(), WireError> {
        self.check_local()?;
        let checked = self.last_active_ms.load(Ordering::Relaxed);
        if !self.router.0.degraded.load(Ordering::Relaxed)
            && credential_current(self.lease_deadline.load(Ordering::Acquire))
            && checked > 0
            && epoch_millis().saturating_sub(checked) < BACKSTOP.as_millis() as u64
        {
            return Ok(());
        }
        self.fresh_authorize().await
    }

    /// Control-plane verification without the backstop, for the write
    /// protection boundary: a control outage must keep failing guarded
    /// writes closed even while the session's cached decision is fresh.
    /// A successful contact also clears the router-wide degradation.
    pub async fn fresh_authorize(&self) -> Result<(), WireError> {
        self.check_local()?;
        let body = CheckBranch {
            principal: self.principal.clone(),
        };
        let path = format!("internal/v1/branches/{}/lease", self.binding.id);
        let response = self.router.post(&path, &body).await?;
        if response.status() != StatusCode::OK {
            return Err(WireError::Backend);
        }
        let lease: LeaseResponse = response.json().await.map_err(|_| WireError::Backend)?;
        if lease.lease_version <= 0 || !credential_current(lease.expires_at) {
            return Err(WireError::Branch);
        }
        self.lease_deadline
            .fetch_max(lease.expires_at, Ordering::AcqRel);
        self.lease_version
            .fetch_max(lease.lease_version, Ordering::AcqRel);
        self.last_active_ms.store(epoch_millis(), Ordering::Relaxed);
        self.check_local()
    }

    pub async fn policy(&self) -> Result<Policy, WireError> {
        self.binding.require_write_access()?;
        self.reconcile_audit_delivery().await?;
        if let Some((policy, checked)) = self
            .policy_cache
            .lock()
            .map_err(|_| WireError::Backend)?
            .as_ref()
            && checked.elapsed() < BACKSTOP
            && policy.grant_expires_at.is_none_or(credential_current)
        {
            return Ok(*policy);
        }
        let policy = self.fetch_policy().await?;
        *self.policy_cache.lock().map_err(|_| WireError::Backend)? = Some((policy, Instant::now()));
        Ok(policy)
    }

    /// Read the branch policy without the backstop cache, for callers whose
    /// decision must reflect a change that may have landed at any point
    /// during a long wait (approval re-validation).
    pub async fn fresh_policy(&self) -> Result<Policy, WireError> {
        let policy = self.fetch_policy().await?;
        *self.policy_cache.lock().map_err(|_| WireError::Backend)? = Some((policy, Instant::now()));
        Ok(policy)
    }

    async fn fetch_policy(&self) -> Result<Policy, WireError> {
        self.check_local()?;
        self.binding.require_write_access()?;
        let path = format!("internal/v1/branches/{}/policy", self.binding.id);
        let body = CheckBranch {
            principal: self.principal.clone(),
        };
        let response = self.router.post(&path, &body).await?;
        let policy: Policy = response.json().await.map_err(|_| WireError::Backend)?;
        self.check_local()?;
        if policy.class != self.binding.class || policy.version <= 0 {
            return Err(WireError::Backend);
        }
        if policy.class == BranchClass::Staging {
            return Err(WireError::Policy);
        }
        Ok(policy)
    }

    /// Revalidate the exact policy/grant context before committing guarded work.
    pub async fn validate_policy_context(&self, policy: &Policy) -> Result<(), WireError> {
        self.check_local()?;
        self.binding.require_write_access()?;
        let body = PolicyContext {
            principal: self.principal.clone(),
            policy_version: policy.version,
            effective_revision: policy.effective_revision,
        };
        let path = format!("internal/v1/branches/{}/policy/validate", self.binding.id);
        let response = self.router.send(&path, &body).await?;
        match response.status() {
            StatusCode::NO_CONTENT => self.check_local(),
            StatusCode::NOT_FOUND => Err(WireError::Branch),
            StatusCode::CONFLICT | StatusCode::FORBIDDEN => Err(WireError::Policy),
            _ => Err(WireError::Backend),
        }
    }

    pub async fn allocate(&self, table_id: i64, count: u16) -> Result<i64, WireError> {
        self.check_local()?;
        self.binding.require_write_access()?;
        self.reconcile_audit_delivery().await?;
        if !(1..=MAX_GENERATED_ROWS).contains(&count)
            || table_id <= 0
            || self.binding.write_schema.is_none()
            || !self
                .binding
                .tables
                .iter()
                .any(|table| table.id == table_id && table.generated_key.is_some())
        {
            return Err(WireError::InvalidValue);
        }
        let path = format!("internal/v1/branches/{}/allocate", self.binding.id);
        let body = AllocateIds {
            principal: self.principal.clone(),
            table_id,
            count,
        };
        let response = self.router.send(&path, &body).await?;
        self.check_local()?;
        match response.status() {
            StatusCode::OK => {
                let allocated: AllocatedIds =
                    response.json().await.map_err(|_| WireError::Backend)?;
                self.check_local()?;
                let last_start = GENERATED_ID_MAX - i64::from(count) + 1;
                (GENERATED_ID_START..=last_start)
                    .contains(&allocated.first)
                    .then_some(allocated.first)
                    .ok_or(WireError::Backend)
            }
            StatusCode::NOT_FOUND => Err(WireError::Branch),
            StatusCode::CONFLICT => Err(WireError::IdsExhausted),
            _ => Err(WireError::Backend),
        }
    }

    fn check_local(&self) -> Result<(), WireError> {
        if *self.receiver.borrow() {
            return Err(WireError::Branch);
        }
        if !credential_current(self.expires_at) {
            return Err(WireError::Auth);
        }
        Ok(())
    }

    pub async fn cancelled(&self) {
        let mut receiver = self.receiver.clone();
        let _ = receiver.wait_for(|cancelled| *cancelled).await;
    }
}

pub(crate) struct PendingApproval {
    router: Router,
    path: String,
    context: Option<ApprovalContext>,
}

impl PendingApproval {
    pub(crate) fn complete(&mut self) {
        self.context = None;
    }
}

impl Drop for PendingApproval {
    fn drop(&mut self) {
        if let (Some(context), Ok(runtime)) =
            (self.context.take(), tokio::runtime::Handle::try_current())
        {
            let router = self.router.clone();
            let path = self.path.clone();
            runtime.spawn(async move {
                let _ = router.post(&path, &context).await;
            });
        }
    }
}

impl Drop for BranchSession {
    fn drop(&mut self) {
        if let Ok(mut sessions) = self.router.0.sessions.lock() {
            sessions.remove(&self.native_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuditStatus;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn router() -> Result<Router, WireError> {
        let url = loopback_http("http://127.0.0.1:8081").ok_or(WireError::Backend)?;
        Router::new(url, "test-token".into(), "mysql")
    }

    pub(super) async fn pending(router: &Router, branch: i64) -> PendingSession {
        PendingSession {
            router: router.clone(),
            binding: BranchBinding {
                id: branch,
                generation_id: 1,
                engine: "mysql".into(),
                name: format!("branch-{branch}"),
                default_schema: "app".into(),
                class: BranchClass::Dev,
                expires_at: i64::MAX,
                write_schema: None,
                access: BranchAccess::ReadOnly,
                layout: BranchLayout::SparseDelta,
                read_strategy: ReadStrategy::Merge,
                snapshot_manifest: None,
                audit_witness_ready: false,
                replay_origin: None,
                tables: Vec::new(),
            },
            principal: "owner".into(),
            expires_at: i64::MAX,
            replay_job_id: None,
            _barrier: router.0.admission.clone().read_owned().await,
        }
    }

    async fn lease_server(
        status: &'static str,
        body: String,
    ) -> Result<(Router, tokio::task::JoinHandle<()>), WireError> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| WireError::Backend)?;
        let address = listener.local_addr().map_err(|_| WireError::Backend)?;
        let url = loopback_http(&format!("http://{address}")).ok_or(WireError::Backend)?;
        let task = tokio::spawn(async move {
            if let Ok((mut connection, _)) = listener.accept().await {
                let mut request = vec![0u8; 4096];
                if connection.read(&mut request).await.is_ok() {
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = connection.write_all(response.as_bytes()).await;
                }
            }
        });
        Ok((Router::new(url, "test-token".into(), "mysql")?, task))
    }

    #[tokio::test]
    async fn pending_delivery_cannot_replace_a_known_commit_with_rollback() -> Result<(), WireError>
    {
        let (router, server) = lease_server("503 Service Unavailable", "{}".into()).await?;
        let branch = pending(&router, 1).await.activate(77)?;
        let mut attempt = branch.new_write_attempt()?;
        attempt.mark_intent_possible();
        assert!(
            branch
                .audit_outcome(&attempt, TransactionOutcome::Committed)
                .await
                .is_err()
        );
        assert!(
            branch
                .audit_outcome(&attempt, TransactionOutcome::RolledBack)
                .await
                .is_err()
        );
        server.await.map_err(|_| WireError::Backend)?;
        let pending = router
            .0
            .audit_pending
            .lock()
            .map_err(|_| WireError::Backend)?;
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending
                .get(&attempt.context().attempt_id)
                .map(|delivery| delivery.request.outcome),
            Some(TransactionOutcome::Committed)
        );
        Ok(())
    }

    #[tokio::test]
    async fn rejected_outcome_delivery_uses_only_a_matching_known_resolution()
    -> Result<(), WireError> {
        for resolution in [
            TransactionOutcome::Committed,
            TransactionOutcome::RolledBack,
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|_| WireError::Backend)?;
            let url = loopback_http(&format!(
                "http://{}",
                listener.local_addr().map_err(|_| WireError::Backend)?
            ))
            .ok_or(WireError::Backend)?;
            let router = Router::new(url, "test-token".into(), "mysql")?;
            let branch = pending(&router, 1).await.activate(77)?;
            let mut attempt = branch.new_write_attempt()?;
            attempt.mark_intent_possible();
            let status = AuditStatus {
                ack: Some(OutcomeAck {
                    attempt_id: attempt.context().attempt_id.clone(),
                    audit_event_id: 10,
                    outcome: TransactionOutcome::Unknown,
                }),
                outcome: Some(AuditedOutcomeRequest {
                    attempt: attempt.context().clone(),
                    outcome: TransactionOutcome::Unknown,
                    armed_step: 0,
                    mongo: None,
                }),
                resolution: Some(OutcomeAck {
                    attempt_id: attempt.context().attempt_id.clone(),
                    audit_event_id: 11,
                    outcome: resolution,
                }),
                retention_ack_event_id: None,
                resolved: true,
                ..Default::default()
            };
            let body = serde_json::to_string(&status).map_err(|_| WireError::Backend)?;
            let server = tokio::spawn(async move {
                let mut paths = Vec::new();
                for (status, body) in [
                    ("503 Service Unavailable", "{}".to_owned()),
                    ("503 Service Unavailable", "{}".to_owned()),
                    ("200 OK", body),
                ] {
                    let (mut socket, _) =
                        listener.accept().await.map_err(|_| WireError::Backend)?;
                    paths.push(read_audit_http_request(&mut socket).await?);
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    socket
                        .write_all(response.as_bytes())
                        .await
                        .map_err(|_| WireError::Backend)?;
                }
                Ok::<_, WireError>(paths)
            });
            assert!(
                branch
                    .audit_outcome(&attempt, TransactionOutcome::Committed)
                    .await
                    .is_err()
            );
            assert!(router.protected_writes_paused()?);
            tokio::time::sleep(Duration::from_millis(1100)).await;
            let recovered = branch.reconcile_audit_delivery().await;
            assert_eq!(
                recovered.is_ok(),
                resolution == TransactionOutcome::Committed
            );
            assert_eq!(
                router.protected_writes_paused()?,
                resolution != TransactionOutcome::Committed
            );
            let paths = server.await.map_err(|_| WireError::Backend)??;
            assert!(paths[0].contains("/audit/outcome"));
            assert!(paths[1].contains("/audit/outcome"));
            assert!(paths[2].contains("/audit/status"));
        }
        Ok(())
    }

    async fn read_audit_http_request(
        socket: &mut tokio::net::TcpStream,
    ) -> Result<String, WireError> {
        read_audit_http_message(socket).await.map(|(path, _)| path)
    }

    pub(super) async fn read_audit_http_message(
        socket: &mut tokio::net::TcpStream,
    ) -> Result<(String, serde_json::Value), WireError> {
        let mut data = Vec::new();
        loop {
            let mut buffer = [0; 4096];
            let count = socket
                .read(&mut buffer)
                .await
                .map_err(|_| WireError::Backend)?;
            if count == 0 {
                return Err(WireError::Backend);
            }
            data.extend_from_slice(&buffer[..count]);
            if let Some(end) = data.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                let headers = std::str::from_utf8(&data[..end]).map_err(|_| WireError::Backend)?;
                let length = headers
                    .lines()
                    .find_map(|line| {
                        line.split_once(':')
                            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                            .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                if data.len() >= end + 4 + length {
                    let path = headers.lines().next().ok_or(WireError::Backend)?.to_owned();
                    let body = serde_json::from_slice(&data[end + 4..end + 4 + length])
                        .map_err(|_| WireError::Backend)?;
                    return Ok((path, body));
                }
            }
        }
    }

    #[tokio::test]
    async fn mongo_unknown_ack_cannot_discard_undelivered_partial_counts() -> Result<(), WireError>
    {
        let router = router()?;
        let branch = pending(&router, 1).await.activate(77)?;
        let mut context = branch.new_write_attempt()?.context().clone();
        context.mode = AuditMode::MongoCommand;
        let request = AuditedOutcomeRequest {
            attempt: context,
            outcome: TransactionOutcome::Unknown,
            armed_step: 1,
            mongo: Some(MongoWriteObservation {
                state: crate::MongoObservationState::Unknown,
                matched: Some(1),
                ..Default::default()
            }),
        };
        let mut generic = request.clone();
        generic.mongo.as_mut().ok_or(WireError::Backend)?.matched = None;
        let mut status = AuditStatus {
            ack: Some(OutcomeAck {
                attempt_id: request.attempt.attempt_id.clone(),
                audit_event_id: 10,
                outcome: TransactionOutcome::Unknown,
            }),
            outcome: Some(generic),
            resolved: true,
            ..Default::default()
        };
        assert!(!audit_status_confirms(&status, &request));
        status.late_ack = Some(OutcomeAck {
            attempt_id: request.attempt.attempt_id.clone(),
            audit_event_id: 11,
            outcome: TransactionOutcome::Unknown,
        });
        status.late_outcome = Some(request.clone());
        assert!(audit_status_confirms(&status, &request));
        status
            .late_outcome
            .as_mut()
            .and_then(|value| value.mongo.as_mut())
            .ok_or(WireError::Backend)?
            .matched = Some(2);
        assert!(!audit_status_confirms(&status, &request));
        Ok(())
    }

    #[tokio::test]
    async fn renewal_updates_an_existing_session_past_its_original_deadline()
    -> Result<(), WireError> {
        let expiry = (epoch_millis() / 1000) as i64 + 60;
        let (router, server) = lease_server(
            "200 OK",
            format!(r#"{{"expires_at":{expiry},"lease_version":2}}"#),
        )
        .await?;
        let mut admission = pending(&router, 1).await;
        admission.binding.expires_at = 1;
        let session = admission.activate(10)?;
        session
            .last_active_ms
            .store(epoch_millis(), Ordering::Relaxed);
        session.authorize().await?;
        assert_eq!(session.lease_deadline.load(Ordering::Relaxed), expiry);
        assert_eq!(session.lease_version.load(Ordering::Relaxed), 2);
        server.await.map_err(|_| WireError::Backend)?;
        // A fresh deadline now uses the bounded cache without needing a server.
        session.authorize().await?;
        Ok(())
    }

    #[tokio::test]
    async fn expired_authoritative_lease_cannot_use_a_warm_authorization_cache()
    -> Result<(), WireError> {
        let (router, server) = lease_server("404 Not Found", "{}".into()).await?;
        let mut admission = pending(&router, 1).await;
        admission.binding.expires_at = 1;
        let session = admission.activate(10)?;
        session
            .last_active_ms
            .store(epoch_millis(), Ordering::Relaxed);
        assert_eq!(session.authorize().await, Err(WireError::Branch));
        server.await.map_err(|_| WireError::Backend)?;
        Ok(())
    }

    #[tokio::test]
    async fn drain_accounts_for_in_progress_admission_and_keeps_other_branches()
    -> Result<(), WireError> {
        let router = router()?;
        let unrelated = pending(&router, 2).await.activate(20)?;
        let target = pending(&router, 1).await;
        let drain_router = router.clone();
        let drain =
            tokio::spawn(async move { drain_router.drain(1, || async { Ok(vec![20]) }).await });
        let target = target.activate(10)?;
        timeout(Duration::from_secs(2), target.cancelled())
            .await
            .map_err(|_| WireError::Backend)?;
        assert!(
            !drain.is_finished(),
            "drain acknowledged before target task exit"
        );
        assert!(!*unrelated.receiver.borrow());
        drop(target);
        drain.await.map_err(|_| WireError::Backend)??;
        Ok(())
    }

    #[tokio::test]
    async fn drain_cannot_acknowledge_unregistered_native_session() -> Result<(), WireError> {
        let router = router()?;
        let operation = router.drain(1, || async { Ok(vec![77]) });
        assert!(timeout(Duration::from_millis(40), operation).await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn explicit_read_only_access_refuses_policy_before_control_contact()
    -> Result<(), WireError> {
        let router = router()?;
        let session = pending(&router, 1).await.activate(10)?;
        assert!(matches!(session.policy().await, Err(WireError::ReadOnly)));
        assert!(matches!(
            session.fresh_policy().await,
            Err(WireError::ReadOnly)
        ));
        assert_eq!(session.allocate(1, 1).await, Err(WireError::ReadOnly));
        Ok(())
    }

    #[tokio::test]
    async fn storage_binding_distinguishes_legacy_mongo_writes_from_base_only_reads()
    -> Result<(), WireError> {
        let router = router()?;
        let mut binding = pending(&router, 1).await.binding;
        assert!(binding.valid_storage_contract());
        binding.read_strategy = ReadStrategy::BaseOnly;
        assert!(binding.valid_storage_contract());
        binding.access = BranchAccess::ReadWrite;
        assert!(!binding.valid_storage_contract());
        binding.engine = "mongodb".into();
        assert!(!binding.valid_storage_contract());
        binding.read_strategy = ReadStrategy::Merge;
        assert!(binding.valid_storage_contract());
        assert!(binding.can_write());
        binding.class = BranchClass::Staging;
        assert!(!binding.valid_storage_contract());
        assert!(!binding.can_write());
        binding.class = BranchClass::Dev;
        binding.layout = BranchLayout::NativeCopy;
        assert!(!binding.valid_storage_contract());
        binding.write_schema = Some("fg_b1".into());
        assert!(binding.valid_storage_contract());
        Ok(())
    }

    #[test]
    fn branch_names_exclude_deployment_and_mongod_reserved_databases() {
        for name in ["postgres", "mysql", "admin", "local", "config"] {
            assert!(!valid_branch_name(name), "{name} must stay reserved");
        }
        assert!(valid_branch_name("app-main"));
        assert!(!valid_branch_name("ab"));
        assert!(!valid_branch_name("Bad-name"));
        assert!(!valid_branch_name("has_underscore"));
    }
}
