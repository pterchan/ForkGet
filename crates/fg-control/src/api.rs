mod audit;
mod budget;
mod github;
mod lifecycle;
mod policy;
mod replay;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::{
        DefaultBodyLimit, Path, State,
        rejection::{JsonRejection, PathRejection},
    },
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use fg_meta::{
    Branch, BranchMode, ForkBranch, LifecycleBranch, MAX_TTL_SECONDS, MetaError, Metadata,
};
use fg_protocol_common::{
    AllocateIds, AllocatedIds, BranchBinding, BranchClass, BranchGrantCheck, CheckBranch,
    MAX_GENERATED_ROWS, ResolveBranch, WireError, bearer_matches, credential_current,
    loopback_client, loopback_http, valid_branch_name,
};
use serde::{Deserialize, Serialize};
use tokio::{
    net::TcpListener,
    sync::Notify,
    time::{Instant, MissedTickBehavior, interval, sleep, timeout, timeout_at},
};

use crate::{ControlError, native::NativeOptions, writable};

const REQUEST_LIMIT: usize = 8 * 1024;
const ACCOUNT_LIMIT: usize = 32;
const TOKEN_LIMIT: usize = 128;
const DRAIN_TIMEOUT: Duration = Duration::from_secs(20);
const GC_TIMEOUT: Duration = Duration::from_secs(15);
const READINESS_TIMEOUT: Duration = Duration::from_secs(5);
const RETRY_DELAY: Duration = Duration::from_secs(1);
const TTL_SCAN_INTERVAL: Duration = Duration::from_secs(60);

pub(crate) struct Settings {
    pub(crate) accounts: String,
    pub(crate) token: String,
    pub(crate) proxy_url: String,
    pub(crate) branch_admin: Option<writable::Admin>,
    pub(crate) github: Option<crate::github::GitHub>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Account {
    user: String,
    token: String,
    expires_at: i64,
    #[serde(default = "default_classes")]
    allowed_classes: Vec<BranchClass>,
    #[serde(default)]
    policy_admin: bool,
    #[serde(default)]
    approver_for: Vec<String>,
}

struct Control {
    metadata: Metadata,
    native: NativeOptions,
    branch_admin: Option<writable::Admin>,
    accounts: Vec<Account>,
    internal_token: String,
    proxy_url: reqwest::Url,
    client: reqwest::Client,
    pending_work: Notify,
    github: Option<crate::github::GitHub>,
    github_pending: Notify,
}

type App = Arc<Control>;

pub(crate) async fn serve(
    address: SocketAddr,
    metadata: Metadata,
    native: NativeOptions,
    settings: Settings,
) -> Result<(), ControlError> {
    let app = Arc::new(Control::new(metadata, native, settings)?);
    let listener = TcpListener::bind(address).await?;
    app.metadata.invalidate_approvals_on_start().await?;
    app.metadata.recover_replays_on_start().await?;
    let public = Router::new()
        .route("/health/live", get(|| async { StatusCode::NO_CONTENT }))
        .route("/health/ready", get(ready))
        .route(
            "/v1/github/webhook",
            post(github::webhook).layer(DefaultBodyLimit::max(github::WEBHOOK_LIMIT)),
        )
        .route("/v1/github/bindings", get(github::bindings))
        .route("/v1/github/recreate", post(github::recreate))
        .route("/v1/capabilities", get(lifecycle::capabilities))
        .route("/v1/budget-requests", get(budget::inbox))
        .route("/v1/branches", get(list).post(fork))
        .route("/v1/branches/{id}", get(detail).delete(drop_branch))
        .route("/v1/branches/{id}/status", get(lifecycle::status))
        .route("/v1/branches/{id}/renew", post(lifecycle::renew))
        .route("/v1/branches/{id}/policy", get(budget::effective))
        .route(
            "/v1/branches/{id}/budget-requests",
            get(budget::requests).post(budget::request),
        )
        .route(
            "/v1/branches/{id}/budget-requests/{request_id}/review",
            post(budget::review),
        )
        .route("/v1/branches/{id}/budget-grants", get(budget::grants))
        .route(
            "/v1/branches/{id}/budget-grants/{grant_id}/revoke",
            post(budget::revoke),
        )
        .route("/v1/policies/{class}", get(policy::read).put(policy::write))
        .route("/v1/branches/{id}/audit", get(policy::audit))
        .route("/v1/branches/{id}/diff", get(policy::diff))
        .route("/v1/branches/{id}/export", get(replay::export))
        .route(
            "/v1/replays",
            post(replay::create).layer(DefaultBodyLimit::disable()),
        )
        .route("/v1/replays/{id}", get(replay::status))
        .route("/v1/replays/{id}/apply", post(replay::apply))
        .route("/v1/replays/{id}/verify", post(replay::verify))
        .route("/v1/branches/{id}/approvals", get(policy::approvals))
        .route(
            "/v1/branches/{id}/approvals/{approval_id}",
            post(policy::review),
        );
    let router = Router::new()
        .merge(public.clone())
        .nest("/api", public)
        .route("/internal/v1/replays/{id}/resolve", post(replay::resolve))
        .route("/internal/v1/replays/{id}/bind", post(replay::bind))
        .route(
            "/internal/v1/replays/{id}/validate",
            post(replay::validate_session),
        )
        .route(
            "/internal/v1/replays/{id}/uncertain",
            post(replay::uncertain),
        )
        .route("/internal/v1/replays/{id}/ids", post(replay::ids))
        .route("/internal/v1/resolve", post(resolve))
        .route("/internal/v1/proxy/start", post(policy::start_proxy))
        .route("/internal/v1/branches/{id}/resolve", post(resolve_by_id))
        .route("/internal/v1/branches/{id}/active", post(active))
        .route("/internal/v1/branches/{id}/lease", post(lifecycle::lease))
        .route("/internal/v1/branches/{id}/allocate", post(allocate))
        .route("/internal/v1/branches/{id}/policy", post(policy::effective))
        .route(
            "/internal/v1/branches/{id}/policy/validate",
            post(policy::validate_context),
        )
        .route(
            "/internal/v1/branches/{id}/decisions",
            post(policy::decision),
        )
        .route("/internal/v1/branches/{id}/outcome", post(policy::outcome))
        .route(
            "/internal/v1/branches/{id}/audit/decisions",
            post(audit::decision),
        )
        .route(
            "/internal/v1/branches/{id}/audit/outcome",
            post(audit::outcome),
        )
        .route(
            "/internal/v1/branches/{id}/audit/status",
            post(audit::status),
        )
        .route(
            "/internal/v1/branches/{id}/audit/mongo-step",
            post(audit::mongo_step),
        )
        .route(
            "/internal/v1/branches/{id}/write-fence",
            post(audit::write_fence),
        )
        .route(
            "/internal/v1/branches/{id}/approvals/{approval_id}/poll",
            post(policy::poll),
        )
        .route(
            "/internal/v1/branches/{id}/approvals/{approval_id}/invalidate",
            post(policy::invalidate),
        )
        .merge(crate::console::routes()?)
        .layer(DefaultBodyLimit::max(REQUEST_LIMIT))
        .with_state(app.clone());
    let expiry_worker = tokio::spawn(expiry_loop(app.clone()));
    let github_worker = tokio::spawn(github::worker(app.clone()));
    let audit_worker = tokio::spawn(audit_recovery_loop(app.clone()));
    let worker = tokio::spawn(lifecycle_loop(app));
    let outcome = axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await;
    worker.abort();
    expiry_worker.abort();
    github_worker.abort();
    audit_worker.abort();
    outcome.map_err(Into::into)
}

impl Control {
    async fn protected_writes_paused(&self) -> Option<bool> {
        crate::diagnostics::audit_pause_state(&self.client, &self.proxy_url, &self.internal_token)
            .await
    }
    fn recovery(&self) -> crate::recovery::Recovery<'_> {
        crate::recovery::Recovery {
            metadata: &self.metadata,
            native: &self.native,
            client: &self.client,
            proxy_url: &self.proxy_url,
            token: &self.internal_token,
            admin: self.branch_admin.as_ref(),
        }
    }
    fn new(
        metadata: Metadata,
        native: NativeOptions,
        settings: Settings,
    ) -> Result<Self, ControlError> {
        let accounts = parse_accounts(&settings.accounts, &settings.token)?;
        let proxy_url = loopback_http(&settings.proxy_url)
            .ok_or(ControlError::Config("FG_PROXY_CONTROL_URL"))?;
        let client = loopback_client(DRAIN_TIMEOUT).map_err(|_| ControlError::Drain)?;
        Ok(Self {
            metadata,
            native,
            branch_admin: settings.branch_admin,
            accounts,
            internal_token: settings.token,
            proxy_url,
            client,
            pending_work: Notify::new(),
            github: settings.github,
            github_pending: Notify::new(),
        })
    }

    fn owner(&self, headers: &HeaderMap) -> Result<&str, ApiError> {
        self.owner_account(headers)
            .map(|account| account.user.as_str())
    }

    fn owner_account(&self, headers: &HeaderMap) -> Result<&Account, ApiError> {
        let token = bearer(headers)?;
        self.accounts
            .iter()
            .find(|account| bearer_matches(token, &account.token))
            .filter(|account| credential_current(account.expires_at))
            .ok_or(ApiError::Auth)
    }

    fn internal(&self, headers: &HeaderMap) -> Result<(), ApiError> {
        if bearer_matches(bearer(headers)?, &self.internal_token) {
            Ok(())
        } else {
            Err(ApiError::Auth)
        }
    }

    async fn drain(&self, id: i64) -> Result<(), ControlError> {
        let path = format!("internal/v1/branches/{id}/drain");
        let url = self
            .proxy_url
            .join(&path)
            .map_err(|_| ControlError::Drain)?;
        let result = self
            .client
            .post(url)
            .bearer_auth(&self.internal_token)
            .send()
            .await
            .map_err(|_| ControlError::Drain)?;
        if result.status() != reqwest::StatusCode::NO_CONTENT {
            return Err(ControlError::Drain);
        }
        Ok(())
    }

    async fn verify_grants(&self, id: i64, grants: BranchGrantCheck) -> Result<(), ControlError> {
        let path = format!("internal/v1/branches/{id}/verify-grants");
        let url = self
            .proxy_url
            .join(&path)
            .map_err(|_| ControlError::Drain)?;
        let response = self
            .client
            .post(url)
            .bearer_auth(&self.internal_token)
            .json(&grants)
            .send()
            .await
            .map_err(|_| ControlError::Drain)?;
        match response.status() {
            StatusCode::NO_CONTENT => Ok(()),
            StatusCode::CONFLICT => Err(ControlError::Provision(
                "proxy service grants differ from the registered branch",
            )),
            _ => Err(ControlError::Drain),
        }
    }

    async fn collect(&self, branch: &LifecycleBranch) -> Result<(), ControlError> {
        self.drain(branch.id).await?;
        self.recovery().pass(Some(branch.id), true).await?;
        if !self
            .metadata
            .audit_cleanup_ready(self.native.engine().name(), branch.id)
            .await?
        {
            return Err(writable::WitnessError::Pending.into());
        }
        if branch.is_native {
            if branch.native_claimed {
                return self.admin()?.collect(&self.metadata, branch).await;
            }
            self.metadata.complete_drop(branch.id).await?;
            return Ok(());
        }
        let tables = self
            .metadata
            .generation_tables(branch.generation_id, self.native.engine().name())
            .await?;
        timeout(GC_TIMEOUT, async {
            let mut native = self.native.connect().await?;
            native.delete_branch(branch.id, &tables).await
        })
        .await
        .map_err(|_| ControlError::NativeTimeout)??;
        self.metadata.complete_drop(branch.id).await?;
        Ok(())
    }

    fn admin(&self) -> Result<&writable::Admin, ControlError> {
        self.branch_admin
            .as_ref()
            .ok_or(ControlError::Config("FG_BRANCH_ADMIN_DSN"))
    }
}

fn parse_accounts(json: &str, internal: &str) -> Result<Vec<Account>, ControlError> {
    let accounts: Vec<Account> =
        serde_json::from_str(json).map_err(|_| ControlError::Config("FG_CONTROL_ACCOUNTS"))?;
    if !valid_token(internal)
        || accounts.is_empty()
        || accounts.len() > ACCOUNT_LIMIT
        || accounts.iter().enumerate().any(|(index, account)| {
            account.user.is_empty()
                || account.user.len() > 63
                || !account
                    .user
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                || account.expires_at <= 0
                || !valid_token(&account.token)
                || bearer_matches(&account.token, internal)
                || account
                    .allowed_classes
                    .iter()
                    .enumerate()
                    .any(|(index, class)| account.allowed_classes[..index].contains(class))
                || account.approver_for.len() >= ACCOUNT_LIMIT
                || account
                    .approver_for
                    .iter()
                    .enumerate()
                    .any(|(index, owner)| {
                        owner == &account.user
                            || account.approver_for[..index].contains(owner)
                            || !accounts.iter().any(|candidate| &candidate.user == owner)
                    })
                || accounts[..index].iter().any(|earlier| {
                    earlier.user == account.user || bearer_matches(&earlier.token, &account.token)
                })
        })
    {
        return Err(ControlError::Config(
            "FG_CONTROL_ACCOUNTS and FG_INTERNAL_TOKEN must identify distinct accounts",
        ));
    }
    Ok(accounts)
}

fn default_classes() -> Vec<BranchClass> {
    vec![BranchClass::Dev]
}

fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= TOKEN_LIMIT
        && token.bytes().all(|byte| byte.is_ascii_graphic())
}

fn bearer(headers: &HeaderMap) -> Result<&str, ApiError> {
    let authorization = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    authorization
        .and_then(|value| value.split_once(' '))
        .filter(|(scheme, token)| scheme.eq_ignore_ascii_case("bearer") && valid_token(token))
        .map(|(_, token)| token)
        .ok_or(ApiError::Auth)
}

async fn ready(State(control): State<App>) -> Result<StatusCode, ApiError> {
    readiness(&control).await
}

async fn readiness(control: &Control) -> Result<StatusCode, ApiError> {
    let deadline = Instant::now() + READINESS_TIMEOUT;
    let generation = timeout_at(
        deadline,
        control
            .metadata
            .has_active_generation(control.native.engine().name()),
    )
    .await;
    match generation {
        Ok(Ok(true)) => {}
        Ok(Ok(false)) => {
            return Err(readiness_failure(
                ReadinessComponent::Metadata,
                "no active generation; run bootstrap for this backend",
            ));
        }
        Ok(Err(error)) => {
            return Err(readiness_failure(
                ReadinessComponent::Metadata,
                &crate::metadata_failure(&error),
            ));
        }
        Err(_) => {
            return Err(readiness_failure(
                ReadinessComponent::Metadata,
                "metadata check timed out",
            ));
        }
    }
    match timeout_at(deadline, control.native.connect()).await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => {
            return Err(readiness_failure(
                ReadinessComponent::Native,
                &error.to_string(),
            ));
        }
        Err(_) => {
            return Err(readiness_failure(
                ReadinessComponent::Native,
                "native GC connection timed out",
            ));
        }
    }
    Ok(StatusCode::NO_CONTENT)
}

fn readiness_failure(component: ReadinessComponent, detail: &str) -> ApiError {
    tracing::error!(component = ?component, detail, "control readiness failed");
    ApiError::Readiness(component)
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReadinessComponent {
    Metadata,
    Native,
}

impl ReadinessComponent {
    fn message(self) -> &'static str {
        match self {
            Self::Metadata => {
                "Metadata or its active generation is unavailable; check FG_META_DSN and bootstrap for this backend"
            }
            Self::Native => {
                "Native backend is unavailable; check FG_BACKEND_GC_DSN and FG_BACKEND_CA"
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fork {
    name: String,
    class: Option<BranchClass>,
    ttl_seconds: Option<u32>,
    #[serde(default)]
    mode: BranchMode,
    expected_generation: Option<fg_protocol_common::ReplayOrigin>,
}

async fn fork(
    State(control): State<App>,
    headers: HeaderMap,
    request: Result<Json<Fork>, JsonRejection>,
) -> Result<(StatusCode, Json<Branch>), ApiError> {
    let account = control.owner_account(&headers)?;
    let Json(request) = request.map_err(|_| ApiError::Invalid)?;
    let class = request.class.unwrap_or_default();
    let ttl = request.ttl_seconds.unwrap_or(class.default_ttl_seconds());
    if !valid_branch_name(&request.name) || !(1..=MAX_TTL_SECONDS).contains(&ttl) {
        return Err(ApiError::Invalid);
    }
    let writable = request.mode == BranchMode::NativeWrite;
    if request
        .expected_generation
        .as_ref()
        .is_some_and(|expected| !writable || !expected.is_valid())
    {
        return Err(ApiError::Invalid);
    }
    if !account.allowed_classes.contains(&class) || (writable && class == BranchClass::Staging) {
        return Err(ApiError::PolicyForbidden);
    }
    if writable && control.branch_admin.is_none() {
        return Err(ApiError::Unavailable);
    }
    let branch = control
        .metadata
        .fork(ForkBranch {
            engine: control.native.engine().name(),
            principal: &account.user,
            name: &request.name,
            ttl_seconds: ttl,
            mode: request.mode,
            class,
            expected_generation: request.expected_generation.as_ref(),
        })
        .await?;
    if writable {
        control.pending_work.notify_one();
        Ok((StatusCode::ACCEPTED, Json(branch)))
    } else {
        Ok((StatusCode::CREATED, Json(branch)))
    }
}

async fn list(
    State(control): State<App>,
    headers: HeaderMap,
) -> Result<Json<Vec<Branch>>, ApiError> {
    let principal = control.owner(&headers)?;
    Ok(Json(control.metadata.list(principal).await?))
}

async fn detail(
    State(control): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<Json<Branch>, ApiError> {
    let principal = control.owner(&headers)?;
    Ok(Json(control.metadata.detail(principal, id).await?))
}

async fn drop_branch(
    State(control): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Branch>), ApiError> {
    let principal = control.owner(&headers)?;
    let branch = control.metadata.begin_drop(principal, id).await?;
    if branch.status == "dropped" {
        return Ok((StatusCode::OK, Json(branch)));
    }
    control.pending_work.notify_one();
    Ok((StatusCode::ACCEPTED, Json(branch)))
}

async fn resolve(
    State(control): State<App>,
    headers: HeaderMap,
    request: Result<Json<ResolveBranch>, JsonRejection>,
) -> Result<Json<BranchBinding>, ApiError> {
    control.internal(&headers)?;
    let Json(request) = request.map_err(|_| ApiError::Invalid)?;
    if !valid_branch_name(&request.branch) {
        return Err(ApiError::NotFound);
    }
    let binding = control
        .metadata
        .resolve(&request.principal, &request.branch)
        .await?;
    if binding.engine != control.native.engine().name() {
        return Err(ApiError::Unavailable);
    }
    Ok(Json(binding))
}

async fn resolve_by_id(
    State(control): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    request: Result<Json<CheckBranch>, JsonRejection>,
) -> Result<Json<BranchBinding>, ApiError> {
    control.internal(&headers)?;
    let Json(request) = request.map_err(|_| ApiError::Invalid)?;
    let binding = control
        .metadata
        .resolve_by_id(&request.principal, id)
        .await?;
    if binding.engine != control.native.engine().name() {
        return Err(ApiError::Unavailable);
    }
    Ok(Json(binding))
}

async fn active(
    State(control): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    request: Result<Json<CheckBranch>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    control.internal(&headers)?;
    let Json(request) = request.map_err(|_| ApiError::Invalid)?;
    if control
        .metadata
        .is_active(&request.principal, id, control.native.engine().name())
        .await?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound)
    }
}

async fn allocate(
    State(control): State<App>,
    id: Result<Path<i64>, PathRejection>,
    headers: HeaderMap,
    request: Result<Json<AllocateIds>, JsonRejection>,
) -> Result<Json<AllocatedIds>, ApiError> {
    control.internal(&headers)?;
    let Path(id) = id.map_err(|_| ApiError::InvalidAllocation)?;
    let Json(request) = request.map_err(|_| ApiError::InvalidAllocation)?;
    if id <= 0
        || request.table_id <= 0
        || request.principal.is_empty()
        || !(1..=MAX_GENERATED_ROWS).contains(&request.count)
    {
        return Err(ApiError::InvalidAllocation);
    }
    let first = control
        .metadata
        .allocate_ids(
            &request.principal,
            id,
            request.table_id,
            request.count,
            control.native.engine().name(),
        )
        .await?;
    Ok(Json(AllocatedIds { first }))
}

async fn lifecycle_loop(control: App) {
    loop {
        let collected = cleanup_pass(&control).await;
        let provisioned = provision_pass(&control).await;
        if collected && provisioned {
            control.pending_work.notified().await;
        } else {
            tokio::select! {
                _ = control.pending_work.notified() => (),
                () = sleep(RETRY_DELAY) => (),
            }
        }
    }
}

async fn cleanup_pass(control: &Control) -> bool {
    let engine = control.native.engine().name();
    let Ok(branches) = control.metadata.dropping_branches(engine).await else {
        return false;
    };
    let mut complete = true;
    for branch in branches {
        if let Err(error) = control.collect(&branch).await {
            let reason = lifecycle_reason(&error);
            let _ = control
                .metadata
                .lifecycle_progress(branch.id, "cleanup_retry", Some(reason))
                .await;
            tracing::warn!(branch_id = branch.id, reason, failure = %safe_lifecycle_failure(&error), "branch remains dropping");
            complete = false;
        }
    }
    complete
}

async fn provision_pass(control: &Control) -> bool {
    let engine = control.native.engine().name();
    let Ok(branches) = control.metadata.provisioning_branches(engine).await else {
        return false;
    };
    let mut complete = true;
    for id in branches {
        let result = match control.admin() {
            Ok(admin) => {
                admin
                    .provision(&control.metadata, id, |grants| {
                        control.verify_grants(id, grants)
                    })
                    .await
            }
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            let reason = lifecycle_reason(&error);
            let _ = control
                .metadata
                .lifecycle_progress(id, "provision_retry", Some(reason))
                .await;
            tracing::warn!(branch_id = id, reason, failure = %safe_lifecycle_failure(&error), "branch provisioning attempt failed");
            complete = false;
        }
    }
    complete
}

async fn expiry_loop(control: App) {
    let mut clock = interval(TTL_SCAN_INTERVAL);
    clock.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let engine = control.native.engine().name();
    loop {
        clock.tick().await;
        replay::cleanup(&control).await;
        loop {
            match control.metadata.expire_branches(engine).await {
                Ok(more) => {
                    control.pending_work.notify_one();
                    if !more {
                        break;
                    }
                }
                Err(error) => {
                    tracing::warn!(error = %error, "branch TTL scan failed");
                    break;
                }
            }
        }
    }
}

async fn audit_recovery_loop(control: App) {
    let mut clock = interval(Duration::from_secs(5));
    clock.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        clock.tick().await;
        if let Err(error) = control.recovery().pass(None, false).await {
            tracing::warn!(
                component = "audit_recovery",
                reason = lifecycle_reason(&error),
                "Audit reconciliation remains pending"
            );
        }
    }
}

fn lifecycle_reason(error: &ControlError) -> &'static str {
    match error {
        ControlError::Capacity(_) => "capacity_preflight_refused",
        ControlError::Witness(error) => error.reason(),
        ControlError::Meta(MetaError::AuditPending) => "audit_recovery_pending",
        ControlError::Meta(MetaError::AuditConflict) => "audit_attempt_conflict",
        ControlError::Provision(_) | ControlError::Seed(_) => "native_copy_validation_failed",
        ControlError::Grants(_) => "native_role_grants_unavailable",
        ControlError::Native(error)
            if error
                .as_database_error()
                .is_some_and(|error| error.code().is_some_and(|code| code.starts_with("23"))) =>
        {
            "native_constraint_violation"
        }
        ControlError::Native(_) | ControlError::Mongo(_) => "native_connection_or_operation_failed",
        ControlError::NativeTimeout => "native_operation_timeout",
        ControlError::Drain => "proxy_drain_unavailable",
        ControlError::Meta(_) => "metadata_unavailable",
        _ => "operator_configuration_or_native_operation_failed",
    }
}

fn safe_lifecycle_failure(error: &ControlError) -> String {
    match error {
        ControlError::Native(error) => crate::native_failure(error),
        ControlError::Meta(error) => crate::metadata_failure(error),
        _ => error.to_string(),
    }
}

#[derive(Clone, Copy)]
enum ApiError {
    Auth,
    InternalProtocol,
    Invalid,
    InvalidAllocation,
    NotFound,
    Conflict,
    LeaseConflict,
    InvalidLease,
    WriteUnavailable,
    ReplayMismatch,
    WriteCapacity,
    IdsExhausted,
    InvalidPolicy,
    PolicyForbidden,
    PolicyConflict,
    ApprovalConflict,
    GitHubConflict,
    GitHubForbidden,
    GitHubInvalid,
    Unavailable,
    Readiness(ReadinessComponent),
}

impl From<MetaError> for ApiError {
    fn from(error: MetaError) -> Self {
        match error {
            MetaError::BranchUnavailable => Self::NotFound,
            MetaError::BranchConflict => Self::Conflict,
            MetaError::LeaseConflict => Self::LeaseConflict,
            MetaError::InvalidLease => Self::InvalidLease,
            MetaError::WriteUnavailable => Self::WriteUnavailable,
            MetaError::ReplayMismatch => Self::ReplayMismatch,
            MetaError::WriteCapacity => Self::WriteCapacity,
            MetaError::IdsExhausted => Self::IdsExhausted,
            MetaError::InvalidAllocation => Self::InvalidAllocation,
            MetaError::InvalidPolicy => Self::InvalidPolicy,
            MetaError::PolicyConflict => Self::PolicyConflict,
            MetaError::ApprovalConflict => Self::ApprovalConflict,
            MetaError::GitHubBindingConflict => Self::GitHubConflict,
            _ => Self::Unavailable,
        }
    }
}

#[derive(Serialize)]
struct Problem {
    code: &'static str,
    message: &'static str,
    reason: &'static str,
    hint: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    component: Option<ReadinessComponent>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::Auth => (
                StatusCode::UNAUTHORIZED,
                WireError::Auth.code(),
                "Authentication failed",
            ),
            Self::InternalProtocol => (
                StatusCode::CONFLICT,
                fg_protocol_common::INVALID_CONTEXT_CODE,
                "Protected audit writes require matching internal protocol version 3",
            ),
            Self::Invalid => (
                StatusCode::BAD_REQUEST,
                WireError::Unsupported.code(),
                "Supply a valid branch request and TTL from 1 to 86400 seconds",
            ),
            Self::InvalidAllocation => (
                StatusCode::BAD_REQUEST,
                WireError::InvalidValue.code(),
                "Invalid generated key allocation request",
            ),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                WireError::Branch.code(),
                "Branch is unavailable for this principal",
            ),
            Self::Conflict => (
                StatusCode::CONFLICT,
                WireError::Branch.code(),
                "A live branch already has this name",
            ),
            Self::LeaseConflict => (
                StatusCode::CONFLICT,
                WireError::Branch.code(),
                "reason=lease_version_conflict; refresh branch status before renewing",
            ),
            Self::InvalidLease => (
                StatusCode::BAD_REQUEST,
                WireError::Branch.code(),
                "reason=invalid_lease_extension; extend a live lease by at most 24 hours within its seven-day lifetime",
            ),
            Self::WriteUnavailable => (
                StatusCode::CONFLICT,
                WireError::Unsupported.code(),
                "The pinned snapshot does not support writable branches; ask the operator to import an admitted snapshot",
            ),
            Self::ReplayMismatch => (
                StatusCode::CONFLICT,
                WireError::Branch.code(),
                "Replay requires the same deployment, complete retained source generation and catalog",
            ),
            Self::WriteCapacity => (
                StatusCode::CONFLICT,
                WireError::Unsupported.code(),
                "The deployment already holds 16 writable branch slots",
            ),
            Self::IdsExhausted => (
                StatusCode::CONFLICT,
                WireError::IdsExhausted.code(),
                "Generated key range exhausted",
            ),
            Self::InvalidPolicy => (
                StatusCode::BAD_REQUEST,
                WireError::Policy.code(),
                "Invalid policy request",
            ),
            Self::PolicyForbidden => (
                StatusCode::FORBIDDEN,
                WireError::Policy.code(),
                "The branch policy denied the operation",
            ),
            Self::PolicyConflict => (
                StatusCode::CONFLICT,
                WireError::Policy.code(),
                "The policy version changed",
            ),
            Self::ApprovalConflict => (
                StatusCode::CONFLICT,
                WireError::Approval.code(),
                "The approval conflicts with an existing invocation or decision",
            ),
            Self::GitHubConflict => (
                StatusCode::CONFLICT,
                WireError::SqlObject.code(),
                "The GitHub source or generated branch name is already bound",
            ),
            Self::GitHubForbidden => (
                StatusCode::FORBIDDEN,
                WireError::SqlObject.code(),
                "The GitHub repository or installation is unavailable",
            ),
            Self::GitHubInvalid => (
                StatusCode::BAD_REQUEST,
                WireError::Unsupported.code(),
                "Supply a supported GitHub App event with a valid source name",
            ),
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                WireError::Backend.code(),
                "Branch metadata or native backend is unavailable",
            ),
            Self::Readiness(component) => (
                StatusCode::SERVICE_UNAVAILABLE,
                WireError::Backend.code(),
                component.message(),
            ),
        };
        let component = match self {
            Self::Readiness(component) => Some(component),
            _ => None,
        };
        let (reason, hint) = self.action();
        (
            status,
            Json(Problem {
                code,
                message,
                reason,
                hint,
                component,
            }),
        )
            .into_response()
    }
}

impl ApiError {
    fn action(self) -> (&'static str, &'static str) {
        match self {
            Self::Auth => (
                "authentication_failed",
                "check the account credential and its independent expiration",
            ),
            Self::InternalProtocol => (
                "internal_protocol_mismatch",
                "stop the old proxy, drain its native sessions and complete the coordinated protocol 3 upgrade",
            ),
            Self::Invalid | Self::InvalidAllocation | Self::GitHubInvalid => (
                "invalid_request",
                "check capabilities and the command arguments",
            ),
            Self::NotFound => (
                "branch_unavailable",
                "check branch ownership, status, deadline and an in-progress export",
            ),
            Self::Conflict => (
                "branch_name_in_use",
                "choose another name or wait for the existing environment to finish cleanup",
            ),
            Self::LeaseConflict => (
                "lease_version_conflict",
                "refresh branch status and retry with its current lease version",
            ),
            Self::InvalidLease => (
                "invalid_lease_extension",
                "extend a live lease within the 24-hour lease and seven-day retention limits",
            ),
            Self::WriteUnavailable => (
                "snapshot_write_unavailable",
                "ask the operator to inspect and import an admitted snapshot",
            ),
            Self::ReplayMismatch => (
                "replay_origin_unavailable",
                "use replay --check and retain the complete original generation",
            ),
            Self::WriteCapacity => (
                "native_copy_slots_exhausted",
                "ask the operator for fg-control status --json to identify the 16-slot blockers and cleanup status",
            ),
            Self::IdsExhausted => (
                "generated_id_range_exhausted",
                "save the branch artifact and create a new environment",
            ),
            Self::InvalidPolicy => (
                "invalid_policy_request",
                "check the effective policy, grant duration and requested limits",
            ),
            Self::PolicyForbidden => (
                "policy_permission_denied",
                "use an independently authorized policy administrator for a temporary branch budget",
            ),
            Self::PolicyConflict => (
                "effective_policy_changed",
                "refresh the effective policy and start a new transaction",
            ),
            Self::ApprovalConflict => (
                "approval_invocation_conflict",
                "refresh the pending invocation or start a new transaction",
            ),
            Self::GitHubConflict => (
                "github_binding_changed",
                "refresh the source binding and use its current immutable branch ID",
            ),
            Self::GitHubForbidden => (
                "github_source_unavailable",
                "check repository installation, owner and current provider state",
            ),
            Self::Unavailable | Self::Readiness(_) => (
                "dependency_unavailable",
                "ask the operator to run fg-control doctor; writes remain blocked until dependencies recover",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::{body::to_bytes, http::StatusCode, response::IntoResponse};

    use super::{ApiError, ReadinessComponent, parse_accounts};

    #[test]
    fn separates_owners_and_internal_credential() {
        let accounts = r#"[{"user":"one","token":"a","expires_at":100}]"#;
        assert!(parse_accounts(accounts, "different").is_ok());
        assert!(parse_accounts(accounts, "a").is_err());
        let duplicate = r#"[{"user":"one","token":"a","expires_at":100},{"user":"two","token":"a","expires_at":100}]"#;
        assert!(parse_accounts(duplicate, "different").is_err());
    }

    #[tokio::test]
    async fn readiness_response_identifies_failed_dependency()
    -> Result<(), Box<dyn std::error::Error>> {
        for (component, expected, setting) in [
            (ReadinessComponent::Metadata, "metadata", "FG_META_DSN"),
            (ReadinessComponent::Native, "native", "FG_BACKEND_GC_DSN"),
        ] {
            let response = ApiError::Readiness(component).into_response();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            let bytes = to_bytes(response.into_body(), 1024).await?;
            let problem: serde_json::Value = serde_json::from_slice(&bytes)?;
            assert_eq!(problem["code"], "FG-1004");
            assert_eq!(problem["component"], expected);
            assert!(
                problem["message"]
                    .as_str()
                    .is_some_and(|message| message.contains(setting))
            );
        }
        Ok(())
    }
}
