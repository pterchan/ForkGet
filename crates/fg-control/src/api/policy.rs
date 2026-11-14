use std::time::Duration;

use axum::{
    Json,
    extract::{Path, RawQuery, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use fg_meta::{ApprovalKey, ApprovalReview, ApprovalSummary, AuditFilter, AuditPage};
use fg_protocol_common::{
    ApprovalContext, ApprovalState, BranchClass, CheckBranch, DecisionRequest, DecisionResponse,
    DiffRequest, OutcomeRequest, Policy, PolicyContext, ProxyEpoch, UpdatePolicy,
    credential_current,
};
use serde::{Deserialize, Serialize};

use super::{ApiError, App};

const DIFF_TIMEOUT: Duration = Duration::from_secs(15);
const DIFF_RESPONSE_LIMIT: usize = 1024 * 1024;
const AUDIT_PAGE_LIMIT: u32 = 100;
const LAST_UNIX_SECOND: i64 = 253_402_300_799;

pub(super) async fn read(
    State(control): State<App>,
    Path(class): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Policy>, ApiError> {
    let account = control.owner_account(&headers)?;
    let class = parse_class(&class)?;
    if !account.policy_admin && !account.allowed_classes.contains(&class) {
        return Err(ApiError::PolicyForbidden);
    }
    Ok(Json(control.metadata.policy(class).await?))
}

pub(super) async fn write(
    State(control): State<App>,
    Path(class): Path<String>,
    headers: HeaderMap,
    request: Result<Json<UpdatePolicy>, JsonRejection>,
) -> Result<Json<Policy>, ApiError> {
    let account = control.owner_account(&headers)?;
    if !account.policy_admin {
        return Err(ApiError::PolicyForbidden);
    }
    let Json(request) = request.map_err(|_| ApiError::InvalidPolicy)?;
    Ok(Json(
        control
            .metadata
            .update_policy(&account.user, parse_class(&class)?, request)
            .await?,
    ))
}

pub(super) async fn effective(
    State(control): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    request: Result<Json<CheckBranch>, JsonRejection>,
) -> Result<Json<Policy>, ApiError> {
    control.internal(&headers)?;
    let Json(request) = request.map_err(|_| ApiError::InvalidPolicy)?;
    Ok(Json(
        control
            .metadata
            .policy_for_branch(control.native.engine().name(), id, &request.principal)
            .await?,
    ))
}

pub(super) async fn validate_context(
    State(control): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    request: Result<Json<PolicyContext>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    control.internal(&headers)?;
    let Json(request) = request.map_err(|_| ApiError::InvalidPolicy)?;
    if request.policy_version <= 0 || request.effective_revision < 0 {
        return Err(ApiError::InvalidPolicy);
    }
    control
        .metadata
        .validate_policy_context(control.native.engine().name(), id, request)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn decision(
    State(control): State<App>,
    Path(_id): Path<i64>,
    headers: HeaderMap,
    _request: Result<Json<DecisionRequest>, JsonRejection>,
) -> Result<Json<DecisionResponse>, ApiError> {
    control.internal(&headers)?;
    Err(ApiError::InternalProtocol)
}

pub(super) async fn outcome(
    State(control): State<App>,
    Path(_id): Path<i64>,
    headers: HeaderMap,
    _request: Result<Json<OutcomeRequest>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    control.internal(&headers)?;
    Err(ApiError::InternalProtocol)
}

#[derive(Serialize)]
pub(super) struct ApprovalList {
    approvals: Vec<ApprovalSummary>,
}

pub(super) async fn approvals(
    State(control): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<Json<ApprovalList>, ApiError> {
    let account = control.owner_account(&headers)?;
    let approvals = control
        .metadata
        .approvals(
            control.native.engine().name(),
            id,
            &account.user,
            &account.approver_for,
        )
        .await?;
    Ok(Json(ApprovalList { approvals }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Review {
    approve: bool,
}

#[derive(Serialize)]
pub(super) struct Reviewed {
    state: ApprovalState,
}

pub(super) async fn review(
    State(control): State<App>,
    Path((branch_id, id)): Path<(i64, i64)>,
    headers: HeaderMap,
    request: Result<Json<Review>, JsonRejection>,
) -> Result<Json<Reviewed>, ApiError> {
    let account = control.owner_account(&headers)?;
    let Json(request) = request.map_err(|_| ApiError::InvalidPolicy)?;
    let review = ApprovalReview {
        actor: &account.user,
        owners: &account.approver_for,
        approve: request.approve,
    };
    let state = control
        .metadata
        .review_approval(
            control.native.engine().name(),
            ApprovalKey { branch_id, id },
            review,
        )
        .await?;
    Ok(Json(Reviewed { state }))
}

pub(super) async fn poll(
    State(control): State<App>,
    Path((branch_id, id)): Path<(i64, i64)>,
    headers: HeaderMap,
    request: Result<Json<ApprovalContext>, JsonRejection>,
) -> Result<Json<ApprovalState>, ApiError> {
    control.internal(&headers)?;
    let context = approval_context(request)?;
    Ok(Json(
        control
            .metadata
            .poll_approval(
                control.native.engine().name(),
                ApprovalKey { branch_id, id },
                context,
            )
            .await?,
    ))
}

pub(super) async fn invalidate(
    State(control): State<App>,
    Path((branch_id, id)): Path<(i64, i64)>,
    headers: HeaderMap,
    request: Result<Json<ApprovalContext>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    control.internal(&headers)?;
    let context = approval_context(request)?;
    control
        .metadata
        .invalidate_approval(
            control.native.engine().name(),
            ApprovalKey { branch_id, id },
            context,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn start_proxy(
    State(control): State<App>,
    headers: HeaderMap,
    request: Result<Json<ProxyEpoch>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    control.internal(&headers)?;
    let Json(request) = request.map_err(|_| ApiError::InvalidPolicy)?;
    if !valid_epoch(&request.epoch)
        || request.protocol_version != fg_protocol_common::BRANCH_PROTOCOL_VERSION
    {
        return Err(ApiError::InvalidPolicy);
    }
    control
        .metadata
        .register_proxy_epoch(&request.epoch)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn parse_class(value: &str) -> Result<BranchClass, ApiError> {
    match value {
        "dev" => Ok(BranchClass::Dev),
        "ci" => Ok(BranchClass::Ci),
        "agent" => Ok(BranchClass::Agent),
        "staging" => Ok(BranchClass::Staging),
        _ => Err(ApiError::InvalidPolicy),
    }
}

fn approval_context(
    request: Result<Json<ApprovalContext>, JsonRejection>,
) -> Result<ApprovalContext, ApiError> {
    let Json(request) = request.map_err(|_| ApiError::InvalidPolicy)?;
    if !valid_session(&request.session_id) {
        return Err(ApiError::InvalidPolicy);
    }
    Ok(request)
}

fn valid_session(session: &str) -> bool {
    session.split_once(':').is_some_and(|(epoch, serial)| {
        valid_epoch(epoch)
            && serial
                .parse::<u64>()
                .is_ok_and(|id| id > 0 && serial == id.to_string())
    })
}

fn valid_epoch(epoch: &str) -> bool {
    epoch.len() == 32
        && epoch
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

pub(super) async fn audit(
    State(control): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Result<impl IntoResponse, ApiError> {
    let principal = control.owner(&headers)?;
    let mut url = control.proxy_url.clone();
    url.set_query(query.as_deref());
    let filters = AuditQuery::parse(&url)?;
    let page: AuditPage = control
        .metadata
        .audit_page(id, principal, filters.filter())
        .await?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(page)))
}

#[derive(Default)]
struct AuditQuery {
    since: Option<i64>,
    until: Option<i64>,
    event_type: Option<String>,
    after: Option<i64>,
    limit: Option<u32>,
}

impl AuditQuery {
    fn parse(url: &reqwest::Url) -> Result<Self, ApiError> {
        let mut query = Self::default();
        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "since" if query.since.is_none() => query.since = Some(unix_second(&value)?),
                "until" if query.until.is_none() => query.until = Some(unix_second(&value)?),
                "event_type" if query.event_type.is_none() && valid_event_type(&value) => {
                    query.event_type = Some(value.into_owned());
                }
                "after" if query.after.is_none() => {
                    query.after = Some(
                        value
                            .parse::<i64>()
                            .ok()
                            .filter(|id| *id >= 0)
                            .ok_or(ApiError::InvalidPolicy)?,
                    );
                }
                "limit" if query.limit.is_none() => {
                    query.limit = Some(
                        value
                            .parse::<u32>()
                            .ok()
                            .filter(|limit| (1..=AUDIT_PAGE_LIMIT).contains(limit))
                            .ok_or(ApiError::InvalidPolicy)?,
                    );
                }
                _ => return Err(ApiError::InvalidPolicy),
            }
        }
        if query
            .since
            .zip(query.until)
            .is_some_and(|(since, until)| since >= until)
        {
            return Err(ApiError::InvalidPolicy);
        }
        Ok(query)
    }

    fn filter(&self) -> AuditFilter<'_> {
        AuditFilter {
            since: self.since,
            until: self.until,
            event_type: self.event_type.as_deref(),
            after: self.after.unwrap_or(0),
            limit: self.limit.unwrap_or(AUDIT_PAGE_LIMIT),
        }
    }
}

fn unix_second(value: &str) -> Result<i64, ApiError> {
    value
        .parse::<i64>()
        .ok()
        .filter(|time| (0..=LAST_UNIX_SECOND).contains(time))
        .ok_or(ApiError::InvalidPolicy)
}

fn valid_event_type(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
}

pub(super) async fn diff(
    State(control): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let account = control.owner_account(&headers)?;
    if !control
        .metadata
        .is_active(&account.user, id, control.native.engine().name())
        .await?
    {
        return Err(ApiError::NotFound);
    }
    let path = format!("internal/v1/branches/{id}/diff");
    let url = control
        .proxy_url
        .join(&path)
        .map_err(|_| ApiError::Unavailable)?;
    let mut response = control
        .client
        .post(url)
        .timeout(DIFF_TIMEOUT)
        .bearer_auth(&control.internal_token)
        .json(&DiffRequest {
            principal: account.user.clone(),
            expires_at: account.expires_at,
        })
        .send()
        .await
        .map_err(|_| ApiError::Unavailable)?;
    let status = response.status();
    if !matches!(
        status,
        StatusCode::OK
            | StatusCode::UNAUTHORIZED
            | StatusCode::NOT_FOUND
            | StatusCode::CONFLICT
            | StatusCode::SERVICE_UNAVAILABLE
    ) || response
        .content_length()
        .is_some_and(|length| length > DIFF_RESPONSE_LIMIT as u64)
    {
        return Err(ApiError::Unavailable);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ApiError::Unavailable)? {
        if bytes.len().saturating_add(chunk.len()) > DIFF_RESPONSE_LIMIT {
            return Err(ApiError::Unavailable);
        }
        bytes.extend_from_slice(&chunk);
    }
    if !credential_current(account.expires_at) {
        return Err(ApiError::Auth);
    }
    Ok((
        status,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::CONTENT_TYPE, "application/json"),
        ],
        bytes,
    )
        .into_response())
}
