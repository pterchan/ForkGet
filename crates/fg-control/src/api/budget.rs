use axum::{
    Json,
    extract::{Path, RawQuery, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
};
use fg_meta::{BudgetGrantSummary, BudgetRequestSummary, BudgetReview};
use fg_protocol_common::{CreateBudgetRequest, Policy};
use serde::{Deserialize, Serialize};

use super::{ApiError, App};

#[derive(Serialize)]
pub(super) struct Requests {
    requests: Vec<BudgetRequestSummary>,
    limit: u32,
}

#[derive(Serialize)]
pub(super) struct Grants {
    grants: Vec<BudgetGrantSummary>,
    limit: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Review {
    approve: bool,
}

#[derive(Default)]
struct InboxQuery {
    state: Option<String>,
    after: Option<i64>,
}

pub(super) async fn effective(
    State(control): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<Json<Policy>, ApiError> {
    let account = control.owner_account(&headers)?;
    Ok(Json(
        control
            .metadata
            .policy_for_branch(control.native.engine().name(), id, &account.user)
            .await?,
    ))
}

pub(super) async fn inbox(
    State(control): State<App>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Result<Json<Requests>, ApiError> {
    let account = control.owner_account(&headers)?;
    let query = inbox_query(query.as_deref())?;
    if query
        .state
        .as_deref()
        .is_some_and(|state| state != "pending")
        || query.after.is_some_and(|id| id < 0)
    {
        return Err(ApiError::InvalidPolicy);
    }
    let owners = if account.policy_admin {
        account.approver_for.as_slice()
    } else {
        &[]
    };
    let requests = control
        .metadata
        .budget_inbox(
            control.native.engine().name(),
            &account.user,
            owners,
            query.after.unwrap_or(0),
        )
        .await?;
    Ok(Json(Requests {
        requests,
        limit: 100,
    }))
}

fn inbox_query(query: Option<&str>) -> Result<InboxQuery, ApiError> {
    let mut parsed = InboxQuery::default();
    for part in query
        .unwrap_or_default()
        .split('&')
        .filter(|part| !part.is_empty())
    {
        let (key, value) = part.split_once('=').ok_or(ApiError::InvalidPolicy)?;
        match key {
            "state" if parsed.state.is_none() => parsed.state = Some(value.to_owned()),
            "after" if parsed.after.is_none() => {
                parsed.after = Some(value.parse().map_err(|_| ApiError::InvalidPolicy)?)
            }
            _ => return Err(ApiError::InvalidPolicy),
        }
    }
    Ok(parsed)
}

pub(super) async fn requests(
    State(control): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<Json<Requests>, ApiError> {
    let account = control.owner_account(&headers)?;
    let owners = if account.policy_admin {
        account.approver_for.as_slice()
    } else {
        &[]
    };
    let requests = control
        .metadata
        .budget_requests(control.native.engine().name(), id, &account.user, owners)
        .await?;
    Ok(Json(Requests {
        requests,
        limit: 100,
    }))
}

pub(super) async fn request(
    State(control): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    request: Result<Json<CreateBudgetRequest>, JsonRejection>,
) -> Result<Json<BudgetRequestSummary>, ApiError> {
    let account = control.owner_account(&headers)?;
    let Json(request) = request.map_err(|_| ApiError::InvalidPolicy)?;
    Ok(Json(
        control
            .metadata
            .request_budget(control.native.engine().name(), id, &account.user, request)
            .await?,
    ))
}

pub(super) async fn review(
    State(control): State<App>,
    Path((id, request_id)): Path<(i64, i64)>,
    headers: HeaderMap,
    request: Result<Json<Review>, JsonRejection>,
) -> Result<Json<BudgetRequestSummary>, ApiError> {
    let account = control.owner_account(&headers)?;
    if !account.policy_admin {
        return Err(ApiError::PolicyForbidden);
    }
    let Json(request) = request.map_err(|_| ApiError::InvalidPolicy)?;
    Ok(Json(
        control
            .metadata
            .review_budget(
                control.native.engine().name(),
                id,
                request_id,
                BudgetReview {
                    actor: &account.user,
                    owners: &account.approver_for,
                    approve: request.approve,
                },
            )
            .await?,
    ))
}

pub(super) async fn grants(
    State(control): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<Json<Grants>, ApiError> {
    let account = control.owner_account(&headers)?;
    let owners = if account.policy_admin {
        account.approver_for.as_slice()
    } else {
        &[]
    };
    let grants = control
        .metadata
        .budget_grants(control.native.engine().name(), id, &account.user, owners)
        .await?;
    Ok(Json(Grants { grants, limit: 100 }))
}

pub(super) async fn revoke(
    State(control): State<App>,
    Path((id, grant_id)): Path<(i64, i64)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let account = control.owner_account(&headers)?;
    // The owner may reduce their own rights; extending them still requires
    // an independent, authorized policy administrator.
    let owners = if account.policy_admin {
        account.approver_for.as_slice()
    } else {
        &[]
    };
    control
        .metadata
        .revoke_budget(
            control.native.engine().name(),
            id,
            grant_id,
            &account.user,
            owners,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
