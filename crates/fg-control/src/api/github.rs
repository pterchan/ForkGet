use std::time::Duration;

use axum::{
    Json,
    body::Bytes,
    extract::{
        Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
};
use fg_meta::{
    GitHubBinding, GitHubFailure, GitHubObservation, GitHubRecreate, GitHubSource, MetaError,
};
use fg_protocol_common::{BranchClass, credential_current};
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

use crate::github::{self, TokenCache, WebhookError};

use super::{ApiError, App, Control};

pub(super) const WEBHOOK_LIMIT: usize = 1024 * 1024;
const IDLE_POLL: Duration = Duration::from_millis(500);

pub(super) async fn webhook(
    State(control): State<App>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let github = control.github.as_ref().ok_or(ApiError::NotFound)?;
    let signature = single_header(&headers, "X-Hub-Signature-256").ok_or(ApiError::Auth)?;
    let event = single_header(&headers, "X-GitHub-Event").ok_or(ApiError::GitHubInvalid)?;
    let Some(incoming) = github
        .receive(signature, event, &body)
        .map_err(|error| match error {
            WebhookError::Signature => ApiError::Auth,
            WebhookError::Access => ApiError::GitHubForbidden,
            WebhookError::Invalid => ApiError::GitHubInvalid,
        })?
    else {
        return Ok(StatusCode::NO_CONTENT);
    };
    let signal = incoming.signal();
    if !authorized(&control, signal.principal, incoming.class()) {
        return Err(ApiError::PolicyForbidden);
    }
    if control.metadata.enqueue_github(signal).await?.is_none() {
        control.github_pending.notify_one();
    }
    Ok(StatusCode::ACCEPTED)
}

#[derive(Serialize)]
struct Bindings {
    bindings: Vec<GitHubBinding>,
    next_cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BindingQuery {
    after: Option<String>,
}

pub(super) async fn bindings(
    State(control): State<App>,
    headers: HeaderMap,
    query: Result<Query<BindingQuery>, QueryRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let principal = control.owner(&headers)?;
    let Query(query) = query.map_err(|_| ApiError::GitHubInvalid)?;
    let bindings = control
        .metadata
        .github_binding_page(principal, query.after.as_deref())
        .await?;
    let next_cursor = if bindings.len() == 200 {
        bindings.last().map(GitHubBinding::cursor).transpose()?
    } else {
        None
    };
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(Bindings {
            bindings,
            next_cursor,
        }),
    ))
}

pub(super) async fn recreate(
    State(control): State<App>,
    headers: HeaderMap,
    request: Result<Json<GitHubRecreate>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let principal = control.owner(&headers)?;
    control.github.as_ref().ok_or(ApiError::NotFound)?;
    let Json(request) = request.map_err(|_| ApiError::GitHubInvalid)?;
    control
        .metadata
        .recreate_github(principal, &request)
        .await?;
    control.github_pending.notify_one();
    Ok(StatusCode::ACCEPTED)
}

pub(super) async fn worker(control: App) {
    let Some(github) = &control.github else {
        return;
    };
    let mut tokens = TokenCache::default();
    loop {
        match control.metadata.next_github().await {
            Ok(Some(source)) => {
                if let Err(error) = process(&control, github, &source, &mut tokens).await {
                    tracing::warn!(error = %error, "GitHub source reconciliation remains pending");
                    sleep(IDLE_POLL).await;
                }
            }
            Ok(None) => tokio::select! {
                _ = control.github_pending.notified() => (),
                () = sleep(IDLE_POLL) => (),
            },
            Err(error) => {
                tracing::warn!(error = %error, "GitHub source lookup failed");
                sleep(IDLE_POLL).await;
            }
        }
    }
}

async fn process(
    control: &Control,
    github: &github::GitHub,
    source: &GitHubSource,
    tokens: &mut TokenCache,
) -> Result<(), MetaError> {
    let class = github::source_class(&source.source_kind);
    if !authorized(control, &source.principal, class) {
        return control
            .metadata
            .github_failed(source, GitHubFailure::AccessUnavailable, None)
            .await;
    }
    let (present, pr_write) = match github.observe(source, tokens).await {
        Ok(observation) => observation,
        Err(error) => {
            return control
                .metadata
                .github_failed(source, error.kind, error.delay)
                .await;
        }
    };
    if !authorized(control, &source.principal, class) {
        return control
            .metadata
            .github_failed(source, GitHubFailure::AccessUnavailable, None)
            .await;
    }
    if present && class == BranchClass::Ci && pr_write && control.branch_admin.is_none() {
        return control
            .metadata
            .github_failed(source, GitHubFailure::MetadataUnavailable, None)
            .await;
    }
    let observation = GitHubObservation {
        source,
        engine: control.native.engine().name(),
        present,
        pr_write,
    };
    match control.metadata.reconcile_github(observation).await {
        Ok(changed) => {
            if changed {
                control.pending_work.notify_one();
            }
            Ok(())
        }
        Err(MetaError::BranchConflict) => {
            control
                .metadata
                .github_failed(source, GitHubFailure::NameConflict, None)
                .await
        }
        Err(_) => {
            control
                .metadata
                .github_failed(
                    source,
                    GitHubFailure::MetadataUnavailable,
                    Some(github::retry_seconds(source.attempts)),
                )
                .await
        }
    }
}

fn authorized(control: &Control, principal: &str, class: BranchClass) -> bool {
    control.accounts.iter().any(|account| {
        account.user == principal
            && account.allowed_classes.contains(&class)
            && credential_current(account.expires_at)
    })
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let values = headers.get_all(name);
    let mut values = values.iter();
    let value = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(value)
}
