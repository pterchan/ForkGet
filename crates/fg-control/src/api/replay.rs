use futures_core::Stream;
use std::{
    io::{BufReader, Write},
    path::PathBuf,
    time::Duration,
};

use axum::{
    Json,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use fg_protocol_common::{
    ARTIFACT_LIMIT, ArtifactReader, DiffRequest, ReplayIds, ReplayPermit, ReplayResolve,
    ReplaySession,
};
use serde_json::json;
use tokio_util::io::ReaderStream;

use super::{ApiError, App};

const CAPTURE_LIMIT: usize = 4;
static CAPTURE_SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(CAPTURE_LIMIT);

pub(super) async fn export(
    State(control): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let owner = control.owner_account(&headers)?;
    let principal = owner.user.clone();
    let expires_at = owner.expires_at;
    if control.native.engine().name() == "mongodb" {
        let slot = CAPTURE_SLOTS
            .try_acquire()
            .map_err(|_| ApiError::Unavailable)?;
        // This task owns the fence even if the HTTP client disconnects.
        return tokio::spawn(async move {
            let _slot = slot;
            let capture = control
                .metadata
                .begin_capture("mongodb", id, &principal)
                .await?;
            let result = async {
                control.drain(id).await.map_err(|_| ApiError::Unavailable)?;
                export_response(&control, id, principal, expires_at).await
            }
            .await;
            control.metadata.finish_capture(id, capture).await?;
            result
        })
        .await
        .map_err(|_| ApiError::Unavailable)?;
    }
    export_response(&control, id, principal, expires_at).await
}

async fn export_response(
    control: &App,
    id: i64,
    principal: String,
    expires_at: i64,
) -> Result<Response, ApiError> {
    if !control
        .metadata
        .is_active(&principal, id, control.native.engine().name())
        .await?
    {
        return Err(ApiError::NotFound);
    }
    let url = control
        .proxy_url
        .join(&format!("internal/v1/branches/{id}/export"))
        .map_err(|_| ApiError::Unavailable)?;
    let response = control
        .client
        .post(url)
        .timeout(Duration::from_secs(330))
        .bearer_auth(&control.internal_token)
        .json(&DiffRequest {
            principal,
            expires_at,
        })
        .send()
        .await
        .map_err(|_| ApiError::Unavailable)?;
    if response.status() != StatusCode::OK
        || response
            .content_length()
            .is_some_and(|bytes| bytes > ARTIFACT_LIMIT)
    {
        return Err(ApiError::Unavailable);
    }
    Ok((
        [(header::CONTENT_TYPE, "application/x-ndjson")],
        Body::from_stream(response.bytes_stream()),
    )
        .into_response())
}

pub(super) async fn create(
    State(control): State<App>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<serde_json::Value>, ApiError> {
    let owner = control.owner_account(&headers)?;
    if !owner
        .allowed_classes
        .contains(&fg_protocol_common::BranchClass::Dev)
        || control.branch_admin.is_none()
    {
        return Err(ApiError::PolicyForbidden);
    }
    let check = headers
        .get("x-forkget-check")
        .and_then(|value| value.to_str().ok())
        == Some("true");
    let name = headers
        .get("x-forkget-replay-name")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !check && !fg_protocol_common::valid_branch_name(name) {
        return Err(ApiError::Invalid);
    }
    let file = tokio::time::timeout(Duration::from_secs(330), receive(body))
        .await
        .map_err(|_| ApiError::Unavailable)??;
    // Upload admission is not authorization to allocate after expiry. A
    // large artifact can spend minutes in receive/parse or metadata waits.
    control.owner_account(&headers)?;
    let mut reader = ArtifactReader::new(BufReader::new(
        file.reopen().map_err(|_| ApiError::Unavailable)?,
    ))
    .map_err(|_| ApiError::Invalid)?;
    let artifact = reader.header().clone();
    if artifact.engine != control.native.engine().name() {
        return Err(ApiError::ReplayMismatch);
    }
    fg_protocol_common::replay_order(&artifact).map_err(|_| ApiError::Invalid)?;
    while let Some(change) = reader.next_entry().map_err(|_| ApiError::Invalid)? {
        control.owner_account(&headers)?;
        change
            .validate_replay(&artifact)
            .map_err(|_| ApiError::Invalid)?;
    }
    control.metadata.replay_preflight(&artifact).await?;
    let owner = control.owner_account(&headers)?;
    if check {
        return Ok(Json(
            json!({"checked":true,"replayable":true,"origin":artifact.origin}),
        ));
    }
    let started = control
        .metadata
        .start_replay(&owner.user, name, &artifact)
        .await?;
    if file
        .persist_noclobber(artifact_path(started.job.id)?)
        .is_err()
    {
        control
            .metadata
            .finish_replay(
                &owner.user,
                started.job.id,
                "failed",
                Some("artifact_publish_failed"),
            )
            .await?;
        control
            .metadata
            .begin_drop(&owner.user, started.branch.id)
            .await?;
        control.pending_work.notify_one();
        return Err(ApiError::Unavailable);
    }
    std::fs::File::open(state_dir()?)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ApiError::Unavailable)?;
    control.pending_work.notify_one();
    Ok(Json(
        serde_json::to_value(started).map_err(|_| ApiError::Unavailable)?,
    ))
}

pub(super) async fn status(
    State(control): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<Json<fg_meta::ReplayJob>, ApiError> {
    let owner = control.owner_account(&headers)?;
    Ok(Json(control.metadata.replay_job(&owner.user, id).await?))
}

pub(super) async fn apply(
    State(control): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    execute(control, id, headers, false).await
}

pub(super) async fn verify(
    State(control): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    execute(control, id, headers, true).await
}

async fn execute(
    control: App,
    id: i64,
    headers: HeaderMap,
    verify_only: bool,
) -> Result<Json<serde_json::Value>, ApiError> {
    let owner = control.owner_account(&headers)?;
    let job = control.metadata.replay_job(&owner.user, id).await?;
    if job.state == "verified" {
        return Ok(Json(json!({"job":job,"verified":true})));
    }
    if !verify_only && job.state != "staged" {
        return Err(ApiError::Conflict);
    }
    if verify_only && !matches!(job.state.as_str(), "unknown" | "failed") {
        return Err(ApiError::Conflict);
    }
    let file = tokio::fs::File::open(artifact_path(id)?)
        .await
        .map_err(|_| ApiError::Unavailable)?;
    let permit = ReplayPermit {
        job_id: id,
        branch_id: job.branch_id,
        owner: owner.user.clone(),
        generation_id: job.generation_id,
        credential_expires_at: owner.expires_at,
    };
    let url = control
        .proxy_url
        .join(&format!(
            "internal/v1/replays/{id}/{}",
            if verify_only { "verify" } else { "apply" }
        ))
        .map_err(|_| ApiError::Unavailable)?;
    let response = control
        .client
        .post(url)
        .bearer_auth(&control.internal_token)
        .header(
            "x-forkget-permit",
            serde_json::to_string(&permit).map_err(|_| ApiError::Unavailable)?,
        )
        .timeout(Duration::from_secs(330))
        .body(reqwest::Body::wrap_stream(ReaderStream::new(file)))
        .send()
        .await;
    let result = match response {
        Ok(response) if response.status().is_success() => {
            response.json::<serde_json::Value>().await.ok()
        }
        _ => None,
    };
    let (state, code) = match result.as_ref() {
        Some(value) if value["verified"] == true => ("verified", None),
        Some(value)
            if value["transaction"] == "rolled_back" || value["transaction"] == "not_started" =>
        {
            ("failed", Some("replay_rolled_back"))
        }
        _ => ("unknown", Some("verify_required")),
    };
    let finished = control
        .metadata
        .finish_replay(&owner.user, id, state, code)
        .await?;
    let verified = finished.state == "verified";
    Ok(Json(
        json!({"job":finished,"verified":verified,"result":result}),
    ))
}

pub(super) async fn resolve(
    State(control): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Json(request): Json<ReplayResolve>,
) -> Result<Json<fg_protocol_common::BranchBinding>, ApiError> {
    control.internal(&headers)?;
    if request.job_id != id || !fg_protocol_common::credential_current(request.expires_at) {
        return Err(ApiError::Auth);
    }
    Ok(Json(
        control
            .metadata
            .claim_replay(
                &request.principal,
                id,
                request.native_session_id,
                request.verify_only,
            )
            .await?,
    ))
}

pub(super) async fn bind(
    State(control): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Json(request): Json<ReplaySession>,
) -> Result<StatusCode, ApiError> {
    control.internal(&headers)?;
    control
        .metadata
        .bind_replay_session(
            &request.principal,
            id,
            request.native_session_id,
            &request.session_id,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn ids(
    State(control): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Json(request): Json<ReplayIds>,
) -> Result<StatusCode, ApiError> {
    control.internal(&headers)?;
    control
        .metadata
        .advance_replay_ids(
            &request.session.principal,
            id,
            &request.session.session_id,
            request.table_id,
            request.highest,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn validate_session(
    State(control): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Json(request): Json<ReplaySession>,
) -> Result<StatusCode, ApiError> {
    control.internal(&headers)?;
    control
        .metadata
        .validate_replay_session(
            &request.principal,
            id,
            request.native_session_id,
            &request.session_id,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn uncertain(
    State(control): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Json(request): Json<ReplaySession>,
) -> Result<StatusCode, ApiError> {
    control.internal(&headers)?;
    control
        .metadata
        .uncertain_replay(
            &request.principal,
            id,
            request.native_session_id,
            &request.session_id,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn artifact_path(job: i64) -> Result<PathBuf, ApiError> {
    Ok(state_dir()?.join(format!("replay-{job}.ndjson")))
}

fn state_dir() -> Result<PathBuf, ApiError> {
    use std::os::unix::fs::PermissionsExt;
    let path = std::env::var_os("FG_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".forkget-state"));
    std::fs::create_dir_all(&path).map_err(|_| ApiError::Unavailable)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .map_err(|_| ApiError::Unavailable)?;
    Ok(path)
}

async fn receive(body: Body) -> Result<tempfile::NamedTempFile, ApiError> {
    let mut file = tempfile::Builder::new()
        .prefix("upload-")
        .tempfile_in(state_dir()?)
        .map_err(|_| ApiError::Unavailable)?;
    let mut stream = Box::pin(body.into_data_stream());
    let mut bytes = 0u64;
    while let Some(chunk) = std::future::poll_fn(|context| stream.as_mut().poll_next(context)).await
    {
        let chunk = chunk.map_err(|_| ApiError::Invalid)?;
        bytes = bytes.saturating_add(chunk.len() as u64);
        if bytes > ARTIFACT_LIMIT {
            return Err(ApiError::Invalid);
        }
        file.write_all(&chunk).map_err(|_| ApiError::Unavailable)?;
    }
    file.as_file()
        .sync_all()
        .map_err(|_| ApiError::Unavailable)?;
    Ok(file)
}

pub(super) async fn cleanup(control: &App) {
    if let Ok(jobs) = control
        .metadata
        .replay_cleanup_jobs(control.native.engine().name())
        .await
    {
        for job in jobs {
            if let Ok(path) = artifact_path(job) {
                let removed = match std::fs::remove_file(path) {
                    Ok(()) => true,
                    Err(error) => error.kind() == std::io::ErrorKind::NotFound,
                };
                if removed {
                    let _ = control.metadata.replay_artifact_cleaned(job).await;
                }
            }
        }
    }
    // Incomplete uploads never receive a replay ID. A killed process can
    // leave its private temporary file, so reclaim only our upload prefix
    // after a grace period longer than the maximum accepted request.
    if let Ok(path) = state_dir() {
        cleanup_uploads(&path);
    }
}

fn cleanup_uploads(path: &std::path::Path) {
    if let Ok(directory) = std::fs::read_dir(path) {
        for entry in directory.flatten() {
            if entry.file_name().to_string_lossy().starts_with("upload-")
                && entry
                    .metadata()
                    .ok()
                    .and_then(|meta| meta.modified().ok())
                    .and_then(|time| time.elapsed().ok())
                    .is_some_and(|age| age > Duration::from_secs(3600))
            {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::{File, FileTimes},
        time::SystemTime,
    };

    #[test]
    fn interrupted_upload_cleanup_preserves_active_uploads_and_job_artifacts() -> std::io::Result<()>
    {
        let directory = tempfile::tempdir()?;
        let old = directory.path().join("upload-interrupted");
        let recent = directory.path().join("upload-active");
        let retained = directory.path().join("replay-42.ndjson");
        File::create(&old)?.set_times(
            FileTimes::new().set_modified(SystemTime::now() - Duration::from_secs(3601)),
        )?;
        File::create(&recent)?;
        File::create(&retained)?.set_times(
            FileTimes::new().set_modified(SystemTime::now() - Duration::from_secs(7200)),
        )?;
        cleanup_uploads(directory.path());
        assert!(!old.exists());
        assert!(recent.exists());
        assert!(retained.exists());
        Ok(())
    }
}
