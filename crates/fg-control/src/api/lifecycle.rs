//! Owner-visible capabilities, renewable leases and actionable branch status.

use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection},
    http::HeaderMap,
};
use fg_meta::BranchLease;
use fg_protocol_common::CheckBranch;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{ApiError, App};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Renew {
    ttl_seconds: u32,
    expected_lease_version: i64,
}

pub(super) async fn renew(
    State(control): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    request: Result<Json<Renew>, JsonRejection>,
) -> Result<Json<BranchLease>, ApiError> {
    let principal = control.owner(&headers)?;
    let Json(request) = request.map_err(|_| ApiError::InvalidLease)?;
    Ok(Json(
        control
            .metadata
            .renew_branch(
                control.native.engine().name(),
                id,
                principal,
                request.ttl_seconds,
                request.expected_lease_version,
            )
            .await?,
    ))
}

pub(super) async fn lease(
    State(control): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    request: Result<Json<CheckBranch>, JsonRejection>,
) -> Result<Json<BranchLease>, ApiError> {
    control.internal(&headers)?;
    let Json(request) = request.map_err(|_| ApiError::Invalid)?;
    Ok(Json(
        control
            .metadata
            .branch_lease(control.native.engine().name(), id, &request.principal)
            .await?,
    ))
}

pub(super) async fn status(
    State(control): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let principal = control.owner(&headers)?;
    let mut status = control
        .metadata
        .branch_status(control.native.engine().name(), id, principal)
        .await?;
    status["audit"]["protected_writes_paused"] = json!(control.protected_writes_paused().await);
    Ok(Json(status))
}

pub(super) async fn capabilities(
    State(control): State<App>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    control.owner(&headers)?;
    let engine = control.native.engine().name();
    Ok(Json(json!({
        "format_version":1,"source_revision":fg_protocol_common::BUILD_REVISION,"engine":engine,"new_branch_default_access":"read_only",
        "access":["read_only","read_write"],"layouts":["sparse_delta","native_copy"],
        "native_copy_limit":16,"physical_generation_limit":2,
        "storage_assurance":crate::capacity::assurance(),
        "known_limitations":crate::diagnostics::known_limitations(engine),
        "max_lease_seconds":86400,"max_branch_lifetime_seconds":604800,
        "budget_scope":"direct_rows_per_transaction",
        "sql_client_ddl":false,"cross_engine_replay":false,
        "snapshot_import":{"admission_required":true,"logical_schemas_per_snapshot":1,
            "sql_primary_keys":"nonnullable integer or composite integer; generated single BIGINT",
            "unsupported_objects":"reported individually before target allocation",
            "mongo_consistency":"explicit frozen_source; server must already be fsync-locked"},
        "statement_limits":{"sql_bytes":1048576,"tokens":65536,"bind_parameters":16384,
            "generated_rows_per_statement":fg_protocol_common::MAX_GENERATED_ROWS},
        "diff_display":{"max_scanned_rows_per_table":20000,"max_changes":4096,"max_bytes":1048576,
            "complete_export_is_separate":true},
        "artifact":{"format_version":2,"complete_output_required":true,
            "default_max_bytes":fg_protocol_common::ARTIFACT_LIMIT,
            "max_record_bytes":fg_protocol_common::ARTIFACT_RECORD_LIMIT},
        "replay":{"preflight_before_target_creation":true,"target_exclusive_until_verified":true,
            "origin":"complete retained original generation",
            "mongo_transaction_semantics":"non_transactional; partial or unknown remains quarantined"},
        "explain":{"supported":engine!="mongodb","select_only":true,"analyze":false,"actual_proxy_execution_plan":true},
        "mongo_pool_scope":if engine=="mongodb" {Some("one_client_pool_per_branch")} else {None},
        "release_gates":"separate_exact_revision_evidence_required"
    })))
}
