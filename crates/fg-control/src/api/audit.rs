use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection},
    http::HeaderMap,
};
use fg_protocol_common::{
    AuditStatus, AuditStatusRequest, AuditedDecisionRequest, AuditedDecisionResponse,
    AuditedOutcomeRequest, MongoStepAck, MongoStepRequest, OutcomeAck, WriteFenceRequest,
    WriteFenceResponse,
};

use super::{ApiError, App};

pub(super) async fn decision(
    State(control): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    request: Result<Json<AuditedDecisionRequest>, JsonRejection>,
) -> Result<Json<AuditedDecisionResponse>, ApiError> {
    control.internal(&headers)?;
    let Json(request) = request.map_err(|_| ApiError::InvalidPolicy)?;
    if id <= 0
        || !request.attempt.is_valid()
        || request.decision.policy_version <= 0
        || request.decision.effective_revision < 0
        || request.decision.operation.table_id <= 0
    {
        return Err(ApiError::InvalidPolicy);
    }
    Ok(Json(
        control
            .metadata
            .record_audited_decision(control.native.engine().name(), id, request)
            .await?,
    ))
}

pub(super) async fn outcome(
    State(control): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    request: Result<Json<AuditedOutcomeRequest>, JsonRejection>,
) -> Result<Json<OutcomeAck>, ApiError> {
    control.internal(&headers)?;
    let Json(request) = request.map_err(|_| ApiError::InvalidPolicy)?;
    if id <= 0 || !request.attempt.is_valid() {
        return Err(ApiError::InvalidPolicy);
    }
    Ok(Json(
        control
            .metadata
            .record_audited_outcome(control.native.engine().name(), id, request)
            .await?,
    ))
}

pub(super) async fn status(
    State(control): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    request: Result<Json<AuditStatusRequest>, JsonRejection>,
) -> Result<Json<AuditStatus>, ApiError> {
    control.internal(&headers)?;
    let Json(request) = request.map_err(|_| ApiError::InvalidPolicy)?;
    if id <= 0 || !request.attempt.is_valid() {
        return Err(ApiError::InvalidPolicy);
    }
    Ok(Json(
        control
            .metadata
            .audit_attempt_status(control.native.engine().name(), id, &request.attempt)
            .await?,
    ))
}

pub(super) async fn mongo_step(
    State(control): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    request: Result<Json<MongoStepRequest>, JsonRejection>,
) -> Result<Json<MongoStepAck>, ApiError> {
    control.internal(&headers)?;
    let Json(request) = request.map_err(|_| ApiError::InvalidPolicy)?;
    if id <= 0 || !request.attempt.is_valid() {
        return Err(ApiError::InvalidPolicy);
    }
    Ok(Json(
        control
            .metadata
            .arm_mongo_step(control.native.engine().name(), id, request)
            .await?,
    ))
}

pub(super) async fn write_fence(
    State(control): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    request: Result<Json<WriteFenceRequest>, JsonRejection>,
) -> Result<Json<WriteFenceResponse>, ApiError> {
    control.internal(&headers)?;
    let Json(request) = request.map_err(|_| ApiError::InvalidPolicy)?;
    if id <= 0
        || !request.attempt.is_valid()
        || request.policy_version <= 0
        || request.effective_revision < 0
    {
        return Err(ApiError::InvalidPolicy);
    }
    Ok(Json(
        control
            .metadata
            .write_fence(control.native.engine().name(), id, request)
            .await?,
    ))
}
