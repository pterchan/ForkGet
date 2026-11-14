//! Only failed or uncertain delivery is retried; ordinary synchronous delivery
//! remains one outcome request per native transaction or MongoDB command.

use std::{
    collections::hash_map::Entry,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

use super::Router;
use crate::{
    AuditMode, AuditStatus, AuditStatusRequest, AuditedOutcomeRequest, OutcomeAck,
    TransactionOutcome, WireError,
};

const AUDIT_RETRY_BATCH: usize = 32;
const AUDIT_RETRY_DELAY: Duration = Duration::from_secs(1);

pub(super) struct PendingDelivery {
    branch: i64,
    pub(super) request: AuditedOutcomeRequest,
    in_flight: bool,
    pub(super) retry_required: bool,
    retry_order: u64,
    retry_after: Instant,
}

struct DeliveryGuard {
    router: Router,
    attempt_id: String,
    finished: bool,
}

struct ClaimedDelivery {
    branch: i64,
    request: AuditedOutcomeRequest,
    guard: DeliveryGuard,
}

impl DeliveryGuard {
    fn complete(mut self) -> Result<(), WireError> {
        self.router
            .0
            .audit_pending
            .lock()
            .map_err(|_| WireError::Backend)?
            .remove(&self.attempt_id);
        self.finished = true;
        Ok(())
    }

    fn keep_pending(mut self) -> Result<(), WireError> {
        if let Some(entry) = self
            .router
            .0
            .audit_pending
            .lock()
            .map_err(|_| WireError::Backend)?
            .get_mut(&self.attempt_id)
        {
            entry.in_flight = false;
            entry.retry_required = true;
            entry.retry_after = Instant::now() + AUDIT_RETRY_DELAY;
        }
        self.finished = true;
        Ok(())
    }
}

impl Drop for DeliveryGuard {
    fn drop(&mut self) {
        if !self.finished
            && let Ok(mut pending) = self.router.0.audit_pending.lock()
            && let Some(entry) = pending.get_mut(&self.attempt_id)
        {
            entry.in_flight = false;
            entry.retry_required = true;
            entry.retry_after = Instant::now() + AUDIT_RETRY_DELAY;
        }
    }
}

impl Router {
    pub(super) async fn deliver_audit_outcome(
        &self,
        branch: i64,
        request: AuditedOutcomeRequest,
    ) -> Result<OutcomeAck, WireError> {
        let guard = self.begin_delivery(branch, &request)?;
        let ack = self.send_audit_outcome(branch, &request).await?;
        if request.attempt.mode == AuditMode::SqlTransaction
            && request.outcome == TransactionOutcome::Unknown
        {
            guard.keep_pending()?;
        } else {
            guard.complete()?;
        }
        Ok(ack)
    }

    fn begin_delivery(
        &self,
        branch: i64,
        request: &AuditedOutcomeRequest,
    ) -> Result<DeliveryGuard, WireError> {
        let mut pending = self
            .0
            .audit_pending
            .lock()
            .map_err(|_| WireError::Backend)?;
        match pending.entry(request.attempt.attempt_id.clone()) {
            Entry::Occupied(mut entry) => {
                let delivery = entry.get_mut();
                if delivery.branch != branch
                    || delivery.request != *request
                    || delivery.in_flight
                    || (delivery.retry_required && delivery.retry_after > Instant::now())
                {
                    return Err(WireError::Backend);
                }
                delivery.in_flight = true;
            }
            Entry::Vacant(entry) => {
                entry.insert(PendingDelivery {
                    branch,
                    request: request.clone(),
                    in_flight: true,
                    retry_required: false,
                    retry_order: 0,
                    retry_after: Instant::now(),
                });
            }
        }
        Ok(DeliveryGuard {
            router: self.clone(),
            attempt_id: request.attempt.attempt_id.clone(),
            finished: false,
        })
    }

    async fn send_audit_outcome(
        &self,
        branch: i64,
        request: &AuditedOutcomeRequest,
    ) -> Result<OutcomeAck, WireError> {
        let response = self
            .post(
                &format!("internal/v1/branches/{branch}/audit/outcome"),
                request,
            )
            .await?;
        let ack: OutcomeAck = response.json().await.map_err(|_| WireError::Backend)?;
        if ack.attempt_id != request.attempt.attempt_id
            || ack.outcome != request.outcome
            || ack.audit_event_id <= 0
        {
            return Err(WireError::Backend);
        }
        Ok(ack)
    }

    /// The proxy's background worker and foreground admission share claims.
    /// Cancelling either caller releases every claimed delivery for retry.
    pub async fn retry_audit_deliveries(&self) -> Result<(), WireError> {
        let claims = self.claim_audit_retries()?;
        let mut result = Ok(());
        for ClaimedDelivery {
            branch,
            request,
            guard,
        } in claims
        {
            if let Err(error) = self.retry_audit_delivery(branch, &request, guard).await {
                result = Err(error);
            }
        }
        result
    }

    fn claim_audit_retries(&self) -> Result<Vec<ClaimedDelivery>, WireError> {
        let mut pending = self
            .0
            .audit_pending
            .lock()
            .map_err(|_| WireError::Backend)?;
        let now = Instant::now();
        let mut candidates: Vec<_> = pending
            .iter()
            .filter(|(_, entry)| {
                entry.retry_required && !entry.in_flight && entry.retry_after <= now
            })
            .map(|(id, entry)| (id.clone(), entry.retry_order))
            .collect();
        candidates.sort_by_key(|(_, order)| *order);
        if candidates.is_empty() {
            return Ok(Vec::new());
        }
        let count = candidates.len().min(AUDIT_RETRY_BATCH) as u64;
        let first = self
            .0
            .next_audit_retry
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(count)
            })
            .map_err(|_| WireError::Backend)?;
        let mut claimed = Vec::new();
        for (index, (id, _)) in candidates.into_iter().take(AUDIT_RETRY_BATCH).enumerate() {
            if let Some(entry) = pending.get_mut(&id) {
                entry.in_flight = true;
                entry.retry_order = first + index as u64;
                claimed.push((entry.branch, entry.request.clone(), id));
            }
        }
        drop(pending);
        Ok(claimed
            .into_iter()
            .map(|(branch, request, id)| ClaimedDelivery {
                branch,
                request,
                guard: DeliveryGuard {
                    router: self.clone(),
                    attempt_id: id,
                    finished: false,
                },
            })
            .collect())
    }

    async fn audit_delivery_status(
        &self,
        branch: i64,
        request: &AuditedOutcomeRequest,
    ) -> Result<AuditStatus, WireError> {
        let response = self
            .post(
                &format!("internal/v1/branches/{branch}/audit/status"),
                &AuditStatusRequest {
                    attempt: request.attempt.clone(),
                },
            )
            .await?;
        response.json().await.map_err(|_| WireError::Backend)
    }

    async fn retry_audit_delivery(
        &self,
        branch: i64,
        request: &AuditedOutcomeRequest,
        guard: DeliveryGuard,
    ) -> Result<(), WireError> {
        if request.attempt.mode == AuditMode::SqlTransaction
            && request.outcome == TransactionOutcome::Unknown
        {
            let status = self.audit_delivery_status(branch, request).await?;
            if audit_status_confirms(&status, request) {
                return guard.complete();
            }
            if status.outcome.as_ref() == Some(request)
                && status.ack.as_ref().is_some_and(|ack| {
                    ack.attempt_id == request.attempt.attempt_id
                        && ack.audit_event_id > 0
                        && ack.outcome == request.outcome
                })
            {
                return guard.keep_pending();
            }
        }
        if self.send_audit_outcome(branch, request).await.is_ok() {
            if request.attempt.mode != AuditMode::SqlTransaction
                || request.outcome != TransactionOutcome::Unknown
            {
                return guard.complete();
            }
            return guard.keep_pending();
        }
        let status = self.audit_delivery_status(branch, request).await?;
        if audit_status_confirms(&status, request) {
            guard.complete()
        } else {
            guard.keep_pending()
        }
    }
}

pub(super) fn audit_status_confirms(status: &AuditStatus, request: &AuditedOutcomeRequest) -> bool {
    let Some(original) = &status.ack else {
        return false;
    };
    let Some(recorded) = &status.outcome else {
        return false;
    };
    if recorded.attempt != request.attempt || recorded.outcome != original.outcome {
        return false;
    }
    let matches_attempt =
        |ack: &OutcomeAck| ack.attempt_id == request.attempt.attempt_id && ack.audit_event_id > 0;
    if !status.resolved
        || !matches_attempt(original)
        || status.retention_ack_event_id.is_some_and(|id| id <= 0)
    {
        return false;
    }
    let resolution = status
        .resolution
        .as_ref()
        .filter(|ack| matches_attempt(ack) && ack.outcome != TransactionOutcome::Unknown);
    if status.resolution.is_some()
        && (resolution.is_none() || original.outcome != TransactionOutcome::Unknown)
    {
        return false;
    }
    if request.attempt.mode == AuditMode::MongoCommand {
        return (original.outcome == request.outcome && status.outcome.as_ref() == Some(request))
            || (status
                .late_ack
                .as_ref()
                .is_some_and(|ack| matches_attempt(ack) && ack.outcome == request.outcome)
                && status.late_outcome.as_ref() == Some(request)
                && original.outcome == TransactionOutcome::Unknown);
    }
    if request.outcome == TransactionOutcome::Unknown {
        return original.outcome != TransactionOutcome::Unknown
            || resolution.is_some()
            || status.retention_ack_event_id.is_some();
    }
    original.outcome == request.outcome
        || (original.outcome == TransactionOutcome::Unknown
            && resolution.is_some_and(|ack| ack.outcome == request.outcome))
}
