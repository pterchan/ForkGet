//! Opt-in operation diagnostics, separate from durable policy audit events.

use std::{
    future::Future,
    sync::{Mutex, MutexGuard},
    time::Instant,
};

use serde_json::{Value, json};

const TARGET: &str = "fg_meta::write_path";

#[derive(Clone, Copy)]
pub(crate) enum WriteOperation {
    Decision,
    Fence,
    Outcome,
}

impl WriteOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Decision => "decision",
            Self::Fence => "fence",
            Self::Outcome => "outcome",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum WritePhase {
    PoolAcquire,
    TransactionBegin,
    TransactionCommit,
    PolicyLock,
    BranchLock,
    AttemptLock,
    Witness,
    Intent,
    FreshScope,
    EffectivePolicy,
    Approval,
    AuditEvent,
    MongoStep,
}

impl WritePhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::PoolAcquire => "pool_acquire_including_health_and_connect",
            Self::TransactionBegin => "transaction_begin",
            Self::TransactionCommit => "transaction_commit",
            Self::PolicyLock => "policy_lock",
            Self::BranchLock => "branch_lock",
            Self::AttemptLock => "attempt_lock",
            Self::Witness => "witness",
            Self::Intent => "intent",
            Self::FreshScope => "fresh_scope",
            Self::EffectivePolicy => "effective_policy",
            Self::Approval => "approval",
            Self::AuditEvent => "audit_event",
            Self::MongoStep => "mongo_step",
        }
    }

    fn is_query(self) -> bool {
        !matches!(
            self,
            Self::PoolAcquire | Self::TransactionBegin | Self::TransactionCommit
        )
    }
}

#[derive(Clone, Copy, Default)]
struct CallCounts {
    started: u64,
    completed: u64,
    failed: u64,
    cancelled: u64,
    elapsed_ns: u64,
}

impl CallCounts {
    fn value(self) -> Value {
        json!({"started":self.started,"completed":self.completed,"failed":self.failed,
            "cancelled":self.cancelled,"elapsed_ns":self.elapsed_ns})
    }
}

struct ObservationState {
    started: Instant,
    result: Option<bool>,
    queries: CallCounts,
    phases: std::collections::BTreeMap<&'static str, CallCounts>,
}

/// This state belongs to one operation. The mutex only permits short diagnostic
/// updates from borrowed async helpers; it never crosses an await or stores data.
pub(crate) struct WriteObservation {
    operation: WriteOperation,
    engine: &'static str,
    state: Option<Mutex<ObservationState>>,
}

impl WriteObservation {
    pub(crate) fn new(operation: WriteOperation, engine: &str) -> Self {
        let enabled = tracing::enabled!(target: TARGET, tracing::Level::DEBUG);
        Self {
            operation,
            engine: match engine {
                "mysql" => "mysql",
                "postgresql" => "postgresql",
                "tidb" => "tidb",
                "mongodb" => "mongodb",
                _ => "unsupported",
            },
            state: enabled.then(|| {
                Mutex::new(ObservationState {
                    started: Instant::now(),
                    result: None,
                    queries: CallCounts::default(),
                    phases: std::collections::BTreeMap::new(),
                })
            }),
        }
    }

    pub(crate) fn disabled() -> Self {
        Self {
            operation: WriteOperation::Decision,
            engine: "unsupported",
            state: None,
        }
    }

    pub(crate) async fn run<T, E>(
        &self,
        phase: WritePhase,
        future: impl Future<Output = Result<T, E>>,
    ) -> Result<T, E> {
        let mut call = self.start(phase);
        let result = future.await;
        call.complete(result.is_err());
        result
    }

    pub(crate) fn finish<T, E>(&self, result: &Result<T, E>) {
        if let Some(state) = &self.state {
            lock(state).result = Some(result.is_ok());
        }
    }

    fn start(&self, phase: WritePhase) -> ObservedCall<'_> {
        let started = self.state.as_ref().map(|state| {
            let mut state = lock(state);
            state.phases.entry(phase.as_str()).or_default().started += 1;
            if phase.is_query() {
                state.queries.started += 1;
            }
            Instant::now()
        });
        ObservedCall {
            observation: self,
            phase,
            started,
            finished: false,
        }
    }
}

impl Drop for WriteObservation {
    fn drop(&mut self) {
        let Some(state) = &self.state else {
            return;
        };
        let state = lock(state);
        let status = match state.result {
            Some(true) => "completed",
            Some(false) => "failed",
            None => "cancelled",
        };
        let phases: serde_json::Map<String, Value> = state
            .phases
            .iter()
            .map(|(phase, counts)| ((*phase).into(), counts.value()))
            .collect();
        tracing::debug!(target: TARGET,
            operation = self.operation.as_str(), engine = self.engine, status,
            elapsed_ns = nanos(state.started), query_calls_started = state.queries.started,
            query_calls_completed = state.queries.completed, query_calls_failed = state.queries.failed,
            query_calls_cancelled = state.queries.cancelled, phases = %serde_json::Value::Object(phases),
            "metadata write operation");
    }
}

struct ObservedCall<'a> {
    observation: &'a WriteObservation,
    phase: WritePhase,
    started: Option<Instant>,
    finished: bool,
}

impl ObservedCall<'_> {
    fn complete(&mut self, failed: bool) {
        self.update(Some(failed));
        self.finished = true;
    }

    fn update(&self, failed: Option<bool>) {
        let (Some(state), Some(started)) = (&self.observation.state, self.started) else {
            return;
        };
        let mut state = lock(state);
        let elapsed_ns = nanos(started);
        update_counts(
            state.phases.entry(self.phase.as_str()).or_default(),
            failed,
            elapsed_ns,
        );
        if self.phase.is_query() {
            update_counts(&mut state.queries, failed, elapsed_ns);
        }
    }
}

impl Drop for ObservedCall<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.update(None);
        }
    }
}

fn update_counts(counts: &mut CallCounts, failed: Option<bool>, elapsed_ns: u64) {
    counts.elapsed_ns = counts.elapsed_ns.saturating_add(elapsed_ns);
    if let Some(failed) = failed {
        counts.completed += 1;
        counts.failed += u64::from(failed);
    } else {
        counts.cancelled += 1;
    }
}

fn nanos(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests;
