use super::*;
use std::{fmt, sync::Arc, task::Poll};
use tracing::{
    Event, Metadata, Subscriber,
    field::{Field, Visit},
    instrument::WithSubscriber,
    span::{Attributes, Id, Record},
};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<Value>>>);

impl Subscriber for Capture {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.target() == TARGET && *metadata.level() <= tracing::Level::DEBUG
    }

    fn new_span(&self, _attributes: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}
    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
    fn enter(&self, _span: &Id) {}
    fn exit(&self, _span: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        lock(&self.0).push(Value::Object(fields.0));
    }
}

#[derive(Default)]
struct Fields(serde_json::Map<String, Value>);

impl Visit for Fields {
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().into(), value.into());
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().into(), value.into());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.0
            .insert(field.name().into(), format!("{value:?}").into());
    }
}

#[tokio::test]
async fn emits_safe_counts_with_pool_and_transaction_calls_separate() {
    let capture = Capture::default();
    let events = capture.0.clone();
    async {
        let observation = WriteObservation::new(
            WriteOperation::Decision,
            "postgres://private-user:secret@private-host/source",
        );
        let result: Result<(), &str> = async {
            observation
                .run(WritePhase::PoolAcquire, async { Ok::<(), &str>(()) })
                .await?;
            observation
                .run(WritePhase::TransactionBegin, async { Ok::<(), &str>(()) })
                .await?;
            observation
                .run(WritePhase::PolicyLock, async { Ok::<(), &str>(()) })
                .await?;
            observation
                .run(WritePhase::AuditEvent, async {
                    Err("SELECT private_value WHERE secret_parameter='secret'")
                })
                .await
        }
        .await;
        observation.finish(&result);
    }
    .with_subscriber(capture)
    .await;
    let events = lock(&events);
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event["engine"], "unsupported");
    assert_eq!(event["status"], "failed");
    assert_eq!(event["query_calls_started"], 2);
    assert_eq!(event["query_calls_completed"], 2);
    assert_eq!(event["query_calls_failed"], 1);
    assert_eq!(event["query_calls_cancelled"], 0);
    let encoded = event.to_string();
    for forbidden in [
        "secret",
        "private-user",
        "private-host",
        "SELECT",
        "parameter",
    ] {
        assert!(!encoded.contains(forbidden));
    }
    let phases: Value =
        serde_json::from_str(event["phases"].as_str().unwrap_or_default()).unwrap_or_default();
    assert_eq!(phases["transaction_begin"]["completed"], 1);
    assert_eq!(
        phases["pool_acquire_including_health_and_connect"]["completed"],
        1
    );
}

#[tokio::test]
async fn cancellation_records_unfinished_query_and_operation() {
    let capture = Capture::default();
    let events = capture.0.clone();
    let mut future = Box::pin(
        async {
            let observation = WriteObservation::new(WriteOperation::Fence, "postgresql");
            observation
                .run(
                    WritePhase::AttemptLock,
                    std::future::pending::<Result<(), ()>>(),
                )
                .await
        }
        .with_subscriber(capture.clone()),
    );
    std::future::poll_fn(|context| {
        assert!(future.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    tracing::subscriber::with_default(capture, || drop(future));
    let events = lock(&events);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["status"], "cancelled");
    assert_eq!(events[0]["query_calls_started"], 1);
    assert_eq!(events[0]["query_calls_completed"], 0);
    assert_eq!(events[0]["query_calls_cancelled"], 1);
}

#[test]
fn disabled_observation_has_no_clock_or_phase_state() {
    tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
        let observation = WriteObservation::new(WriteOperation::Outcome, "mysql");
        assert!(observation.state.is_none());
        let call = observation.start(WritePhase::AuditEvent);
        assert!(call.started.is_none());
        drop(call);
        assert!(observation.state.is_none());
    });
}
