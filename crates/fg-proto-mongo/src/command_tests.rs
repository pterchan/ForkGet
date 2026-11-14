//! Protocol fault tests use a real loopback HTTP boundary and an in-memory
//! native socket. Metadata durability/recovery is tested by fg-meta.
use super::*;
use axum::{Json, extract::State, http::StatusCode, routing::post};
use fg_protocol_common::{
    AuditMode, AuditStatus, AuditStatusRequest, AuditedDecisionRequest, AuditedDecisionResponse,
    AuditedOutcomeRequest, BranchAccess, BranchBinding, BranchLayout, MongoStepAck,
    MongoStepRequest, OutcomeAck, Policy, ReadStrategy,
};
use std::{
    io,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};
use tokio::{io::DuplexStream, time::timeout};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
type Shared = Arc<Mutex<Journal>>;

#[derive(Default)]
struct Journal {
    events: Vec<String>,
    attempt_ids: Vec<String>,
    steps: Vec<(String, u32, Option<MongoWriteObservation>)>,
    outcomes: Vec<AuditedOutcomeRequest>,
    fail_arm: bool,
    fail_outcome: bool,
    fail_validation: bool,
}

fn lock(journal: &Shared) -> Result<MutexGuard<'_, Journal>, io::Error> {
    journal
        .lock()
        .map_err(|_| io::Error::other("test journal poisoned"))
}

struct Control {
    router: Router,
    journal: Shared,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Control {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn binding() -> BranchBinding {
    BranchBinding {
        id: 1,
        generation_id: 900,
        engine: "mongodb".into(),
        name: "alpha".into(),
        default_schema: "app".into(),
        class: Default::default(),
        access: BranchAccess::ReadWrite,
        layout: BranchLayout::NativeCopy,
        read_strategy: ReadStrategy::Merge,
        expires_at: i64::MAX,
        write_schema: Some("fg_b1".into()),
        replay_origin: None,
        snapshot_manifest: None,
        audit_witness_ready: false,
        tables: vec![CatalogEntry {
            id: 1,
            baseline_rows: 100,
            logical_schema: "app".into(),
            logical_table: "orders".into(),
            base_schema: "fg_g900".into(),
            base_table: "orders".into(),
            delta_schema: "fg_g900".into(),
            delta_table: "_d_g900_t1".into(),
            generated_key: None,
            columns: Vec::new(),
        }],
    }
}

async fn control() -> Result<Control, Box<dyn std::error::Error + Send + Sync>> {
    async fn decision(
        State(state): State<Shared>,
        Json(request): Json<AuditedDecisionRequest>,
    ) -> Result<Json<AuditedDecisionResponse>, StatusCode> {
        if !request.attempt.is_valid() || request.attempt.mode != AuditMode::MongoCommand {
            return Err(StatusCode::BAD_REQUEST);
        }
        let mut journal = lock(&state).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        journal.events.push("intent".into());
        journal.attempt_ids.push(request.attempt.attempt_id.clone());
        Ok(Json(AuditedDecisionResponse {
            attempt_id: request.attempt.attempt_id,
            approval_id: None,
            witness: None,
        }))
    }
    async fn arm(
        State(state): State<Shared>,
        Json(request): Json<MongoStepRequest>,
    ) -> Result<Json<MongoStepAck>, StatusCode> {
        let mut journal = lock(&state).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        journal.events.push("arm".into());
        journal.steps.push((
            request.attempt.attempt_id.clone(),
            request.expected_step,
            request.previous,
        ));
        if journal.fail_arm {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        Ok(Json(MongoStepAck {
            attempt_id: request.attempt.attempt_id,
            armed_step: request.expected_step + 1,
        }))
    }
    async fn outcome(
        State(state): State<Shared>,
        Json(request): Json<AuditedOutcomeRequest>,
    ) -> Result<Json<OutcomeAck>, StatusCode> {
        let mut journal = lock(&state).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        journal.events.push("outcome".into());
        let ack = OutcomeAck {
            attempt_id: request.attempt.attempt_id.clone(),
            audit_event_id: 1,
            outcome: request.outcome,
        };
        if journal.fail_outcome {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        if !journal
            .outcomes
            .iter()
            .any(|old| old.attempt.attempt_id == request.attempt.attempt_id)
        {
            journal.outcomes.push(request);
        }
        Ok(Json(ack))
    }
    async fn status(
        State(state): State<Shared>,
        Json(request): Json<AuditStatusRequest>,
    ) -> Result<Json<AuditStatus>, StatusCode> {
        let journal = lock(&state).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let outcome = journal
            .outcomes
            .iter()
            .find(|o| o.attempt.attempt_id == request.attempt.attempt_id)
            .cloned();
        let ack = outcome.as_ref().map(|o| OutcomeAck {
            attempt_id: o.attempt.attempt_id.clone(),
            audit_event_id: 1,
            outcome: o.outcome,
        });
        Ok(Json(AuditStatus {
            resolved: ack.is_some(),
            ack,
            outcome,
            ..Default::default()
        }))
    }
    async fn validate(State(state): State<Shared>) -> Result<StatusCode, StatusCode> {
        let journal = lock(&state).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if journal.fail_validation {
            Err(StatusCode::SERVICE_UNAVAILABLE)
        } else {
            Ok(StatusCode::NO_CONTENT)
        }
    }
    let journal = Arc::new(Mutex::new(Journal::default()));
    let app = axum::Router::new()
        .route("/internal/v1/resolve", post(|| async { Json(binding()) }))
        .route(
            "/internal/v1/branches/{id}/lease",
            post(|| async { Json(serde_json::json!({"expires_at":i64::MAX,"lease_version":1})) }),
        )
        .route(
            "/internal/v1/branches/{id}/policy",
            post(|| async {
                Json(Policy {
                    class: Default::default(),
                    version: 1,
                    effective_revision: 0,
                    grant_expires_at: None,
                    max_transaction_rows: 1000,
                    small_table_floor: 1,
                    table_limit_bps: None,
                    approval_after_rows: None,
                })
            }),
        )
        .route("/internal/v1/branches/{id}/policy/validate", post(validate))
        .route("/internal/v1/branches/{id}/audit/decisions", post(decision))
        .route("/internal/v1/branches/{id}/audit/mongo-step", post(arm))
        .route("/internal/v1/branches/{id}/audit/outcome", post(outcome))
        .route("/internal/v1/branches/{id}/audit/status", post(status))
        .with_state(journal.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let router = Router::new(
        format!("http://{address}/").parse()?,
        "test-only".into(),
        "mongodb",
    )?;
    Ok(Control {
        router,
        journal,
        task,
    })
}

async fn bound(control: &Control) -> Result<BoundSession, WireError> {
    Ok(BoundSession::new(
        control
            .router
            .begin("alice", "alpha", i64::MAX)
            .await?
            .activate(1)?,
    ))
}

async fn dispatch_document(
    control: &Control,
    backend: &mut Backend,
    bound: &mut Option<BoundSession>,
    document: &Document,
    flags: u32,
) -> Result<Vec<u8>, Error> {
    let request = Message {
        request_id: 7,
        response_to: 0,
        opcode: crate::OPCODE_MSG,
        body: crate::wire::op_msg_body(flags, document)?,
    };
    let message = crate::wire::parse_op_msg(&request.body)?;
    let name = crate::wire::command_name(document).ok_or(Error::Invalid)?;
    dispatch(
        &control.router,
        backend,
        bound,
        CommandContext {
            request: &request,
            op_msg: &message,
            document,
            name,
            principal: "alice",
            expires_at: i64::MAX,
            connection_id: 1,
        },
    )
    .await
}

fn insert_command() -> Document {
    doc! {"insert":"orders","documents":[{"_id":1}],"$db":"alpha"}
}

async fn native_reply(
    peer: &mut DuplexStream,
    journal: &Shared,
    reply: &Document,
) -> Result<(), Error> {
    let request = crate::backend::read_message(peer).await?;
    {
        let mut journal = lock(journal)?;
        assert_eq!(journal.events.last().map(String::as_str), Some("arm"));
        journal.events.push("native".into());
    }
    let reply = Message {
        request_id: 22,
        response_to: request.request_id,
        opcode: crate::OPCODE_MSG,
        body: crate::wire::op_msg_body(0, reply)?,
    };
    crate::backend::write_message(peer, &reply.into_bytes()).await?;
    Ok(())
}

#[tokio::test]
async fn two_commands_have_distinct_intents_before_each_send() -> TestResult {
    let control = control().await?;
    let (stream, mut peer) = tokio::io::duplex(8192);
    let mut backend = Backend::test_stream(stream);
    let state = control.journal.clone();
    let native = tokio::spawn(async move {
        for _ in 0..2 {
            native_reply(&mut peer, &state, &doc! {"ok":1.0,"n":1}).await?;
        }
        Ok::<_, Error>(())
    });
    let mut session = None;
    for _ in 0..2 {
        dispatch_document(&control, &mut backend, &mut session, &insert_command(), 0).await?;
    }
    native.await??;
    let journal = lock(&control.journal)?;
    assert_eq!(journal.attempt_ids.len(), 2);
    assert_ne!(journal.attempt_ids[0], journal.attempt_ids[1]);
    assert_eq!(
        journal.events,
        [
            "intent", "arm", "native", "outcome", "intent", "arm", "native", "outcome"
        ]
    );
    assert_eq!(journal.outcomes.len(), 2);
    Ok(())
}

#[tokio::test]
async fn lost_arm_ack_never_sends_native_write() -> TestResult {
    let control = control().await?;
    lock(&control.journal)?.fail_arm = true;
    let (stream, mut peer) = tokio::io::duplex(8192);
    let mut backend = Backend::test_stream(stream);
    let reply = dispatch_document(&control, &mut backend, &mut None, &insert_command(), 0).await?;
    assert!(!reply.is_empty());
    assert!(
        timeout(
            Duration::from_millis(20),
            crate::backend::read_message(&mut peer)
        )
        .await
        .is_err()
    );
    let journal = lock(&control.journal)?;
    assert_eq!(journal.steps.len(), 1);
    assert_eq!(journal.outcomes.len(), 1);
    assert_eq!(
        journal.outcomes[0].mongo.as_ref().map(|o| o.state),
        Some(MongoObservationState::NotSent)
    );
    Ok(())
}

#[tokio::test]
async fn lost_native_ack_reports_unknown_and_closes_poisoned_socket() -> TestResult {
    let control = control().await?;
    let (stream, mut peer) = tokio::io::duplex(8192);
    let mut backend = Backend::test_stream(stream);
    let native = tokio::spawn(async move { crate::backend::read_message(&mut peer).await });
    assert!(
        dispatch_document(&control, &mut backend, &mut None, &insert_command(), 0)
            .await
            .is_err()
    );
    native.await??;
    assert!(!backend.is_usable());
    let journal = lock(&control.journal)?;
    assert_eq!(journal.steps.len(), 1);
    assert_eq!(
        journal.outcomes[0].mongo.as_ref().map(|o| o.state),
        Some(MongoObservationState::Unknown)
    );
    Ok(())
}

#[tokio::test]
async fn native_partial_reply_is_preserved_while_audit_excludes_values() -> TestResult {
    let control = control().await?;
    let (stream, mut peer) = tokio::io::duplex(8192);
    let mut backend = Backend::test_stream(stream);
    let expected = doc! {"ok":1.0,"n":1,"writeErrors":[{"index":1,"code":11000,"errmsg":"secret-customer-key"}]};
    let expected_native = expected.clone();
    let state = control.journal.clone();
    let native =
        tokio::spawn(async move { native_reply(&mut peer, &state, &expected_native).await });
    let command =
        doc! {"insert":"orders","documents":[{"_id":1},{"_id":1}],"ordered":false,"$db":"alpha"};
    let reply = dispatch_document(&control, &mut backend, &mut None, &command, 0).await?;
    native.await??;
    let reply = crate::wire::parse(&reply)?;
    let reply = crate::wire::parse_op_msg(&reply.body)?;
    assert_eq!(crate::wire::kind_zero_document(&reply.sections)?, expected);
    let journal = lock(&control.journal)?;
    let observation = journal.outcomes[0]
        .mongo
        .as_ref()
        .ok_or_else(|| io::Error::other("missing Mongo observation"))?;
    assert_eq!(
        observation.state,
        MongoObservationState::AcknowledgedWithErrors
    );
    assert_eq!(
        (
            observation.inserted,
            observation.error_count,
            observation.native_code
        ),
        (Some(1), Some(1), Some(11000))
    );
    assert!(!serde_json::to_string(&journal.outcomes[0])?.contains("secret-customer-key"));
    Ok(())
}

#[tokio::test]
async fn legacy_prefix_is_acknowledged_before_next_step_can_send() -> TestResult {
    let control = control().await?;
    let mut session = bound(&control).await?;
    let entry = session.session.binding().tables[0].clone();
    write::Capture {
        entry: &entry,
        branch_id: 1,
    }
    .admit(
        &mut session.session,
        &mut session.budget,
        WriteKind::Insert,
        2,
    )
    .await?;
    let (stream, mut peer) = tokio::io::duplex(8192);
    let mut backend = Backend::test_stream(stream);
    let state = control.journal.clone();
    let native = tokio::spawn(async move {
        native_reply(&mut peer, &state, &doc! {"ok":1,"n":1,"nModified":1}).await?;
        crate::backend::read_message(&mut peer).await?;
        Ok::<_, Error>(())
    });
    let command = doc! {"update":"delta","updates":[{"q":{"_id":1},"u":{"_id":1}}]};
    observed_write(
        &mut session,
        &mut backend,
        NativeWrite {
            command: &command,
            kind: WriteKind::Update,
            planned: 1,
        },
    )
    .await?;
    assert!(
        observed_write(
            &mut session,
            &mut backend,
            NativeWrite {
                command: &command,
                kind: WriteKind::Update,
                planned: 1
            }
        )
        .await
        .is_err()
    );
    session.finish_write(true).await;
    native.await??;
    let journal = lock(&control.journal)?;
    assert_eq!(journal.steps.len(), 2);
    assert!(journal.steps[0].2.is_none());
    assert_eq!(journal.steps[1].1, 1);
    assert_eq!(journal.steps[1].2.as_ref().and_then(|o| o.matched), Some(1));
    assert_eq!(journal.outcomes[0].armed_step, 2);
    assert_eq!(
        journal.outcomes[0].mongo.as_ref().map(|o| o.state),
        Some(MongoObservationState::Unknown)
    );
    Ok(())
}

#[tokio::test]
async fn unacknowledged_requests_never_bind_or_reach_native() -> TestResult {
    let control = control().await?;
    let (stream, mut peer) = tokio::io::duplex(8192);
    let mut backend = Backend::test_stream(stream);
    let mut command = insert_command();
    command.insert("writeConcern", doc! {"w":0});
    let mut session = None;
    assert!(
        !dispatch_document(&control, &mut backend, &mut session, &command, 0)
            .await?
            .is_empty()
    );
    assert!(
        dispatch_document(
            &control,
            &mut backend,
            &mut session,
            &command,
            crate::wire::FLAG_MORE_TO_COME
        )
        .await
        .is_err()
    );
    assert!(session.is_none());
    assert!(lock(&control.journal)?.events.is_empty());
    assert!(
        timeout(
            Duration::from_millis(20),
            crate::backend::read_message(&mut peer)
        )
        .await
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn int64_delete_many_is_refused_before_intent_or_native_send() -> TestResult {
    let control = control().await?;
    let (stream, mut peer) = tokio::io::duplex(8192);
    let mut backend = Backend::test_stream(stream);
    let command = doc! {"delete":"orders","deletes":[{"q":{},"limit":0i64}],"$db":"alpha"};
    let reply = dispatch_document(&control, &mut backend, &mut None, &command, 0).await?;
    let message = crate::wire::parse(&reply)?;
    let message = crate::wire::parse_op_msg(&message.body)?;
    let reply = crate::wire::kind_zero_document(&message.sections)?;
    assert_eq!(reply.get_f64("ok"), Ok(0.0));
    assert!(lock(&control.journal)?.attempt_ids.is_empty());
    assert!(
        timeout(
            Duration::from_millis(20),
            crate::backend::read_message(&mut peer)
        )
        .await
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn failed_delivery_preserves_result_and_blocks_other_session_until_resend() -> TestResult {
    let control = control().await?;
    lock(&control.journal)?.fail_outcome = true;
    let (stream, mut peer) = tokio::io::duplex(8192);
    let mut backend = Backend::test_stream(stream);
    let state = control.journal.clone();
    let native = tokio::spawn(async move {
        native_reply(&mut peer, &state, &doc! {"ok":1,"n":1}).await?;
        Ok::<_, Error>(peer)
    });
    let mut first = None;
    let reply = dispatch_document(&control, &mut backend, &mut first, &insert_command(), 0).await?;
    let message = crate::wire::parse(&reply)?;
    let message = crate::wire::parse_op_msg(&message.body)?;
    assert_eq!(
        crate::wire::kind_zero_document(&message.sections)?.get_i32("n"),
        Ok(1)
    );
    let mut peer = native.await??;
    assert!(lock(&control.journal)?.outcomes.is_empty());

    let second = control
        .router
        .begin("alice", "alpha", i64::MAX)
        .await?
        .activate(2)?;
    let mut second = Some(BoundSession::new(second));
    let (stream, mut second_peer) = tokio::io::duplex(8192);
    let mut second_backend = Backend::test_stream(stream);
    dispatch_document(
        &control,
        &mut second_backend,
        &mut second,
        &insert_command(),
        0,
    )
    .await?;
    assert_eq!(lock(&control.journal)?.attempt_ids.len(), 1);
    assert!(
        timeout(
            Duration::from_millis(20),
            crate::backend::read_message(&mut second_peer)
        )
        .await
        .is_err()
    );

    lock(&control.journal)?.fail_outcome = false;
    // Failed deliveries become eligible after the common one-second backoff.
    // A foreground write before that deadline must retain its refusal.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let state = control.journal.clone();
    let native =
        tokio::spawn(async move { native_reply(&mut peer, &state, &doc! {"ok":1,"n":1}).await });
    timeout(
        Duration::from_secs(2),
        dispatch_document(&control, &mut backend, &mut first, &insert_command(), 0),
    )
    .await??;
    timeout(Duration::from_secs(2), native).await???;
    let journal = lock(&control.journal)?;
    assert_eq!(journal.attempt_ids.len(), 2);
    assert_eq!(journal.outcomes.len(), 2);
    assert_eq!(
        journal
            .events
            .iter()
            .filter(|event| event.as_str() == "native")
            .count(),
        2
    );
    Ok(())
}

#[tokio::test]
async fn cancelled_write_leaves_intent_and_armed_step_without_fabricated_outcome() -> TestResult {
    let control = control().await?;
    let mut session = bound(&control).await?;
    let entry = session.session.binding().tables[0].clone();
    write::Capture {
        entry: &entry,
        branch_id: 1,
    }
    .admit(
        &mut session.session,
        &mut session.budget,
        WriteKind::Insert,
        1,
    )
    .await?;
    let (stream, mut peer) = tokio::io::duplex(8192);
    let mut backend = Backend::test_stream(stream);
    let task = tokio::spawn(async move {
        observed_write(
            &mut session,
            &mut backend,
            NativeWrite {
                command: &insert_command(),
                kind: WriteKind::Insert,
                planned: 1,
            },
        )
        .await
    });
    timeout(
        Duration::from_secs(2),
        crate::backend::read_message(&mut peer),
    )
    .await??;
    task.abort();
    let result = task.await;
    assert!(result.is_err_and(|error| error.is_cancelled()));
    let journal = lock(&control.journal)?;
    assert_eq!(journal.attempt_ids.len(), 1);
    assert_eq!(journal.steps.len(), 1);
    assert!(journal.outcomes.is_empty());
    assert_eq!(journal.events, ["intent", "arm"]);
    Ok(())
}

#[tokio::test]
async fn lost_next_arm_ack_does_not_reuse_previous_native_ack() -> TestResult {
    let control = control().await?;
    let mut session = bound(&control).await?;
    let entry = session.session.binding().tables[0].clone();
    write::Capture {
        entry: &entry,
        branch_id: 1,
    }
    .admit(
        &mut session.session,
        &mut session.budget,
        WriteKind::Insert,
        2,
    )
    .await?;
    let (stream, mut peer) = tokio::io::duplex(8192);
    let mut backend = Backend::test_stream(stream);
    let state = control.journal.clone();
    let native = tokio::spawn(async move {
        native_reply(&mut peer, &state, &doc! {"ok":1,"n":1,"nModified":1}).await?;
        Ok::<_, Error>(peer)
    });
    let command = doc! {"update":"delta","updates":[{"q":{"_id":1},"u":{"_id":1}}]};
    observed_write(
        &mut session,
        &mut backend,
        NativeWrite {
            command: &command,
            kind: WriteKind::Update,
            planned: 1,
        },
    )
    .await?;
    let mut peer = native.await??;
    lock(&control.journal)?.fail_arm = true;
    assert!(
        observed_write(
            &mut session,
            &mut backend,
            NativeWrite {
                command: &command,
                kind: WriteKind::Update,
                planned: 1
            }
        )
        .await
        .is_err()
    );
    session.finish_write(true).await;
    assert!(
        timeout(
            Duration::from_millis(20),
            crate::backend::read_message(&mut peer)
        )
        .await
        .is_err()
    );
    let journal = lock(&control.journal)?;
    assert_eq!(
        journal.steps[1].2.as_ref().map(|o| o.state),
        Some(MongoObservationState::Acknowledged)
    );
    let observation = journal.outcomes[0]
        .mongo
        .as_ref()
        .ok_or_else(|| io::Error::other("missing outcome"))?;
    assert_eq!(observation.state, MongoObservationState::Unknown);
    assert_eq!(observation.matched, None);
    Ok(())
}

#[tokio::test]
async fn next_step_fresh_refusal_preserves_partial_prefix_without_claiming_full_success()
-> TestResult {
    let control = control().await?;
    let mut session = bound(&control).await?;
    let entry = session.session.binding().tables[0].clone();
    write::Capture {
        entry: &entry,
        branch_id: 1,
    }
    .admit(
        &mut session.session,
        &mut session.budget,
        WriteKind::Insert,
        2,
    )
    .await?;
    let (stream, mut peer) = tokio::io::duplex(8192);
    let mut backend = Backend::test_stream(stream);
    let state = control.journal.clone();
    let native = tokio::spawn(async move {
        native_reply(&mut peer, &state, &doc! {"ok":1,"n":1,"nModified":1}).await?;
        Ok::<_, Error>(peer)
    });
    let command = doc! {"update":"delta","updates":[{"q":{"_id":1},"u":{"_id":1}}]};
    observed_write(
        &mut session,
        &mut backend,
        NativeWrite {
            command: &command,
            kind: WriteKind::Update,
            planned: 1,
        },
    )
    .await?;
    let mut peer = native.await??;
    lock(&control.journal)?.fail_validation = true;
    assert!(
        observed_write(
            &mut session,
            &mut backend,
            NativeWrite {
                command: &command,
                kind: WriteKind::Update,
                planned: 1
            }
        )
        .await
        .is_err()
    );
    session.finish_write(true).await;
    assert!(
        timeout(
            Duration::from_millis(20),
            crate::backend::read_message(&mut peer)
        )
        .await
        .is_err()
    );
    let journal = lock(&control.journal)?;
    assert_eq!(journal.steps.len(), 1);
    let observation = journal.outcomes[0]
        .mongo
        .as_ref()
        .ok_or_else(|| io::Error::other("missing partial observation"))?;
    assert_eq!(
        observation.state,
        MongoObservationState::AcknowledgedWithErrors
    );
    assert_eq!(observation.matched, Some(1));
    assert_eq!(
        journal.outcomes[0].outcome,
        fg_protocol_common::TransactionOutcome::Unknown
    );
    Ok(())
}
