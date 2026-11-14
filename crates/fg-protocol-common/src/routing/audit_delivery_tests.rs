use super::{
    tests::{pending, read_audit_http_message},
    *,
};
use crate::{AuditStatus, WriteFenceRequest};
use std::sync::atomic::AtomicUsize;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::Notify,
};

async fn listener() -> Result<(Router, TcpListener), WireError> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| WireError::Backend)?;
    let address = listener.local_addr().map_err(|_| WireError::Backend)?;
    let url = loopback_http(&format!("http://{address}")).ok_or(WireError::Backend)?;
    Ok((Router::new(url, "test-token".into(), "mysql")?, listener))
}

async fn respond(
    socket: &mut TcpStream,
    status: &str,
    body: serde_json::Value,
) -> Result<(), WireError> {
    let body = serde_json::to_string(&body).map_err(|_| WireError::Backend)?;
    socket.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes())
        .await.map_err(|_|WireError::Backend)
}

fn ack(request: &AuditedOutcomeRequest) -> serde_json::Value {
    serde_json::json!({"attempt_id":request.attempt.attempt_id,"audit_event_id":1,"outcome":request.outcome})
}

#[tokio::test]
async fn one_hundred_healthy_outcomes_are_neither_reposted_nor_reported_paused()
-> Result<(), WireError> {
    let (router, listener) = listener().await?;
    let received = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let server_received = received.clone();
    let server_release = release.clone();
    let server = tokio::spawn(async move {
        let mut waiting = Vec::new();
        for _ in 0..100 {
            let (mut socket, _) = listener.accept().await.map_err(|_| WireError::Backend)?;
            let (path, body) = read_audit_http_message(&mut socket).await?;
            assert!(path.contains("/audit/outcome"));
            let request: AuditedOutcomeRequest =
                serde_json::from_value(body).map_err(|_| WireError::Backend)?;
            waiting.push((socket, request));
        }
        server_received.notify_one();
        server_release.notified().await;
        for (mut socket, request) in waiting {
            respond(&mut socket, "200 OK", ack(&request)).await?;
        }
        assert!(
            timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err(),
            "healthy delivery was reposted"
        );
        Ok::<_, WireError>(())
    });
    let branch = Arc::new(pending(&router, 1).await.activate(77)?);
    let mut deliveries = Vec::new();
    for _ in 0..100 {
        let mut attempt = branch.new_write_attempt()?;
        attempt.mark_intent_possible();
        let session = branch.clone();
        deliveries.push(tokio::spawn(async move {
            session
                .audit_outcome(&attempt, TransactionOutcome::Committed)
                .await
        }));
    }
    timeout(Duration::from_secs(10), received.notified())
        .await
        .map_err(|_| WireError::Backend)?;
    assert!(!router.protected_writes_paused()?);
    timeout(Duration::from_millis(100), router.retry_audit_deliveries())
        .await
        .map_err(|_| WireError::Backend)??;
    branch.reconcile_audit_delivery().await?;
    assert!(!router.protected_writes_paused()?);
    release.notify_one();
    for delivery in deliveries {
        delivery.await.map_err(|_| WireError::Backend)??;
    }
    server.await.map_err(|_| WireError::Backend)??;
    assert!(!router.protected_writes_paused()?);
    Ok(())
}

async fn failed_delivery_recovers(cancel: bool) -> Result<(), WireError> {
    let (router, listener) = listener().await?;
    let first_received = Arc::new(Notify::new());
    let release_first = Arc::new(Notify::new());
    let retry_received = Arc::new(Notify::new());
    let release_retry = Arc::new(Notify::new());
    let count = Arc::new(AtomicUsize::new(0));
    let signals = (
        first_received.clone(),
        release_first.clone(),
        retry_received.clone(),
        release_retry.clone(),
        count.clone(),
    );
    let server = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.map_err(|_| WireError::Backend)?;
        let (_, body) = read_audit_http_message(&mut first).await?;
        let request: AuditedOutcomeRequest =
            serde_json::from_value(body.clone()).map_err(|_| WireError::Backend)?;
        signals.4.fetch_add(1, Ordering::Relaxed);
        signals.0.notify_one();
        if cancel {
            signals.1.notified().await;
        } else {
            let mut wrong = ack(&request);
            wrong["attempt_id"] = serde_json::json!("wrong-attempt");
            respond(&mut first, "200 OK", wrong).await?;
        }
        drop(first);
        let (mut retry, _) = listener.accept().await.map_err(|_| WireError::Backend)?;
        let (_, retried) = read_audit_http_message(&mut retry).await?;
        assert_eq!(retried, body, "retry changed a known native observation");
        signals.4.fetch_add(1, Ordering::Relaxed);
        signals.2.notify_one();
        signals.3.notified().await;
        respond(&mut retry, "200 OK", ack(&request)).await
    });
    let branch = Arc::new(pending(&router, 1).await.activate(77)?);
    let mut attempt = branch.new_write_attempt()?;
    attempt.mark_intent_possible();
    let session = branch.clone();
    let delivery = tokio::spawn(async move {
        session
            .audit_outcome(&attempt, TransactionOutcome::Committed)
            .await
    });
    first_received.notified().await;
    if cancel {
        delivery.abort();
        assert!(delivery.await.is_err());
        release_first.notify_one();
    } else {
        assert!(delivery.await.map_err(|_| WireError::Backend)?.is_err());
    }
    assert!(router.protected_writes_paused()?);
    for _ in 0..10 {
        router.retry_audit_deliveries().await?;
    }
    assert_eq!(
        count.load(Ordering::Relaxed),
        1,
        "foreground retry ignored its backoff"
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let retry_router = router.clone();
    let recovery = tokio::spawn(async move { retry_router.retry_audit_deliveries().await });
    retry_received.notified().await;
    assert!(
        router.protected_writes_paused()?,
        "in-flight recovery cleared backpressure early"
    );
    router.retry_audit_deliveries().await?;
    assert_eq!(count.load(Ordering::Relaxed), 2);
    release_retry.notify_one();
    recovery.await.map_err(|_| WireError::Backend)??;
    server.await.map_err(|_| WireError::Backend)??;
    assert!(!router.protected_writes_paused()?);
    Ok(())
}

#[tokio::test]
async fn failed_ack_retries_after_backoff_without_duplicate_retry_flights() -> Result<(), WireError>
{
    failed_delivery_recovers(false).await
}

#[tokio::test]
async fn cancelled_initial_delivery_is_retained_and_retried() -> Result<(), WireError> {
    failed_delivery_recovers(true).await
}

#[tokio::test]
async fn one_failed_retry_does_not_starve_the_rest_of_its_claimed_batch() -> Result<(), WireError> {
    let (router, listener) = listener().await?;
    let server = tokio::spawn(async move {
        for index in 0..5 {
            let (mut socket, _) = listener.accept().await.map_err(|_| WireError::Backend)?;
            let (_, body) = read_audit_http_message(&mut socket).await?;
            if index == 4 {
                let request: AuditedOutcomeRequest =
                    serde_json::from_value(body).map_err(|_| WireError::Backend)?;
                respond(&mut socket, "200 OK", ack(&request)).await?;
            } else {
                respond(
                    &mut socket,
                    "503 Service Unavailable",
                    serde_json::json!({}),
                )
                .await?;
            }
        }
        Ok::<_, WireError>(())
    });
    let branch = pending(&router, 1).await.activate(77)?;
    for _ in 0..2 {
        let mut attempt = branch.new_write_attempt()?;
        attempt.mark_intent_possible();
        assert!(
            branch
                .audit_outcome(&attempt, TransactionOutcome::Committed)
                .await
                .is_err()
        );
    }
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(router.retry_audit_deliveries().await.is_err());
    assert_eq!(
        router
            .0
            .audit_pending
            .lock()
            .map_err(|_| WireError::Backend)?
            .len(),
        1
    );
    assert!(router.protected_writes_paused()?);
    server.await.map_err(|_| WireError::Backend)??;
    Ok(())
}

#[tokio::test]
async fn sql_uncertainty_can_settle_from_a_known_primary_fact() -> Result<(), WireError> {
    for known in [
        TransactionOutcome::Committed,
        TransactionOutcome::RolledBack,
    ] {
        let (router, listener) = listener().await?;
        let server = tokio::spawn(async move {
            let (mut initial, _) = listener.accept().await.map_err(|_| WireError::Backend)?;
            let (_, body) = read_audit_http_message(&mut initial).await?;
            let mut request: AuditedOutcomeRequest =
                serde_json::from_value(body).map_err(|_| WireError::Backend)?;
            assert_eq!(request.outcome, TransactionOutcome::Unknown);
            respond(
                &mut initial,
                "503 Service Unavailable",
                serde_json::json!({}),
            )
            .await?;
            drop(initial);
            let (mut status, _) = listener.accept().await.map_err(|_| WireError::Backend)?;
            let (path, _) = read_audit_http_message(&mut status).await?;
            assert!(
                path.contains("/audit/status"),
                "uncertainty should check proof before reposting"
            );
            request.outcome = known;
            let evidence = AuditStatus {
                ack: Some(OutcomeAck {
                    attempt_id: request.attempt.attempt_id.clone(),
                    audit_event_id: 3,
                    outcome: known,
                }),
                outcome: Some(request),
                resolved: true,
                ..Default::default()
            };
            respond(
                &mut status,
                "200 OK",
                serde_json::to_value(evidence).map_err(|_| WireError::Backend)?,
            )
            .await
        });
        let branch = pending(&router, 1).await.activate(77)?;
        let mut attempt = branch.new_write_attempt()?;
        attempt.mark_intent_possible();
        assert!(
            branch
                .audit_outcome(&attempt, TransactionOutcome::Unknown)
                .await
                .is_err()
        );
        tokio::time::sleep(Duration::from_millis(1100)).await;
        router.retry_audit_deliveries().await?;
        assert!(!router.protected_writes_paused()?);
        server.await.map_err(|_| WireError::Backend)??;
    }
    Ok(())
}

#[tokio::test]
async fn primary_status_requires_its_complete_matching_native_context() -> Result<(), WireError> {
    let (router, _listener) = listener().await?;
    let branch = pending(&router, 1).await.activate(77)?;
    let request = AuditedOutcomeRequest {
        attempt: branch.new_write_attempt()?.context().clone(),
        outcome: TransactionOutcome::Committed,
        armed_step: 0,
        mongo: None,
    };
    let make_status = || AuditStatus {
        ack: Some(OutcomeAck {
            attempt_id: request.attempt.attempt_id.clone(),
            audit_event_id: 1,
            outcome: request.outcome,
        }),
        outcome: Some(request.clone()),
        resolved: true,
        ..Default::default()
    };
    assert!(audit_status_confirms(&make_status(), &request));
    for fault in [
        "missing",
        "native_session",
        "generation",
        "principal",
        "attempt",
        "outcome",
    ] {
        let mut status = make_status();
        if fault == "missing" {
            status.outcome = None;
        } else {
            let recorded = status.outcome.as_mut().ok_or(WireError::Backend)?;
            match fault {
                "native_session" => recorded.attempt.native_session_id += 1,
                "generation" => recorded.attempt.generation_id += 1,
                "principal" => recorded.attempt.principal = "other-owner".into(),
                "attempt" => recorded.attempt.attempt_id = "swapped-attempt".into(),
                "outcome" => recorded.outcome = TransactionOutcome::RolledBack,
                _ => {}
            }
        }
        assert!(!audit_status_confirms(&status, &request), "{fault}");
    }
    Ok(())
}

#[tokio::test]
async fn write_fence_requires_the_exact_verified_context_echo() -> Result<(), WireError> {
    for fault in [
        "none",
        "missing",
        "branch",
        "engine",
        "revision",
        "generation",
        "attempt",
    ] {
        let (router, listener) = listener().await?;
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.map_err(|_| WireError::Backend)?;
            let (_, body) = read_audit_http_message(&mut socket).await?;
            let request: WriteFenceRequest =
                serde_json::from_value(body).map_err(|_| WireError::Backend)?;
            let mut response = serde_json::json!({"branch_id":1,"engine":"mysql","context":request,"expires_at":i64::MAX,"lease_version":1});
            match fault {
                "missing" => {
                    response
                        .as_object_mut()
                        .ok_or(WireError::Backend)?
                        .remove("context");
                }
                "branch" => response["branch_id"] = serde_json::json!(2),
                "engine" => response["engine"] = serde_json::json!("postgresql"),
                "revision" => response["context"]["effective_revision"] = serde_json::json!(1),
                "generation" => {
                    response["context"]["attempt"]["generation_id"] = serde_json::json!(2)
                }
                "attempt" => {
                    response["context"]["attempt"]["attempt_id"] =
                        serde_json::json!("wrong-attempt")
                }
                _ => {}
            }
            respond(&mut socket, "200 OK", response).await
        });
        let branch = pending(&router, 1).await.activate(77)?;
        let attempt = branch.new_write_attempt()?;
        let policy = Policy {
            class: BranchClass::Dev,
            version: 1,
            max_transaction_rows: 100,
            table_limit_bps: None,
            approval_after_rows: None,
            small_table_floor: 1,
            effective_revision: 0,
            grant_expires_at: None,
        };
        assert_eq!(
            branch.fresh_write_fence(&attempt, &policy).await.is_ok(),
            fault == "none",
            "{fault}"
        );
        server.await.map_err(|_| WireError::Backend)??;
    }
    Ok(())
}
