use super::{
    tests::{pending, read_audit_http_message},
    *,
};
use crate::{CatalogEntry, TransactionBudget, WriteKind, WriteOperation};
use tokio::{io::AsyncWriteExt, net::TcpListener, sync::oneshot};

fn policy() -> Policy {
    Policy {
        class: BranchClass::Dev,
        version: 1,
        max_transaction_rows: 100,
        table_limit_bps: None,
        approval_after_rows: None,
        small_table_floor: 1,
        effective_revision: 0,
        grant_expires_at: None,
    }
}

async fn writable(router: &Router) -> Result<BranchSession, WireError> {
    let mut session = pending(router, 1).await;
    session.binding.access = BranchAccess::ReadWrite;
    session.binding.layout = BranchLayout::NativeCopy;
    session.binding.write_schema = Some("fgwrite".into());
    session.binding.audit_witness_ready = true;
    session.binding.tables.push(CatalogEntry {
        id: 7,
        baseline_rows: 100,
        logical_schema: "app".into(),
        logical_table: "items".into(),
        base_schema: "fg_g1".into(),
        base_table: "items".into(),
        delta_schema: "fg_g1".into(),
        delta_table: "items_delta".into(),
        generated_key: None,
        columns: Vec::new(),
    });
    session.activate(77)
}

struct Peer {
    router: Router,
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<Result<Vec<(String, serde_json::Value)>, WireError>>,
}

impl Peer {
    async fn new(fault: &'static str) -> Result<Self, WireError> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| WireError::Backend)?;
        let address = listener.local_addr().map_err(|_| WireError::Backend)?;
        let router = Router::new(
            loopback_http(&format!("http://{address}")).ok_or(WireError::Backend)?,
            "test-token".into(),
            "mysql",
        )?;
        let server_router = router.clone();
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            loop {
                let (mut stream, _) = tokio::select! {
                    biased;
                    _ = &mut stopped => break,
                    result = listener.accept() => result.map_err(|_| WireError::Backend)?,
                };
                let (request_line, body) = read_audit_http_message(&mut stream).await?;
                let path = request_line
                    .split_whitespace()
                    .nth(1)
                    .ok_or(WireError::Backend)?
                    .to_owned();
                let (status, response) = reply(&server_router, &path, &body, fault)?;
                requests.push((path, body));
                let response = if status.starts_with("204 ") {
                    String::new()
                } else {
                    serde_json::to_string(&response).map_err(|_| WireError::Backend)?
                };
                stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len()).as_bytes())
                    .await.map_err(|_| WireError::Backend)?;
            }
            Ok(requests)
        });
        Ok(Self { router, stop, task })
    }

    async fn finish(self) -> Result<Vec<(String, serde_json::Value)>, WireError> {
        let _ = self.stop.send(());
        self.task.await.map_err(|_| WireError::Backend)?
    }
}

fn reply(
    router: &Router,
    path: &str,
    body: &serde_json::Value,
    fault: &str,
) -> Result<(&'static str, serde_json::Value), WireError> {
    let mut status = "200 OK";
    let response = if path.ends_with("/audit/decisions") {
        let request: AuditedDecisionRequest =
            serde_json::from_value(body.clone()).map_err(|_| WireError::Backend)?;
        serde_json::json!({"attempt_id":request.attempt.attempt_id,"approval_id":null,"witness":{
            "format_version":1,"deployment_id":"00000000-0000-0000-0000-000000000001",
            "branch_id":1,"generation_id":1,"storage_incarnation":"0123456789abcdef0123456789abcdef"}})
    } else if path.ends_with("/write-fence") {
        let mut response = serde_json::json!({"branch_id":1,"engine":"mysql","context":body,"expires_at":i64::MAX,"lease_version":1});
        match fault {
            "conflict" => status = "409 Conflict",
            "backend" => status = "503 Service Unavailable",
            "echo" => response["context"]["effective_revision"] = serde_json::json!(1),
            "expired" => response["expires_at"] = serde_json::json!(1),
            "cancelled" => {
                let sessions = router.0.sessions.lock().map_err(|_| WireError::Backend)?;
                sessions
                    .get(&77)
                    .ok_or(WireError::Backend)?
                    .cancel
                    .send_replace(true);
            }
            _ => {}
        }
        response
    } else if path.ends_with("/audit/outcome") {
        let request: AuditedOutcomeRequest =
            serde_json::from_value(body.clone()).map_err(|_| WireError::Backend)?;
        serde_json::json!({"attempt_id":request.attempt.attempt_id,"audit_event_id":9,"outcome":request.outcome})
    } else if path.ends_with("/lease") {
        if fault == "lease_unavailable" {
            status = "503 Service Unavailable";
        }
        serde_json::json!({"expires_at":if fault=="lease_expired" {1}else{i64::MAX},"lease_version":1})
    } else if path.ends_with("/policy/validate") {
        status = "204 No Content";
        serde_json::json!({})
    } else {
        return Err(WireError::Backend);
    };
    Ok((status, response))
}

fn operation() -> WriteOperation {
    WriteOperation {
        table_id: 7,
        kind: WriteKind::Insert,
    }
}

#[tokio::test]
async fn autocommit_has_three_requests_and_its_fence_refreshes_authorization()
-> Result<(), WireError> {
    let peer = Peer::new("none").await?;
    let branch = writable(&peer.router).await?;
    let mut budget = TransactionBudget::default();
    budget
        .evaluate_autocommit(&branch, &policy(), operation(), 1)
        .await?;
    assert_eq!(branch.last_active_ms.load(Ordering::Relaxed), 0);
    budget.fence_for_commit(&branch).await?;
    assert!(branch.last_active_ms.load(Ordering::Relaxed) > 0);
    branch.authorize().await?;
    let attempt = budget.take_attempt().ok_or(WireError::Backend)?;
    branch
        .audit_outcome(&attempt, TransactionOutcome::Committed)
        .await?;
    let requests = peer.finish().await?;
    let paths: Vec<_> = requests.iter().map(|(path, _)| path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "/internal/v1/branches/1/audit/decisions",
            "/internal/v1/branches/1/write-fence",
            "/internal/v1/branches/1/audit/outcome"
        ]
    );
    assert_eq!(requests[0].1["attempt"], requests[1].1["attempt"]);
    assert_eq!(requests[0].1["attempt"], requests[2].1["attempt"]);
    Ok(())
}

#[tokio::test]
async fn explicit_statements_keep_their_checks_and_share_one_final_attempt() -> Result<(), WireError>
{
    let peer = Peer::new("none").await?;
    let branch = writable(&peer.router).await?;
    let mut budget = TransactionBudget::default();
    for _ in 0..2 {
        budget.evaluate(&branch, &policy(), operation(), 1).await?;
    }
    budget.fence_for_commit(&branch).await?;
    let attempt = budget.take_attempt().ok_or(WireError::Backend)?;
    branch
        .audit_outcome(&attempt, TransactionOutcome::Committed)
        .await?;
    let requests = peer.finish().await?;
    assert_eq!(requests.len(), 8);
    for suffix in ["/audit/decisions", "/lease", "/policy/validate"] {
        assert_eq!(
            requests
                .iter()
                .filter(|(path, _)| path.ends_with(suffix))
                .count(),
            2
        );
    }
    assert_eq!(requests[0].1["attempt"], requests[3].1["attempt"]);
    assert!(requests[6].0.ends_with("/write-fence"));
    assert!(requests[7].0.ends_with("/audit/outcome"));
    Ok(())
}

#[tokio::test]
async fn deferred_checks_preserve_context_pin_and_rollback_on_a_refused_final_fence()
-> Result<(), WireError> {
    for fault in ["conflict", "backend", "echo", "expired", "cancelled"] {
        let peer = Peer::new(fault).await?;
        let branch = writable(&peer.router).await?;
        let mut budget = TransactionBudget::default();
        budget
            .evaluate_autocommit(&branch, &policy(), operation(), 1)
            .await?;
        let changed = Policy {
            effective_revision: 1,
            ..policy()
        };
        assert!(matches!(
            budget
                .evaluate_autocommit(&branch, &changed, operation(), 1)
                .await,
            Err(WireError::Policy)
        ));
        assert!(budget.fence_for_commit(&branch).await.is_err(), "{fault}");
        assert_eq!(branch.last_active_ms.load(Ordering::Relaxed), 0, "{fault}");
        let attempt = budget.take_attempt().ok_or(WireError::Backend)?;
        branch
            .audit_outcome(&attempt, TransactionOutcome::RolledBack)
            .await?;
        let requests = peer.finish().await?;
        assert_eq!(requests.len(), 3, "{fault}");
        assert_eq!(requests[2].1["outcome"], "rolled_back", "{fault}");
    }
    Ok(())
}

#[tokio::test]
async fn error_only_attempt_keeps_a_fresh_observer_lease_without_fabricating_admission()
-> Result<(), WireError> {
    for fault in ["none", "lease_unavailable", "lease_expired"] {
        let peer = Peer::new(fault).await?;
        let branch = writable(&peer.router).await?;
        let mut budget = TransactionBudget::default();
        budget.fence_for_commit(&branch).await?;
        budget.native_error(&branch, &policy(), operation()).await;
        assert!(budget.attempt().is_some_and(AuditAttempt::is_prepared));
        let result = budget.fence_for_commit(&branch).await;
        assert_eq!(result.is_ok(), fault == "none");
        let attempt = budget.take_attempt().ok_or(WireError::Backend)?;
        branch
            .audit_outcome(
                &attempt,
                if result.is_ok() {
                    TransactionOutcome::Committed
                } else {
                    TransactionOutcome::RolledBack
                },
            )
            .await?;
        let requests = peer.finish().await?;
        assert_eq!(requests.len(), 3, "{fault}");
        assert!(requests[0].0.ends_with("/audit/decisions"));
        assert_eq!(requests[0].1["decision"]["verdict"], "native_error");
        assert!(requests[1].0.ends_with("/lease"));
        assert!(requests[2].0.ends_with("/audit/outcome"));
        assert_eq!(
            requests[2].1["outcome"],
            if fault == "none" {
                "committed"
            } else {
                "rolled_back"
            }
        );
    }
    Ok(())
}
