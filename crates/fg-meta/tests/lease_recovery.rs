//! Real metadata tests; the harness supplies an isolated disposable database.

use fg_meta::{
    BranchMode, ForkBranch, GitHubObservation, GitHubRecreate, GitHubSignal, MetaError, Metadata,
    RefreshGeneration, SeedColumn, SeedTable,
};
use fg_protocol_common::BranchClass;
use sqlx::{Connection, Executor, PgConnection};

const COLUMN: SeedColumn = SeedColumn {
    name: "id",
    type_name: "bigint",
    collation: None,
    nullable: false,
    primary_key_ordinal: Some(1),
};

fn tables() -> Vec<SeedTable> {
    vec![SeedTable {
        name: "records",
        columns: &[COLUMN],
        generated_key: None,
        baseline_rows: 100,
    }]
}

async fn metadata() -> Result<(Metadata, PgConnection), Box<dyn std::error::Error>> {
    let dsn = std::env::var("FG_T10_LEASE_DSN")?;
    let metadata = Metadata::connect(&dsn, None).await?;
    metadata.migrate().await?;
    let mut admin = PgConnection::connect(&dsn).await?;
    admin
        .execute("TRUNCATE generation,audit_event,github_source CASCADE")
        .await?;
    let generation = metadata
        .allocate_generation("postgresql", &tables())
        .await?;
    metadata.claim_generation(generation.id).await?;
    metadata.activate_generation(generation.id).await?;
    Ok((metadata, admin))
}

fn fork<'a>(name: &'a str) -> ForkBranch<'a> {
    ForkBranch {
        engine: "postgresql",
        principal: "alice",
        name,
        ttl_seconds: 3600,
        mode: BranchMode::ReadOnly,
        class: BranchClass::Dev,
        expected_generation: None,
    }
}

#[tokio::test]
#[ignore = "requires isolated FG_T10_LEASE_DSN; run serially"]
async fn capture_fence_blocks_new_clients_and_recovers_after_interruption()
-> Result<(), Box<dyn std::error::Error>> {
    let (metadata, _admin) = metadata().await?;
    let branch = metadata.fork(fork("capture-case")).await?;
    metadata.resolve("alice", &branch.name).await?;
    let guard = metadata
        .begin_capture("postgresql", branch.id, "alice")
        .await?;
    assert!(metadata.resolve("alice", &branch.name).await.is_err());
    assert!(metadata.resolve_by_id("alice", branch.id).await.is_ok());
    assert!(
        metadata
            .begin_capture("postgresql", branch.id, "alice")
            .await
            .is_err()
    );
    drop(guard);
    // A lost capture remains fenced until a new export obtains the lock and
    // drains the native sessions; this API does not silently make it writable.
    assert_eq!(
        metadata
            .branch_status("postgresql", branch.id, "alice")
            .await?["export_in_progress"],
        true
    );
    let retry = metadata
        .begin_capture("postgresql", branch.id, "alice")
        .await?;
    metadata.finish_capture(branch.id, retry).await?;
    assert!(metadata.resolve("alice", &branch.name).await.is_ok());
    assert!(
        metadata
            .begin_capture("postgresql", branch.id, "bob")
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated FG_T10_LEASE_DSN; run serially"]
async fn renewal_is_cas_bounded_and_never_revives_expiry() -> Result<(), Box<dyn std::error::Error>>
{
    let (metadata, mut admin) = metadata().await?;
    let branch = metadata.fork(fork("lease-case")).await?;
    let (left, right) = tokio::join!(
        metadata.renew_branch("postgresql", branch.id, "alice", 7200, 1),
        metadata.renew_branch("postgresql", branch.id, "alice", 7200, 1)
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    assert!(
        matches!(left, Err(MetaError::LeaseConflict))
            || matches!(right, Err(MetaError::LeaseConflict))
    );
    let status = metadata
        .branch_status("postgresql", branch.id, "alice")
        .await?;
    assert_eq!(status["lease_version"], 2);
    assert!(
        metadata
            .renew_branch("postgresql", branch.id, "bob", 86400, 2)
            .await
            .is_err()
    );
    assert!(
        metadata
            .renew_branch("postgresql", branch.id, "alice", 86401, 2)
            .await
            .is_err()
    );
    sqlx::query("UPDATE branch SET created_at=clock_timestamp()-INTERVAL '7 days'+INTERVAL '20 seconds',expires_at=clock_timestamp()+INTERVAL '10 seconds',lease_renewed_at=clock_timestamp() WHERE id=$1").bind(branch.id).execute(&mut admin).await?;
    let renewed = metadata
        .renew_branch("postgresql", branch.id, "alice", 86400, 2)
        .await?;
    let status = metadata
        .branch_status("postgresql", branch.id, "alice")
        .await?;
    assert_eq!(
        serde_json::json!(renewed.expires_at),
        status["retain_until_max"]
    );
    sqlx::query("UPDATE branch SET expires_at=clock_timestamp()-INTERVAL '1 second' WHERE id=$1")
        .bind(branch.id)
        .execute(&mut admin)
        .await?;
    assert!(matches!(
        metadata
            .renew_branch("postgresql", branch.id, "alice", 86400, 3)
            .await,
        Err(MetaError::BranchUnavailable)
    ));
    metadata.expire_branches("postgresql").await?;
    assert_eq!(
        metadata.detail("alice", branch.id).await?.status,
        "dropping"
    );
    assert!(
        metadata
            .branch_lease("postgresql", branch.id, "alice")
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated FG_T10_LEASE_DSN; run serially"]
async fn renewal_cannot_cross_expiry_while_waiting_for_an_unchanged_tuple_lock()
-> Result<(), Box<dyn std::error::Error>> {
    let (metadata, mut observer) = metadata().await?;
    let metadata = std::sync::Arc::new(metadata);
    let branch = metadata.fork(fork("lease-lock-deadline")).await?;
    sqlx::query("UPDATE branch SET expires_at=clock_timestamp()+INTERVAL '5 seconds' WHERE id=$1")
        .bind(branch.id)
        .execute(&mut observer)
        .await?;
    let mut blocker = PgConnection::connect(&std::env::var("FG_T10_LEASE_DSN")?).await?;
    let mut lock = blocker.begin().await?;
    // Lock without changing the row: no EvalPlanQual refresh should be needed
    // to make the deadline check occur after the blocked SELECT completes.
    sqlx::query("SELECT id FROM branch WHERE id=$1 FOR UPDATE")
        .bind(branch.id)
        .execute(&mut *lock)
        .await?;
    let renewal_metadata = metadata.clone();
    let renewal = tokio::spawn(async move {
        renewal_metadata
            .renew_branch("postgresql", branch.id, "alice", 3600, 1)
            .await
    });
    let mut waiting = false;
    for _ in 0..100 {
        waiting=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE query LIKE 'SELECT b.lease_version,%' AND wait_event_type='Lock')")
            .fetch_one(&mut observer).await?;
        if waiting {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        waiting,
        "renewal did not reach the tuple lock before expiry"
    );
    loop {
        let expired: bool =
            sqlx::query_scalar("SELECT expires_at<=clock_timestamp() FROM branch WHERE id=$1")
                .bind(branch.id)
                .fetch_one(&mut observer)
                .await?;
        if expired {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    lock.commit().await?;
    let result = renewal.await?;
    assert!(
        result.is_err(),
        "renewal revived a branch after its lock wait crossed the deadline"
    );
    let (expired, version): (bool, i64) = sqlx::query_as(
        "SELECT expires_at<=clock_timestamp(),lease_version FROM branch WHERE id=$1",
    )
    .bind(branch.id)
    .fetch_one(&mut observer)
    .await?;
    assert!(expired);
    assert_eq!(version, 1);
    let renewed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_event WHERE branch_id=$1 AND event_type='branch_renewed'",
    )
    .bind(branch.id)
    .fetch_one(&mut observer)
    .await?;
    assert_eq!(renewed, 0);
    Ok(())
}

async fn refresh(metadata: &Metadata, snapshot: &str) -> Result<i64, MetaError> {
    let generation = metadata
        .allocate_refresh(RefreshGeneration {
            engine: "postgresql",
            snapshot,
            tables: &tables(),
            cooldown_seconds: 0,
        })
        .await?;
    metadata.claim_generation(generation.id).await?;
    metadata
        .switch_generation(generation.id, "postgresql")
        .await?;
    Ok(generation.id)
}

#[tokio::test]
#[ignore = "requires isolated FG_T10_LEASE_DSN; run serially"]
async fn retirement_is_durably_sealed_before_new_replay_pins()
-> Result<(), Box<dyn std::error::Error>> {
    let (metadata, _admin) = metadata().await?;
    let first = metadata
        .active_generation_id("postgresql")
        .await?
        .ok_or("generation missing")?;
    refresh(&metadata, "v2").await?;
    metadata.retirement_candidate(first, "postgresql").await?;
    metadata.complete_retirement(first).await?;
    let branch = metadata.fork(fork("original-case")).await?;
    let binding = metadata.resolve("alice", &branch.name).await?;
    let origin = binding.replay_origin.ok_or("replay origin missing")?;
    refresh(&metadata, "v3").await?;
    let mut request = fork("retained-replay");
    request.mode = BranchMode::NativeWrite;
    request.expected_generation = Some(&origin);
    let replay = metadata.fork(request).await?;
    assert_eq!(replay.generation_id, branch.generation_id);
    assert!(matches!(
        metadata
            .retirement_candidate(branch.generation_id, "postgresql")
            .await,
        Err(MetaError::GenerationPinned)
    ));
    for id in [branch.id, replay.id] {
        metadata.begin_drop("alice", id).await?;
        metadata.complete_drop(id).await?;
    }
    assert!(
        metadata
            .retirement_candidate(branch.generation_id, "postgresql")
            .await?
            .is_some()
    );
    let mut request = fork("unsafe-replay");
    request.mode = BranchMode::NativeWrite;
    request.expected_generation = Some(&origin);
    assert!(matches!(
        metadata.fork(request).await,
        Err(MetaError::ReplayMismatch)
    ));
    // Simulate a restart during partial physical removal: the marker remains.
    assert!(
        metadata
            .retirement_candidate(branch.generation_id, "postgresql")
            .await?
            .is_some()
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated FG_T10_LEASE_DSN; run serially"]
async fn github_recreation_uses_old_identity_and_fresh_observation()
-> Result<(), Box<dyn std::error::Error>> {
    let (metadata, _admin) = metadata().await?;
    metadata
        .enqueue_github(GitHubSignal {
            repository_id: 123,
            installation_id: 456,
            source_kind: "ref",
            source_key: "refs/heads/pilot",
            principal: "alice",
            name: Some("github-pilot"),
        })
        .await?;
    let source = metadata.next_github().await?.ok_or("source missing")?;
    metadata
        .reconcile_github(GitHubObservation {
            source: &source,
            engine: "postgresql",
            present: true,
            pr_write: false,
        })
        .await?;
    let binding = serde_json::to_value(metadata.github_bindings("alice").await?)?;
    let old = binding[0]["branch_id"].as_i64().ok_or("branch missing")?;
    metadata.begin_drop("alice", old).await?;
    metadata.complete_drop(old).await?;
    let bindings = serde_json::to_value(metadata.github_bindings("alice").await?)?;
    assert_eq!(bindings[0]["environment_state"], "expired");
    let request = GitHubRecreate {
        repository_id: 123,
        source_kind: "ref".into(),
        source_key: "refs/heads/pilot".into(),
        expected_branch_id: old,
    };
    assert!(metadata.recreate_github("bob", &request).await.is_err());
    metadata.recreate_github("alice", &request).await?;
    let source = metadata
        .next_github()
        .await?
        .ok_or("requeued source missing")?;
    metadata
        .reconcile_github(GitHubObservation {
            source: &source,
            engine: "postgresql",
            present: true,
            pr_write: false,
        })
        .await?;
    let bindings = serde_json::to_value(metadata.github_bindings("alice").await?)?;
    assert_ne!(bindings[0]["branch_id"], old);
    assert!(metadata.recreate_github("alice", &request).await.is_err());
    Ok(())
}
