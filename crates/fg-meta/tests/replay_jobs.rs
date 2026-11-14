//! Real PostgreSQL job-permit and quarantine invariants.
use fg_meta::{BranchMode, ForkBranch, Metadata, RefreshGeneration, SeedColumn, SeedTable};
use fg_protocol_common::{ArtifactHeader, ArtifactTable, BranchClass, GENERATED_ID_START};
use sqlx::{Connection, Executor, PgConnection};

#[tokio::test]
#[ignore = "requires isolated FG_T10_LEASE_DSN; run serially"]
async fn replay_jobs_are_exclusive_session_bound_and_never_reapply_unknown_commits()
-> Result<(), Box<dyn std::error::Error>> {
    let dsn = std::env::var("FG_T10_LEASE_DSN")?;
    let metadata = Metadata::connect(&dsn, None).await?;
    metadata.migrate().await?;
    let mut admin = PgConnection::connect(&dsn).await?;
    admin
        .execute("TRUNCATE generation,audit_event,github_source CASCADE")
        .await?;
    const ID: SeedColumn = SeedColumn {
        name: "id",
        type_name: "bigint",
        collation: None,
        nullable: false,
        primary_key_ordinal: Some(1),
    };
    let tables = vec![SeedTable {
        name: "records",
        columns: &[ID],
        generated_key: Some("id"),
        baseline_rows: 100,
    }];
    let first = metadata.allocate_generation("postgresql", &tables).await?;
    metadata.claim_generation(first.id).await?;
    metadata.activate_generation(first.id).await?;
    let generation = metadata
        .allocate_refresh(RefreshGeneration {
            engine: "postgresql",
            snapshot: "v2",
            tables: &tables,
            cooldown_seconds: 0,
        })
        .await?;
    metadata.claim_generation(generation.id).await?;
    metadata
        .switch_generation(generation.id, "postgresql")
        .await?;
    let source = metadata
        .fork(ForkBranch {
            engine: "postgresql",
            principal: "alice",
            name: "artifact-source",
            ttl_seconds: 3600,
            mode: BranchMode::ReadOnly,
            class: BranchClass::Dev,
            expected_generation: None,
        })
        .await?;
    let binding = metadata.resolve("alice", &source.name).await?;
    let header = ArtifactHeader {
        format_version: 2,
        engine: binding.engine,
        source_branch_id: source.id,
        origin: binding.replay_origin.ok_or("origin")?,
        native_write: false,
        manifest: binding.snapshot_manifest,
        tables: binding
            .tables
            .into_iter()
            .map(|table| ArtifactTable {
                id: table.id,
                schema: table.logical_schema,
                table: table.logical_table,
                generated_key: table.generated_key,
                columns: table.columns,
            })
            .collect(),
    };
    let mut invalid = header.clone();
    invalid.tables[0].id += 100;
    assert!(
        metadata
            .start_replay("alice", "invalid-target", &invalid)
            .await
            .is_err()
    );
    assert_eq!(
        metadata.list("alice").await?.len(),
        1,
        "preflight must precede branch creation"
    );
    let started = metadata
        .start_replay("alice", "private-target", &header)
        .await?;
    assert_eq!(started.branch.status, "provisioning");
    assert!(metadata.resolve("alice", "private-target").await.is_err());
    metadata.claim_branch(started.branch.id).await?;
    metadata.activate_branch(started.branch.id).await?;
    assert!(
        metadata
            .resolve_by_id("alice", started.branch.id)
            .await
            .is_err()
    );
    assert!(
        metadata
            .claim_replay("bob", started.job.id, 42, false)
            .await
            .is_err()
    );
    metadata
        .claim_replay("alice", started.job.id, 42, false)
        .await?;
    assert!(
        metadata
            .bind_replay_session("alice", started.job.id, 43, "writer")
            .await
            .is_err()
    );
    metadata
        .bind_replay_session("alice", started.job.id, 42, "writer")
        .await?;
    assert!(
        metadata
            .bind_replay_session("alice", started.job.id, 42, "other")
            .await
            .is_err()
    );
    metadata
        .validate_replay_session("alice", started.job.id, 42, "writer")
        .await?;
    assert!(
        metadata
            .validate_replay_session("alice", started.job.id, 43, "writer")
            .await
            .is_err()
    );
    assert!(
        metadata
            .advance_replay_ids(
                "alice",
                started.job.id,
                "wrong",
                header.tables[0].id,
                GENERATED_ID_START + 41
            )
            .await
            .is_err()
    );
    metadata
        .advance_replay_ids(
            "alice",
            started.job.id,
            "writer",
            header.tables[0].id,
            GENERATED_ID_START + 41,
        )
        .await?;
    let next: i64 =
        sqlx::query_scalar("SELECT next_id FROM generated_id_cursor WHERE branch_id=$1")
            .bind(started.branch.id)
            .fetch_one(&mut admin)
            .await?;
    assert_eq!(next, GENERATED_ID_START + 42);
    metadata.recover_replays_on_start().await?;
    assert!(
        metadata
            .validate_replay_session("alice", started.job.id, 42, "writer")
            .await
            .is_err()
    );
    assert!(
        metadata
            .claim_replay("alice", started.job.id, 44, false)
            .await
            .is_err(),
        "unknown commit must never reapply"
    );
    metadata
        .claim_replay("alice", started.job.id, 44, true)
        .await?;
    metadata
        .bind_replay_session("alice", started.job.id, 44, "observer")
        .await?;
    assert!(
        metadata
            .validate_replay_session("alice", started.job.id, 44, "observer")
            .await
            .is_err(),
        "verification cannot receive mutation rights"
    );
    assert!(metadata.resolve("alice", "private-target").await.is_err());
    metadata
        .finish_replay("alice", started.job.id, "verified", None)
        .await?;
    assert!(metadata.resolve("alice", "private-target").await.is_ok());
    assert_eq!(
        metadata
            .finish_replay("alice", started.job.id, "unknown", None)
            .await?
            .state,
        "verified"
    );
    assert!(
        metadata
            .replay_cleanup_jobs("postgresql")
            .await?
            .contains(&started.job.id)
    );
    Ok(())
}
