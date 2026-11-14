use super::*;
use fg_protocol_common::{
    BranchClass, DecisionRequest, DecisionVerdict, MongoWriteObservation, Policy, WriteKind,
    WriteOperation,
};
use sqlx::{PgPool, postgres::PgConnectOptions};
use std::time::Duration;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const ENGINE: &str = "postgresql";

struct Fixture {
    metadata: Metadata,
    pool: PgPool,
    branch: i64,
    table: i64,
    generation: i64,
    policy: Policy,
    engine: &'static str,
}

enum FixturePolicySource {
    CurrentBranch,
    PreAuditClass,
}

impl Fixture {
    async fn new(pool: PgPool, engine: &'static str) -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_policy_source(pool, engine, FixturePolicySource::CurrentBranch).await
    }

    async fn with_policy_source(
        pool: PgPool,
        engine: &'static str,
        policy_source: FixturePolicySource,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let metadata = Metadata {
            pool: pool.clone(),
            options: PgConnectOptions::new(),
        };
        let generation:i64=sqlx::query_scalar("INSERT INTO generation(engine,status,native_claimed,activated_at,snapshot) VALUES($1,'active',TRUE,clock_timestamp(),'v2') RETURNING id")
            .bind(engine).fetch_one(&pool).await?;
        let table:i64=sqlx::query_scalar("INSERT INTO catalog_table(generation_id,logical_schema,logical_table,base_table,baseline_rows) VALUES($1,'app','orders','orders',100) RETURNING id")
            .bind(generation).fetch_one(&pool).await?;
        let branch:i64=sqlx::query_scalar("INSERT INTO branch(name,class,generation_id,created_by,expires_at,status,mode,native_claimed,access,layout,read_strategy)
            VALUES('audit-test','dev',$1,'alice',clock_timestamp()+INTERVAL '2 hours','active','native_write',TRUE,'read_write','native_copy','merge') RETURNING id")
            .bind(generation).fetch_one(&pool).await?;
        metadata.register_proxy_epoch(&"a".repeat(32)).await?;
        let policy = match policy_source {
            FixturePolicySource::CurrentBranch => {
                metadata.policy_for_branch(engine, branch, "alice").await?
            }
            // The migration fixture has no grants and deliberately has no
            // audit columns yet. Current-schema APIs run only after migration.
            FixturePolicySource::PreAuditClass => metadata.policy(BranchClass::Dev).await?,
        };
        Ok(Self {
            metadata,
            pool,
            branch,
            table,
            generation,
            policy,
            engine,
        })
    }

    fn context(&self, ordinal: u64) -> AuditAttemptContext {
        let session_id = format!("{}:1", "a".repeat(32));
        AuditAttemptContext {
            attempt_id: format!("{session_id}:{ordinal}"),
            principal: "alice".into(),
            session_id,
            native_session_id: 77,
            generation_id: self.generation,
            replay_job_id: None,
            mode: if self.engine == "mongodb" {
                AuditMode::MongoCommand
            } else {
                AuditMode::SqlTransaction
            },
        }
    }

    fn decision(&self, ordinal: u64) -> AuditedDecisionRequest {
        AuditedDecisionRequest {
            attempt: self.context(ordinal),
            decision: DecisionRequest {
                principal: "alice".into(),
                session_id: self.context(ordinal).session_id,
                policy_version: self.policy.version,
                effective_revision: self.policy.effective_revision,
                operation: WriteOperation {
                    table_id: self.table,
                    kind: WriteKind::Insert,
                },
                rows: 1,
                verdict: DecisionVerdict::Allowed,
            },
        }
    }

    async fn prepare(&self) -> Result<NativeWitnessBinding, MetaError> {
        let binding = self
            .metadata
            .plan_audit_witness(self.engine, self.branch, &"b".repeat(32))
            .await?;
        self.metadata
            .mark_audit_witness_ready(self.engine, &binding)
            .await?;
        Ok(binding)
    }

    async fn admit(&self, ordinal: u64) -> Result<AuditedDecisionResponse, MetaError> {
        self.metadata
            .record_audited_decision(self.engine, self.branch, self.decision(ordinal))
            .await
    }

    fn outcome(&self, ordinal: u64, outcome: TransactionOutcome) -> AuditedOutcomeRequest {
        AuditedOutcomeRequest {
            attempt: self.context(ordinal),
            outcome,
            armed_step: 0,
            mongo: None,
        }
    }

    fn fence(&self, binding: NativeWitnessBinding) -> WriteFenceRequest {
        WriteFenceRequest {
            attempt: self.context(1),
            policy_version: self.policy.version,
            effective_revision: self.policy.effective_revision,
            witness: Some(binding),
        }
    }
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires DATABASE_URL for an isolated metadata PostgreSQL"]
async fn decisions_are_atomic_and_late_outcomes_have_exact_ack(pool: PgPool) -> TestResult {
    let fixture = Fixture::new(pool, ENGINE).await?;
    assert!(matches!(
        fixture.admit(1).await,
        Err(MetaError::AuditPending)
    ));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_attempt")
        .fetch_one(&fixture.pool)
        .await?;
    assert_eq!(count, 0);
    let binding = fixture.prepare().await?;
    assert_eq!(fixture.admit(1).await?.witness, Some(binding));
    let counts:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM audit_attempt),(SELECT count(*) FROM audit_event WHERE event_type='policy_decision')")
        .fetch_one(&fixture.pool).await?;
    assert_eq!(counts, (1, 1));
    let status = fixture
        .metadata
        .branch_status(ENGINE, fixture.branch, "alice")
        .await?;
    assert_eq!(status["audit"]["witness_ready"], true);
    assert_eq!(status["audit"]["pending_delivery"], 1);
    assert!(status["audit"]["oldest_pending_at"].is_i64());
    assert!(matches!(
        fixture
            .metadata
            .branch_status(ENGINE, fixture.branch, "bob")
            .await,
        Err(MetaError::BranchUnavailable)
    ));
    fixture
        .metadata
        .register_proxy_epoch(&"c".repeat(32))
        .await?;
    let request = fixture.outcome(1, TransactionOutcome::Committed);
    let ack = fixture
        .metadata
        .record_audited_outcome(ENGINE, fixture.branch, request.clone())
        .await?;
    assert_eq!(
        fixture
            .metadata
            .record_audited_outcome(ENGINE, fixture.branch, request)
            .await?,
        ack
    );
    assert!(matches!(
        fixture
            .metadata
            .record_audited_outcome(
                ENGINE,
                fixture.branch,
                fixture.outcome(1, TransactionOutcome::RolledBack)
            )
            .await,
        Err(MetaError::AuditConflict)
    ));
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_event WHERE event_type='policy_outcome'")
            .fetch_one(&fixture.pool)
            .await?;
    assert_eq!(count, 1);
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires DATABASE_URL for an isolated metadata PostgreSQL"]
async fn current_epoch_orphans_are_listed_without_sealing_live_attempts(
    pool: PgPool,
) -> TestResult {
    let fixture = Fixture::new(pool, ENGINE).await?;
    fixture.prepare().await?;
    fixture.admit(1).await?;
    let pending = fixture.metadata.pending_audit_attempts(ENGINE).await?;
    assert_eq!(pending.len(), 1);
    assert!(pending[0].is_current_epoch);
    assert!(!pending[0].sealed);
    assert_eq!(pending[0].context, fixture.context(1));
    fixture
        .metadata
        .note_audit_recovery_deferred(ENGINE, &fixture.context(1).attempt_id)
        .await?;
    fixture.admit(1).await?;
    let sealed: bool = sqlx::query_scalar("SELECT sealed FROM audit_attempt WHERE attempt_id=$1")
        .bind(fixture.context(1).attempt_id)
        .fetch_one(&fixture.pool)
        .await?;
    assert!(!sealed);
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires DATABASE_URL for an isolated metadata PostgreSQL"]
async fn recovery_events_lock_branch_before_attempt_even_after_expiry(pool: PgPool) -> TestResult {
    let fixture = Fixture::new(pool, ENGINE).await?;
    fixture.prepare().await?;
    fixture.admit(1).await?;
    let id = fixture.context(1).attempt_id;
    fixture
        .metadata
        .record_audited_outcome(
            ENGINE,
            fixture.branch,
            fixture.outcome(1, TransactionOutcome::Unknown),
        )
        .await?;
    fixture.metadata.seal_audit_attempt(ENGINE, &id).await?;
    fixture
        .metadata
        .resolve_audit_attempt(ENGINE, &id, AuditRecoveryEvidence::Unknown)
        .await?;
    sqlx::query("UPDATE branch SET created_at=clock_timestamp()-INTERVAL '2 hours',expires_at=clock_timestamp()-INTERVAL '1 second' WHERE id=$1")
        .bind(fixture.branch).execute(&fixture.pool).await?;
    for acknowledge in [false, true] {
        let mut blocker = fixture.pool.begin().await?;
        sqlx::query("SELECT id FROM branch WHERE id=$1 FOR UPDATE")
            .bind(fixture.branch)
            .execute(&mut *blocker)
            .await?;
        let metadata = fixture.metadata.clone();
        let attempt = id.clone();
        let waiter = tokio::spawn(async move {
            if acknowledge {
                metadata
                    .acknowledge_audit_unknown(ENGINE, &attempt, "operator")
                    .await
            } else {
                metadata
                    .resolve_audit_attempt(ENGINE, &attempt, AuditRecoveryEvidence::Unknown)
                    .await
                    .map(|_| ())
            }
        });
        wait_for_lock(&fixture.pool).await?;
        sqlx::query("SELECT attempt_id FROM audit_attempt WHERE attempt_id=$1 FOR UPDATE NOWAIT")
            .bind(&id)
            .execute(&mut *blocker)
            .await?;
        blocker.commit().await?;
        waiter.await??;
    }
    assert!(
        fixture
            .metadata
            .audit_cleanup_ready(ENGINE, fixture.branch)
            .await?
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires DATABASE_URL for an isolated metadata PostgreSQL"]
async fn unknown_is_immutable_and_resolution_is_unique(pool: PgPool) -> TestResult {
    let fixture = Fixture::new(pool, ENGINE).await?;
    let binding = fixture.prepare().await?;
    fixture.admit(1).await?;
    let request = fixture.outcome(1, TransactionOutcome::Unknown);
    let original = fixture
        .metadata
        .record_audited_outcome(ENGINE, fixture.branch, request.clone())
        .await?;
    assert!(
        !fixture
            .metadata
            .audit_cleanup_ready(ENGINE, fixture.branch)
            .await?
    );
    let current = fixture.metadata.pending_audit_attempts(ENGINE).await?;
    assert_eq!(current.len(), 1);
    assert!(current[0].is_current_epoch);
    assert_pending_index(&fixture.pool).await?;
    fixture
        .metadata
        .register_proxy_epoch(&"c".repeat(32))
        .await?;
    assert!(!fixture.metadata.pending_audit_attempts(ENGINE).await?[0].is_current_epoch);
    fixture
        .metadata
        .seal_audit_attempt(ENGINE, &request.attempt.attempt_id)
        .await?;
    let mut wrong = binding.clone();
    wrong.storage_incarnation = "d".repeat(32);
    assert!(matches!(
        fixture
            .metadata
            .resolve_audit_attempt(
                ENGINE,
                &request.attempt.attempt_id,
                AuditRecoveryEvidence::SqlCommitted(wrong)
            )
            .await,
        Err(MetaError::AuditConflict)
    ));
    let resolved = fixture
        .metadata
        .resolve_audit_attempt(
            ENGINE,
            &request.attempt.attempt_id,
            AuditRecoveryEvidence::SqlCommitted(binding.clone()),
        )
        .await?;
    assert_eq!(resolved.outcome, TransactionOutcome::Committed);
    let status = fixture
        .metadata
        .audit_attempt_status(ENGINE, fixture.branch, &request.attempt)
        .await?;
    assert_eq!(status.ack, Some(original.clone()));
    assert_eq!(status.resolution, Some(resolved.clone()));
    assert!(status.resolved);
    assert_eq!(
        fixture
            .metadata
            .resolve_audit_attempt(
                ENGINE,
                &request.attempt.attempt_id,
                AuditRecoveryEvidence::SqlCommitted(binding)
            )
            .await?,
        resolved
    );
    assert_eq!(
        fixture
            .metadata
            .record_audited_outcome(ENGINE, fixture.branch, request.clone())
            .await?,
        original
    );
    assert!(
        fixture
            .metadata
            .audit_cleanup_ready(ENGINE, fixture.branch)
            .await?
    );
    let status = fixture
        .metadata
        .branch_status(ENGINE, fixture.branch, "alice")
        .await?;
    assert_eq!(status["audit"]["sql_unresolved_unknown"], 0);
    assert_eq!(status["audit"]["cleanup_blocked"], false);
    assert_collection_index(&fixture.pool, fixture.branch).await?;
    assert_eq!(
        fixture
            .metadata
            .completed_sql_audit_attempts(ENGINE, fixture.branch, 10)
            .await?,
        vec![request.attempt.attempt_id.clone()]
    );
    fixture
        .metadata
        .mark_witness_collected(ENGINE, &[request.attempt.attempt_id])
        .await?;
    assert!(
        fixture
            .metadata
            .completed_sql_audit_attempts(ENGINE, fixture.branch, 10)
            .await?
            .is_empty()
    );
    let counts:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM audit_event WHERE event_type='policy_outcome'),(SELECT count(*) FROM audit_event WHERE event_type='policy_outcome_resolved')")
        .fetch_one(&fixture.pool).await?;
    assert_eq!(counts, (1, 1));
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires DATABASE_URL for an isolated metadata PostgreSQL"]
async fn rollback_tombstone_closes_lost_first_decision(pool: PgPool) -> TestResult {
    let fixture = Fixture::new(pool, ENGINE).await?;
    fixture.prepare().await?;
    let request = fixture.outcome(1, TransactionOutcome::RolledBack);
    let ack = fixture
        .metadata
        .record_audited_outcome(ENGINE, fixture.branch, request.clone())
        .await?;
    assert_eq!(
        fixture
            .metadata
            .record_audited_outcome(ENGINE, fixture.branch, request)
            .await?,
        ack
    );
    assert!(matches!(
        fixture.admit(1).await,
        Err(MetaError::AuditConflict)
    ));
    let decisions: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_event WHERE event_type='policy_decision'")
            .fetch_one(&fixture.pool)
            .await?;
    assert_eq!(decisions, 0);
    assert!(
        fixture
            .metadata
            .audit_cleanup_ready(ENGINE, fixture.branch)
            .await?
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires DATABASE_URL for an isolated metadata PostgreSQL"]
async fn existing_outcomes_share_the_branch_while_gc_waits(pool: PgPool) -> TestResult {
    let fixture = Fixture::new(pool, ENGINE).await?;
    fixture.prepare().await?;
    fixture.admit(1).await?;
    fixture.admit(2).await?;
    sqlx::query("UPDATE branch SET status='dropping' WHERE id=$1")
        .bind(fixture.branch)
        .execute(&fixture.pool)
        .await?;
    let mut blocker = fixture.pool.begin().await?;
    sqlx::query("SELECT attempt_id FROM audit_attempt WHERE attempt_id=$1 FOR UPDATE")
        .bind(fixture.context(1).attempt_id)
        .execute(&mut *blocker)
        .await?;
    let metadata = fixture.metadata.clone();
    let branch = fixture.branch;
    let first = fixture.outcome(1, TransactionOutcome::Committed);
    let waiter =
        tokio::spawn(async move { metadata.record_audited_outcome(ENGINE, branch, first).await });
    wait_for_query_lock(
        &fixture.pool,
        "%FROM audit_attempt WHERE attempt_id=%FOR UPDATE%",
    )
    .await?;
    let second = tokio::time::timeout(
        Duration::from_secs(5),
        fixture.metadata.record_audited_outcome(
            ENGINE,
            fixture.branch,
            fixture.outcome(2, TransactionOutcome::RolledBack),
        ),
    )
    .await??;
    assert_eq!(second.outcome, TransactionOutcome::RolledBack);
    assert!(!waiter.is_finished());
    let metadata = fixture.metadata.clone();
    let reclaim =
        tokio::spawn(async move { metadata.begin_audit_storage_reclaim(ENGINE, branch).await });
    wait_for_query_lock(&fixture.pool, "%FROM branch WHERE id=%FOR UPDATE%").await?;
    assert!(!reclaim.is_finished());
    blocker.rollback().await?;
    assert_eq!(waiter.await??.outcome, TransactionOutcome::Committed);
    reclaim.await??;
    fixture.metadata.complete_drop(fixture.branch).await?;
    let status: String = sqlx::query_scalar("SELECT status FROM branch WHERE id=$1")
        .bind(fixture.branch)
        .fetch_one(&fixture.pool)
        .await?;
    assert_eq!(status, "dropped");
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires DATABASE_URL for an isolated metadata PostgreSQL"]
async fn missing_outcome_waits_for_an_uncommitted_first_decision(pool: PgPool) -> TestResult {
    let fixture = Fixture::new(pool, ENGINE).await?;
    fixture.prepare().await?;
    sqlx::raw_sql(
        "CREATE FUNCTION hold_first_decision() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.event_type='policy_decision' THEN
            PERFORM pg_advisory_xact_lock(9271201); END IF; RETURN NEW; END $$;
        CREATE TRIGGER hold_first_decision BEFORE INSERT ON audit_event
        FOR EACH ROW EXECUTE FUNCTION hold_first_decision();",
    )
    .execute(&fixture.pool)
    .await?;
    let mut blocker = fixture.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(9271201)")
        .execute(&mut *blocker)
        .await?;
    let metadata = fixture.metadata.clone();
    let branch = fixture.branch;
    let decision = fixture.decision(1);
    let first = tokio::spawn(async move {
        metadata
            .record_audited_decision(ENGINE, branch, decision)
            .await
    });
    wait_for_query_lock(&fixture.pool, "%INSERT INTO audit_event%policy_decision%").await?;
    let metadata = fixture.metadata.clone();
    let request = fixture.outcome(1, TransactionOutcome::RolledBack);
    let outcome = tokio::spawn(async move {
        metadata
            .record_audited_outcome(ENGINE, branch, request)
            .await
    });
    wait_for_query_lock(&fixture.pool, "%FROM branch WHERE id=%FOR UPDATE%").await?;
    blocker.rollback().await?;
    first.await??;
    outcome.await??;
    let counts: (i64,i64) = sqlx::query_as("SELECT
        (SELECT count(*) FROM audit_event WHERE event_type='policy_decision'),
        (SELECT count(*) FROM audit_event WHERE event_type='policy_outcome' AND payload->>'admitted'='false')")
        .fetch_one(&fixture.pool).await?;
    assert_eq!(counts, (1, 0));
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires DATABASE_URL for an isolated metadata PostgreSQL"]
async fn missing_outcome_tombstone_serializes_before_queued_admission(pool: PgPool) -> TestResult {
    let fixture = Fixture::new(pool, ENGINE).await?;
    fixture.prepare().await?;
    let mut blocker = fixture.pool.begin().await?;
    sqlx::query("SELECT id FROM branch WHERE id=$1 FOR UPDATE")
        .bind(fixture.branch)
        .execute(&mut *blocker)
        .await?;
    let metadata = fixture.metadata.clone();
    let branch = fixture.branch;
    let request = fixture.outcome(1, TransactionOutcome::RolledBack);
    let outcome = tokio::spawn(async move {
        metadata
            .record_audited_outcome(ENGINE, branch, request)
            .await
    });
    wait_for_query_lock(&fixture.pool, "%FROM branch WHERE id=%FOR UPDATE%").await?;
    let metadata = fixture.metadata.clone();
    let decision = fixture.decision(1);
    let admission = tokio::spawn(async move {
        metadata
            .record_audited_decision(ENGINE, branch, decision)
            .await
    });
    wait_for_lock(&fixture.pool).await?;
    blocker.rollback().await?;
    outcome.await??;
    assert!(matches!(admission.await?, Err(MetaError::AuditConflict)));
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_event WHERE event_type='policy_decision'")
            .fetch_one(&fixture.pool)
            .await?;
    assert_eq!(count, 0);
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires DATABASE_URL for an isolated metadata PostgreSQL"]
async fn authority_preserves_custom_grants_observers_and_table_scope(pool: PgPool) -> TestResult {
    let mut fixture = Fixture::new(pool, ENGINE).await?;
    let binding = fixture.prepare().await?;
    fixture.policy = fixture
        .metadata
        .update_policy(
            "reviewer",
            BranchClass::Dev,
            fg_protocol_common::UpdatePolicy {
                expected_version: fixture.policy.version,
                max_transaction_rows: 100000,
                table_limit_bps: Some(1200),
                approval_after_rows: Some(50),
                small_table_floor: Some(7),
            },
        )
        .await?;
    let request = fixture
        .metadata
        .request_budget(
            ENGINE,
            fixture.branch,
            "alice",
            fg_protocol_common::CreateBudgetRequest {
                max_transaction_rows: 200000,
                table_limit_bps: None,
                small_table_floor: 13,
                ttl_seconds: 60,
                reason: "Run the scoped fixture".into(),
            },
        )
        .await?;
    fixture
        .metadata
        .review_budget(
            ENGINE,
            fixture.branch,
            request.id,
            crate::BudgetReview {
                actor: "reviewer",
                owners: &["alice".into()],
                approve: true,
            },
        )
        .await?;
    fixture.policy = fixture
        .metadata
        .policy_for_branch(ENGINE, fixture.branch, "alice")
        .await?;
    assert_eq!(fixture.policy.max_transaction_rows, 200000);
    assert_eq!(fixture.policy.table_limit_bps, None);
    assert_eq!(fixture.policy.small_table_floor, 13);
    assert_eq!(fixture.policy.approval_after_rows, Some(50));
    let expected: i64 = sqlx::query_scalar("SELECT forkget_budget_revision($1)")
        .bind(fixture.branch)
        .fetch_one(&fixture.pool)
        .await?;
    assert_eq!(fixture.policy.effective_revision, expected);
    fixture.admit(1).await?;
    let grants = fixture
        .metadata
        .budget_grants(ENGINE, fixture.branch, "alice", &[])
        .await?;
    fixture
        .metadata
        .revoke_budget(ENGINE, fixture.branch, grants[0].id, "alice", &[])
        .await?;
    assert!(matches!(
        fixture
            .metadata
            .write_fence(ENGINE, fixture.branch, fixture.fence(binding))
            .await,
        Err(MetaError::PolicyConflict)
    ));
    fixture.policy = fixture
        .metadata
        .policy_for_branch(ENGINE, fixture.branch, "alice")
        .await?;
    assert_eq!(fixture.policy.max_transaction_rows, 100000);
    assert_eq!(fixture.policy.table_limit_bps, Some(1200));
    assert_eq!(fixture.policy.small_table_floor, 7);
    let readonly: i64 = sqlx::query_scalar(
        "INSERT INTO branch(name,class,generation_id,created_by,expires_at,status,mode,
            native_claimed,access,layout,read_strategy,capture_active)
         VALUES('audit-read-observer','dev',$1,'alice',clock_timestamp()+INTERVAL '2 hours',
            'active','native_write',TRUE,'read_only','native_copy','merge',TRUE) RETURNING id",
    )
    .bind(fixture.generation)
    .fetch_one(&fixture.pool)
    .await?;
    sqlx::query("UPDATE generation SET reclaim_started_at=clock_timestamp() WHERE id=$1")
        .bind(fixture.generation)
        .execute(&fixture.pool)
        .await?;
    let observer = fixture
        .metadata
        .policy_for_branch(ENGINE, readonly, "alice")
        .await?;
    assert_eq!(observer.max_transaction_rows, 100000);
    assert!(matches!(
        fixture
            .metadata
            .record_audited_decision(ENGINE, readonly, fixture.decision(2))
            .await,
        Err(MetaError::BranchUnavailable)
    ));
    sqlx::query("UPDATE generation SET reclaim_started_at=NULL WHERE id=$1")
        .bind(fixture.generation)
        .execute(&fixture.pool)
        .await?;
    let mut wrong_table = fixture.decision(2);
    wrong_table.decision.operation.table_id += 1000;
    assert!(matches!(
        fixture
            .metadata
            .record_audited_decision(ENGINE, fixture.branch, wrong_table)
            .await,
        Err(MetaError::BranchUnavailable)
    ));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_attempt")
        .fetch_one(&fixture.pool)
        .await?;
    assert_eq!(count, 1);
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires DATABASE_URL for an isolated metadata PostgreSQL"]
async fn authority_samples_deadline_after_the_attempt_lock_wait(pool: PgPool) -> TestResult {
    let fixture = Fixture::new(pool, ENGINE).await?;
    let binding = fixture.prepare().await?;
    fixture.admit(1).await?;
    sqlx::query(
        "UPDATE branch SET expires_at=clock_timestamp()+INTERVAL '400 milliseconds' WHERE id=$1",
    )
    .bind(fixture.branch)
    .execute(&fixture.pool)
    .await?;
    let mut blocker = fixture.pool.begin().await?;
    sqlx::query("SELECT attempt_id FROM audit_attempt WHERE attempt_id=$1 FOR UPDATE")
        .bind(fixture.context(1).attempt_id)
        .execute(&mut *blocker)
        .await?;
    let metadata = fixture.metadata.clone();
    let branch = fixture.branch;
    let request = fixture.fence(binding);
    let waiter = tokio::spawn(async move { metadata.write_fence(ENGINE, branch, request).await });
    wait_for_query_lock(
        &fixture.pool,
        "%FROM audit_attempt WHERE attempt_id=%FOR UPDATE%",
    )
    .await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    blocker.rollback().await?;
    assert!(matches!(waiter.await?, Err(MetaError::BranchUnavailable)));
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires DATABASE_URL for an isolated metadata PostgreSQL"]
async fn native_error_observation_keeps_prior_admission_but_limit_does_not(
    pool: PgPool,
) -> TestResult {
    let fixture = Fixture::new(pool, ENGINE).await?;
    let binding = fixture.prepare().await?;
    fixture.admit(1).await?;
    let mut error = fixture.decision(1);
    error.decision.verdict = DecisionVerdict::NativeError;
    error.decision.rows = 0;
    fixture
        .metadata
        .record_audited_decision(ENGINE, fixture.branch, error)
        .await?;
    fixture
        .metadata
        .write_fence(ENGINE, fixture.branch, fixture.fence(binding.clone()))
        .await?;
    let mut limit = fixture.decision(1);
    limit.decision.verdict = DecisionVerdict::Limit;
    limit.decision.rows = fixture.policy.max_transaction_rows + 1;
    fixture
        .metadata
        .record_audited_decision(ENGINE, fixture.branch, limit)
        .await?;
    assert!(matches!(
        fixture
            .metadata
            .write_fence(ENGINE, fixture.branch, fixture.fence(binding))
            .await,
        Err(MetaError::PolicyConflict)
    ));
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires DATABASE_URL for an isolated metadata PostgreSQL"]
async fn only_never_admitted_provisioning_storage_can_reset_readiness(pool: PgPool) -> TestResult {
    let fixture = Fixture::new(pool, ENGINE).await?;
    let binding = fixture.prepare().await?;
    assert!(
        fixture
            .metadata
            .plan_audit_witness_replacement(ENGINE, fixture.branch, &"c".repeat(32))
            .await
            .is_err()
    );
    assert!(
        fixture
            .metadata
            .mark_audit_witness_replacement_ready_by(ENGINE, &binding, "operator")
            .await
            .is_err()
    );
    assert!(
        !fixture
            .metadata
            .reset_provisioning_audit_witness(ENGINE, fixture.branch)
            .await?
    );
    sqlx::query("UPDATE branch SET status='provisioning' WHERE id=$1")
        .bind(fixture.branch)
        .execute(&fixture.pool)
        .await?;
    assert!(
        fixture
            .metadata
            .reset_provisioning_audit_witness(ENGINE, fixture.branch)
            .await?
    );
    let (ready, incarnation): (bool, String) = sqlx::query_as(
        "SELECT audit_witness_ready,audit_witness_incarnation FROM branch WHERE id=$1",
    )
    .bind(fixture.branch)
    .fetch_one(&fixture.pool)
    .await?;
    assert!(!ready);
    assert_eq!(incarnation, binding.storage_incarnation);
    fixture
        .metadata
        .mark_audit_witness_ready(ENGINE, &binding)
        .await?;
    sqlx::query("UPDATE branch SET status='active' WHERE id=$1")
        .bind(fixture.branch)
        .execute(&fixture.pool)
        .await?;
    fixture.admit(1).await?;
    sqlx::query("UPDATE branch SET status='provisioning' WHERE id=$1")
        .bind(fixture.branch)
        .execute(&fixture.pool)
        .await?;
    assert!(
        !fixture
            .metadata
            .reset_provisioning_audit_witness(ENGINE, fixture.branch)
            .await?
    );
    assert_eq!(
        fixture
            .metadata
            .audit_witness_binding(ENGINE, fixture.branch)
            .await?,
        Some(binding)
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires DATABASE_URL for an isolated metadata PostgreSQL"]
async fn cleanup_and_retirement_keep_unresolved_native_evidence(pool: PgPool) -> TestResult {
    let fixture = Fixture::new(pool, ENGINE).await?;
    let binding = fixture.prepare().await?;
    fixture.admit(1).await?;
    fixture.metadata.begin_drop("alice", fixture.branch).await?;
    assert!(matches!(
        fixture.metadata.complete_drop(fixture.branch).await,
        Err(MetaError::AuditPending)
    ));
    sqlx::query("UPDATE generation SET status='retiring' WHERE id=$1")
        .bind(fixture.generation)
        .execute(&fixture.pool)
        .await?;
    assert!(matches!(
        fixture
            .metadata
            .retirement_candidate(fixture.generation, ENGINE)
            .await,
        Err(MetaError::GenerationPinned)
    ));
    let id = fixture.context(1).attempt_id;
    fixture.metadata.seal_audit_attempt(ENGINE, &id).await?;
    fixture
        .metadata
        .resolve_audit_attempt(ENGINE, &id, AuditRecoveryEvidence::SqlRolledBack(binding))
        .await?;
    fixture.metadata.complete_drop(fixture.branch).await?;
    assert!(
        fixture
            .metadata
            .retirement_candidate(fixture.generation, ENGINE)
            .await?
            .is_some()
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires DATABASE_URL for an isolated metadata PostgreSQL"]
async fn reclaim_requires_durable_facts_and_can_resume_after_native_removal(
    pool: PgPool,
) -> TestResult {
    let fixture = Fixture::new(pool, ENGINE).await?;
    let binding = fixture.prepare().await?;
    assert!(matches!(
        fixture
            .metadata
            .begin_audit_storage_reclaim(ENGINE, fixture.branch)
            .await,
        Err(MetaError::BranchUnavailable)
    ));
    sqlx::query("UPDATE branch SET status='provisioning' WHERE id=$1")
        .bind(fixture.branch)
        .execute(&fixture.pool)
        .await?;
    assert!(matches!(
        fixture
            .metadata
            .begin_audit_storage_reclaim(ENGINE, fixture.branch)
            .await,
        Err(MetaError::BranchUnavailable)
    ));
    sqlx::query("UPDATE branch SET status='active' WHERE id=$1")
        .bind(fixture.branch)
        .execute(&fixture.pool)
        .await?;
    fixture.admit(1).await?;
    fixture.metadata.begin_drop("alice", fixture.branch).await?;
    assert!(matches!(
        fixture
            .metadata
            .begin_audit_storage_reclaim(ENGINE, fixture.branch)
            .await,
        Err(MetaError::AuditPending)
    ));
    assert_eq!(
        fixture
            .metadata
            .audit_witness_binding(ENGINE, fixture.branch)
            .await?,
        Some(binding.clone())
    );
    fixture
        .metadata
        .record_audited_outcome(
            ENGINE,
            fixture.branch,
            fixture.outcome(1, TransactionOutcome::Committed),
        )
        .await?;
    fixture
        .metadata
        .begin_audit_storage_reclaim(ENGINE, fixture.branch)
        .await?;
    fixture
        .metadata
        .begin_audit_storage_reclaim(ENGINE, fixture.branch)
        .await?;
    let status = fixture
        .metadata
        .branch_status(ENGINE, fixture.branch, "alice")
        .await?;
    assert_eq!(status["audit"]["storage_reclaim_started"], true);
    assert_eq!(status["audit"]["witness_ready"], false);
    assert_eq!(status["audit"]["requires_witness"], false);
    assert!(
        fixture
            .metadata
            .audit_witness_binding(ENGINE, fixture.branch)
            .await?
            .is_none()
    );
    let catalog = fixture.metadata.native_catalog(ENGINE).await?;
    assert!(
        !catalog
            .branches
            .iter()
            .find(|branch| branch.target.branch_id() == fixture.branch)
            .ok_or("missing dropping branch")?
            .audit_witness_ready
    );
    assert_eq!(
        fixture
            .metadata
            .completed_sql_audit_attempts(ENGINE, fixture.branch, 256)
            .await?,
        vec![fixture.context(1).attempt_id]
    );
    assert!(
        fixture
            .metadata
            .mark_audit_witness_ready(ENGINE, &binding)
            .await
            .is_err()
    );
    assert!(
        fixture
            .metadata
            .plan_audit_witness(ENGINE, fixture.branch, &"c".repeat(32))
            .await
            .is_err()
    );
    assert!(
        !fixture
            .metadata
            .audit_storage_replacement_allowed(ENGINE, fixture.branch)
            .await?
    );
    assert!(
        fixture
            .metadata
            .invalidate_audit_storage(ENGINE, fixture.branch, "operator")
            .await
            .is_err()
    );
    assert!(matches!(
        fixture
            .metadata
            .resolve_audit_attempt(
                ENGINE,
                &fixture.context(1).attempt_id,
                AuditRecoveryEvidence::SqlCommitted(binding)
            )
            .await,
        Err(MetaError::AuditConflict)
    ));
    fixture.metadata.complete_drop(fixture.branch).await?;
    assert_eq!(
        fixture
            .metadata
            .detail("alice", fixture.branch)
            .await?
            .status,
        "dropped"
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires DATABASE_URL for an isolated metadata PostgreSQL"]
async fn fence_rechecks_deadline_after_branch_lock_wait(pool: PgPool) -> TestResult {
    let fixture = Fixture::new(pool, ENGINE).await?;
    let binding = fixture.prepare().await?;
    fixture.admit(1).await?;
    sqlx::query(
        "UPDATE branch SET expires_at=clock_timestamp()+INTERVAL '400 milliseconds' WHERE id=$1",
    )
    .bind(fixture.branch)
    .execute(&fixture.pool)
    .await?;
    let mut blocker = fixture.pool.begin().await?;
    sqlx::query("SELECT id FROM branch WHERE id=$1 FOR UPDATE")
        .bind(fixture.branch)
        .execute(&mut *blocker)
        .await?;
    let metadata = fixture.metadata.clone();
    let branch = fixture.branch;
    let fence = fixture.fence(binding);
    let waiter = tokio::spawn(async move { metadata.write_fence(ENGINE, branch, fence).await });
    wait_for_lock(&fixture.pool).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    blocker.commit().await?;
    assert!(matches!(waiter.await?, Err(MetaError::BranchUnavailable)));
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires DATABASE_URL for an isolated metadata PostgreSQL"]
async fn fence_rechecks_grant_after_lock_wait_and_policy_change(pool: PgPool) -> TestResult {
    let mut fixture = Fixture::new(pool, ENGINE).await?;
    let binding = fixture.prepare().await?;
    let request = fixture
        .metadata
        .request_budget(
            ENGINE,
            fixture.branch,
            "alice",
            fg_protocol_common::CreateBudgetRequest {
                max_transaction_rows: 100000,
                table_limit_bps: Some(10000),
                small_table_floor: 10,
                ttl_seconds: 900,
                reason: "Run a bounded fixture".into(),
            },
        )
        .await?;
    fixture
        .metadata
        .review_budget(
            ENGINE,
            fixture.branch,
            request.id,
            crate::BudgetReview {
                actor: "reviewer",
                owners: &["alice".into()],
                approve: true,
            },
        )
        .await?;
    fixture.policy = fixture
        .metadata
        .policy_for_branch(ENGINE, fixture.branch, "alice")
        .await?;
    fixture.admit(1).await?;
    sqlx::query("UPDATE budget_grant SET expires_at=clock_timestamp()+INTERVAL '400 milliseconds' WHERE branch_id=$1")
        .bind(fixture.branch).execute(&fixture.pool).await?;
    let mut blocker = fixture.pool.begin().await?;
    sqlx::query("SELECT id FROM branch WHERE id=$1 FOR UPDATE")
        .bind(fixture.branch)
        .execute(&mut *blocker)
        .await?;
    let metadata = fixture.metadata.clone();
    let branch = fixture.branch;
    let fence = fixture.fence(binding.clone());
    let waiter = tokio::spawn(async move { metadata.write_fence(ENGINE, branch, fence).await });
    wait_for_lock(&fixture.pool).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    blocker.commit().await?;
    assert!(matches!(waiter.await?, Err(MetaError::PolicyConflict)));
    fixture
        .metadata
        .update_policy(
            "reviewer",
            BranchClass::Dev,
            fg_protocol_common::UpdatePolicy {
                expected_version: fixture.policy.version,
                max_transaction_rows: 200000,
                table_limit_bps: Some(10000),
                approval_after_rows: None,
                small_table_floor: Some(10),
            },
        )
        .await?;
    assert!(matches!(
        fixture
            .metadata
            .write_fence(ENGINE, fixture.branch, fixture.fence(binding))
            .await,
        Err(MetaError::PolicyConflict)
    ));
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires DATABASE_URL for an isolated metadata PostgreSQL"]
async fn fence_enforces_capture_reclaim_epoch_and_replay_session(pool: PgPool) -> TestResult {
    let fixture = Fixture::new(pool, ENGINE).await?;
    let binding = fixture.prepare().await?;
    fixture.admit(1).await?;
    let expected = fixture.fence(binding.clone());
    let response = fixture
        .metadata
        .write_fence(ENGINE, fixture.branch, expected.clone())
        .await?;
    assert_eq!(response.branch_id, fixture.branch);
    assert_eq!(response.engine, ENGINE);
    assert_eq!(response.context, expected);
    assert_missing_singletons_fail_closed(&fixture).await?;
    sqlx::query("UPDATE branch SET capture_active=TRUE WHERE id=$1")
        .bind(fixture.branch)
        .execute(&fixture.pool)
        .await?;
    assert!(matches!(
        fixture
            .metadata
            .write_fence(ENGINE, fixture.branch, fixture.fence(binding.clone()))
            .await,
        Err(MetaError::BranchUnavailable)
    ));
    sqlx::query("UPDATE branch SET capture_active=FALSE WHERE id=$1")
        .bind(fixture.branch)
        .execute(&fixture.pool)
        .await?;
    sqlx::query("UPDATE generation SET reclaim_started_at=clock_timestamp() WHERE id=$1")
        .bind(fixture.generation)
        .execute(&fixture.pool)
        .await?;
    assert!(matches!(
        fixture
            .metadata
            .write_fence(ENGINE, fixture.branch, fixture.fence(binding.clone()))
            .await,
        Err(MetaError::BranchUnavailable)
    ));
    sqlx::query("UPDATE generation SET reclaim_started_at=NULL WHERE id=$1")
        .bind(fixture.generation)
        .execute(&fixture.pool)
        .await?;
    let job:i64=sqlx::query_scalar("INSERT INTO replay_job(branch_id,principal,generation_id,state,session_id,native_session_id) VALUES($1,'alice',$2,'running',$3,77) RETURNING id")
        .bind(fixture.branch).bind(fixture.generation).bind(fixture.context(2).session_id).fetch_one(&fixture.pool).await?;
    assert!(matches!(
        fixture
            .metadata
            .write_fence(ENGINE, fixture.branch, fixture.fence(binding.clone()))
            .await,
        Err(MetaError::BranchUnavailable)
    ));
    let mut request = fixture.decision(2);
    request.attempt.replay_job_id = Some(job);
    let context = request.attempt.clone();
    fixture
        .metadata
        .record_audited_decision(ENGINE, fixture.branch, request)
        .await?;
    let fence = || WriteFenceRequest {
        attempt: context.clone(),
        policy_version: fixture.policy.version,
        effective_revision: fixture.policy.effective_revision,
        witness: Some(binding.clone()),
    };
    fixture
        .metadata
        .write_fence(ENGINE, fixture.branch, fence())
        .await?;
    sqlx::query("UPDATE replay_job SET native_session_id=78 WHERE id=$1")
        .bind(job)
        .execute(&fixture.pool)
        .await?;
    assert!(matches!(
        fixture
            .metadata
            .write_fence(ENGINE, fixture.branch, fence())
            .await,
        Err(MetaError::BranchUnavailable)
    ));
    fixture
        .metadata
        .register_proxy_epoch(&"c".repeat(32))
        .await?;
    assert!(matches!(
        fixture
            .metadata
            .write_fence(ENGINE, fixture.branch, fence())
            .await,
        Err(MetaError::BranchUnavailable)
    ));
    Ok(())
}

async fn assert_missing_singletons_fail_closed(fixture: &Fixture) -> TestResult {
    for (query, missing_epoch) in [
        ("DELETE FROM policy_proxy_epoch WHERE singleton", true),
        ("DELETE FROM replay_deployment WHERE singleton", false),
    ] {
        let mut transaction = fixture.metadata.begin_policy(false).await?;
        lock_branch(&mut transaction, fixture.branch, false).await?;
        let context = fixture.context(1);
        load_attempt(&mut transaction, &context.attempt_id, true).await?;
        sqlx::query(query).execute(&mut *transaction).await?;
        let observation = WriteObservation::disabled();
        let authority = load_authority(
            &mut transaction,
            AuthorityLookup {
                engine: fixture.engine,
                branch: fixture.branch,
                principal: "alice",
                write: Some(WriteAccess {
                    context: &context,
                    table_id: None,
                    approval_id: None,
                }),
            },
            &observation,
        )
        .await?;
        if missing_epoch {
            assert!(matches!(
                authority.require_write(),
                Err(MetaError::BranchUnavailable)
            ));
        } else {
            authority.require_write()?;
            assert!(matches!(
                authority.witness(),
                Err(MetaError::InvalidCatalog)
            ));
        }
        let observer = load_authority(
            &mut transaction,
            AuthorityLookup {
                engine: fixture.engine,
                branch: fixture.branch,
                principal: "alice",
                write: None,
            },
            &observation,
        )
        .await?;
        assert_eq!(observer.policy()?.version, fixture.policy.version);
        transaction.rollback().await?;
    }
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires DATABASE_URL for an isolated metadata PostgreSQL"]
async fn fence_requires_consumed_statement_approval(pool: PgPool) -> TestResult {
    let mut fixture = Fixture::new(pool, ENGINE).await?;
    fixture.policy = fixture
        .metadata
        .update_policy(
            "reviewer",
            BranchClass::Dev,
            fg_protocol_common::UpdatePolicy {
                expected_version: fixture.policy.version,
                max_transaction_rows: 100,
                table_limit_bps: None,
                approval_after_rows: Some(1),
                small_table_floor: Some(10),
            },
        )
        .await?;
    let binding = fixture.prepare().await?;
    let mut request = fixture.decision(1);
    request.decision.verdict = DecisionVerdict::AwaitApproval;
    let approval = fixture
        .metadata
        .record_audited_decision(ENGINE, fixture.branch, request)
        .await?
        .approval_id
        .ok_or("missing approval")?;
    assert!(matches!(
        fixture
            .metadata
            .write_fence(ENGINE, fixture.branch, fixture.fence(binding.clone()))
            .await,
        Err(MetaError::PolicyConflict)
    ));
    let key = crate::ApprovalKey {
        branch_id: fixture.branch,
        id: approval,
    };
    fixture
        .metadata
        .review_approval(
            ENGINE,
            key,
            crate::ApprovalReview {
                actor: "reviewer",
                owners: &["alice".into()],
                approve: true,
            },
        )
        .await?;
    assert!(matches!(
        fixture
            .metadata
            .write_fence(ENGINE, fixture.branch, fixture.fence(binding.clone()))
            .await,
        Err(MetaError::PolicyConflict)
    ));
    fixture
        .metadata
        .poll_approval(
            ENGINE,
            key,
            fg_protocol_common::ApprovalContext {
                principal: "alice".into(),
                session_id: fixture.context(1).session_id,
            },
        )
        .await?;
    fixture
        .metadata
        .write_fence(ENGINE, fixture.branch, fixture.fence(binding))
        .await?;
    Ok(())
}

async fn wait_for_lock(pool: &PgPool) -> TestResult {
    wait_for_query_lock(pool, "%FROM branch WHERE id=%FOR SHARE%").await
}

async fn wait_for_query_lock(pool: &PgPool, pattern: &str) -> TestResult {
    for _ in 0..100 {
        let waiting: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_stat_activity
            WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE $1)",
        )
        .bind(pattern)
        .fetch_one(pool)
        .await?;
        if waiting {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err("the operation never reached the deliberately held metadata lock".into())
}

async fn assert_pending_index(pool: &PgPool) -> TestResult {
    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL enable_seqscan=off")
        .execute(&mut *tx)
        .await?;
    let plan: Value = sqlx::query_scalar(
        "EXPLAIN(FORMAT JSON) SELECT a.* FROM audit_attempt a WHERE engine='postgresql'
        AND forkget_audit_pending(a) ORDER BY updated_at,attempt_id LIMIT 256",
    )
    .fetch_one(&mut *tx)
    .await?;
    assert!(
        plan.to_string().contains("audit_attempt_pending"),
        "pending predicate must permit the bounded index: {plan}"
    );
    tx.rollback().await?;
    Ok(())
}

async fn assert_collection_index(pool: &PgPool, branch: i64) -> TestResult {
    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL enable_seqscan=off")
        .execute(&mut *tx)
        .await?;
    let plan:Value=sqlx::query_scalar("EXPLAIN(FORMAT JSON) SELECT attempt_id FROM audit_attempt WHERE engine='postgresql' AND branch_id=$1
        AND mode='sql_transaction' AND NOT witness_collected AND outcome IS NOT NULL AND (outcome<>'unknown' OR resolution IS NOT NULL)
        ORDER BY created_at LIMIT 256")
        .bind(branch).fetch_one(&mut *tx).await?;
    assert!(
        plan.to_string()
            .contains("audit_attempt_witness_collection"),
        "completed witness scan must permit the bounded index: {plan}"
    );
    tx.rollback().await?;
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires DATABASE_URL for an isolated metadata PostgreSQL"]
async fn storage_invalidation_cannot_turn_absence_into_rollback(pool: PgPool) -> TestResult {
    let fixture = Fixture::new(pool, ENGINE).await?;
    let old = fixture.prepare().await?;
    fixture.admit(1).await?;
    let id = fixture.context(1).attempt_id;
    fixture
        .metadata
        .invalidate_audit_storage(ENGINE, fixture.branch, "operator")
        .await?;
    assert!(
        fixture
            .metadata
            .audit_witness_binding(ENGINE, fixture.branch)
            .await?
            .is_none()
    );
    assert!(matches!(
        fixture
            .metadata
            .resolve_audit_attempt(ENGINE, &id, AuditRecoveryEvidence::SqlRolledBack(old))
            .await,
        Err(MetaError::AuditConflict)
    ));
    assert!(matches!(
        fixture
            .metadata
            .acknowledge_audit_unknown(ENGINE, &id, "operator")
            .await,
        Err(MetaError::AuditConflict)
    ));
    assert!(
        !fixture
            .metadata
            .audit_storage_replacement_allowed(ENGINE, fixture.branch)
            .await?
    );
    fixture
        .metadata
        .resolve_audit_attempt(ENGINE, &id, AuditRecoveryEvidence::Unknown)
        .await?;
    assert!(matches!(
        fixture
            .metadata
            .plan_audit_witness(ENGINE, fixture.branch, &"e".repeat(32))
            .await,
        Err(MetaError::AuditPending)
    ));
    fixture
        .metadata
        .acknowledge_audit_unknown(ENGINE, &id, "operator")
        .await?;
    fixture
        .metadata
        .acknowledge_audit_unknown(ENGINE, &id, "operator")
        .await?;
    assert!(
        fixture
            .metadata
            .audit_storage_replacement_allowed(ENGINE, fixture.branch)
            .await?
    );
    assert!(
        fixture
            .metadata
            .audit_cleanup_ready(ENGINE, fixture.branch)
            .await?
    );
    assert!(
        fixture
            .metadata
            .plan_audit_witness(ENGINE, fixture.branch, &"e".repeat(32))
            .await
            .is_err()
    );
    let fresh = fixture
        .metadata
        .plan_audit_witness_replacement(ENGINE, fixture.branch, &"e".repeat(32))
        .await?;
    assert!(
        fixture
            .metadata
            .mark_audit_witness_ready(ENGINE, &fresh)
            .await
            .is_err()
    );
    assert!(
        fixture
            .metadata
            .mark_audit_witness_ready_by(ENGINE, &fresh, "operator")
            .await
            .is_err()
    );
    assert_eq!(
        fixture
            .metadata
            .branch_status(ENGINE, fixture.branch, "alice")
            .await?["audit"]["storage_invalidated"],
        true
    );
    fixture
        .metadata
        .mark_audit_witness_replacement_ready_by(ENGINE, &fresh, "operator")
        .await?;
    fixture
        .metadata
        .mark_audit_witness_replacement_ready_by(ENGINE, &fresh, "operator")
        .await?;
    assert!(
        !fixture
            .metadata
            .audit_storage_replacement_allowed(ENGINE, fixture.branch)
            .await?
    );
    assert_eq!(fresh.storage_incarnation, "e".repeat(32));
    let (outcome,resolution,acks):(String,Option<String>,i64)=sqlx::query_as("SELECT outcome,resolution,(SELECT count(*) FROM audit_event WHERE event_type='policy_outcome_retention_ack') FROM audit_attempt WHERE attempt_id=$1")
        .bind(id).fetch_one(&fixture.pool).await?;
    assert_eq!((outcome, resolution, acks), ("unknown".into(), None, 1));
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires DATABASE_URL for an isolated metadata PostgreSQL"]
async fn mongo_steps_are_idempotent_and_preserve_partial_facts(pool: PgPool) -> TestResult {
    let fixture = Fixture::new(pool, "mongodb").await?;
    fixture.admit(1).await?;
    let first = MongoStepRequest {
        attempt: fixture.context(1),
        expected_step: 0,
        previous: None,
    };
    let ack = fixture
        .metadata
        .arm_mongo_step("mongodb", fixture.branch, first)
        .await?;
    assert_eq!(ack.armed_step, 1);
    assert_eq!(
        fixture
            .metadata
            .arm_mongo_step(
                "mongodb",
                fixture.branch,
                MongoStepRequest {
                    attempt: fixture.context(1),
                    expected_step: 0,
                    previous: None
                }
            )
            .await?,
        ack
    );
    let previous = MongoWriteObservation {
        state: MongoObservationState::Acknowledged,
        inserted: Some(1),
        ..Default::default()
    };
    let next = fixture
        .metadata
        .arm_mongo_step(
            "mongodb",
            fixture.branch,
            MongoStepRequest {
                attempt: fixture.context(1),
                expected_step: 1,
                previous: Some(previous.clone()),
            },
        )
        .await?;
    assert_eq!(next.armed_step, 2);
    assert_eq!(
        fixture
            .metadata
            .arm_mongo_step(
                "mongodb",
                fixture.branch,
                MongoStepRequest {
                    attempt: fixture.context(1),
                    expected_step: 1,
                    previous: Some(previous)
                }
            )
            .await?,
        next
    );
    let terminal = MongoWriteObservation {
        state: MongoObservationState::AcknowledgedWithErrors,
        inserted: Some(1),
        error_count: Some(1),
        native_code: Some(11000),
        ..Default::default()
    };
    let outcome = AuditedOutcomeRequest {
        attempt: fixture.context(1),
        outcome: TransactionOutcome::Unknown,
        armed_step: 2,
        mongo: Some(terminal),
    };
    let ack = fixture
        .metadata
        .record_audited_outcome("mongodb", fixture.branch, outcome.clone())
        .await?;
    assert_eq!(
        fixture
            .metadata
            .record_audited_outcome("mongodb", fixture.branch, outcome)
            .await?,
        ack
    );
    let payload: Value = sqlx::query_scalar("SELECT payload FROM audit_event WHERE id=$1")
        .bind(ack.audit_event_id)
        .fetch_one(&fixture.pool)
        .await?;
    assert_eq!(payload["atomic"], false);
    assert_eq!(payload["confirmed_steps"], 2);
    let status = fixture
        .metadata
        .branch_status("mongodb", fixture.branch, "alice")
        .await?;
    assert_eq!(status["audit"]["mongo_partial"], 1);
    assert_eq!(
        status["audit"]["latest_mongo_observation"]["observation"]["state"],
        "acknowledged_with_errors"
    );
    assert_eq!(payload["mongo_steps"][0]["observation"]["inserted"], 1);
    assert_eq!(
        payload["mongo_steps"][1]["observation"]["native_code"],
        11000
    );
    assert!(
        !fixture
            .metadata
            .audit_cleanup_ready("mongodb", fixture.branch)
            .await?
    );
    fixture
        .metadata
        .seal_audit_attempt("mongodb", &fixture.context(1).attempt_id)
        .await?;
    fixture
        .metadata
        .resolve_audit_attempt(
            "mongodb",
            &fixture.context(1).attempt_id,
            AuditRecoveryEvidence::Unknown,
        )
        .await?;
    assert!(
        fixture
            .metadata
            .audit_cleanup_ready("mongodb", fixture.branch)
            .await?
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires DATABASE_URL for an isolated metadata PostgreSQL"]
async fn uncertain_mongo_arm_settles_without_claiming_rollback(pool: PgPool) -> TestResult {
    let fixture = Fixture::new(pool, "mongodb").await?;
    fixture.admit(1).await?;
    let request = AuditedOutcomeRequest {
        attempt: fixture.context(1),
        outcome: TransactionOutcome::Unknown,
        armed_step: 1,
        mongo: Some(MongoWriteObservation {
            state: MongoObservationState::NotSent,
            ..Default::default()
        }),
    };
    fixture
        .metadata
        .record_audited_outcome("mongodb", fixture.branch, request)
        .await?;
    assert!(matches!(
        fixture
            .metadata
            .arm_mongo_step(
                "mongodb",
                fixture.branch,
                MongoStepRequest {
                    attempt: fixture.context(1),
                    expected_step: 0,
                    previous: None
                }
            )
            .await,
        Err(MetaError::AuditConflict)
    ));
    assert!(
        !fixture
            .metadata
            .audit_cleanup_ready("mongodb", fixture.branch)
            .await?
    );
    fixture
        .metadata
        .seal_audit_attempt("mongodb", &fixture.context(1).attempt_id)
        .await?;
    fixture
        .metadata
        .resolve_audit_attempt(
            "mongodb",
            &fixture.context(1).attempt_id,
            AuditRecoveryEvidence::Unknown,
        )
        .await?;
    assert!(
        fixture
            .metadata
            .audit_cleanup_ready("mongodb", fixture.branch)
            .await?
    );
    let row: (String, i32) =
        sqlx::query_as("SELECT outcome,armed_step FROM audit_attempt WHERE attempt_id=$1")
            .bind(fixture.context(1).attempt_id)
            .fetch_one(&fixture.pool)
            .await?;
    assert_eq!(row, ("unknown".into(), 0));
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires DATABASE_URL for an isolated metadata PostgreSQL"]
async fn mongo_late_observation_preserves_unknown_and_exact_native_material(
    pool: PgPool,
) -> TestResult {
    let fixture = Fixture::new(pool, "mongodb").await?;
    for (ordinal, state, outcome) in [
        (
            1,
            MongoObservationState::Acknowledged,
            TransactionOutcome::Committed,
        ),
        (
            2,
            MongoObservationState::Unknown,
            TransactionOutcome::Unknown,
        ),
    ] {
        fixture.admit(ordinal).await?;
        fixture
            .metadata
            .arm_mongo_step(
                "mongodb",
                fixture.branch,
                MongoStepRequest {
                    attempt: fixture.context(ordinal),
                    expected_step: 0,
                    previous: None,
                },
            )
            .await?;
        let id = fixture.context(ordinal).attempt_id;
        let request = AuditedOutcomeRequest {
            attempt: fixture.context(ordinal),
            outcome,
            armed_step: 1,
            mongo: Some(MongoWriteObservation {
                state,
                matched: Some(1),
                modified: Some(1),
                ..Default::default()
            }),
        };
        let original = fixture
            .metadata
            .record_audited_outcome(
                "mongodb",
                fixture.branch,
                AuditedOutcomeRequest {
                    attempt: fixture.context(ordinal),
                    outcome: TransactionOutcome::Unknown,
                    armed_step: 1,
                    mongo: Some(MongoWriteObservation::default()),
                },
            )
            .await?;
        assert!(matches!(
            fixture
                .metadata
                .record_audited_outcome("mongodb", fixture.branch, request.clone())
                .await,
            Err(MetaError::AuditConflict)
        ));
        fixture.metadata.seal_audit_attempt("mongodb", &id).await?;
        assert!(matches!(
            fixture
                .metadata
                .record_audited_outcome("mongodb", fixture.branch, request.clone())
                .await,
            Err(MetaError::AuditConflict)
        ));
        assert_eq!(
            fixture
                .metadata
                .resolve_audit_attempt("mongodb", &id, AuditRecoveryEvidence::Unknown)
                .await?,
            original
        );
        let ack = fixture
            .metadata
            .record_audited_outcome("mongodb", fixture.branch, request.clone())
            .await?;
        assert_eq!(ack.outcome, outcome);
        assert_ne!(ack.audit_event_id, original.audit_event_id);
        assert_eq!(
            fixture
                .metadata
                .record_audited_outcome("mongodb", fixture.branch, request.clone())
                .await?,
            ack
        );
        let mut conflict = request.clone();
        conflict
            .mongo
            .as_mut()
            .ok_or("missing observation")?
            .matched = Some(2);
        assert!(matches!(
            fixture
                .metadata
                .record_audited_outcome("mongodb", fixture.branch, conflict)
                .await,
            Err(MetaError::AuditConflict)
        ));
        let status = fixture
            .metadata
            .audit_attempt_status("mongodb", fixture.branch, &request.attempt)
            .await?;
        assert_eq!(status.ack, Some(original.clone()));
        assert_eq!(status.late_ack, Some(ack));
        assert_eq!(status.late_outcome, Some(request));
        assert!(status.resolution.is_none());
        let original_payload: Value =
            sqlx::query_scalar("SELECT payload FROM audit_event WHERE id=$1")
                .bind(original.audit_event_id)
                .fetch_one(&fixture.pool)
                .await?;
        assert_eq!(original_payload["outcome"], "unknown");
        let health = fixture
            .metadata
            .branch_status("mongodb", fixture.branch, "alice")
            .await?;
        assert_eq!(
            health["audit"]["latest_mongo_observation"]["outcome"],
            "unknown"
        );
        assert_eq!(
            health["audit"]["latest_mongo_observation"]["late_observation"]["matched"],
            1
        );
    }
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM audit_event WHERE event_type='policy_outcome_late_observation' AND payload->>'atomic'='false' AND payload->>'original_outcome'='unknown'")
        .fetch_one(&fixture.pool).await?;
    assert_eq!(count, 2);
    Ok(())
}

#[sqlx::test(migrations = false)]
#[ignore = "requires DATABASE_URL for an isolated metadata PostgreSQL"]
async fn forward_migration_preserves_existing_native_data_registration(pool: PgPool) -> TestResult {
    let migrations = sqlx::migrate!("./migrations");
    for migration in migrations.iter().filter(|migration| migration.version < 20) {
        sqlx::raw_sql(&migration.sql).execute(&pool).await?;
    }
    let fixture =
        Fixture::with_policy_source(pool, ENGINE, FixturePolicySource::PreAuditClass).await?;
    sqlx::raw_sql(include_str!(
        "../../migrations/0020_durable_write_audit.sql"
    ))
    .execute(&fixture.pool)
    .await?;
    let state:(bool,bool,bool,String)=sqlx::query_as("SELECT b.native_claimed,b.audit_witness_ready,b.audit_storage_invalidated,b.access FROM branch b WHERE id=$1")
        .bind(fixture.branch).fetch_one(&fixture.pool).await?;
    assert_eq!(state, (true, false, false, "read_write".into()));
    let upgraded = fixture
        .metadata
        .policy_for_branch(ENGINE, fixture.branch, "alice")
        .await?;
    assert_eq!(upgraded.version, fixture.policy.version);
    assert_eq!(
        upgraded.max_transaction_rows,
        fixture.policy.max_transaction_rows
    );
    assert_eq!(upgraded.effective_revision, 0);
    assert!(matches!(
        fixture.admit(1).await,
        Err(MetaError::AuditPending)
    ));
    assert_eq!(
        fixture.metadata.policy(BranchClass::Dev).await?.version,
        fixture.policy.version
    );
    Ok(())
}
