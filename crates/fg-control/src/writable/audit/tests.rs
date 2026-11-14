use sqlx::{Connection, PgConnection, PgPool};

use super::*;
use crate::native::NativeOptions;

struct CollectionFixture {
    pool: PgPool,
    metadata: Metadata,
    collector: NativeOptions,
    admin: Admin,
    target: WriteTarget,
    identity: NativeWitnessBinding,
    attempt_id: String,
}

#[sqlx::test(migrations = "../fg-meta/migrations")]
#[ignore = "requires an isolated native PostgreSQL test database"]
async fn collector_lock_survives_admin_loss_and_marks_only_committed_cleanup(
    pool: PgPool,
) -> Result<(), ControlError> {
    let role = format!(
        "fg_witness_gc_{}",
        new_incarnation()?.chars().take(16).collect::<String>()
    );
    let password = new_incarnation()?;
    sqlx::raw_sql(&format!(
        "CREATE ROLE {} LOGIN PASSWORD '{password}'",
        Engine::Postgres.quote(&role)
    ))
    .execute(&pool)
    .await?;
    let result = async {
        let fixture = CollectionFixture::new(pool.clone(), &role, &password).await?;
        fixture.admin_and_collector_loss(&role).await?;
        fixture.committed_delete_precedes_metadata_mark().await
    }
    .await;
    // Keep this independent role scoped to the test even when a proof fails.
    sqlx::query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename=$1 AND datname=current_database()")
        .bind(&role).execute(&pool).await?;
    sqlx::raw_sql(&format!(
        "DROP OWNED BY {0}; DROP ROLE {0}",
        Engine::Postgres.quote(&role)
    ))
    .execute(&pool)
    .await?;
    result
}

impl CollectionFixture {
    async fn new(pool: PgPool, role: &str, password: &str) -> Result<Self, ControlError> {
        let options = pool.connect_options();
        let source = std::env::var("DATABASE_URL")
            .map_err(|_| ControlError::Config("native test DATABASE_URL"))?;
        let mut source = reqwest::Url::parse(&source)
            .map_err(|_| ControlError::Config("native test metadata URL"))?;
        source.set_path(&format!(
            "/{}",
            options
                .get_database()
                .ok_or(ControlError::Config("native test database"))?
        ));
        let metadata = Metadata::connect(source.as_str(), None).await?;
        let generation: i64 = sqlx::query_scalar("INSERT INTO generation(engine,status,native_claimed,activated_at,snapshot) VALUES('postgresql','active',TRUE,clock_timestamp(),'v2') RETURNING id")
            .fetch_one(&pool).await?;
        let table: i64 = sqlx::query_scalar("INSERT INTO catalog_table(generation_id,logical_schema,logical_table,base_table,baseline_rows) VALUES($1,'app','orders','orders',1) RETURNING id")
            .bind(generation).fetch_one(&pool).await?;
        let branch: i64 = sqlx::query_scalar("INSERT INTO branch(name,class,generation_id,created_by,expires_at,status,mode,native_claimed,access,layout,read_strategy) VALUES('collector-lock','dev',$1,'alice',clock_timestamp()+INTERVAL '1 hour','active','native_write',TRUE,'read_write','native_copy','merge') RETURNING id")
            .bind(generation).fetch_one(&pool).await?;
        let target = WriteTarget::for_branch(branch, false);
        let identity = metadata
            .plan_audit_witness("postgresql", branch, &new_incarnation()?)
            .await?;
        let mut native = Native::Postgres(PgConnection::connect_with(&options).await?);
        native
            .execute(&format!(
                "CREATE SCHEMA {}",
                Engine::Postgres.quote(target.schema())
            ))
            .await?;
        create(&mut native, &target, &identity).await?;
        let relation = Engine::Postgres.relation(target.schema(), &target.table(TXN_WITNESS_TABLE));
        native
            .execute(&format!(
                "GRANT USAGE ON SCHEMA {} TO {}",
                Engine::Postgres.quote(target.schema()),
                Engine::Postgres.quote(role)
            ))
            .await?;
        native
            .execute(&format!(
                "GRANT SELECT, DELETE ON {relation} TO {}",
                Engine::Postgres.quote(role)
            ))
            .await?;
        metadata
            .mark_audit_witness_ready("postgresql", &identity)
            .await?;
        let epoch = "a".repeat(32);
        metadata.register_proxy_epoch(&epoch).await?;
        let session_id = format!("{epoch}:1");
        let attempt = fg_protocol_common::AuditAttemptContext {
            attempt_id: format!("{session_id}:1"),
            principal: "alice".into(),
            session_id: session_id.clone(),
            native_session_id: 77,
            generation_id: generation,
            replay_job_id: None,
            mode: fg_protocol_common::AuditMode::SqlTransaction,
        };
        let policy = metadata
            .policy_for_branch("postgresql", branch, "alice")
            .await?;
        metadata
            .record_audited_decision(
                "postgresql",
                branch,
                fg_protocol_common::AuditedDecisionRequest {
                    attempt: attempt.clone(),
                    decision: fg_protocol_common::DecisionRequest {
                        principal: "alice".into(),
                        session_id,
                        policy_version: policy.version,
                        effective_revision: policy.effective_revision,
                        operation: fg_protocol_common::WriteOperation {
                            table_id: table,
                            kind: fg_protocol_common::WriteKind::Insert,
                        },
                        rows: 1,
                        verdict: fg_protocol_common::DecisionVerdict::Allowed,
                    },
                },
            )
            .await?;
        sqlx::query(&format!(
            "INSERT INTO {relation} VALUES($1,$2,$3,$4,$5,$6,'77')"
        ))
        .bind(i16::try_from(identity.format_version).map_err(|_| WitnessError::Identity)?)
        .bind(&identity.deployment_id)
        .bind(branch)
        .bind(generation)
        .bind(&identity.storage_incarnation)
        .bind(&attempt.attempt_id)
        .execute(pg(&mut native)?)
        .await?;
        metadata
            .record_audited_outcome(
                "postgresql",
                branch,
                fg_protocol_common::AuditedOutcomeRequest {
                    attempt: attempt.clone(),
                    outcome: fg_protocol_common::TransactionOutcome::Committed,
                    armed_step: 0,
                    mongo: None,
                },
            )
            .await?;
        let collector =
            NativeOptions::Postgres((*options).clone().username(role).password(password));
        let roles = NativeRoles::new(
            Engine::Postgres,
            "fg_service",
            role,
            Some(options.get_username()),
        )?;
        Ok(Self {
            pool,
            metadata,
            collector,
            admin: Admin {
                options: NativeOptions::Postgres((*options).clone()),
                roles,
            },
            target,
            identity,
            attempt_id: attempt.attempt_id,
        })
    }

    async fn admin_and_collector_loss(&self, role: &str) -> Result<(), ControlError> {
        let schema = Engine::Postgres.quote(self.target.schema());
        let relation =
            Engine::Postgres.relation(self.target.schema(), &self.target.table(TXN_WITNESS_TABLE));
        let sequence = format!("{schema}.collector_loss_sequence");
        let function = format!("{schema}.collector_loss_trigger()");
        sqlx::raw_sql(&format!("CREATE SEQUENCE {sequence}; CREATE FUNCTION {function} RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN PERFORM nextval('{sequence}'); RETURN OLD; END $$;"))
            .execute(&self.pool).await?;
        let mut collector = self.collector.connect().await?;
        let current: String = sqlx::query_scalar("SELECT current_user::text")
            .fetch_one(pg(&mut collector)?)
            .await?;
        require(
            current == role,
            "collector test did not use its dedicated role",
        )?;
        let privileges: bool = sqlx::query_scalar("SELECT has_table_privilege(current_user,$1,'SELECT') AND has_table_privilege(current_user,$1,'DELETE') AND NOT has_table_privilege(current_user,$1,'UPDATE') AND NOT has_table_privilege(current_user,$1,'INSERT')")
            .bind(&relation).fetch_one(pg(&mut collector)?).await?;
        require(
            privileges,
            "collector test privileges exceed SELECT and DELETE",
        )?;
        begin_collection(&mut collector, &self.target).await?;
        let collector_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(pg(&mut collector)?)
            .await?;
        let mut attestation = self
            .admin
            .attest_witness(&self.target, &self.identity)
            .await?;
        let admin_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(pg(&mut attestation)?)
            .await?;
        kill(&self.pool, admin_pid).await?;
        let ddl_pool = self.pool.clone();
        let create_trigger = format!(
            "CREATE TRIGGER collector_loss BEFORE DELETE ON {relation} FOR EACH ROW EXECUTE FUNCTION {function}"
        );
        let ddl = tokio::spawn(async move {
            let mut connection = ddl_pool.acquire().await?;
            sqlx::query("SET statement_timeout='5s'")
                .execute(&mut *connection)
                .await?;
            sqlx::query(&create_trigger).execute(&mut *connection).await
        });
        wait_for_trigger_lock(&self.pool).await?;
        delete_completed(
            &mut collector,
            &self.target,
            std::slice::from_ref(&self.attempt_id),
        )
        .await?;
        let called: bool = sqlx::query_scalar(&format!("SELECT is_called FROM {sequence}"))
            .fetch_one(&self.pool)
            .await?;
        require(
            !called,
            "concurrent trigger executed during protected witness deletion",
        )?;
        require(
            !ddl.is_finished(),
            "trigger DDL crossed the collector relation lock",
        )?;
        kill(&self.pool, collector_pid).await?;
        drop(collector);
        drop(attestation);
        ddl.await
            .map_err(|_| ControlError::Config("collector test DDL task failed"))??;
        let rows: i64 = sqlx::query_scalar(&format!(
            "SELECT count(*) FROM {relation} WHERE attempt_id=$1"
        ))
        .bind(&self.attempt_id)
        .fetch_one(&self.pool)
        .await?;
        require(
            rows == 1,
            "collector disconnect did not roll back witness deletion",
        )?;
        let called: bool = sqlx::query_scalar(&format!("SELECT is_called FROM {sequence}"))
            .fetch_one(&self.pool)
            .await?;
        require(
            !called,
            "trigger caused an irreversible sequence side effect",
        )?;
        require(
            !self.marked().await?,
            "collector disconnect marked uncommitted cleanup",
        )?;
        sqlx::query(&format!("DROP TRIGGER collector_loss ON {relation}"))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn committed_delete_precedes_metadata_mark(&self) -> Result<(), ControlError> {
        sqlx::raw_sql("CREATE FUNCTION reject_collection_mark() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.witness_collected AND NOT OLD.witness_collected THEN RAISE EXCEPTION 'test mark unavailable'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_collection_mark BEFORE UPDATE OF witness_collected ON audit_attempt FOR EACH ROW EXECUTE FUNCTION reject_collection_mark();")
            .execute(&self.pool).await?;
        let failure = collect_completed(self.request()).await;
        require(
            matches!(failure, Err(ControlError::Meta(fg_meta::MetaError::Database(sqlx::Error::Database(ref error)))) if error.code().as_deref()==Some("P0001")),
            "collection did not reach the injected metadata-mark failure",
        )?;
        let relation =
            Engine::Postgres.relation(self.target.schema(), &self.target.table(TXN_WITNESS_TABLE));
        let rows: i64 = sqlx::query_scalar(&format!(
            "SELECT count(*) FROM {relation} WHERE attempt_id=$1"
        ))
        .bind(&self.attempt_id)
        .fetch_one(&self.pool)
        .await?;
        require(
            rows == 0,
            "metadata mark was attempted before native COMMIT",
        )?;
        require(
            !self.marked().await?,
            "failed metadata mark changed collection state",
        )?;
        sqlx::query("DROP TRIGGER reject_collection_mark ON audit_attempt")
            .execute(&self.pool)
            .await?;
        require(
            collect_completed(self.request()).await? == 1,
            "idempotent cleanup retry did not finish",
        )?;
        require(
            self.marked().await?,
            "committed cleanup retry did not record its acknowledgement",
        )?;
        Ok(())
    }

    fn request(&self) -> WitnessCollection<'_> {
        WitnessCollection {
            metadata: &self.metadata,
            options: &self.collector,
            admin: &self.admin,
            target: &self.target,
        }
    }

    async fn marked(&self) -> Result<bool, ControlError> {
        Ok(
            sqlx::query_scalar("SELECT witness_collected FROM audit_attempt WHERE attempt_id=$1")
                .bind(&self.attempt_id)
                .fetch_one(&self.pool)
                .await?,
        )
    }
}

fn pg(native: &mut Native) -> Result<&mut PgConnection, ControlError> {
    if let Native::Postgres(connection) = native {
        Ok(connection)
    } else {
        Err(WitnessError::Identity.into())
    }
}

fn require(condition: bool, message: &'static str) -> Result<(), ControlError> {
    if condition {
        Ok(())
    } else {
        Err(ControlError::Config(message))
    }
}

async fn kill(pool: &PgPool, pid: i32) -> Result<(), ControlError> {
    require(
        sqlx::query_scalar("SELECT pg_terminate_backend($1)")
            .bind(pid)
            .fetch_one(pool)
            .await?,
        "collector test could not terminate its owned native connection",
    )?;
    for _ in 0..100 {
        let gone: bool =
            sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)")
                .bind(pid)
                .fetch_one(pool)
                .await?;
        if gone {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    Err(ControlError::Config(
        "terminated collector test connection remains active",
    ))
}

async fn wait_for_trigger_lock(pool: &PgPool) -> Result<(), ControlError> {
    for _ in 0..100 {
        let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND query LIKE 'CREATE TRIGGER collector_loss %' AND wait_event_type='Lock')")
            .fetch_one(pool).await?;
        if blocked {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    Err(ControlError::Config(
        "trigger DDL did not wait for the collector relation lock",
    ))
}

#[sqlx::test]
#[ignore = "requires an isolated native PostgreSQL test database"]
async fn attestation_blocks_trigger_ddl_but_allows_collector_delete(
    pool: PgPool,
) -> Result<(), ControlError> {
    let options = pool.connect_options();
    let roles = NativeRoles::new(
        Engine::Postgres,
        "fg_service",
        "fg_gc",
        Some(options.get_username()),
    )?;
    let admin = Admin {
        options: NativeOptions::Postgres((*options).clone()),
        roles,
    };
    let target = WriteTarget::for_branch(7, false);
    let identity = NativeWitnessBinding {
        format_version: TXN_WITNESS_FORMAT,
        deployment_id: "00000000-0000-0000-0000-000000000001".into(),
        branch_id: 7,
        generation_id: 1,
        storage_incarnation: "00000000000000000000000000000001".into(),
    };
    let mut native = Native::Postgres(PgConnection::connect_with(&options).await?);
    native.execute("CREATE SCHEMA fg_b7").await?;
    create(&mut native, &target, &identity).await?;
    native.execute("CREATE FUNCTION fg_b7.witness_test_trigger() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END;'").await?;
    let attestation = admin.attest_witness(&target, &identity).await?;

    let mut ddl = pool.acquire().await?;
    sqlx::query("SET lock_timeout='100ms'")
        .execute(&mut *ddl)
        .await?;
    let create_trigger = "CREATE TRIGGER witness_test BEFORE INSERT ON fg_b7._fg_txn_witness FOR EACH ROW EXECUTE FUNCTION fg_b7.witness_test_trigger()";
    let blocked = sqlx::query(create_trigger).execute(&mut *ddl).await;
    assert!(
        matches!(blocked, Err(sqlx::Error::Database(ref error)) if error.code().as_deref()==Some("55P03"))
    );

    let mut collector = pool.acquire().await?;
    sqlx::query("SET lock_timeout='200ms'")
        .execute(&mut *collector)
        .await?;
    sqlx::query("DELETE FROM fg_b7._fg_txn_witness WHERE attempt_id<>''")
        .execute(&mut *collector)
        .await?;
    drop(attestation);
    sqlx::query("SET lock_timeout='2s'")
        .execute(&mut *ddl)
        .await?;
    sqlx::query(create_trigger).execute(&mut *ddl).await?;
    assert!(matches!(
        admin.attest_witness(&target, &identity).await,
        Err(ControlError::Witness(WitnessError::Storage))
    ));
    sqlx::query("DROP TRIGGER witness_test ON fg_b7._fg_txn_witness")
        .execute(&mut *ddl)
        .await?;
    sqlx::query(
        "CREATE RULE witness_test_rule AS ON INSERT TO fg_b7._fg_txn_witness DO INSTEAD NOTHING",
    )
    .execute(&mut *ddl)
    .await?;
    assert!(matches!(
        admin.attest_witness(&target, &identity).await,
        Err(ControlError::Witness(WitnessError::Storage))
    ));
    Ok(())
}
