use futures_core::Stream;
use std::{
    collections::HashMap,
    fs::File,
    io::{BufReader, Seek, SeekFrom, Write},
};

use axum::{
    Json,
    body::Body,
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use fg_protocol_common::{
    ARTIFACT_LIMIT, ArtifactHeader, ArtifactReader, ChangeOperation, ReplayPermit,
    TransactionBudget, TransactionOutcome, TypedChange, replay_order, replay_statement,
    witness_insert_sql,
};

use super::*;

pub(crate) async fn apply_route(
    State(state): State<Drain>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    route(state, id, headers, body, false).await
}

pub(crate) async fn verify_route(
    State(state): State<Drain>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    route(state, id, headers, body, true).await
}

async fn route(
    state: Drain,
    id: i64,
    headers: HeaderMap,
    body: Body,
    verify_only: bool,
) -> Response {
    if !internal_authorized(&headers, &state.token) {
        return Failure::Wire(WireError::Auth).into_response();
    }
    let permit: ReplayPermit = match headers
        .get("x-forkget-permit")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| serde_json::from_str(value).ok())
    {
        Some(permit) => permit,
        None => return Failure::Invalid.into_response(),
    };
    if permit.job_id != id {
        return Failure::Invalid.into_response();
    }
    let Ok(_slot) = state.diff_slots.clone().try_acquire_owned() else {
        return Failure::Unavailable.into_response();
    };
    match timeout(Duration::from_secs(300), async {
        let file = receive(body).await?;
        let header = validate(&file)?;
        if header.engine == "mongodb" {
            return super::document::replay(&state, &permit, &file, &header, verify_only).await;
        }
        if verify_only {
            let verified = verify(&state, &permit, &file, &header).await?;
            return Ok(json!({"verified":verified,"transaction":"unknown","applied":false}));
        }
        apply(&state, &permit, &file, &header).await
    })
    .await
    {
        Ok(Ok(result)) => Json(result).into_response(),
        Ok(Err(error)) => error.into_response(),
        Err(_) => Failure::Unavailable.into_response(),
    }
}

async fn receive(body: Body) -> Result<File, Failure> {
    let mut file = tempfile::tempfile().map_err(|_| Failure::Unavailable)?;
    let mut stream = Box::pin(body.into_data_stream());
    let mut bytes = 0u64;
    while let Some(chunk) = poll_fn(|context| stream.as_mut().poll_next(context)).await {
        let chunk = chunk.map_err(|_| Failure::Invalid)?;
        bytes = bytes.saturating_add(chunk.len() as u64);
        if bytes > ARTIFACT_LIMIT {
            return Err(Failure::Limit);
        }
        file.write_all(&chunk).map_err(|_| Failure::Unavailable)?;
    }
    file.sync_all().map_err(|_| Failure::Unavailable)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| Failure::Unavailable)?;
    Ok(file)
}

fn reader(file: &File) -> Result<ArtifactReader<BufReader<File>>, Failure> {
    let mut copy = file.try_clone().map_err(|_| Failure::Unavailable)?;
    copy.seek(SeekFrom::Start(0))
        .map_err(|_| Failure::Unavailable)?;
    ArtifactReader::new(BufReader::new(copy)).map_err(|_| Failure::Invalid)
}

fn validate(file: &File) -> Result<ArtifactHeader, Failure> {
    let mut reader = reader(file)?;
    let header = reader.header().clone();
    replay_order(&header).map_err(|_| Failure::Invalid)?;
    while let Some(change) = reader.next_entry().map_err(|_| Failure::Invalid)? {
        change
            .validate_replay(&header)
            .map_err(|_| Failure::Invalid)?;
    }
    Ok(header)
}

async fn session(
    state: &Drain,
    permit: &ReplayPermit,
    verify_only: bool,
) -> Result<(Native, fg_protocol_common::BranchSession), Failure> {
    let (native, native_id) = Native::connect(&state.observer).await?;
    let pending = state
        .router
        .begin_replay(permit, native_id, verify_only)
        .await?;
    let branch = pending.activate(native_id)?;
    branch.bind_replay(permit.job_id).await?;
    branch.fresh_authorize().await?;
    Ok((native, branch))
}

fn validate_binding(header: &ArtifactHeader, binding: &BranchBinding) -> Result<(), Failure> {
    let target = super::export::artifact_header(binding)?;
    if target.origin != header.origin
        || target.engine != header.engine
        || target.tables != header.tables
        || target.manifest != header.manifest
        || !target.native_write
    {
        return Err(Failure::Invalid);
    }
    Ok(())
}

async fn apply(
    state: &Drain,
    permit: &ReplayPermit,
    file: &File,
    header: &ArtifactHeader,
) -> Result<serde_json::Value, Failure> {
    let (mut native, branch) = session(state, permit, false).await?;
    validate_binding(header, branch.binding())?;
    let initial =
        super::export::write_snapshot(&mut native, branch.binding(), state.engine).await?;
    if reader(&initial)?
        .next_change()
        .map_err(|_| Failure::Invalid)?
        .is_some()
    {
        return Err(Failure::Invalid);
    }
    execute(&mut native, "ROLLBACK").await?;
    advance_allocators(&branch, permit.job_id, file, header).await?;
    execute(&mut native, "BEGIN").await?;
    if state.engine == "postgresql" {
        execute(&mut native, "SET CONSTRAINTS ALL DEFERRED").await?;
    }
    let mut budget = TransactionBudget::default();
    let applied = tokio::select! {
        biased;
        () = branch.cancelled() => Err(Failure::Wire(WireError::Branch)),
        result = apply_changes(&mut native,&branch,permit.job_id,header,file,&mut budget) => result,
    };
    let allowed = match applied {
        Err(error) => Err(error),
        Ok(()) => {
            async {
                if let Some(attempt) = budget.attempt() {
                    let witness = witness_insert_sql(branch.binding(), attempt)?;
                    if execute(&mut native, &witness).await? != 1 {
                        return Err(Failure::Unavailable);
                    }
                }
                budget.validate_for_commit(&branch).await?;
                branch.fresh_authorize().await?;
                branch.validate_replay(permit.job_id).await?;
                budget.fence_for_commit(&branch).await?;
                Ok::<_, Failure>(())
            }
            .await
        }
    };
    if let Err(error) = allowed {
        let rolled_back = execute(&mut native, "ROLLBACK").await.is_ok();
        let audit_delivery = deliver_outcome(
            &branch,
            &mut budget,
            if rolled_back {
                TransactionOutcome::RolledBack
            } else {
                TransactionOutcome::Unknown
            },
        )
        .await;
        let code = match error {
            Failure::Wire(wire) => wire.code(),
            Failure::Invalid => WireError::Unsupported.code(),
            _ => WireError::Backend.code(),
        };
        return Ok(
            json!({"verified":false,"transaction":if rolled_back {"rolled_back"} else {"unknown"},"audit_delivery":audit_delivery,"failure":{"phase":"apply","code":code}}),
        );
    }
    let committed = execute(&mut native, "COMMIT").await.is_ok();
    let audit_delivery = deliver_outcome(
        &branch,
        &mut budget,
        if committed {
            TransactionOutcome::Committed
        } else {
            TransactionOutcome::Unknown
        },
    )
    .await;
    if committed {
        let actual =
            super::export::write_snapshot(&mut native, branch.binding(), state.engine).await?;
        let verified = equal_files(file, &actual)?;
        branch.fresh_authorize().await?;
        Ok(json!({"verified":verified,"transaction":"committed","audit_delivery":audit_delivery}))
    } else {
        // The first COMMIT may have reached the engine. Only observe with a
        // fresh read session; never issue the typed plan a second time.
        branch.uncertain_replay(permit.job_id).await?;
        drop(native);
        drop(branch);
        let verified = verify(state, permit, file, header).await.unwrap_or(false);
        Ok(
            json!({"verified":verified,"transaction":"unknown","applied_again":false,"audit_delivery":audit_delivery}),
        )
    }
}

async fn deliver_outcome(
    branch: &fg_protocol_common::BranchSession,
    budget: &mut TransactionBudget,
    outcome: TransactionOutcome,
) -> &'static str {
    let Some(attempt) = budget.take_attempt() else {
        return "not_required";
    };
    if branch.audit_outcome(&attempt, outcome).await.is_ok() {
        "recorded"
    } else {
        "pending"
    }
}

async fn advance_allocators(
    branch: &fg_protocol_common::BranchSession,
    job: i64,
    file: &File,
    header: &ArtifactHeader,
) -> Result<(), Failure> {
    let target = WriteTarget::new(
        &header.engine,
        branch.binding().id,
        branch
            .binding()
            .write_schema
            .as_deref()
            .ok_or(Failure::Invalid)?,
    )
    .ok_or(Failure::Invalid)?;
    let mut maximums: HashMap<i64, i64> = HashMap::new();
    let mut input = reader(file)?;
    while let Some(change) = input.next_change().map_err(|_| Failure::Invalid)? {
        if let Some(id) = replay_statement(header, &change, &target)
            .map_err(|_| Failure::Invalid)?
            .generated_id
        {
            maximums
                .entry(change.table_id)
                .and_modify(|highest| *highest = (*highest).max(id))
                .or_insert(id);
        }
    }
    for (table, highest) in maximums {
        branch.advance_replay_ids(job, table, highest).await?;
    }
    Ok(())
}

async fn apply_changes(
    native: &mut Native,
    branch: &fg_protocol_common::BranchSession,
    job: i64,
    header: &ArtifactHeader,
    file: &File,
    budget: &mut TransactionBudget,
) -> Result<(), Failure> {
    let target = WriteTarget::new(
        &header.engine,
        branch.binding().id,
        branch
            .binding()
            .write_schema
            .as_deref()
            .ok_or(Failure::Invalid)?,
    )
    .ok_or(Failure::Invalid)?;
    let order = replay_order(header).map_err(|_| Failure::Invalid)?;
    for phase in [
        ChangeOperation::Insert,
        ChangeOperation::Update,
        ChangeOperation::Delete,
    ] {
        if phase == ChangeOperation::Update || phase == ChangeOperation::Delete {
            legacy_links(
                native,
                branch,
                &ReplayPlan {
                    job,
                    header,
                    file,
                    target: &target,
                },
                budget,
                phase == ChangeOperation::Update,
            )
            .await?;
        }
        let ids: Vec<_> = if phase == ChangeOperation::Delete {
            order.iter().rev().copied().collect()
        } else {
            order.clone()
        };
        for table in ids {
            let mut input = reader(file)?;
            while let Some(change) = input.next_change().map_err(|_| Failure::Invalid)? {
                if change.table_id != table || change.operation != phase {
                    continue;
                }
                branch.validate_replay(job).await?;
                let mut change = change;
                if phase == ChangeOperation::Insert
                    && let Some(index) = legacy_parent_link(header, change.table_id)
                    && let Some(after) = &mut change.after
                {
                    after[index] = None;
                }
                guarded_change(native, branch, header, &target, &change, budget).await?;
            }
        }
    }
    Ok(())
}

struct ReplayPlan<'a> {
    job: i64,
    header: &'a ArtifactHeader,
    file: &'a File,
    target: &'a WriteTarget,
}

fn legacy_parent_link(header: &ArtifactHeader, table_id: i64) -> Option<usize> {
    if header.manifest.is_some() {
        return None;
    }
    let table = header
        .tables
        .iter()
        .find(|table| table.id == table_id && table.schema == "app" && table.table == "parents")?;
    let names: Vec<_> = table
        .columns
        .iter()
        .map(|column| column.name.as_str())
        .collect();
    if names != ["id", "tenant_id", "code", "parent_code", "label"] {
        return None;
    }
    Some(3)
}

async fn legacy_links(
    native: &mut Native,
    branch: &fg_protocol_common::BranchSession,
    plan: &ReplayPlan<'_>,
    budget: &mut TransactionBudget,
    inserted: bool,
) -> Result<(), Failure> {
    let mut input = reader(plan.file)?;
    while let Some(change) = input.next_change().map_err(|_| Failure::Invalid)? {
        let Some(index) = legacy_parent_link(plan.header, change.table_id) else {
            continue;
        };
        let row = if inserted && change.operation == ChangeOperation::Insert {
            change.after.as_ref()
        } else if !inserted && change.operation == ChangeOperation::Delete {
            change.before.as_ref()
        } else {
            None
        };
        let Some(row) = row.filter(|row| row[index].is_some()) else {
            continue;
        };
        let mut detached = row.clone();
        detached[index] = None;
        let transition = TypedChange {
            table_id: change.table_id,
            operation: ChangeOperation::Update,
            key: change.key.clone(),
            before: Some(if inserted {
                detached.clone()
            } else {
                row.clone()
            }),
            after: Some(if inserted { row.clone() } else { detached }),
        };
        branch.validate_replay(plan.job).await?;
        guarded_change(
            native,
            branch,
            plan.header,
            plan.target,
            &transition,
            budget,
        )
        .await?;
    }
    Ok(())
}

async fn guarded_change(
    native: &mut Native,
    branch: &fg_protocol_common::BranchSession,
    header: &ArtifactHeader,
    target: &WriteTarget,
    change: &TypedChange,
    budget: &mut TransactionBudget,
) -> Result<(), Failure> {
    let statement = replay_statement(header, change, target).map_err(|_| Failure::Invalid)?;
    branch.fresh_authorize().await?;
    let policy = branch.policy().await?;
    let rows = match execute(native, &statement.sql).await {
        Ok(rows) => rows,
        Err(error) => {
            budget
                .native_error(branch, &policy, statement.operation)
                .await;
            return Err(error);
        }
    };
    budget
        .evaluate(branch, &policy, statement.operation, rows)
        .await?;
    if rows != 1 {
        return Err(Failure::Invalid);
    }
    Ok(())
}

async fn verify(
    state: &Drain,
    permit: &ReplayPermit,
    expected: &File,
    header: &ArtifactHeader,
) -> Result<bool, Failure> {
    let (mut native, branch) = session(state, permit, true).await?;
    validate_binding(header, branch.binding())?;
    let actual = super::export::write_snapshot(&mut native, branch.binding(), state.engine).await?;
    let result = equal_files(expected, &actual)?;
    branch.fresh_authorize().await?;
    Ok(result)
}

pub(super) fn equal_files(expected: &File, actual: &File) -> Result<bool, Failure> {
    // File clones share an offset, but these are distinct source files and
    // each comparison consumes exactly one reader per source at a time.
    let mut left = reader(expected)?;
    let mut right = reader(actual)?;
    loop {
        let a = left.next_entry().map_err(|_| Failure::Invalid)?;
        let b = right.next_entry().map_err(|_| Failure::Invalid)?;
        if a != b {
            return Ok(false);
        }
        if a.is_none() {
            return Ok(true);
        }
    }
}

async fn execute(native: &mut Native, sql: &str) -> Result<u64, Failure> {
    match native {
        Native::MySql(connection) => Ok(connection.execute(sql).await?.rows_affected()),
        Native::Postgres(connection) => Ok(connection.execute(sql).await?.rows_affected()),
    }
}
