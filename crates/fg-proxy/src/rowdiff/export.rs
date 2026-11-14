use std::{
    fs::File,
    io::{Seek, SeekFrom},
    time::Duration,
};

use axum::{
    Json,
    body::Body,
    extract::{Path, State, rejection::JsonRejection},
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
};
use fg_protocol_common::{
    ARTIFACT_LIMIT, ArtifactHeader, ArtifactTable, ArtifactWriter, ChangeOperation, TypedChange,
};
use tokio_util::io::ReaderStream;

use super::*;

const EXPORT_TIMEOUT: Duration = Duration::from_secs(300);

pub(crate) async fn route(
    State(state): State<Drain>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    request: Result<Json<DiffRequest>, JsonRejection>,
) -> Response {
    if !internal_authorized(&headers, &state.token) {
        return Failure::Wire(WireError::Auth).into_response();
    }
    let Ok(Json(request)) = request else {
        return Failure::Invalid.into_response();
    };
    let Ok(slot) = state.diff_slots.clone().try_acquire_owned() else {
        return Failure::Unavailable.into_response();
    };
    match timeout(EXPORT_TIMEOUT, capture(&state, id, &request)).await {
        Ok(Ok(mut file)) => {
            if file.seek(SeekFrom::Start(0)).is_err() {
                return Failure::Unavailable.into_response();
            }
            let body = Body::from_stream(ExportStream {
                stream: ReaderStream::new(tokio::fs::File::from_std(file)),
                _slot: slot,
            });
            ([(header::CONTENT_TYPE, "application/x-ndjson")], body).into_response()
        }
        Ok(Err(error)) => error.into_response(),
        Err(_) => Failure::Unavailable.into_response(),
    }
}

// Keep the capture slot until the private file is consumed or the downloader
// disconnects. Slow clients must not accumulate unbounded completed spools.
struct ExportStream {
    stream: ReaderStream<tokio::fs::File>,
    _slot: tokio::sync::OwnedSemaphorePermit,
}

impl futures_core::Stream for ExportStream {
    type Item = <ReaderStream<tokio::fs::File> as futures_core::Stream>::Item;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::pin::Pin::new(&mut self.stream).poll_next(context)
    }
}

pub(super) async fn capture(
    state: &Drain,
    id: i64,
    request: &DiffRequest,
) -> Result<File, Failure> {
    if state.engine == "mongodb" {
        return super::document::capture(state, id, request).await;
    }
    let pending = state
        .router
        .begin_id(&request.principal, id, request.expires_at)
        .await?;
    let (mut native, native_id) = Native::connect(&state.observer).await?;
    let session = pending.activate(native_id)?;
    session.fresh_authorize().await?;
    let result = tokio::select! {
        biased;
        () = session.cancelled() => Err(Failure::Wire(WireError::Branch)),
        result = write_snapshot(&mut native, session.binding(), state.engine) => result,
    };
    drop(native);
    session.fresh_authorize().await?;
    result
}

pub(super) fn artifact_header(binding: &BranchBinding) -> Result<ArtifactHeader, Failure> {
    Ok(ArtifactHeader {
        format_version: fg_protocol_common::ARTIFACT_VERSION,
        engine: binding.engine.clone(),
        source_branch_id: binding.id,
        origin: binding.replay_origin.clone().ok_or(Failure::Unavailable)?,
        native_write: binding.write_schema.is_some(),
        manifest: binding.snapshot_manifest.clone(),
        tables: binding
            .tables
            .iter()
            .map(|table| ArtifactTable {
                id: table.id,
                schema: table.logical_schema.clone(),
                table: table.logical_table.clone(),
                generated_key: table.generated_key.clone(),
                columns: table.columns.clone(),
            })
            .collect(),
    })
}

pub(super) async fn write_snapshot(
    native: &mut Native,
    binding: &BranchBinding,
    engine: &str,
) -> Result<File, Failure> {
    native.begin(engine).await?;
    let header = artifact_header(binding)?;
    let file = tempfile::tempfile().map_err(|_| Failure::Unavailable)?;
    let mut writer = ArtifactWriter::new(file, header).map_err(|_| Failure::Invalid)?;
    let target = binding
        .write_schema
        .as_ref()
        .map(|schema| WriteTarget::new(engine, binding.id, schema).ok_or(Failure::Unavailable))
        .transpose()?;
    for table in &binding.tables {
        if target.is_none() && binding.read_strategy == fg_protocol_common::ReadStrategy::BaseOnly {
            continue;
        }
        let keys = ordered_keys(table)?;
        let sql = if let Some(target) = &target {
            writable_diff_sql(native.dialect(), target, table, &keys, usize::MAX)?
        } else {
            // This is our generated query, not a rewritten client statement.
            sparse_snapshot_sql(native.dialect(), binding, table, &keys)?
                .replace(&format!(" LIMIT {}", SCAN_LIMIT + 1), "")
        };
        stream_table(native, &sql, table, &keys, target.is_some(), &mut writer).await?;
    }
    let file = writer.finish(Vec::new()).map_err(|_| Failure::Limit)?;
    file.sync_all().map_err(|_| Failure::Unavailable)?;
    Ok(file)
}

async fn stream_table(
    native: &mut Native,
    sql: &str,
    table: &CatalogEntry,
    keys: &[usize],
    writable: bool,
    writer: &mut ArtifactWriter<File>,
) -> Result<(), Failure> {
    let mut budget = ChangeBudget {
        remaining: usize::MAX,
        bytes: ARTIFACT_LIMIT as usize,
    };
    let mut pending: Vec<Image> = Vec::with_capacity(2);
    macro_rules! stream {
        ($connection:expr) => {{
            let mut rows = sqlx::query(sql).fetch($connection);
            while let Some(row) = poll_fn(|context| rows.as_mut().poll_next(context)).await {
                let row = row?;
                if writable {
                    let change = budget.decode(&row, table.columns.len(), keys)?;
                    write_change(writer, table.id, change)?;
                } else {
                    let image = decode(&row, table.columns.len())?;
                    if let Some(first) = pending.first() {
                        if row_key(&first.values, keys)? != row_key(&image.values, keys)? {
                            flush_images(writer, table.id, &mut pending, keys)?;
                        }
                    }
                    pending.push(image);
                    if pending.len() > 2 {
                        return Err(Failure::Unavailable);
                    }
                }
            }
        }};
    }
    match native {
        Native::MySql(connection) => stream!(connection),
        Native::Postgres(connection) => stream!(connection),
    }
    flush_images(writer, table.id, &mut pending, keys)
}

fn flush_images(
    writer: &mut ArtifactWriter<File>,
    table: i64,
    images: &mut Vec<Image>,
    keys: &[usize],
) -> Result<(), Failure> {
    for change in differences(std::mem::take(images), keys, usize::MAX)? {
        write_change(writer, table, change)?;
    }
    Ok(())
}

fn write_change(
    writer: &mut ArtifactWriter<File>,
    table_id: i64,
    change: Change,
) -> Result<(), Failure> {
    let operation = match change.operation {
        "insert" => ChangeOperation::Insert,
        "update" => ChangeOperation::Update,
        "delete" => ChangeOperation::Delete,
        _ => return Err(Failure::Unavailable),
    };
    writer
        .change(TypedChange {
            table_id,
            operation,
            key: change.key,
            before: change.before,
            after: change.after,
        })
        .map_err(|_| Failure::Limit)
}
