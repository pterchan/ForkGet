//! A bounded, owner-authorized snapshot over the pinned generation and branch.

mod document;
mod export;
mod replay;
pub(super) use export::route as export_route;
pub(super) use replay::{apply_route as replay_apply_route, verify_route as replay_verify_route};

use std::{future::poll_fn, time::Duration};

use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use fg_protocol_common::{
    BranchBinding, CatalogColumn, CatalogEntry, DiffRequest, ReplayOrigin, WireError, WriteTarget,
};
use fg_rewrite::{BranchId, Dialect, TableRef, TableShape, render_visible_relation};
use serde::Serialize;
use serde_json::json;
use sqlx::{Connection, Executor, MySqlConnection, PgConnection, Row};
use tokio::time::timeout;

use mongodb::{
    Client,
    bson::{Bson, Document, doc},
};

use crate::{Drain, internal_authorized, settings::NativeOptions};

pub(super) const CONCURRENT_LIMIT: usize = 4;
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(12);
const SCAN_LIMIT: usize = 20_000;
const CHANGE_LIMIT: usize = 4_096;
const REPORT_LIMIT: usize = 1024 * 1024;
const MAX_BYTEA_OCTETS: usize = fg_protocol_common::ARTIFACT_RECORD_LIMIT / 4;

pub(super) async fn route(
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
    if id <= 0 || request.principal.is_empty() {
        return Failure::Invalid.into_response();
    }
    let Ok(_slot) = state.diff_slots.try_acquire() else {
        return Failure::Unavailable.into_response();
    };
    match timeout(SNAPSHOT_TIMEOUT, snapshot(&state, id, &request)).await {
        Ok(Ok(report)) => ([(header::CONTENT_TYPE, "application/json")], report).into_response(),
        Ok(Err(error)) => error.into_response(),
        Err(_) => Failure::Unavailable.into_response(),
    }
}

#[derive(Debug)]
enum Failure {
    Wire(WireError),
    Invalid,
    Limit,
    Unavailable,
}

impl From<WireError> for Failure {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl From<sqlx::Error> for Failure {
    fn from(_: sqlx::Error) -> Self {
        Self::Unavailable
    }
}

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::Wire(WireError::Auth) => (
                StatusCode::UNAUTHORIZED,
                WireError::Auth.code(),
                "Authentication failed",
            ),
            Self::Wire(WireError::Branch) => (
                StatusCode::NOT_FOUND,
                WireError::Branch.code(),
                "Branch is unavailable for this principal",
            ),
            Self::Invalid => (
                StatusCode::BAD_REQUEST,
                WireError::Unsupported.code(),
                "Invalid row difference request",
            ),
            Self::Limit => (
                StatusCode::CONFLICT,
                WireError::Unsupported.code(),
                "Row difference exceeded the supported snapshot limits",
            ),
            _ => (
                StatusCode::SERVICE_UNAVAILABLE,
                WireError::Backend.code(),
                "A consistent row difference could not be captured",
            ),
        };
        (status, Json(json!({ "code": code, "message": message }))).into_response()
    }
}

enum Native {
    MySql(MySqlConnection),
    Postgres(PgConnection),
}

impl Native {
    async fn connect(options: &NativeOptions) -> Result<(Self, u32), Failure> {
        match options {
            NativeOptions::MySql(options) => {
                let mut connection = MySqlConnection::connect_with(options).await?;
                let id: u64 = sqlx::query_scalar("SELECT CAST(CONNECTION_ID() AS UNSIGNED)")
                    .fetch_one(&mut connection)
                    .await?;
                Ok((
                    Self::MySql(connection),
                    u32::try_from(id).map_err(|_| Failure::Unavailable)?,
                ))
            }
            NativeOptions::Postgres(options) => {
                let mut connection = PgConnection::connect_with(options).await?;
                let id: i32 = sqlx::query_scalar("SELECT pg_catalog.pg_backend_pid()")
                    .fetch_one(&mut connection)
                    .await?;
                Ok((Self::Postgres(connection), id.cast_unsigned()))
            }
            // This connection helper is SQL-only; document snapshots use
            // the native MongoDB client instead.
            NativeOptions::Mongo(_) => Err(Failure::Unavailable),
        }
    }

    const fn dialect(&self) -> Dialect {
        match self {
            Self::MySql(_) => Dialect::MySql,
            Self::Postgres(_) => Dialect::PostgreSql,
        }
    }

    async fn begin(&mut self, engine: &str) -> Result<(), Failure> {
        match self {
            Self::MySql(connection) => {
                connection.execute("SET TIME_ZONE = '+00:00'").await?;
                connection
                    .execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                    .await?;
                // TiDB rejects the trailing READ ONLY characteristic;
                // its REPEATABLE READ is snapshot isolation either way.
                let start = if engine == "tidb" {
                    "START TRANSACTION WITH CONSISTENT SNAPSHOT"
                } else {
                    "START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY"
                };
                connection.execute(start).await?;
            }
            Self::Postgres(connection) => {
                connection.execute("SET TIME ZONE 'UTC'").await?;
                connection
                    .execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
                    .await?;
            }
        }
        Ok(())
    }

    async fn rows(&mut self, sql: &str, count: usize) -> Result<Vec<Image>, Failure> {
        match self {
            Self::MySql(connection) => sqlx::query(sql)
                .fetch_all(connection)
                .await?
                .iter()
                .map(|row| decode(row, count))
                .collect(),
            Self::Postgres(connection) => sqlx::query(sql)
                .fetch_all(connection)
                .await?
                .iter()
                .map(|row| decode(row, count))
                .collect(),
        }
    }

    async fn changes(
        &mut self,
        sql: &str,
        count: usize,
        keys: &[usize],
        budget: &mut ChangeBudget,
    ) -> Result<Vec<Change>, Failure> {
        let mut changes = Vec::new();
        match self {
            Self::MySql(connection) => {
                let mut rows = sqlx::query(sql).fetch(connection);
                while let Some(row) = poll_fn(|context| rows.as_mut().poll_next(context)).await {
                    changes.push(budget.decode(&row?, count, keys)?);
                }
            }
            Self::Postgres(connection) => {
                let mut rows = sqlx::query(sql).fetch(connection);
                while let Some(row) = poll_fn(|context| rows.as_mut().poll_next(context)).await {
                    changes.push(budget.decode(&row?, count, keys)?);
                }
            }
        }
        Ok(changes)
    }
}

struct Image {
    baseline: bool,
    values: Vec<Option<String>>,
}

fn decode<R: Row>(row: &R, count: usize) -> Result<Image, Failure>
where
    usize: sqlx::ColumnIndex<R>,
    String: for<'row> sqlx::Decode<'row, R::Database> + sqlx::Type<R::Database>,
{
    let source: String = row.try_get_unchecked(0)?;
    let baseline = match source.as_str() {
        "base" => true,
        "current" => false,
        _ => return Err(Failure::Unavailable),
    };
    let values = decode_values(row, 1, count)?;
    Ok(Image { baseline, values })
}

fn decode_values<R: Row>(
    row: &R,
    start: usize,
    count: usize,
) -> Result<Vec<Option<String>>, Failure>
where
    usize: sqlx::ColumnIndex<R>,
    String: for<'row> sqlx::Decode<'row, R::Database> + sqlx::Type<R::Database>,
{
    (start..start + count)
        .map(|index| row.try_get_unchecked(index).map_err(Failure::from))
        .collect()
}

#[derive(Serialize)]
struct Report<'a> {
    format_version: u8,
    engine: &'a str,
    branch_id: i64,
    generation_id: i64,
    replay_origin: Option<&'a ReplayOrigin>,
    native_write: bool,
    tables: Vec<TableChanges<'a>>,
}

#[derive(Serialize)]
struct TableChanges<'a> {
    id: i64,
    schema: &'a str,
    table: &'a str,
    generated_key: Option<&'a str>,
    columns: &'a [CatalogColumn],
    changes: Vec<Change>,
}

#[derive(Serialize)]
struct Change {
    operation: &'static str,
    key: Vec<String>,
    before: Option<Vec<Option<String>>>,
    after: Option<Vec<Option<String>>>,
}

struct ChangeBudget {
    remaining: usize,
    bytes: usize,
}

impl ChangeBudget {
    fn decode<R: Row>(&mut self, row: &R, count: usize, keys: &[usize]) -> Result<Change, Failure>
    where
        usize: sqlx::ColumnIndex<R>,
        String: for<'row> sqlx::Decode<'row, R::Database> + sqlx::Type<R::Database>,
    {
        self.remaining = self.remaining.checked_sub(1).ok_or(Failure::Limit)?;
        let operation: String = row.try_get_unchecked(0)?;
        let (operation, before, after) = match operation.as_str() {
            "insert" => ("insert", None, Some(decode_values(row, count + 1, count)?)),
            "delete" => ("delete", Some(decode_values(row, 1, count)?), None),
            "update" => (
                "update",
                Some(decode_values(row, 1, count)?),
                Some(decode_values(row, count + 1, count)?),
            ),
            "oversize" => return Err(Failure::Limit),
            _ => return Err(Failure::Unavailable),
        };
        let key = row_key(
            before
                .as_ref()
                .or(after.as_ref())
                .ok_or(Failure::Unavailable)?,
            keys,
        )?;
        let change = Change {
            operation,
            key,
            before,
            after,
        };
        let bytes = serde_json::to_vec(&change)
            .map_err(|_| Failure::Unavailable)?
            .len();
        self.bytes = self.bytes.checked_sub(bytes).ok_or(Failure::Limit)?;
        Ok(change)
    }
}

async fn snapshot(state: &Drain, id: i64, request: &DiffRequest) -> Result<Vec<u8>, Failure> {
    if state.engine == "mongodb" {
        return mongo_snapshot(state, id, request).await;
    }
    let pending = state
        .router
        .begin_id(&request.principal, id, request.expires_at)
        .await?;
    let (mut native, native_id) = Native::connect(&state.observer).await?;
    let session = pending.activate(native_id)?;
    session.authorize().await?;
    let report = tokio::select! {
        biased;
        () = session.cancelled() => Err(Failure::Wire(WireError::Branch)),
        report = read(&mut native, session.binding(), state.engine) => report,
    };
    drop(native);
    let report = report?;
    session.authorize().await?;
    Ok(report)
}

async fn read(
    native: &mut Native,
    binding: &BranchBinding,
    engine: &str,
) -> Result<Vec<u8>, Failure> {
    native.begin(engine).await?;
    let mut tables = Vec::with_capacity(binding.tables.len());
    let mut budget = ChangeBudget {
        remaining: CHANGE_LIMIT,
        bytes: REPORT_LIMIT,
    };
    let target = binding
        .write_schema
        .as_ref()
        .map(|schema| {
            WriteTarget::new(&binding.engine, binding.id, schema).ok_or(Failure::Unavailable)
        })
        .transpose()?;
    for table in &binding.tables {
        let keys = ordered_keys(table)?;
        let changes = if target.is_none()
            && binding.read_strategy == fg_protocol_common::ReadStrategy::BaseOnly
        {
            Vec::new()
        } else if let Some(target) = &target {
            let sql = writable_diff_sql(native.dialect(), target, table, &keys, budget.remaining)?;
            native
                .changes(&sql, table.columns.len(), &keys, &mut budget)
                .await?
        } else {
            let sql = sparse_snapshot_sql(native.dialect(), binding, table, &keys)?;
            let rows = native.rows(&sql, table.columns.len()).await?;
            let changes = differences(rows, &keys, budget.remaining)?;
            budget.remaining -= changes.len();
            changes
        };
        tables.push(TableChanges {
            id: table.id,
            schema: &table.logical_schema,
            table: &table.logical_table,
            generated_key: table.generated_key.as_deref(),
            columns: &table.columns,
            changes,
        });
    }
    let report = serde_json::to_vec(&Report {
        format_version: 1,
        engine: &binding.engine,
        branch_id: binding.id,
        generation_id: binding.generation_id,
        replay_origin: binding.replay_origin.as_ref(),
        native_write: binding.write_schema.is_some(),
        tables,
    })
    .map_err(|_| Failure::Unavailable)?;
    if report.len() > REPORT_LIMIT {
        return Err(Failure::Limit);
    }
    Ok(report)
}

fn ordered_keys(table: &CatalogEntry) -> Result<Vec<usize>, Failure> {
    let mut keys: Vec<_> = table
        .columns
        .iter()
        .enumerate()
        .filter_map(|(index, column)| column.primary_key_ordinal.map(|ordinal| (ordinal, index)))
        .collect();
    keys.sort_unstable();
    if keys.is_empty()
        || keys.iter().enumerate().any(|(offset, &(ordinal, index))| {
            usize::from(ordinal) != offset + 1
                || !matches!(
                    table.columns[index].type_name.as_str(),
                    "smallint" | "int2" | "int" | "integer" | "int4" | "bigint" | "int8"
                )
        })
    {
        return Err(Failure::Unavailable);
    }
    Ok(keys.into_iter().map(|(_, index)| index).collect())
}

fn writable_diff_sql(
    dialect: Dialect,
    target: &WriteTarget,
    table: &CatalogEntry,
    keys: &[usize],
    remaining: usize,
) -> Result<String, Failure> {
    let keys = keys
        .iter()
        .map(|&index| table.columns[index].name.as_str())
        .collect::<Vec<_>>();
    let first_key = keys.first().ok_or(Failure::Unavailable)?;
    let baseline = relation(dialect, &table.base_schema, &table.base_table);
    let current = relation(
        dialect,
        target.schema(),
        &target.table(&table.logical_table),
    );
    let left_keys = key_list(dialect, "b", &keys);
    let right_keys = key_list(dialect, "c", &keys);
    let changed_keys = key_list(dialect, "k", &keys);
    let key_order = keys
        .iter()
        .map(|key| quote(dialect, key))
        .collect::<Vec<_>>()
        .join(", ");
    let join = key_join(dialect, &keys, ["b", "c"]);
    let before_join = key_join(dialect, &keys, ["k", "b"]);
    let after_join = key_join(dialect, &keys, ["k", "c"]);
    let no_before = format!("{} IS NULL", qualified(dialect, "b", first_key));
    let no_after = format!("{} IS NULL", qualified(dialect, "c", first_key));
    let equal = equal_values(dialect, table);
    let (images, overflow) = writable_projections(dialect, &table.columns)?;
    let limit = if remaining == usize::MAX {
        String::new()
    } else {
        format!("LIMIT {}", remaining + 1)
    };
    // Bound changed keys before projecting canonical row images. The reverse
    // anti-join finds inserts without relying on MySQL support for FULL JOIN.
    Ok(format!(
        "WITH changed_keys AS (
          SELECT {left_keys} FROM {baseline} AS b LEFT JOIN {current} AS c ON {join}
          WHERE {no_after} OR NOT ({equal})
          UNION ALL
          SELECT {right_keys} FROM {current} AS c
          WHERE NOT EXISTS (SELECT 1 FROM {baseline} AS b WHERE {join})
          ORDER BY {key_order} {limit}
         )
         SELECT CASE {overflow}WHEN {no_before} THEN 'insert'
             WHEN {no_after} THEN 'delete' ELSE 'update' END, {images}
         FROM changed_keys AS k
         LEFT JOIN {baseline} AS b ON {before_join}
         LEFT JOIN {current} AS c ON {after_join}
         ORDER BY {changed_keys}"
    ))
}

fn key_list(dialect: Dialect, alias: &str, keys: &[&str]) -> String {
    keys.iter()
        .map(|key| qualified(dialect, alias, key))
        .collect::<Vec<_>>()
        .join(", ")
}

fn key_join(dialect: Dialect, keys: &[&str], [left, right]: [&str; 2]) -> String {
    keys.iter()
        .map(|key| {
            format!(
                "{} = {}",
                qualified(dialect, left, key),
                qualified(dialect, right, key)
            )
        })
        .collect::<Vec<_>>()
        .join(" AND ")
}

fn equal_values(dialect: Dialect, table: &CatalogEntry) -> String {
    let comparisons = table.columns.iter().filter(|column| column.primary_key_ordinal.is_none())
        .map(|column| {
            let left = qualified(dialect, "b", &column.name);
            let right = qualified(dialect, "c", &column.name);
            match (dialect, fg_protocol_common::native_type(&column.type_name)) {
                (Dialect::MySql, Some(fg_protocol_common::SnapshotType::Text { .. })) =>
                    format!("CAST({left} AS BINARY) <=> CAST({right} AS BINARY)"),
                (Dialect::PostgreSql, Some(fg_protocol_common::SnapshotType::Text { .. })) =>
                    format!("pg_catalog.convert_to({left}, 'UTF8') IS NOT DISTINCT FROM pg_catalog.convert_to({right}, 'UTF8')"),
                (Dialect::MySql, _) => format!("{left} <=> {right}"),
                (Dialect::PostgreSql, _) => format!("{left} IS NOT DISTINCT FROM {right}"),
            }
        }).collect::<Vec<_>>();
    if comparisons.is_empty() {
        "TRUE".to_owned()
    } else {
        comparisons.join(" AND ")
    }
}

fn writable_projections(
    dialect: Dialect,
    columns: &[CatalogColumn],
) -> Result<(String, String), Failure> {
    let mut images = Vec::new();
    let mut oversized = Vec::new();
    for side in ["b", "c"] {
        for column in columns {
            let value = projection(dialect, side, column)?;
            if dialect == Dialect::PostgreSql && column.type_name == "bytea" {
                let name = qualified(dialect, side, &column.name);
                let check = format!("pg_catalog.octet_length({name}) > {MAX_BYTEA_OCTETS}");
                images.push(format!("CASE WHEN {check} THEN NULL ELSE {value} END"));
                oversized.push(check);
            } else {
                images.push(value);
            }
        }
    }
    let overflow = if oversized.is_empty() {
        String::new()
    } else {
        format!("WHEN {} THEN 'oversize' ", oversized.join(" OR "))
    };
    Ok((images.join(", "), overflow))
}

fn sparse_snapshot_sql(
    dialect: Dialect,
    binding: &BranchBinding,
    table: &CatalogEntry,
    keys: &[usize],
) -> Result<String, Failure> {
    let columns: Vec<_> = table
        .columns
        .iter()
        .map(|column| column.name.as_str())
        .collect();
    let selected = columns
        .iter()
        .map(|name| quote(dialect, name))
        .collect::<Vec<_>>()
        .join(", ");
    let sort_keys = keys
        .iter()
        .map(|&index| format!("images.{}", quote(dialect, columns[index])))
        .collect::<Vec<_>>()
        .join(", ");
    let projections = table
        .columns
        .iter()
        .map(|column| projection(dialect, "images", column))
        .collect::<Result<Vec<_>, _>>()?
        .join(", ");
    let baseline = relation(dialect, &table.base_schema, &table.base_table);
    let current = sparse_relation(dialect, binding, table, &columns, keys)?;
    let limit = SCAN_LIMIT + 1;
    Ok(format!(
        "SELECT images._fg_side, {projections} FROM (
          SELECT 'base' AS _fg_side, {selected} FROM {baseline}
          UNION ALL
          SELECT 'current' AS _fg_side, {selected} FROM {current}
         ) AS images ORDER BY {sort_keys}, images._fg_side LIMIT {limit}"
    ))
}

fn sparse_relation(
    dialect: Dialect,
    binding: &BranchBinding,
    table: &CatalogEntry,
    columns: &[&str],
    keys: &[usize],
) -> Result<String, Failure> {
    let primary_key: Vec<_> = keys.iter().map(|&index| columns[index]).collect();
    let shape = TableShape {
        base: TableRef {
            schema: &table.base_schema,
            table: &table.base_table,
        },
        delta: TableRef {
            schema: &table.delta_schema,
            table: &table.delta_table,
        },
        columns,
        primary_key: &primary_key,
    };
    let branch = BranchId::new(binding.id).map_err(|_| Failure::Unavailable)?;
    let sql = render_visible_relation(dialect, branch, &shape).map_err(|_| Failure::Unavailable)?;
    Ok(format!("({sql}) AS visible"))
}

fn projection(dialect: Dialect, side: &str, column: &CatalogColumn) -> Result<String, Failure> {
    let name = qualified(dialect, side, &column.name);
    use fg_protocol_common::SnapshotType;
    match (dialect, fg_protocol_common::native_type(&column.type_name)) {
        (Dialect::MySql, Some(SnapshotType::Binary { .. })) => Ok(format!("LOWER(HEX({name}))")),
        (Dialect::PostgreSql, Some(SnapshotType::Binary { .. })) => {
            Ok(format!("pg_catalog.encode({name}, 'hex')"))
        }
        (Dialect::MySql, Some(SnapshotType::Timestamp { .. })) => {
            Ok(format!("DATE_FORMAT({name}, '%Y-%m-%dT%H:%i:%s.%f')"))
        }
        (Dialect::PostgreSql, Some(SnapshotType::Timestamp { timezone: true, .. })) => Ok(format!(
            "pg_catalog.to_char({name} AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')"
        )),
        (
            Dialect::PostgreSql,
            Some(SnapshotType::Timestamp {
                timezone: false, ..
            }),
        ) => Ok(format!(
            "pg_catalog.to_char({name}, 'YYYY-MM-DD\"T\"HH24:MI:SS.US')"
        )),
        (Dialect::MySql, Some(_)) => Ok(format!("CAST({name} AS CHAR CHARACTER SET utf8mb4)")),
        (Dialect::PostgreSql, Some(_)) => Ok(format!("CAST({name} AS text)")),
        _ => Err(Failure::Unavailable),
    }
}

fn relation(dialect: Dialect, schema: &str, table: &str) -> String {
    format!("{}.{}", quote(dialect, schema), quote(dialect, table))
}

fn qualified(dialect: Dialect, side: &str, column: &str) -> String {
    format!("{side}.{}", quote(dialect, column))
}

fn quote(dialect: Dialect, identifier: &str) -> String {
    match dialect {
        Dialect::MySql => format!("`{}`", identifier.replace('`', "``")),
        Dialect::PostgreSql => format!("\"{}\"", identifier.replace('"', "\"\"")),
    }
}

fn differences(rows: Vec<Image>, keys: &[usize], remaining: usize) -> Result<Vec<Change>, Failure> {
    if rows.len() > SCAN_LIMIT {
        return Err(Failure::Limit);
    }
    let mut rows = rows.into_iter().peekable();
    let mut changes = Vec::new();
    while let Some(image) = rows.next() {
        let key = row_key(&image.values, keys)?;
        let peer = if rows.peek().is_some_and(|next| {
            keys.iter()
                .zip(&key)
                .all(|(&index, key)| next.values[index].as_ref() == Some(key))
        }) {
            rows.next()
        } else {
            None
        };
        let (operation, before, after) = match (image.baseline, peer) {
            (true, Some(peer)) if !peer.baseline && image.values == peer.values => continue,
            (true, Some(peer)) if !peer.baseline => {
                ("update", Some(image.values), Some(peer.values))
            }
            (true, None) => ("delete", Some(image.values), None),
            (false, None) => ("insert", None, Some(image.values)),
            _ => return Err(Failure::Unavailable),
        };
        if changes.len() == remaining {
            return Err(Failure::Limit);
        }
        changes.push(Change {
            operation,
            key,
            before,
            after,
        });
    }
    Ok(changes)
}

fn row_key(values: &[Option<String>], keys: &[usize]) -> Result<Vec<String>, Failure> {
    keys.iter()
        .map(|&index| values[index].clone().ok_or(Failure::Unavailable))
        .collect()
}

/// MongoDB document difference: the baseline is the pinned
/// generation collection, the current side is the materialized branch copy
/// (write branch) or the merged base+delta view (read branch). Documents
/// canonically serialize as relaxed extended JSON, keyed by `_id`.
async fn mongo_snapshot(state: &Drain, id: i64, request: &DiffRequest) -> Result<Vec<u8>, Failure> {
    let NativeOptions::Mongo(observer) = &*state.observer else {
        return Err(Failure::Unavailable);
    };
    let observer = observer.clone();
    let credential = mongodb::options::Credential::builder()
        .username(observer.user.clone())
        .password(observer.password.clone())
        .source(observer.auth_db.clone())
        .build();
    let options = mongodb::options::ClientOptions::builder()
        .hosts(vec![mongodb::options::ServerAddress::Tcp {
            host: observer.host.clone(),
            port: Some(observer.addr.port()),
        }])
        .credential(credential)
        .tls(observer.tls_ca.as_ref().map(|ca| {
            mongodb::options::Tls::Enabled(
                mongodb::options::TlsOptions::builder()
                    .ca_file_path(ca.clone())
                    .build(),
            )
        }))
        .max_pool_size(2)
        .build();
    let client = Client::with_options(options).map_err(|_| Failure::Unavailable)?;

    let pending = state
        .router
        .begin_id(&request.principal, id, request.expires_at)
        .await?;
    // The session pins the branch against cancellation. The drain registry
    // keys on a per-session id derived from the branch: mongod connection ids
    // would only describe one pooled connection of the diff client.
    let session = pending.activate(id as u32 ^ 0x6d6f6e67)?;
    session.authorize().await?;
    let report = mongo_diff(&client, &observer, session.binding()).await?;
    session.authorize().await?;
    Ok(report)
}

/// Synthetic column metadata for the one-column document encoding.
fn mongo_diff_columns() -> [CatalogColumn; 1] {
    [CatalogColumn {
        name: "document".to_owned(),
        type_name: "bson".to_owned(),
        nullable: false,
        primary_key_ordinal: Some(1),
    }]
}

async fn mongo_diff(
    client: &Client,
    _observer: &crate::settings::MongoObserver,
    binding: &BranchBinding,
) -> Result<Vec<u8>, Failure> {
    let target = binding
        .write_schema
        .clone()
        .map(|schema| {
            WriteTarget::new(&binding.engine, binding.id, &schema).ok_or(Failure::Unavailable)
        })
        .transpose()?;

    let columns = mongo_diff_columns();
    let mut tables = Vec::with_capacity(binding.tables.len());
    let mut budget = ChangeBudget {
        remaining: CHANGE_LIMIT,
        bytes: REPORT_LIMIT,
    };
    for table in &binding.tables {
        let changes =
            mongo_table_changes(client, binding, target.as_ref(), table, &mut budget).await?;
        tables.push(TableChanges {
            id: table.id,
            schema: &table.logical_schema,
            table: &table.logical_table,
            generated_key: table.generated_key.as_deref(),
            columns: &columns,
            changes,
        });
    }
    let report = serde_json::to_vec(&Report {
        format_version: 1,
        engine: &binding.engine,
        branch_id: binding.id,
        generation_id: binding.generation_id,
        replay_origin: binding.replay_origin.as_ref(),
        native_write: binding.write_schema.is_some(),
        tables,
    })
    .map_err(|_| Failure::Unavailable)?;
    if report.len() > REPORT_LIMIT {
        return Err(Failure::Limit);
    }
    Ok(report)
}

/// The current view of one table: the materialized copy on a write branch,
/// the merged base+delta aggregation on a read branch. Returns the database
/// to query, the collection name and (for the read branch) the full
/// aggregate command.
async fn mongo_current_source(
    client: &Client,
    binding: &BranchBinding,
    target: Option<&WriteTarget>,
    table: &CatalogEntry,
) -> Result<(mongodb::Database, String, Option<Document>), Failure> {
    if let Some(target) = target {
        return Ok((
            client.database(target.schema()),
            target.table(&table.logical_table),
            None,
        ));
    }
    let pipeline = fg_proto_mongo::read::merged_pipeline(table, binding.id, Vec::new(), true);
    let command = doc! {
        "aggregate": table.base_table.as_str(),
        "pipeline": pipeline,
        "cursor": {},
    };
    Ok((
        client.database(&table.base_schema),
        table.base_table.clone(),
        Some(command),
    ))
}

async fn mongo_load(
    database: &mongodb::Database,
    collection: &str,
    command: Option<Document>,
) -> Result<Vec<Document>, Failure> {
    if let Some(command) = command {
        let reply = database
            .run_command(command)
            .await
            .map_err(|_| Failure::Unavailable)?;
        let cursor = reply
            .get_document("cursor")
            .map_err(|_| Failure::Unavailable)?;
        let batch = cursor
            .get_array("firstBatch")
            .map_err(|_| Failure::Unavailable)?;
        Ok(batch
            .iter()
            .filter_map(|value| value.as_document().cloned())
            .collect())
    } else {
        let mut cursor = database
            .collection::<Document>(collection)
            .find(doc! {})
            .sort(doc! { "_id": 1i32 })
            .await
            .map_err(|_| Failure::Unavailable)?;
        let mut documents = Vec::new();
        while cursor.advance().await.map_err(|_| Failure::Unavailable)? {
            documents.push(
                cursor
                    .deserialize_current()
                    .map_err(|_| Failure::Unavailable)?,
            );
        }
        Ok(documents)
    }
}

async fn mongo_table_changes(
    client: &Client,
    binding: &BranchBinding,
    target: Option<&WriteTarget>,
    table: &CatalogEntry,
    budget: &mut ChangeBudget,
) -> Result<Vec<Change>, Failure> {
    let canonical = |document: &Document| -> Result<String, Failure> {
        serde_json::to_string(&serde_json::to_value(document).map_err(|_| Failure::Unavailable)?)
            .map_err(|_| Failure::Unavailable)
    };
    let base_database = client.database(&table.base_schema);
    let base = mongo_load(&base_database, &table.base_table, None).await?;
    let (database, collection, command) =
        mongo_current_source(client, binding, target, table).await?;
    let current = mongo_load(&database, &collection, command).await?;
    if base.len() > SCAN_LIMIT || current.len() > SCAN_LIMIT {
        return Err(Failure::Limit);
    }

    let mut changes = Vec::new();
    let mut base_iter = base.iter();
    let mut current_iter = current.iter();
    let mut base_next = base_iter.next();
    let mut current_next = current_iter.next();
    loop {
        match (base_next, current_next) {
            (Some(base), Some(current)) => {
                let base_id = bson_id(base);
                let current_id = bson_id(current);
                match base_id.cmp(&current_id) {
                    std::cmp::Ordering::Less => {
                        push_mongo_change(
                            &mut changes,
                            budget,
                            "delete",
                            &base_id,
                            Some(base),
                            None,
                        )?;
                        base_next = base_iter.next();
                    }
                    std::cmp::Ordering::Greater => {
                        push_mongo_change(
                            &mut changes,
                            budget,
                            "insert",
                            &current_id,
                            None,
                            Some(current),
                        )?;
                        current_next = current_iter.next();
                    }
                    std::cmp::Ordering::Equal => {
                        let (before, after) = (canonical(base)?, canonical(current)?);
                        if before != after {
                            push_mongo_change(
                                &mut changes,
                                budget,
                                "update",
                                &base_id,
                                Some(base),
                                Some(current),
                            )?;
                        }
                        base_next = base_iter.next();
                        current_next = current_iter.next();
                    }
                }
            }
            (Some(base), None) => {
                push_mongo_change(
                    &mut changes,
                    budget,
                    "delete",
                    &bson_id(base),
                    Some(base),
                    None,
                )?;
                base_next = base_iter.next();
            }
            (None, Some(current)) => {
                push_mongo_change(
                    &mut changes,
                    budget,
                    "insert",
                    &bson_id(current),
                    None,
                    Some(current),
                )?;
                current_next = current_iter.next();
            }
            (None, None) => break,
        }
    }
    Ok(changes)
}

fn push_mongo_change(
    changes: &mut Vec<Change>,
    budget: &mut ChangeBudget,
    operation: &'static str,
    id: &str,
    before: Option<&Document>,
    after: Option<&Document>,
) -> Result<(), Failure> {
    if changes.len() >= budget.remaining {
        return Err(Failure::Limit);
    }
    let encode = |document: &Document| -> Result<Vec<Option<String>>, Failure> {
        Ok(vec![Some(canonical_document(document)?)])
    };
    let (before, after) = match (before, after) {
        (Some(before), Some(after)) => (Some(encode(before)?), Some(encode(after)?)),
        (Some(before), None) => (Some(encode(before)?), None),
        (None, Some(after)) => (None, Some(encode(after)?)),
        (None, None) => return Err(Failure::Unavailable),
    };
    let change = Change {
        operation,
        key: vec![id.to_owned()],
        before: before.clone(),
        after: after.clone(),
    };
    let bytes = serde_json::to_vec(&change)
        .map_err(|_| Failure::Unavailable)?
        .len();
    budget.bytes = budget.bytes.checked_sub(bytes).ok_or(Failure::Limit)?;
    changes.push(change);
    Ok(())
}

/// Canonical document text: the driver's JSON encoding (deterministic for a
/// fixed mongod write).
fn canonical_document(document: &Document) -> Result<String, Failure> {
    serde_json::to_string(&serde_json::to_value(document).map_err(|_| Failure::Unavailable)?)
        .map_err(|_| Failure::Unavailable)
}

fn bson_id(document: &Document) -> String {
    match document.get("_id") {
        Some(Bson::ObjectId(oid)) => oid.to_string(),
        Some(Bson::String(text)) => text.clone(),
        Some(other) => match other.as_document() {
            Some(nested) => canonical_document(nested).unwrap_or_default(),
            None => serde_json::to_string(&serde_json::to_value(other).unwrap_or_default())
                .unwrap_or_default(),
        },
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(baseline: bool, tenant: &str, id: &str, value: Option<&str>) -> Image {
        Image {
            baseline,
            values: vec![
                Some(tenant.to_owned()),
                Some(id.to_owned()),
                value.map(str::to_owned),
            ],
        }
    }

    #[test]
    fn computes_net_changes_on_composite_keys() -> Result<(), Failure> {
        let rows = vec![
            image(true, "1", "2", None),
            image(false, "1", "2", None),
            image(true, "1", "3", None),
            image(false, "1", "3", Some("00ff")),
            image(true, "2", "2", Some("")),
            image(false, "2", "3", None),
        ];
        let changes = differences(rows, &[0, 1], 3)?;
        assert_eq!(
            changes
                .iter()
                .map(|change| change.operation)
                .collect::<Vec<_>>(),
            ["update", "delete", "insert"]
        );
        assert_eq!(changes[0].key, ["1", "3"]);
        assert_eq!(
            changes[1].before.as_ref().and_then(|row| row[2].as_deref()),
            Some("")
        );
        assert_eq!(
            changes[2].after.as_ref().and_then(|row| row[2].as_deref()),
            None
        );
        Ok(())
    }

    #[test]
    fn refuses_an_incomplete_or_ambiguous_report() {
        let insert = vec![image(false, "1", "1", None)];
        assert!(matches!(
            differences(insert, &[0, 1], 0),
            Err(Failure::Limit)
        ));
        let duplicate = vec![image(false, "1", "1", None), image(false, "1", "1", None)];
        assert!(matches!(
            differences(duplicate, &[0, 1], 2),
            Err(Failure::Unavailable)
        ));
    }

    #[test]
    fn writable_filter_compares_complete_keys_and_binary_text() -> Result<(), Failure> {
        for (dialect, integer, text, bytes) in [
            (Dialect::MySql, "int", "varchar(64)", "varbinary(16)"),
            (
                Dialect::PostgreSql,
                "integer",
                "character varying(64)",
                "bytea",
            ),
        ] {
            let column = |name: &str, type_name: &str, key: Option<u16>| CatalogColumn {
                name: name.to_owned(),
                type_name: type_name.to_owned(),
                nullable: key.is_none(),
                primary_key_ordinal: key,
            };
            let table = CatalogEntry {
                id: 1,
                baseline_rows: 25_001,
                logical_schema: "app".to_owned(),
                logical_table: "orders".to_owned(),
                base_schema: "fg_g1".to_owned(),
                base_table: "orders".to_owned(),
                delta_schema: "forkget_delta".to_owned(),
                delta_table: "_d_g1_t1".to_owned(),
                generated_key: None,
                columns: vec![
                    column("id", "bigint", Some(2)),
                    column("tenant_id", integer, Some(1)),
                    column("note", text, None),
                    column("payload", bytes, None),
                ],
            };
            let keys = ordered_keys(&table)?;
            let target = WriteTarget::for_branch(17, dialect == Dialect::MySql);
            let sql = writable_diff_sql(dialect, &target, &table, &keys, 3)?;
            let tenant = quote(dialect, "tenant_id");
            let id = quote(dialect, "id");
            assert!(sql.contains(&format!("b.{tenant} = c.{tenant} AND b.{id} = c.{id}")));
            assert!(sql.contains(&format!("ORDER BY {tenant}, {id} LIMIT 4")));
            assert!(sql.ends_with(&format!("ORDER BY k.{tenant}, k.{id}")));
            if dialect == Dialect::MySql {
                assert!(sql.contains("`fgwrite`.`fg_b17_orders`"));
                assert!(sql.contains("CAST(b.`note` AS BINARY) <=> CAST(c.`note` AS BINARY)"));
                assert!(sql.contains("b.`payload` <=> c.`payload`"));
            } else {
                assert!(
                    sql.contains("pg_catalog.convert_to(b.\"note\", 'UTF8') IS NOT DISTINCT FROM")
                );
                assert!(sql.contains("b.\"payload\" IS NOT DISTINCT FROM c.\"payload\""));
                assert!(sql.contains("THEN 'oversize'"));
            }
        }
        Ok(())
    }
}
