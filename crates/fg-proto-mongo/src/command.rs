//! The admitted-command dispatcher binds the branch from the
//! first data command's `$db`, forwards only the
//! pre-bind liveness allowlist to mongod, and serves the admitted subset —
//! reads through `read`'s merged pipelines, writes through `write`'s delta
//! capture — with every refusal typed through the WireError registry.

use std::collections::HashMap;

use bson::{Document, doc};
use fg_protocol_common::{
    AuditAttempt, BranchSession, CatalogEntry, MongoObservationState, MongoWriteObservation,
    Router, TransactionBudget, WireError, WriteKind,
};

use crate::backend::Backend;
use crate::observation::{NativeWriteCategory, NativeWriteObservation, observe_write};
use crate::read::{self, CursorState};
use crate::session::{error_document, ok_document, reply};
use crate::wire::{Message, OpMsg};
use crate::{Error, write};

/// mongod-reserved databases; commands addressed here are never branch data.
pub(crate) const RESERVED_DATABASES: [&str; 3] = ["admin", "local", "config"];

/// Liveness commands mongod answers before any branch is bound.
const LIVENESS_ALLOWLIST: [&str; 2] = ["ping", "buildInfo"];

/// Teardown commands drivers send that have no backend meaning under the
/// standalone topology (no driver sessions to end).
const TEARDOWN_ALLOWLIST: [&str; 2] = ["endSessions", "logout"];

/// Synthetic cursor ids start here so a mongod id can never collide.
const FIRST_CURSOR_ID: i64 = 1_000_000_000;
/// mongod's code for getMore against an unknown cursor id.
const CURSOR_NOT_FOUND: i32 = 13011;

/// The control-plane session bound after the first data command, plus the
/// per-session capture state: policy budget and replayed-cursor registry.
pub(crate) struct BoundSession {
    pub(crate) session: BranchSession,
    budget: TransactionBudget,
    cursors: HashMap<i64, CursorState>,
    next_cursor: i64,
    attempt: Option<AuditAttempt>,
    previous: Option<MongoWriteObservation>,
    possible_sends: u64,
}

impl BoundSession {
    fn new(session: BranchSession) -> Self {
        Self {
            session,
            budget: TransactionBudget::default(),
            cursors: HashMap::new(),
            next_cursor: FIRST_CURSOR_ID,
            attempt: None,
            previous: None,
            possible_sends: 0,
        }
    }

    fn branch_id(&self) -> i64 {
        self.session.binding().id
    }

    async fn arm_write(&mut self) -> Result<(), WireError> {
        if self.attempt.is_none() {
            self.attempt = self.budget.attempt().cloned();
        }
        let attempt = self.attempt.as_mut().ok_or(WireError::Backend)?;
        self.session.fresh_authorize().await?;
        self.budget.validate_for_commit(&self.session).await?;
        let previous = self.previous.take();
        let before = attempt.armed_step();
        if let Err(error) = self.session.arm_mongo_step(attempt, previous.clone()).await {
            // A possible new arm must not reuse the previous step's ACK as
            // proof for that new step when its HTTP response is lost.
            if attempt.armed_step() == before {
                self.previous = previous;
            }
            return Err(error);
        }
        self.possible_sends = self
            .possible_sends
            .checked_add(1)
            .ok_or(WireError::Backend)?;
        Ok(())
    }

    async fn finish_write(&mut self, failed: bool) {
        let attempt = self.attempt.take().or_else(|| self.budget.take_attempt());
        let mut observation = self
            .previous
            .take()
            .unwrap_or_else(|| MongoWriteObservation {
                state: if self.possible_sends == 0 {
                    MongoObservationState::NotSent
                } else {
                    MongoObservationState::Unknown
                },
                ..Default::default()
            });
        if failed && observation.state == MongoObservationState::Acknowledged {
            observation.state = MongoObservationState::AcknowledgedWithErrors;
        }
        if let Some(attempt) = attempt.filter(AuditAttempt::intent_possible) {
            // A failed delivery applies router-wide write backpressure; a
            // confirmed native reply must not become a fabricated rollback.
            let _ = self
                .session
                .finish_mongo_attempt(&attempt, observation)
                .await;
        }
        self.possible_sends = 0;
        self.budget.reset();
    }
}

/// One authenticated command plus the per-session facts the dispatcher
/// needs to bind, authorize and correlate its reply.
pub(crate) struct CommandContext<'a> {
    pub request: &'a Message,
    pub op_msg: &'a OpMsg,
    pub document: &'a Document,
    pub name: &'a str,
    pub principal: &'a str,
    pub expires_at: i64,
    pub connection_id: i32,
}

/// Dispatch one authenticated command. Every path either replies through the
/// frontend or forwards the frame byte-exact; a refusal never closes the
/// connection (mirroring mongod, which keeps the socket open on errors).
pub(crate) async fn dispatch(
    router: &Router,
    backend: &mut Backend,
    bound: &mut Option<BoundSession>,
    command: CommandContext<'_>,
) -> Result<Vec<u8>, Error> {
    if matches!(command.name, "insert" | "update" | "delete") {
        // An unacknowledged client must not receive a fabricated response,
        // and its write must never reach the native socket.
        if command.op_msg.more_to_come {
            return Err(Error::Invalid);
        }
        if let Err(error) = write::require_acknowledged(command.document) {
            return reply(
                command.connection_id,
                command.request.request_id,
                &wire_refusal(&error),
            );
        }
    }
    let database = command.document.get_str("$db").unwrap_or("admin");
    if RESERVED_DATABASES.contains(&database) {
        return reserved_database(backend, &command).await;
    }
    let bound = match bound {
        Some(bound) if bound.session.binding().name != database => {
            return reply(
                command.connection_id,
                command.request.request_id,
                &refusal(
                    WireError::Branch,
                    &format!(
                        "commands must stay on the bound branch '{}'",
                        bound.session.binding().name
                    ),
                ),
            );
        }
        Some(bound) => bound,
        None => {
            let pending = match router
                .begin(command.principal, database, command.expires_at)
                .await
            {
                Ok(pending) => pending,
                Err(error) => {
                    return reply(
                        command.connection_id,
                        command.request.request_id,
                        &binding_failure(&error, database),
                    );
                }
            };
            let session = match pending.activate(backend.connection_id()) {
                Ok(session) => session,
                Err(error) => {
                    return reply(
                        command.connection_id,
                        command.request.request_id,
                        &binding_failure(&error, database),
                    );
                }
            };
            bound.insert(BoundSession::new(session))
        }
    };
    data_command(bound, backend, &command).await
}

/// Branch-scoped commands: liveness re-check per command (the SQL
/// frontends' per-command authorize), then the admitted subset. Standalone
/// write observations retain partial results and uncertainty.
async fn data_command(
    bound: &mut BoundSession,
    backend: &mut Backend,
    command: &CommandContext<'_>,
) -> Result<Vec<u8>, Error> {
    if let Err(error) = bound.session.authorize().await {
        return reply(
            command.connection_id,
            command.request.request_id,
            &wire_refusal(&error),
        );
    }
    let outcome: Result<Vec<u8>, WireError> = match command.name {
        "find" => find(bound, backend, command).await,
        "aggregate" => aggregate(bound, backend, command).await,
        "count" => count(bound, backend, command).await,
        "distinct" => distinct(bound, backend, command).await,
        "getMore" => get_more(bound, backend, command).await,
        "killCursors" => kill_cursors(bound, command),
        "insert" | "update" | "delete" => capture(bound, backend, command).await,
        "listCollections" => list_collections(bound, command),
        _ => ok_reply(
            command.connection_id,
            command.request.request_id,
            &refusal(
                WireError::Unsupported,
                &format!(
                    "command '{}' is not in the admitted MongoDB subset",
                    command.name
                ),
            ),
        ),
    };
    if matches!(command.name, "insert" | "update" | "delete") {
        bound.finish_write(outcome.is_err()).await;
    }
    match outcome {
        Ok(reply_bytes) => Ok(reply_bytes),
        Err(error) => {
            if !backend.is_usable() {
                return Err(Error::Invalid);
            }
            Ok(reply(
                command.connection_id,
                command.request.request_id,
                &wire_refusal(&error),
            )?)
        }
    }
}

/// Resolve a driver collection name to its registered catalog entry.
fn catalog_entry(bound: &BoundSession, collection: &str) -> Result<CatalogEntry, WireError> {
    bound
        .session
        .binding()
        .tables
        .iter()
        .find(|entry| entry.logical_table == collection)
        .cloned()
        .ok_or(WireError::SqlObject)
}

/// The physical entry a command runs against plus whether the branch owns a
/// materialized copy. On a write branch the entry points at the branch
/// database with the same collection name, so every command handler needs
/// only this pair to choose direct-copy or merged-view execution.
fn resolve_entry(
    bound: &BoundSession,
    collection: &str,
) -> Result<(CatalogEntry, bool), WireError> {
    let entry = catalog_entry(bound, collection)?;
    match bound.session.binding().write_schema.clone() {
        Some(database) => Ok((
            CatalogEntry {
                base_schema: database,
                base_table: entry.logical_table.clone(),
                delta_schema: String::new(),
                delta_table: String::new(),
                ..entry
            },
            true,
        )),
        None => Ok((entry, false)),
    }
}

fn collection_name(command: &CommandContext<'_>) -> Result<String, WireError> {
    command
        .document
        .get_str(command.name)
        .map(str::to_owned)
        .map_err(|_| WireError::InvalidValue)
}

fn first_batch(reply: &Document) -> Result<Vec<bson::Bson>, WireError> {
    reply
        .get_document("cursor")
        .map_err(|_| WireError::Backend)?
        .get_array("firstBatch")
        .map_err(|_| WireError::Backend)
        .cloned()
}

fn mongod_cursor_live(reply: &Document) -> bool {
    reply
        .get_document("cursor")
        .and_then(|cursor| cursor.get_i64("id"))
        .map(|id| id != 0)
        .unwrap_or(false)
}

async fn run_merged(
    backend: &mut Backend,
    entry: &CatalogEntry,
    pipeline: Vec<Document>,
    batch_size: Option<i64>,
) -> Result<Document, WireError> {
    let mut command = read::aggregate_command(entry, pipeline, batch_size);
    command.insert("$db", entry.base_schema.clone());
    backend
        .command(&command)
        .await
        .map_err(|_| WireError::Backend)
}

/// A live mongod cursor becomes a proxy-owned replay cursor.
fn register_cursor(
    bound: &mut BoundSession,
    entry: &CatalogEntry,
    pipeline: Vec<Document>,
    fetched: i64,
) -> i64 {
    let binding = bound.session.binding();
    let id = bound.next_cursor;
    bound.next_cursor += 1;
    bound.cursors.insert(
        id,
        CursorState {
            pipeline,
            base_db: entry.base_schema.clone(),
            base_coll: entry.base_table.clone(),
            driver_db: binding.name.clone(),
            driver_coll: entry.logical_table.clone(),
            fetched,
        },
    );
    id
}

// ---------------------------------------------------------------- reads

async fn find(
    bound: &mut BoundSession,
    backend: &mut Backend,
    command: &CommandContext<'_>,
) -> Result<Vec<u8>, WireError> {
    let collection = collection_name(command)?;
    let (entry, native) = resolve_entry(bound, &collection)?;
    let branch_id = bound.branch_id();
    let stages = read::find_stages(command.document);
    let batch_size = read::positive_int(command.document.get("batchSize"));
    let pipeline = read::step_pipeline(&entry, branch_id, stages, true, native);
    let mut reply_document = run_merged(backend, &entry, pipeline.clone(), batch_size).await?;
    let fetched = first_batch(&reply_document)?.len() as i64;
    let synthetic = mongod_cursor_live(&reply_document)
        .then(|| register_cursor(bound, &entry, pipeline, fetched));
    read::rewrite_reply(
        &mut reply_document,
        &bound.session.binding().name,
        &entry.logical_table,
        synthetic,
    )?;
    ok_reply(
        command.connection_id,
        command.request.request_id,
        &reply_document,
    )
}

async fn aggregate(
    bound: &mut BoundSession,
    backend: &mut Backend,
    command: &CommandContext<'_>,
) -> Result<Vec<u8>, WireError> {
    let collection = collection_name(command)?;
    let (entry, native) = resolve_entry(bound, &collection)?;
    let branch_id = bound.branch_id();
    let driver_pipeline = command
        .document
        .get_array("pipeline")
        .map_err(|_| WireError::InvalidValue)?
        .iter()
        .map(|stage| stage.as_document().cloned().ok_or(WireError::InvalidValue))
        .collect::<Result<Vec<_>, _>>()?;
    let stages = read::admitted_stages(&driver_pipeline)?;
    let pipeline = read::step_pipeline(&entry, branch_id, stages, true, native);
    let mut reply_document = run_merged(backend, &entry, pipeline.clone(), None).await?;
    let fetched = first_batch(&reply_document)?.len() as i64;
    let synthetic = mongod_cursor_live(&reply_document)
        .then(|| register_cursor(bound, &entry, pipeline, fetched));
    read::rewrite_reply(
        &mut reply_document,
        &bound.session.binding().name,
        &entry.logical_table,
        synthetic,
    )?;
    ok_reply(
        command.connection_id,
        command.request.request_id,
        &reply_document,
    )
}

async fn count(
    bound: &mut BoundSession,
    backend: &mut Backend,
    command: &CommandContext<'_>,
) -> Result<Vec<u8>, WireError> {
    let collection = collection_name(command)?;
    let entry = catalog_entry(bound, &collection)?;
    let branch_id = bound.branch_id();
    let stages = read::count_stages(command.document);
    let reply_document = run_merged(
        backend,
        &entry,
        read::merged_pipeline(&entry, branch_id, stages, false),
        None,
    )
    .await?;
    let total = first_batch(&reply_document)?
        .first()
        .and_then(|value| value.as_document())
        .and_then(|document| document.get_i32("n").ok())
        .ok_or(WireError::Backend)?;
    ok_reply(
        command.connection_id,
        command.request.request_id,
        &doc! { "n": total, "ok": 1.0 },
    )
}

async fn distinct(
    bound: &mut BoundSession,
    backend: &mut Backend,
    command: &CommandContext<'_>,
) -> Result<Vec<u8>, WireError> {
    let collection = collection_name(command)?;
    let entry = catalog_entry(bound, &collection)?;
    let branch_id = bound.branch_id();
    let key = command
        .document
        .get_str("key")
        .map_err(|_| WireError::InvalidValue)?;
    let stages = read::distinct_stages(key, command.document);
    let reply_document = run_merged(
        backend,
        &entry,
        read::merged_pipeline(&entry, branch_id, stages, false),
        None,
    )
    .await?;
    let values: Vec<bson::Bson> = first_batch(&reply_document)?
        .iter()
        .filter_map(|value| {
            value
                .as_document()
                .and_then(|document| document.get("_id"))
                .cloned()
        })
        .collect();
    ok_reply(
        command.connection_id,
        command.request.request_id,
        &doc! { "values": values, "ok": 1.0 },
    )
}

async fn get_more(
    bound: &mut BoundSession,
    backend: &mut Backend,
    command: &CommandContext<'_>,
) -> Result<Vec<u8>, WireError> {
    let id = read::positive_int(command.document.get("getMore"))
        .or_else(|| command.document.get_i64("getMore").ok())
        .ok_or(WireError::InvalidValue)?;
    let Some(state) = bound.cursors.get(&id) else {
        return ok_reply(
            command.connection_id,
            command.request.request_id,
            &error_document(&format!("cursor id {id} not found"), CURSOR_NOT_FOUND),
        );
    };
    let batch_size = read::positive_int(command.document.get("batchSize"));
    let mut continuation = state.continuation(batch_size);
    continuation.insert("$db", state.base_db.clone());
    let mut reply_document = backend
        .command(&continuation)
        .await
        .map_err(|_| WireError::Backend)?;
    let delivered = first_batch(&reply_document)?.len() as i64;
    let exhausted = !mongod_cursor_live(&reply_document);
    let state = bound.cursors.get_mut(&id).ok_or(WireError::Backend)?;
    state.fetched += delivered;
    read::rewrite_reply(
        &mut reply_document,
        &state.driver_db,
        &state.driver_coll,
        Some(if exhausted { 0 } else { id }),
    )?;
    // A continuation batch is `nextBatch` in the driver contract; mongod's
    // aggregate reply names it `firstBatch`.
    if let Ok(cursor) = reply_document.get_document_mut("cursor")
        && let Some(batch) = cursor.remove("firstBatch")
    {
        cursor.insert("nextBatch", batch);
    }
    if exhausted {
        bound.cursors.remove(&id);
    }
    ok_reply(
        command.connection_id,
        command.request.request_id,
        &reply_document,
    )
}

fn kill_cursors(
    bound: &mut BoundSession,
    command: &CommandContext<'_>,
) -> Result<Vec<u8>, WireError> {
    let ids = command
        .document
        .get_array("cursors")
        .map_err(|_| WireError::InvalidValue)?;
    let mut killed = Vec::new();
    let mut missing = Vec::new();
    for id in ids {
        let parsed = id.as_i64().ok_or(WireError::InvalidValue)?;
        if bound.cursors.remove(&parsed).is_some() {
            killed.push(id.clone());
        } else {
            missing.push(id.clone());
        }
    }
    ok_reply(
        command.connection_id,
        command.request.request_id,
        &doc! {
            "cursorsKilled": killed,
            "cursorsNotFound": missing,
            "cursorsAlive": [],
            "cursorsUnknown": [],
            "ok": 1.0,
        },
    )
}

fn list_collections(
    bound: &BoundSession,
    command: &CommandContext<'_>,
) -> Result<Vec<u8>, WireError> {
    let binding = bound.session.binding();
    let first: Vec<bson::Bson> = binding
        .tables
        .iter()
        .map(|entry| {
            bson::Bson::Document(doc! {
                "name": entry.logical_table.clone(),
                "type": "collection",
            })
        })
        .collect();
    ok_reply(
        command.connection_id,
        command.request.request_id,
        &doc! {
            "cursor": {
                "id": 0i64,
                "ns": format!("{}.$cmd.listCollections", binding.name),
                "firstBatch": first,
            },
            "ok": 1.0,
        },
    )
}

// ---------------------------------------------------------------- writes

/// Insert capture: identity conflicts are checked against the merged view,
/// then every accepted document lands as a full-image `I` delta entry.
async fn insert(
    bound: &mut BoundSession,
    backend: &mut Backend,
    command: &CommandContext<'_>,
) -> Result<Vec<u8>, WireError> {
    let collection = collection_name(command)?;
    let entry = catalog_entry(bound, &collection)?;
    let branch_id = bound.branch_id();
    let documents = command
        .document
        .get_array("documents")
        .map_err(|_| WireError::InvalidValue)?;
    let ordered = write::optional_bool(command.document, "ordered", true)?;
    let mut images = Vec::with_capacity(documents.len());
    for value in documents {
        let mut image = value
            .as_document()
            .cloned()
            .ok_or(WireError::InvalidValue)?;
        if !image.contains_key("_id") {
            image.insert("_id", bson::Bson::ObjectId(bson::oid::ObjectId::new()));
        }
        images.push(image);
    }
    let capture = write::Capture {
        entry: &entry,
        branch_id,
    };
    capture
        .admit(
            &mut bound.session,
            &mut bound.budget,
            fg_protocol_common::WriteKind::Insert,
            images.len() as u64,
        )
        .await?;
    let ids: Vec<bson::Bson> = images
        .iter()
        .filter_map(|image| image.get("_id").cloned())
        .collect();
    let mut taken = captured_ids(backend, &entry, branch_id, &ids).await?;
    let mut accepted = Vec::new();
    let mut write_errors = Vec::new();
    for (index, image) in images.iter().enumerate() {
        let Some(id) = image.get("_id") else {
            continue;
        };
        if taken.contains(id) {
            write_errors.push(doc! {
                "index": index as i32,
                "code": 11000i32,
                "errmsg": "duplicate key on the branch view",
            });
            if ordered {
                break;
            }
            continue;
        }
        taken.push(id.clone());
        accepted.push(image.clone());
    }
    for image in &accepted {
        capture_delta(
            bound,
            backend,
            DeltaWrite {
                capture: &capture,
                operation: "I",
                image,
            },
        )
        .await?;
    }
    let mut reply_document = doc! { "n": accepted.len() as i32, "ok": 1.0 };
    if !write_errors.is_empty() {
        let observation = bound.previous.get_or_insert_with(|| MongoWriteObservation {
            state: MongoObservationState::NotSent,
            ..Default::default()
        });
        if observation.state == MongoObservationState::Acknowledged {
            observation.state = MongoObservationState::AcknowledgedWithErrors;
        }
        observation.error_count = Some(write_errors.len() as u64);
        observation.native_code = Some(11000);
        reply_document.insert("writeErrors", write_errors);
    }
    ok_reply(
        command.connection_id,
        command.request.request_id,
        &reply_document,
    )
}

/// Update capture: replacement or {set, unset, inc} operator bodies applied
/// to the merged image; the result lands as a `U` delta entry.
async fn update(
    bound: &mut BoundSession,
    backend: &mut Backend,
    command: &CommandContext<'_>,
) -> Result<Vec<u8>, WireError> {
    let collection = collection_name(command)?;
    let entry = catalog_entry(bound, &collection)?;
    let branch_id = bound.branch_id();
    let statements = command
        .document
        .get_array("updates")
        .map_err(|_| WireError::InvalidValue)?;
    let mut resolved = Vec::new();
    for value in statements {
        let statement = value.as_document().ok_or(WireError::InvalidValue)?;
        let filter = statement
            .get_document("q")
            .map_err(|_| WireError::InvalidValue)?;
        let body = statement
            .get_document("u")
            .map_err(|_| WireError::InvalidValue)?;
        if write::optional_bool(statement, "multi", false)? {
            return Err(WireError::Unsupported);
        }
        if write::optional_bool(statement, "upsert", false)? {
            return Err(WireError::Unsupported);
        }
        let Some(current) = resolve_merged(backend, &entry, branch_id, filter).await? else {
            continue;
        };
        let mut image = current.clone();
        if write::is_operator_form(body) {
            write::apply_operators(&mut image, body)?;
        } else {
            if !write::replacement_keeps_id(body, &current) {
                return Err(WireError::InvalidValue);
            }
            image = body.clone();
            if !image.contains_key("_id")
                && let Some(id) = current.get("_id")
            {
                image.insert("_id", id.clone());
            }
        }
        let id = image.get("_id").cloned().ok_or(WireError::InvalidValue)?;
        resolved.push((id, image));
    }
    let capture = write::Capture {
        entry: &entry,
        branch_id,
    };
    capture
        .admit(
            &mut bound.session,
            &mut bound.budget,
            fg_protocol_common::WriteKind::Update,
            resolved.len() as u64,
        )
        .await?;
    for (_, image) in &resolved {
        capture_delta(
            bound,
            backend,
            DeltaWrite {
                capture: &capture,
                operation: "U",
                image,
            },
        )
        .await?;
    }
    let matched = resolved.len() as i32;
    ok_reply(
        command.connection_id,
        command.request.request_id,
        &doc! { "n": matched, "nModified": matched, "ok": 1.0 },
    )
}

/// Delete capture: a `D` tombstone reserves the natural key so the merged
/// view hides the base document.
async fn delete(
    bound: &mut BoundSession,
    backend: &mut Backend,
    command: &CommandContext<'_>,
) -> Result<Vec<u8>, WireError> {
    let collection = collection_name(command)?;
    let entry = catalog_entry(bound, &collection)?;
    let branch_id = bound.branch_id();
    let statements = command
        .document
        .get_array("deletes")
        .map_err(|_| WireError::InvalidValue)?;
    let mut images = Vec::new();
    for value in statements {
        let statement = value.as_document().ok_or(WireError::InvalidValue)?;
        let filter = statement
            .get_document("q")
            .map_err(|_| WireError::InvalidValue)?;
        write::require_single_delete(statement)?;
        if let Some(current) = resolve_merged(backend, &entry, branch_id, filter).await?
            && let Some(id) = current.get("_id")
        {
            let mut tombstone = Document::new();
            tombstone.insert("_id", id.clone());
            images.push(tombstone);
        }
    }
    let capture = write::Capture {
        entry: &entry,
        branch_id,
    };
    capture
        .admit(
            &mut bound.session,
            &mut bound.budget,
            fg_protocol_common::WriteKind::Delete,
            images.len() as u64,
        )
        .await?;
    for image in &images {
        capture_delta(
            bound,
            backend,
            DeltaWrite {
                capture: &capture,
                operation: "D",
                image,
            },
        )
        .await?;
    }
    ok_reply(
        command.connection_id,
        command.request.request_id,
        &doc! { "n": images.len() as i32, "ok": 1.0 },
    )
}

/// The merged-view identities already visible for a candidate insert set:
/// live base documents plus this branch's captured I/U images.
async fn captured_ids(
    backend: &mut Backend,
    entry: &CatalogEntry,
    branch_id: i64,
    ids: &[bson::Bson],
) -> Result<Vec<bson::Bson>, WireError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let stages = vec![
        doc! { "$match": { "_id": { "$in": ids } } },
        doc! { "$project": { "_id": 1i32 } },
    ];
    let reply = run_merged(
        backend,
        entry,
        read::merged_pipeline(entry, branch_id, stages, false),
        None,
    )
    .await?;
    let mut taken: Vec<bson::Bson> = first_batch(&reply)?
        .iter()
        .filter_map(|value| {
            value
                .as_document()
                .and_then(|document| document.get("_id"))
                .cloned()
        })
        .collect();
    let delta = doc! {
        "find": entry.delta_table.as_str(),
        "filter": {
            "_fg_branch": branch_id,
            "_doc._id": { "$in": ids },
            "_fg_op": { "$in": ["I", "U"] },
        },
        "projection": { "_doc._id": 1i32 },
        "$db": entry.delta_schema.clone(),
    };
    let reply = backend
        .command(&delta)
        .await
        .map_err(|_| WireError::Backend)?;
    taken.extend(first_batch(&reply)?.iter().filter_map(|value| {
        value
            .as_document()
            .and_then(|document| document.get_document("_doc").ok())
            .and_then(|document| document.get("_id"))
            .cloned()
    }));
    Ok(taken)
}

/// Resolve one merged document by filter for update/delete targeting.
async fn resolve_merged(
    backend: &mut Backend,
    entry: &CatalogEntry,
    branch_id: i64,
    filter: &Document,
) -> Result<Option<Document>, WireError> {
    let reply = run_merged(
        backend,
        entry,
        read::resolve_pipeline(entry, branch_id, filter),
        Some(1),
    )
    .await?;
    Ok(first_batch(&reply)?
        .first()
        .and_then(|value| value.as_document())
        .cloned())
}

/// Write one captured operation into the branch delta (last write wins).
struct DeltaWrite<'a> {
    capture: &'a write::Capture<'a>,
    operation: &'a str,
    image: &'a Document,
}

async fn capture_delta(
    bound: &mut BoundSession,
    backend: &mut Backend,
    write: DeltaWrite<'_>,
) -> Result<(), WireError> {
    let Some(id) = write.image.get("_id") else {
        return Err(WireError::InvalidValue);
    };
    let command = doc! {
        "update": write.capture.entry.delta_table.as_str(),
        "updates": [{
            "q": write.capture.delta_filter(id),
            "u": write.capture.delta_document(write.operation, write.image),
            "upsert": true,
            "multi": false,
        }],
        "$db": write.capture.entry.delta_schema.clone(),
    };
    let (_, observation) = observed_write(
        bound,
        backend,
        NativeWrite {
            command: &command,
            kind: WriteKind::Update,
            planned: 1,
        },
    )
    .await?;
    if observation.category != NativeWriteCategory::Acknowledged || observation.n != Some(1) {
        return Err(WireError::Backend);
    }
    Ok(())
}

// ---------------------------------------------------------------- reserved

/// Reserved-database commands: only liveness reaches mongod; teardown
/// commands are acknowledged locally; everything else is a typed refusal.
async fn reserved_database(
    backend: &mut Backend,
    command: &CommandContext<'_>,
) -> Result<Vec<u8>, Error> {
    if LIVENESS_ALLOWLIST.contains(&command.name) {
        return backend.forward(command.request, command.op_msg).await;
    }
    if TEARDOWN_ALLOWLIST.contains(&command.name) {
        return reply(
            command.connection_id,
            command.request.request_id,
            &ok_document(),
        );
    }
    reply(
        command.connection_id,
        command.request.request_id,
        &refusal(
            WireError::Unsupported,
            "administrative databases are not addressable through this proxy",
        ),
    )
}

/// Control-plane failures at binding time answer with branch semantics;
/// the frontend socket stays open for a retry against another branch.
fn binding_failure(error: &WireError, database: &str) -> Document {
    match error {
        WireError::Branch => refusal(
            WireError::Branch,
            &format!("branch '{database}' does not exist or has expired"),
        ),
        WireError::Auth => refusal(WireError::Auth, "the frontend account is no longer current"),
        _ => refusal(
            WireError::Backend,
            "the branch control plane refused the session",
        ),
    }
}

/// A typed refusal: the FG code rides the errmsg text (drivers surface it
/// verbatim), and the numeric code is the mongod-registry mapping.
fn refusal(error: WireError, detail: &str) -> Document {
    error_document(&format!("{error} ({detail})"), error.mongo())
}

fn wire_refusal(error: &WireError) -> Document {
    error_document(&error.to_string(), error.mongo())
}

/// `reply` fails only on BSON encoding, which surfaces as a backend-class
/// wire error in the WireError-returning handlers.
fn ok_reply(
    connection_id: i32,
    request_id: i32,
    document: &Document,
) -> Result<Vec<u8>, WireError> {
    reply(connection_id, request_id, document).map_err(|_| WireError::Backend)
}

/// Route one capture command by its admitted verb.
async fn capture(
    bound: &mut BoundSession,
    backend: &mut Backend,
    command: &CommandContext<'_>,
) -> Result<Vec<u8>, WireError> {
    // A native-copy branch executes against its own materialized documents.
    // Legacy writable sparse branches retain full images in their delta.
    bound.session.binding().require_write_access()?;
    bound.budget.reset();
    let reply_bytes = if bound.session.binding().write_schema.is_some() {
        native_write(bound, backend, command).await?
    } else {
        match command.name {
            "insert" => insert(bound, backend, command).await?,
            "update" => update(bound, backend, command).await?,
            _ => delete(bound, backend, command).await?,
        }
    };
    Ok(reply_bytes)
}

/// Native execution against the materialized copy. Every statement targets
/// at most one document (multi/limit-0 stay refused: without multi-document
/// transactions the affected bound that the budget admits pre-write could
/// not be enforced), and update upsert is admitted as a bounded +1.
async fn native_write(
    bound: &mut BoundSession,
    backend: &mut Backend,
    command: &CommandContext<'_>,
) -> Result<Vec<u8>, WireError> {
    let collection = collection_name(command)?;
    let entry = catalog_entry(bound, &collection)?;
    let statements = match command.name {
        "insert" => command
            .document
            .get_array("documents")
            .map_err(|_| WireError::InvalidValue)?
            .len() as u64,
        "update" => command
            .document
            .get_array("updates")
            .map_err(|_| WireError::InvalidValue)?
            .iter()
            .map(|statement| {
                let statement = statement.as_document().ok_or(WireError::InvalidValue)?;
                if write::optional_bool(statement, "multi", false)? {
                    return Err(WireError::Unsupported);
                }
                write::optional_bool(statement, "upsert", false)?;
                Ok(())
            })
            .collect::<Result<Vec<_>, WireError>>()?
            .len() as u64,
        _ => {
            let statements = command
                .document
                .get_array("deletes")
                .map_err(|_| WireError::InvalidValue)?;
            for statement in statements {
                let statement = statement.as_document().ok_or(WireError::InvalidValue)?;
                write::require_single_delete(statement)?;
            }
            statements.len() as u64
        }
    };
    let kind = match command.name {
        "insert" => fg_protocol_common::WriteKind::Insert,
        "update" => fg_protocol_common::WriteKind::Update,
        _ => fg_protocol_common::WriteKind::Delete,
    };
    crate::write::Capture {
        entry: &entry,
        branch_id: bound.branch_id(),
    }
    .admit(&mut bound.session, &mut bound.budget, kind, statements)
    .await?;
    let mut command_document = command.document.clone();
    command_document.insert("$db", bound.session.binding().write_schema.clone());
    let (reply, _) = observed_write(
        bound,
        backend,
        NativeWrite {
            command: &command_document,
            kind,
            planned: statements,
        },
    )
    .await?;
    // The driver sees mongod's own reply: n, nModified, writeErrors and
    // upserted all keep native semantics.
    ok_reply(command.connection_id, command.request.request_id, &reply)
}

struct NativeWrite<'a> {
    command: &'a Document,
    kind: WriteKind,
    planned: u64,
}

async fn observed_write(
    bound: &mut BoundSession,
    backend: &mut Backend,
    write: NativeWrite<'_>,
) -> Result<(Document, NativeWriteObservation), WireError> {
    bound.arm_write().await?;
    let reply = backend
        .command(write.command)
        .await
        .map_err(|_| WireError::Backend)?;
    let observation = match observe_write(&reply, write.kind, write.planned) {
        Ok(observation) => observation,
        Err(_) => {
            backend.invalidate();
            return Err(WireError::Backend);
        }
    };
    bound.previous = Some(observation.audit(write.kind));
    Ok((reply, observation))
}

#[cfg(test)]
mod diagnostic_tests {
    use super::wire_refusal;
    use fg_protocol_common::WireError;

    #[test]
    fn mongo_refusals_retain_safe_budget_values_and_readonly_reason() {
        let error = wire_refusal(&WireError::TransactionRowLimit {
            rows: 1003,
            limit: 1000,
        });
        assert_eq!(error.get_i32("code"), Ok(20));
        let message = error.get_str("errmsg").unwrap_or_default();
        assert!(message.contains("cumulative rows 1003 > max_transaction_rows 1000"));
        assert!(message.contains("reason=transaction_row_budget"));
        assert!(
            wire_refusal(&WireError::ReadOnly)
                .get_str("errmsg")
                .unwrap_or_default()
                .contains("reason=branch_read_only")
        );
    }
}

#[cfg(test)]
#[path = "command_tests.rs"]
mod audit_tests;
