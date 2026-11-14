//! Raw BSON artifacts and private, non-transactional standalone-Mongo replay.
use super::*;
use fg_proto_mongo::observation::{NativeWriteCategory, observe_write};
use fg_protocol_common::{
    ArtifactEntry, ArtifactHeader, ArtifactReader, ArtifactWriter, AuditAttempt, BranchSession,
    ChangeOperation, DocumentChange, MongoObservationState, MongoWriteObservation, ReplayPermit,
    TransactionBudget, WriteKind, WriteOperation, bson_document, bson_key, encode_bson,
};
use mongodb::{Collection, Cursor, bson::RawDocumentBuf};
use std::{
    fs::File,
    io::{BufReader, Seek, SeekFrom},
};

async fn client(state: &Drain) -> Result<(Client, u32), Failure> {
    let NativeOptions::Mongo(observer) = &*state.observer else {
        return Err(Failure::Unavailable);
    };
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
        .max_pool_size(1)
        .retry_writes(false)
        .build();
    let client = Client::with_options(options).map_err(|_| Failure::Unavailable)?;
    let hello = client
        .database("admin")
        .run_command(doc! {"hello":1})
        .await
        .map_err(|_| Failure::Unavailable)?;
    let native_id = hello
        .get_i64("connectionId")
        .ok()
        .or_else(|| hello.get_i32("connectionId").ok().map(i64::from))
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value != 0)
        .ok_or(Failure::Unavailable)?;
    Ok((client, native_id))
}

pub(super) async fn capture(
    state: &Drain,
    id: i64,
    request: &DiffRequest,
) -> Result<File, Failure> {
    let (client, native_id) = client(state).await?;
    let branch = state
        .router
        .begin_id(&request.principal, id, request.expires_at)
        .await?
        .activate(native_id)?;
    branch.fresh_authorize().await?;
    let file = tokio::select! {biased; ()=branch.cancelled()=>Err(Failure::Wire(WireError::Branch)),
    result=snapshot(&client,branch.binding())=>result}?;
    branch.fresh_authorize().await?;
    Ok(file)
}

fn key_filter(document: &RawDocumentBuf) -> Result<Document, Failure> {
    let key = bson_document(&bson_key(document).map_err(|_| Failure::Invalid)?)
        .map_err(|_| Failure::Invalid)?;
    exact_filter(&key)
}

fn exact_filter(key: &RawDocumentBuf) -> Result<Document, Failure> {
    let key: Document = mongodb::bson::from_slice(key.as_bytes()).map_err(|_| Failure::Invalid)?;
    let id = key.get("_id").ok_or(Failure::Invalid)?;
    Ok(doc! {"_id":{"$eq":id.clone()}})
}

fn base(client: &Client, table: &CatalogEntry) -> Collection<RawDocumentBuf> {
    client
        .database(&table.base_schema)
        .collection(&table.base_table)
}

async fn current_cursor(
    client: &Client,
    binding: &BranchBinding,
    table: &CatalogEntry,
    filter: Document,
) -> Result<Cursor<RawDocumentBuf>, Failure> {
    let (schema, collection, mut pipeline) = if let Some(schema) = &binding.write_schema {
        let target = WriteTarget::new("mongodb", binding.id, schema).ok_or(Failure::Invalid)?;
        (
            target.schema().to_owned(),
            target.table(&table.logical_table),
            Vec::new(),
        )
    } else {
        (
            table.base_schema.clone(),
            table.base_table.clone(),
            fg_proto_mongo::read::merged_pipeline(table, binding.id, Vec::new(), true),
        )
    };
    if !filter.is_empty() {
        pipeline.push(doc! {"$match":filter});
    }
    pipeline.push(doc! {"$sort":{"_id":1}});
    client
        .database(&schema)
        .collection::<RawDocumentBuf>(&collection)
        .aggregate(pipeline)
        .with_type::<RawDocumentBuf>()
        .batch_size(64)
        .await
        .map_err(|_| Failure::Unavailable)
}

async fn next(cursor: &mut Cursor<RawDocumentBuf>) -> Result<Option<RawDocumentBuf>, Failure> {
    if !cursor.advance().await.map_err(|_| Failure::Unavailable)? {
        return Ok(None);
    }
    cursor
        .deserialize_current()
        .map(Some)
        .map_err(|_| Failure::Unavailable)
}

async fn snapshot(client: &Client, binding: &BranchBinding) -> Result<File, Failure> {
    let header = super::export::artifact_header(binding)?;
    let file = tempfile::tempfile().map_err(|_| Failure::Unavailable)?;
    let mut writer = ArtifactWriter::new(file, header).map_err(|_| Failure::Invalid)?;
    // Native _id ordering is MongoDB's, including mixed BSON key types. Point
    // lookups avoid a lossy Rust string comparator and bound memory to images.
    for table in &binding.tables {
        let baseline = base(client, table);
        let mut cursor = baseline
            .find(doc! {})
            .sort(doc! {"_id":1})
            .batch_size(64)
            .await
            .map_err(|_| Failure::Unavailable)?;
        while let Some(before) = next(&mut cursor).await? {
            let mut current = current_cursor(client, binding, table, key_filter(&before)?).await?;
            let after = next(&mut current).await?;
            if after
                .as_ref()
                .is_some_and(|after| after.as_bytes() == before.as_bytes())
            {
                continue;
            }
            writer
                .document(DocumentChange {
                    collection_id: table.id,
                    operation: if after.is_some() {
                        ChangeOperation::Update
                    } else {
                        ChangeOperation::Delete
                    },
                    key_bson: bson_key(&before).map_err(|_| Failure::Invalid)?,
                    before_bson: Some(encode_bson(before.as_bytes())),
                    after_bson: after.as_ref().map(|image| encode_bson(image.as_bytes())),
                })
                .map_err(|_| Failure::Limit)?;
        }
        let mut cursor = current_cursor(client, binding, table, doc! {}).await?;
        while let Some(after) = next(&mut cursor).await? {
            if baseline
                .find_one(key_filter(&after)?)
                .await
                .map_err(|_| Failure::Unavailable)?
                .is_some()
            {
                continue;
            }
            writer
                .document(DocumentChange {
                    collection_id: table.id,
                    operation: ChangeOperation::Insert,
                    key_bson: bson_key(&after).map_err(|_| Failure::Invalid)?,
                    before_bson: None,
                    after_bson: Some(encode_bson(after.as_bytes())),
                })
                .map_err(|_| Failure::Limit)?;
        }
    }
    let file = writer.finish(Vec::new()).map_err(|_| Failure::Limit)?;
    file.sync_all().map_err(|_| Failure::Unavailable)?;
    Ok(file)
}

fn reader(file: &File) -> Result<ArtifactReader<BufReader<File>>, Failure> {
    let mut copy = file.try_clone().map_err(|_| Failure::Unavailable)?;
    copy.seek(SeekFrom::Start(0))
        .map_err(|_| Failure::Unavailable)?;
    ArtifactReader::new(BufReader::new(copy)).map_err(|_| Failure::Invalid)
}

async fn session(
    state: &Drain,
    permit: &ReplayPermit,
    verify_only: bool,
) -> Result<(Client, BranchSession), Failure> {
    let (client, native_id) = client(state).await?;
    let branch = state
        .router
        .begin_replay(permit, native_id, verify_only)
        .await?
        .activate(native_id)?;
    branch.bind_replay(permit.job_id).await?;
    branch.fresh_authorize().await?;
    Ok((client, branch))
}

pub(super) async fn replay(
    state: &Drain,
    permit: &ReplayPermit,
    file: &File,
    header: &ArtifactHeader,
    verify_only: bool,
) -> Result<serde_json::Value, Failure> {
    let (client, branch) = session(state, permit, verify_only).await?;
    let actual_header = super::export::artifact_header(branch.binding())?;
    if actual_header.tables != header.tables
        || actual_header.manifest != header.manifest
        || actual_header.origin != header.origin
        || branch.binding().write_schema.is_none()
    {
        return Err(Failure::Invalid);
    }
    if verify_only {
        let actual = snapshot(&client, branch.binding()).await?;
        branch.fresh_authorize().await?;
        return Ok(
            json!({"verified":super::replay::equal_files(file,&actual)?,"transaction":"non_transactional","applied":false}),
        );
    }
    let initial = snapshot(&client, branch.binding()).await?;
    if reader(&initial)?
        .next_entry()
        .map_err(|_| Failure::Invalid)?
        .is_some()
    {
        return Err(Failure::Invalid);
    }
    let mut budget = TransactionBudget::default();
    if let Err(error) = admit(&branch, file, &mut budget).await {
        if let Some(attempt) = budget.take_attempt().filter(AuditAttempt::intent_possible) {
            let _ = branch
                .finish_mongo_attempt(
                    &attempt,
                    MongoWriteObservation {
                        state: MongoObservationState::NotSent,
                        ..Default::default()
                    },
                )
                .await;
        }
        let code = match error {
            Failure::Wire(error) => error.code(),
            _ => WireError::Backend.code(),
        };
        return Ok(
            json!({"verified":false,"transaction":"not_started","applied":0,"failure":{"code":code,"phase":"admission"}}),
        );
    }
    let mut progress = ReplayProgress {
        attempt: budget.attempt().cloned(),
        previous: None,
        possible_sends: 0,
        applied: 0,
    };
    let result = apply(
        &client,
        ReplayPlan {
            branch: &branch,
            job: permit.job_id,
            file,
            budget: &budget,
        },
        &mut progress,
    )
    .await;
    progress.finish(&branch, result.is_err()).await;
    let applied = progress.applied;
    match result {
        Ok(()) => {
            let actual = snapshot(&client, branch.binding()).await?;
            branch.fresh_authorize().await?;
            Ok(
                json!({"verified":super::replay::equal_files(file,&actual)?,"transaction":"non_transactional","applied":applied}),
            )
        }
        Err(error) => {
            let code = match error {
                Failure::Wire(error) => error.code(),
                _ => WireError::Backend.code(),
            };
            Ok(
                json!({"verified":false,"transaction":"partial","applied":applied,"failure":{"code":code,"phase":"apply"},"verify_required":true}),
            )
        }
    }
}

struct ReplayProgress {
    attempt: Option<AuditAttempt>,
    previous: Option<MongoWriteObservation>,
    possible_sends: u64,
    applied: u64,
}

impl ReplayProgress {
    async fn arm(
        &mut self,
        branch: &BranchSession,
        budget: &TransactionBudget,
    ) -> Result<(), Failure> {
        branch.fresh_authorize().await?;
        budget.validate_for_commit(branch).await?;
        let attempt = self.attempt.as_mut().ok_or(Failure::Unavailable)?;
        let previous = self.previous.take();
        let before = attempt.armed_step();
        if let Err(error) = branch.arm_mongo_step(attempt, previous.clone()).await {
            if attempt.armed_step() == before {
                self.previous = previous;
            }
            return Err(Failure::Wire(error));
        }
        self.possible_sends = self.possible_sends.checked_add(1).ok_or(Failure::Limit)?;
        Ok(())
    }

    async fn finish(&mut self, branch: &BranchSession, failed: bool) {
        let Some(attempt) = self.attempt.take() else {
            return;
        };
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
        // Delivery failures are retained by the shared pending journal and
        // block subsequent writes. They cannot authorize document retries.
        let _ = branch.finish_mongo_attempt(&attempt, observation).await;
    }
}

async fn admit(
    branch: &BranchSession,
    file: &File,
    budget: &mut TransactionBudget,
) -> Result<(), Failure> {
    let mut input = reader(file)?;
    while let Some(entry) = input.next_entry().map_err(|_| Failure::Invalid)? {
        let ArtifactEntry::Document(change) = entry else {
            return Err(Failure::Invalid);
        };
        let policy = branch.policy().await?;
        budget
            .evaluate(branch, &policy, operation(&change), 1)
            .await?;
    }
    budget.validate_for_commit(branch).await?;
    Ok(())
}

fn operation(change: &DocumentChange) -> WriteOperation {
    WriteOperation {
        table_id: change.collection_id,
        kind: match change.operation {
            ChangeOperation::Insert => WriteKind::Insert,
            ChangeOperation::Update => WriteKind::Update,
            ChangeOperation::Delete => WriteKind::Delete,
        },
    }
}

struct ReplayPlan<'a> {
    branch: &'a BranchSession,
    job: i64,
    file: &'a File,
    budget: &'a TransactionBudget,
}

async fn apply(
    client: &Client,
    plan: ReplayPlan<'_>,
    progress: &mut ReplayProgress,
) -> Result<(), Failure> {
    let ReplayPlan {
        branch,
        job,
        file,
        budget,
    } = plan;
    let binding = branch.binding();
    let target = WriteTarget::new(
        "mongodb",
        binding.id,
        binding.write_schema.as_deref().ok_or(Failure::Invalid)?,
    )
    .ok_or(Failure::Invalid)?;
    for phase in [
        ChangeOperation::Delete,
        ChangeOperation::Update,
        ChangeOperation::Insert,
    ] {
        let mut input = reader(file)?;
        while let Some(entry) = input.next_entry().map_err(|_| Failure::Invalid)? {
            let ArtifactEntry::Document(change) = entry else {
                return Err(Failure::Invalid);
            };
            if change.operation != phase {
                continue;
            }
            branch.validate_replay(job).await?;
            branch.fresh_authorize().await?;
            budget.validate_for_commit(branch).await?;
            let table = binding
                .tables
                .iter()
                .find(|table| table.id == change.collection_id)
                .ok_or(Failure::Invalid)?;
            let collection = client
                .database(target.schema())
                .collection::<RawDocumentBuf>(&target.table(&table.logical_table));
            let raw = bson_document(&change.key_bson).map_err(|_| Failure::Invalid)?;
            let filter = exact_filter(&raw)?;
            let current = collection
                .find_one(filter.clone())
                .await
                .map_err(|_| Failure::Unavailable)?;
            if current
                .as_ref()
                .map(|document| encode_bson(document.as_bytes()))
                != change.before_bson
            {
                return Err(Failure::Invalid);
            }
            let mut command = replay_command(&change, collection.name(), filter)?;
            command.insert("writeConcern", doc! {"w":1});
            progress.arm(branch, budget).await?;
            let reply = client.database(target.schema()).run_command(command).await;
            let reply = match reply {
                Ok(reply) => reply,
                Err(error) => {
                    let native_code = match error.kind.as_ref() {
                        mongodb::error::ErrorKind::Command(error) => Some(error.code),
                        _ => None,
                    };
                    progress.previous = Some(MongoWriteObservation {
                        native_code,
                        ..Default::default()
                    });
                    return Err(Failure::Unavailable);
                }
            };
            let kind = operation(&change).kind;
            let observation = observe_write(&reply, kind, 1).map_err(|_| Failure::Unavailable)?;
            progress.previous = Some(observation.audit(kind));
            if observation.category != NativeWriteCategory::Acknowledged
                || observation.n != Some(1)
                || (kind == WriteKind::Update && observation.upserted != 0)
            {
                return Err(Failure::Invalid);
            }
            progress.applied += 1;
        }
    }
    Ok(())
}

fn replay_command(
    change: &DocumentChange,
    collection: &str,
    filter: Document,
) -> Result<Document, Failure> {
    Ok(match change.operation {
        ChangeOperation::Insert => doc! {"insert":collection,"documents":[replay_image(change)?]},
        ChangeOperation::Update => {
            doc! {"update":collection,"updates":[{"q":filter,"u":replay_image(change)?,"multi":false,"upsert":false}]}
        }
        ChangeOperation::Delete => doc! {"delete":collection,"deletes":[{"q":filter,"limit":1}]},
    })
}

fn replay_image(change: &DocumentChange) -> Result<Document, Failure> {
    let image = bson_document(change.after_bson.as_deref().ok_or(Failure::Invalid)?)
        .map_err(|_| Failure::Invalid)?;
    mongodb::bson::from_slice(image.as_bytes()).map_err(|_| Failure::Invalid)
}

#[cfg(test)]
mod audit_tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn full_reply_commands_preserve_typed_bson_images_without_markers() -> Result<(), Failure> {
        let image = doc! {
            "_id": 7i64,
            "small": 7i32,
            "decimal": mongodb::bson::Decimal128::from_str("123.4500").map_err(|_| Failure::Invalid)?,
            "time": mongodb::bson::DateTime::from_millis(1735689600123),
            "binary": mongodb::bson::Binary { subtype: mongodb::bson::spec::BinarySubtype::Uuid, bytes: vec![9;16] },
            "stamp": mongodb::bson::Timestamp { time: 21, increment: 8 },
            "nested": {"z": 1i32, "a": 2i64},
            "array": [true, Bson::Null, 8i64],
        };
        let bytes = mongodb::bson::to_vec(&image).map_err(|_| Failure::Invalid)?;
        let mut change = DocumentChange {
            collection_id: 1,
            operation: ChangeOperation::Insert,
            key_bson: encode_bson(
                &mongodb::bson::to_vec(&doc! {"_id":7i64}).map_err(|_| Failure::Invalid)?,
            ),
            before_bson: None,
            after_bson: Some(encode_bson(&bytes)),
        };
        let command = replay_command(&change, "orders", doc! {"_id":{"$eq":7i64}})?;
        let stored = command
            .get_array("documents")
            .map_err(|_| Failure::Invalid)?[0]
            .as_document()
            .ok_or(Failure::Invalid)?;
        assert_eq!(
            mongodb::bson::to_vec(stored).map_err(|_| Failure::Invalid)?,
            bytes
        );
        assert_eq!(
            stored.keys().collect::<Vec<_>>(),
            image.keys().collect::<Vec<_>>()
        );
        change.operation = ChangeOperation::Update;
        let command = replay_command(&change, "orders", doc! {"_id":{"$eq":7i64}})?;
        let update = command.get_array("updates").map_err(|_| Failure::Invalid)?[0]
            .as_document()
            .ok_or(Failure::Invalid)?;
        assert_eq!(update.get_bool("upsert"), Ok(false));
        assert_eq!(update.get_bool("multi"), Ok(false));
        let stored = update.get_document("u").map_err(|_| Failure::Invalid)?;
        assert_eq!(
            mongodb::bson::to_vec(stored).map_err(|_| Failure::Invalid)?,
            bytes
        );
        Ok(())
    }
}
