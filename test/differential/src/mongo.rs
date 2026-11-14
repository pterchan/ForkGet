//! MongoDB axis of the differential runner: corpus command steps run
//! against mongod in reference-vs-reference mode, canonically comparing whole
//! command replies. Reference-vs-proxy stays the SQL axis; the mongo branch
//! proxy behavior is checked separately by `test/p2/mongo.py`.

use bson::{Bson, Document, doc};
use mongodb::{Client, error::ErrorKind, options::ClientOptions};
use serde_json::Value;

use crate::{
    CanonValue, CaseReport, HarnessError, Observation, QueryShape, RunContext, classify_error,
    compare_step, shape_for,
};
use fg_diff::{ColumnMeta, CorpusCase, Step};

/// One side's mongo connection bound to a case namespace database.
pub(super) struct MongoSide {
    client: Client,
    db: String,
}

impl MongoSide {
    /// Run one command; a failed (`ok: 0`) command becomes a synthetic error
    /// reply so observations and refusal classification stay uniform (the
    /// driver surfaces it as an Err).
    async fn run(&self, command: Document) -> Result<Document, HarnessError> {
        match self.client.database(&self.db).run_command(command).await {
            Ok(reply) => Ok(reply),
            Err(error) => match &*error.kind {
                ErrorKind::Command(command_error) => Ok(doc! {
                    "ok": 0.0,
                    "code": command_error.code,
                    "errmsg": command_error.message.clone(),
                }),
                other => Err(HarnessError::Transport {
                    side: "mongo",
                    message: other.to_string(),
                }),
            },
        }
    }
}

async fn open_client(url: &str) -> Result<Client, HarnessError> {
    let options: ClientOptions =
        ClientOptions::parse(url)
            .await
            .map_err(|error| HarnessError::Transport {
                side: "mongo",
                message: error.to_string(),
            })?;
    Client::with_options(options).map_err(|error| HarnessError::Transport {
        side: "mongo",
        message: error.to_string(),
    })
}

pub(super) async fn connect(url: &str, namespace: &str) -> Result<MongoSide, HarnessError> {
    Ok(MongoSide {
        client: open_client(url).await?,
        db: namespace.to_owned(),
    })
}

/// Namespace recreation: `dropDatabase` answers ok on a missing database, so
/// recreate is idempotent; collections are created implicitly by the fixture.
pub(super) async fn recreate_namespace(url: &str, namespace: &str) -> Result<(), HarnessError> {
    open_client(url)
        .await?
        .database(namespace)
        .run_command(doc! { "dropDatabase": 1i32 })
        .await
        .map(|_| ())
        .map_err(|error| HarnessError::Transport {
            side: "mongo",
            message: error.to_string(),
        })
}

pub(super) async fn engine_version(url: &str) -> Result<String, HarnessError> {
    let reply = open_client(url)
        .await?
        .database("admin")
        .run_command(doc! { "buildInfo": 1i32 })
        .await
        .map_err(|error| HarnessError::Transport {
            side: "mongo",
            message: error.to_string(),
        })?;
    reply
        .get_str("version")
        .map(str::to_owned)
        .map_err(|error| HarnessError::Transport {
            side: "mongo",
            message: format!("buildInfo reply: {error}"),
        })
}

/// A mongo corpus fixture: `{collection: [documents...]}`, inserted into the
/// namespace exactly as written (documents carry their own `_id`).
fn fixture_collections(
    fixtures_dir: &std::path::Path,
    corpus_name: &str,
    case: &CorpusCase,
) -> Result<Vec<(String, Vec<Document>)>, HarnessError> {
    let path = fixtures_dir
        .join(corpus_name)
        .join(format!("{}.json", case.fixture));
    let text = std::fs::read_to_string(&path).map_err(|error| {
        HarnessError::Io(format!(
            "fixture {} at {}: {error}",
            case.fixture,
            path.display()
        ))
    })?;
    let parsed: Value =
        serde_json::from_str(&text).map_err(|error| HarnessError::InvalidCorpus {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
    let Value::Object(map) = parsed else {
        return Err(HarnessError::InvalidCorpus {
            path: path.display().to_string(),
            message: "fixture root must be an object of collection arrays".to_owned(),
        });
    };
    let mut collections = Vec::new();
    for (collection, documents) in map {
        let Value::Array(items) = documents else {
            return Err(HarnessError::InvalidCorpus {
                path: path.display().to_string(),
                message: format!("collection '{collection}' must be an array"),
            });
        };
        let mut docs = Vec::with_capacity(items.len());
        for item in items {
            docs.push(to_document(item)?);
        }
        collections.push((collection, docs));
    }
    Ok(collections)
}

fn to_bson_document(value: Value) -> Result<Bson, HarnessError> {
    bson::to_bson(&value).map_err(|error| HarnessError::Io(error.to_string()))
}

fn to_document(value: Value) -> Result<Document, HarnessError> {
    match bson::to_bson(&value).map_err(|error| HarnessError::Io(error.to_string()))? {
        Bson::Document(document) => Ok(document),
        other => Err(HarnessError::Io(format!(
            "fixture value is not an object: {other:?}"
        ))),
    }
}

/// Run one mongo corpus case: recreate both namespace databases, load the
/// fixture on both sides, then execute the command steps and compare the
/// canonical replies.
pub(super) async fn run_case(
    context: &RunContext,
    case: &CorpusCase,
    reference_url: &str,
    candidate_url: &str,
) -> Result<CaseReport, HarnessError> {
    let suffix = crate::case_hash(&case.id);
    let reference_namespace = format!("fg_diff_ref_{suffix}");
    let candidate_namespace = format!("fg_diff_cand_{suffix}");
    recreate_namespace(reference_url, &reference_namespace).await?;
    recreate_namespace(candidate_url, &candidate_namespace).await?;
    let reference = connect(reference_url, &reference_namespace).await?;
    let candidate = connect(candidate_url, &candidate_namespace).await?;

    let mut mismatches = Vec::new();
    let mut poisoned = false;
    for (collection, documents) in
        fixture_collections(&context.fixtures, context.engine.corpus_name(), case)?
    {
        if documents.is_empty() {
            continue;
        }
        let command = doc! {
            "insert": collection.as_str(),
            "documents": documents,
            "ordered": true,
        };
        for (side, side_client) in [("reference", &reference), ("candidate", &candidate)] {
            let reply: Document = side_client.run(command.clone()).await?;
            if reply.get_f64("ok").map(|ok| ok != 1.0).unwrap_or(true) {
                mismatches.push(format!(
                    "fixture insert for '{collection}' failed on the {side} side: {reply:?}"
                ));
                poisoned = true;
            }
        }
    }

    if !poisoned {
        for (index, step) in case.steps.iter().enumerate() {
            let Step::Command {
                command,
                collection,
                document,
                expect,
            } = step
            else {
                mismatches.push(format!(
                    "step {index}: SQL steps are not valid in a mongodb corpus case"
                ));
                continue;
            };
            // The command name must be the first key; mongod reads it
            // positionally.
            let mut command_document = Document::new();
            command_document.insert(command.as_str(), collection.as_str());
            if let Bson::Document(body) = to_bson_document(document.clone())? {
                for (key, value) in body {
                    command_document.insert(key, value);
                }
            }
            let shape = shape_for(expect);
            let mut observations = Vec::with_capacity(2);
            for side_client in [&reference, &candidate] {
                let reply = side_client.run(command_document.clone()).await?;
                observations.push(observe_reply(&reply, shape));
            }
            if let Err(mismatch) = compare_step(index, expect, &observations[0], &observations[1]) {
                mismatches.push(mismatch.detail);
            }
        }
    }

    Ok(CaseReport {
        id: case.id.clone(),
        fixture: case.fixture.clone(),
        mismatches,
    })
}

/// Reply to observation. `ok: 0` is an error observation with the mongo (or
/// Forkget proxy) class; successes become one canonical-reply row or an
/// affected count from `n`.
fn observe_reply(reply: &Document, shape: QueryShape) -> Observation {
    // Bulk writes carry per-document failures in writeErrors while ok stays
    // 1; the first error is the observation.
    if let Some(Bson::Array(errors)) = reply.get("writeErrors")
        && let Some(Bson::Document(first)) = errors.first()
    {
        let code = first
            .get_i32("code")
            .map(|code| code.to_string())
            .or_else(|_| first.get_i64("code").map(|code| code.to_string()))
            .ok();
        let message = first
            .get_str("errmsg")
            .map(str::to_owned)
            .unwrap_or_default();
        return Observation::Error {
            class: classify_error("mongodb", code.as_deref()),
            code,
            message,
        };
    }
    if reply.get_f64("ok").map(|ok| ok != 1.0).unwrap_or(true) {
        let code = reply
            .get_i32("code")
            .map(|code| code.to_string())
            .or_else(|_| reply.get_i64("code").map(|code| code.to_string()))
            .ok();
        let message = reply
            .get_str("errmsg")
            .map(str::to_owned)
            .unwrap_or_default();
        let class = if message.starts_with("[FORKGET") {
            message
                .split_whitespace()
                .find(|token| token.starts_with("FG-"))
                .map(|fg| format!("proxy_refusal_{}", fg.trim_end_matches(']')))
                .unwrap_or_else(|| "proxy_refusal".to_owned())
        } else {
            classify_error("mongodb", code.as_deref())
        };
        return Observation::Error {
            class,
            code,
            message,
        };
    }
    match shape {
        QueryShape::Rows => Observation::Rows {
            columns: vec![ColumnMeta {
                name: "reply".to_owned(),
                type_name: "bson".to_owned(),
            }],
            rows: vec![vec![CanonValue::Bytes(canonical_reply(reply))]],
        },
        QueryShape::Affected => {
            let affected = reply
                .get_i32("n")
                .map(i64::from)
                .or_else(|_| reply.get_i64("n"))
                .unwrap_or_default();
            Observation::Affected(affected.unsigned_abs())
        }
    }
}

/// The canonical form of one successful reply: volatile fields (ok, cursor
/// bookkeeping, cluster time) leave, field order is the reply's own, and the
/// relaxed extended-JSON string compares byte-for-byte.
fn canonical_reply(reply: &Document) -> Vec<u8> {
    let mut trimmed = reply.clone();
    trimmed.remove("ok");
    trimmed.remove("operationTime");
    trimmed.remove("$clusterTime");
    if let Some(Bson::Document(cursor)) = trimmed.get_mut("cursor") {
        cursor.remove("id");
        cursor.remove("ns");
    }
    // serde_json conversion keeps field order and the relaxed ext-JSON of
    // the bson crate for exotic types.
    serde_json::to_vec(&trimmed).unwrap_or_default()
}
