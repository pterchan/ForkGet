//! Handshake and branch-data checks against a live, auth-enabled
//! mongod on 127.0.0.1:27027:
//!
//! 1. `pymongo_style_passthrough_with_scram_termination` — the standalone
//!    proxy passes a real pymongo driver through (hello, SCRAM-SHA-256,
//!    insert/find/drop).
//! 2. `branch_data_plane_merges_reads_and_captures_writes` — the
//!    branch frontend (`serve_branches`) with an in-process stub control
//!    plane: merged reads, delta write capture, base immutability, branch
//!    isolation, and typed refusals.
//!
//! ```sh
//! # The test/local compose service works; export its password:
//! set -a; source test/local/.env; set +a
//! cargo test -p fg-proto-mongo --test integration -- --nocapture
//! ```
//!
//! The root password comes from FG_TEST_MONGO_ROOT_PASSWORD (spike
//! container default: spike-root-pw).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::time::Duration;

use bson::doc;
use fg_protocol_common::{BranchBinding, CatalogEntry, FrontendAccount, ResolveBranch, Router};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use fg_proto_mongo::scram;
use fg_proto_mongo::{Account, SpikeConfig};

const BACKEND: &str = "127.0.0.1:27027";
const FRONTEND_LISTEN: &str = "127.0.0.1:28017";
const SPIKE_USER: &str = "alice";
const SPIKE_PASSWORD: &str = "spike-alice-pw";
const DB: &str = "admin";
const BRANCH_USER: &str = "alice";
const BRANCH_PASSWORD: &str = "branch-alice-pw";
/// The generation the stub control plane binds; seeded directly with root.
const GENERATION_DB: &str = "fg_g900";
const BRANCH_COPY_DB: &str = "fg_b2";
const DELTA_TABLE: &str = "_d_g900_t1";
const INTERNAL_TOKEN: &str = "stub-internal-token";

fn root_password() -> String {
    std::env::var("FG_TEST_MONGO_ROOT_PASSWORD").unwrap_or_else(|_| "spike-root-pw".into())
}

/// The live-mongod evidence runs only with the test environment loaded
/// (test/local/.env or CI); a bare cargo test skips it.
fn mongod_enabled() -> bool {
    std::env::var("FG_TEST_MONGO_ROOT_PASSWORD").is_ok()
}

/// mongod reports `ok` as a double; accept the numeric forms.
fn command_ok(reply: &bson::Document) -> bool {
    reply.get_f64("ok").map(|ok| ok == 1.0).unwrap_or(false)
        || reply.get_i32("ok").map(|ok| ok == 1).unwrap_or(false)
}

/// Minimal raw OP_MSG client used for setup and for the branch session.
struct RawClient {
    stream: TcpStream,
    request_id: i32,
}

impl RawClient {
    async fn connect(addr: &str) -> tokio::io::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true).ok();
        Ok(Self {
            stream,
            request_id: 100,
        })
    }

    async fn command(&mut self, document: &bson::Document) -> bson::Document {
        self.request_id += 1;
        let message = fg_proto_mongo::Message {
            request_id: self.request_id,
            response_to: 0,
            opcode: 2013,
            body: {
                let mut body = Vec::new();
                body.extend_from_slice(&0u32.to_le_bytes());
                body.push(0);
                body.extend_from_slice(&bson::to_vec(document).unwrap());
                body
            },
        };
        self.stream.write_all(&message.into_bytes()).await.unwrap();
        let mut header = [0u8; 16];
        self.stream.read_exact(&mut header).await.unwrap();
        let length = i32::from_le_bytes(header[0..4].try_into().unwrap()) as usize;
        let mut body = vec![0u8; length - 16];
        self.stream.read_exact(&mut body).await.unwrap();
        let op_msg = fg_proto_mongo::parse_op_msg(&body).unwrap();
        fg_proto_mongo::kind_zero_document(&op_msg.sections).unwrap()
    }

    /// SCRAM-SHA-256 client against the admin database.
    async fn authenticate(&mut self, user: &str, password: &str) {
        let client = scram::ClientExchange::start(user).unwrap();
        let start = doc! {
            "saslStart": 1i32,
            "mechanism": scram::MECHANISM,
            "payload": bson::Binary {
                bytes: client.initial_payload().into_bytes(),
                subtype: bson::spec::BinarySubtype::Generic,
            },
            "options": { "skipEmptyExchange": true },
            "$db": DB,
        };
        let first = self.command(&start).await;
        let payload = match first.get("payload") {
            Some(bson::Bson::Binary(binary)) => binary.bytes.clone(),
            _ => panic!("saslStart reply missing payload: {first:?}"),
        };
        let (client_final, server_signature) = client.finish(&payload, user, password).unwrap();
        let continue_command = doc! {
            "saslContinue": 1i32,
            "conversationId": first.get_i32("conversationId").unwrap(),
            "payload": bson::Binary {
                bytes: client_final.into_bytes(),
                subtype: bson::spec::BinarySubtype::Generic,
            },
            "$db": DB,
        };
        let final_reply = self.command(&continue_command).await;
        let payload = match final_reply.get("payload") {
            Some(bson::Bson::Binary(binary)) => binary.bytes.clone(),
            _ => panic!("saslContinue reply missing payload: {final_reply:?}"),
        };
        scram::verify_server(&payload, &server_signature).unwrap();
        if !final_reply.get_bool("done").unwrap_or(true) {
            let empty = doc! {
                "saslContinue": 1i32,
                "conversationId": final_reply.get_i32("conversationId").unwrap(),
                "payload": bson::Binary {
                    bytes: Vec::new(),
                    subtype: bson::spec::BinarySubtype::Generic,
                },
                "$db": DB,
            };
            self.command(&empty).await;
        }
    }
}

async fn connect_root() -> Option<RawClient> {
    if !mongod_enabled() {
        println!("skipped: FG_TEST_MONGO_ROOT_PASSWORD is not set (source test/local/.env)");
        return None;
    }
    let Ok(mut root) = RawClient::connect(BACKEND).await else {
        println!("skipped: mongod not reachable at {BACKEND}; start test/local first");
        return None;
    };
    root.authenticate("root", &root_password()).await;
    Some(root)
}

/// The reviewed seed fixture, mirroring the SQL v1 orders rows.
fn base_documents() -> Vec<bson::Document> {
    vec![
        doc! { "_id": 1i32, "tenant_id": 1i32, "customer_id": 10i32, "amount": 10.0, "note": "base-one" },
        doc! { "_id": 2i32, "tenant_id": 1i32, "customer_id": 20i32, "amount": 20.0, "note": "base-two" },
        doc! { "_id": 3i32, "tenant_id": 2i32, "customer_id": 10i32, "amount": 30.0, "note": "base-three" },
        doc! { "_id": 4i32, "tenant_id": 2i32, "customer_id": 30i32, "amount": 40.0, "note": "base-four" },
    ]
}

fn catalog_entry() -> CatalogEntry {
    CatalogEntry {
        id: 1,
        baseline_rows: 4,
        logical_schema: "app".into(),
        logical_table: "orders".into(),
        base_schema: GENERATION_DB.into(),
        base_table: "orders".into(),
        // MongoDB deltas share the generation database (migration 0013).
        delta_schema: GENERATION_DB.into(),
        delta_table: DELTA_TABLE.into(),
        generated_key: None,
        columns: Vec::new(),
    }
}

fn branch_binding(name: &str, id: i64) -> BranchBinding {
    // The write branch owns its separate materialized-copy database.
    let write_schema = (id == 2).then(|| BRANCH_COPY_DB.to_owned());
    BranchBinding {
        id,
        generation_id: 900,
        engine: "mongodb".into(),
        name: name.into(),
        default_schema: "app".into(),
        class: Default::default(),
        access: fg_protocol_common::BranchAccess::ReadWrite,
        layout: if id == 2 {
            fg_protocol_common::BranchLayout::NativeCopy
        } else {
            fg_protocol_common::BranchLayout::SparseDelta
        },
        read_strategy: fg_protocol_common::ReadStrategy::Merge,
        snapshot_manifest: None,
        audit_witness_ready: false,
        expires_at: i64::MAX,
        write_schema,
        replay_origin: None,
        tables: vec![catalog_entry()],
    }
}

/// The stub control plane: enough of fg-control for one proxy to resolve
/// two branches and admit their writes.
async fn stub_control() -> SocketAddr {
    async fn resolve(Json(request): Json<ResolveBranch>) -> Json<BranchBinding> {
        match request.branch.as_str() {
            "beta" => Json(branch_binding("beta", 2)),
            "gamma" => Json(branch_binding("gamma", 3)),
            _ => Json(branch_binding("alpha", 1)),
        }
    }
    async fn policy() -> Json<fg_protocol_common::Policy> {
        Json(fg_protocol_common::Policy {
            class: Default::default(),
            version: 1,
            max_transaction_rows: 1000,
            table_limit_bps: None,
            approval_after_rows: None,
            small_table_floor: 1,
            effective_revision: 0,
            grant_expires_at: None,
        })
    }
    async fn legacy_protocol() -> (StatusCode, Json<serde_json::Value>) {
        (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "code":"FG-2003", "reason":"internal_protocol_mismatch"
            })),
        )
    }
    async fn audited_decision(
        Json(request): Json<fg_protocol_common::AuditedDecisionRequest>,
    ) -> Json<fg_protocol_common::AuditedDecisionResponse> {
        Json(fg_protocol_common::AuditedDecisionResponse {
            attempt_id: request.attempt.attempt_id,
            approval_id: None,
            witness: None,
        })
    }
    async fn mongo_step(
        Json(request): Json<fg_protocol_common::MongoStepRequest>,
    ) -> Json<fg_protocol_common::MongoStepAck> {
        Json(fg_protocol_common::MongoStepAck {
            attempt_id: request.attempt.attempt_id,
            armed_step: request.expected_step + 1,
        })
    }
    async fn audited_outcome(
        Json(request): Json<fg_protocol_common::AuditedOutcomeRequest>,
    ) -> Json<fg_protocol_common::OutcomeAck> {
        Json(fg_protocol_common::OutcomeAck {
            attempt_id: request.attempt.attempt_id,
            audit_event_id: 1,
            outcome: request.outcome,
        })
    }
    use axum::{Json, http::StatusCode, routing::post};
    let app = axum::Router::new()
        .route("/internal/v1/resolve", post(resolve))
        .route(
            "/internal/v1/branches/{id}/active",
            post(|| async { StatusCode::NO_CONTENT }),
        )
        .route("/internal/v1/branches/{id}/policy", post(policy))
        .route(
            "/internal/v1/branches/{id}/lease",
            post(|| async { Json(serde_json::json!({"expires_at":i64::MAX,"lease_version":1})) }),
        )
        .route(
            "/internal/v1/branches/{id}/policy/validate",
            post(|| async { StatusCode::NO_CONTENT }),
        )
        .route(
            "/internal/v1/branches/{id}/decisions",
            post(legacy_protocol),
        )
        .route(
            "/internal/v1/branches/{id}/audit/decisions",
            post(audited_decision),
        )
        .route(
            "/internal/v1/branches/{id}/audit/mongo-step",
            post(mongo_step),
        )
        .route(
            "/internal/v1/branches/{id}/audit/outcome",
            post(audited_outcome),
        )
        .route("/internal/v1/branches/{id}/outcome", post(legacy_protocol));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    address
}

/// Seed the stub generation: base collection plus a delta collection with
/// the validator and uniqueness index, exactly like the control plane's
/// mongo build.
async fn seed_generation(root: &mut RawClient) {
    root.command(&doc! { "dropDatabase": 1i32, "$db": GENERATION_DB })
        .await;
    root.command(&doc! { "create": "orders", "$db": GENERATION_DB })
        .await;
    root.command(&doc! {
        "insert": "orders",
        "documents": base_documents(),
        "$db": GENERATION_DB,
    })
    .await;
    root.command(&doc! { "create": DELTA_TABLE, "$db": GENERATION_DB })
        .await;
    root.command(&doc! {
        "createIndexes": DELTA_TABLE,
        "indexes": [{
            "key": { "_fg_branch": 1i32, "_doc._id": 1i32 },
            "name": "_fg_branch_document",
            "unique": true,
        }],
        "$db": GENERATION_DB,
    })
    .await;
    // The materialized write branch (beta): the control plane would clone
    // the generation into BRANCH_COPY_DB; the fixture does the same directly.
    root.command(&doc! { "dropDatabase": 1i32, "$db": BRANCH_COPY_DB })
        .await;
    root.command(&doc! { "create": "orders", "$db": BRANCH_COPY_DB })
        .await;
    root.command(&doc! {
        "insert": "orders",
        "documents": base_documents(),
        "$db": BRANCH_COPY_DB,
    })
    .await;
}

#[tokio::test]
async fn branch_data_plane_merges_reads_and_captures_writes() {
    let Some(mut root) = connect_root().await else {
        return;
    };
    seed_generation(&mut root).await;
    let control = stub_control().await;
    let router = Router::new(
        fg_protocol_common::loopback_http(&format!("http://{control}")).unwrap(),
        INTERNAL_TOKEN.into(),
        "mongodb",
    )
    .unwrap();
    // An ephemeral port: the spike test binds the fixed evidence port.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen: SocketAddr = listener.local_addr().unwrap();
    let config = fg_proto_mongo::BranchConfig {
        transport: None,
        backend: BACKEND.parse().unwrap(),
        backend_auth_db: DB.to_owned(),
        backend_account: Account {
            user: "root".into(),
            password: root_password(),
        },
    };
    let accounts = vec![FrontendAccount {
        user: BRANCH_USER.into(),
        password: BRANCH_PASSWORD.into(),
        expires_at: i64::MAX,
    }];
    tokio::spawn(fg_proto_mongo::serve_branches(
        listener, config, accounts, router,
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Branch alpha binds and sees the pinned generation.
    let mut alpha = RawClient::connect(&listen.to_string()).await.unwrap();
    alpha.command(&doc! { "ping": 1i32, "$db": DB }).await;
    alpha.authenticate(BRANCH_USER, BRANCH_PASSWORD).await;
    let listing = alpha
        .command(&doc! { "listCollections": 1i32, "$db": "alpha" })
        .await;
    assert!(command_ok(&listing), "listCollections: {listing:?}");
    let names = listing
        .get_document("cursor")
        .unwrap()
        .get_array("firstBatch")
        .unwrap()
        .iter()
        .filter_map(|entry| {
            entry
                .as_document()
                .and_then(|document| document.get_str("name").ok())
                .map(str::to_owned)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec!["orders".to_owned()],
        "catalog listing: {listing:?}"
    );

    let all = alpha
        .command(&doc! { "find": "orders", "$db": "alpha" })
        .await;
    assert_eq!(
        all.get_document("cursor")
            .unwrap()
            .get_array("firstBatch")
            .unwrap()
            .len(),
        4,
        "unmerged base read: {all:?}"
    );

    // Insert capture lands in the delta, never in the base collection.
    let insert = alpha
        .command(&doc! {
            "insert": "orders",
            "documents": [
                { "_id": 10i32, "tenant_id": 1i32, "customer_id": 10i32, "amount": 1.5, "note": "branch-insert" },
            ],
            "ordered": true,
            "$db": "alpha",
        })
        .await;
    assert_eq!(insert.get_i32("n"), Ok(1), "insert: {insert:?}");
    let delta = root
        .command(&doc! {
            "find": DELTA_TABLE,
            "filter": { "_fg_branch": 1i64 },
            "$db": GENERATION_DB,
        })
        .await;
    let delta_docs = delta
        .get_document("cursor")
        .unwrap()
        .get_array("firstBatch")
        .unwrap();
    assert_eq!(delta_docs.len(), 1, "capture: {delta:?}");
    let captured = delta_docs[0].as_document().unwrap();
    assert_eq!(captured.get_str("_fg_op"), Ok("I"));

    // Duplicate identity against the merged view refuses with 11000.
    let duplicate = alpha
        .command(&doc! {
            "insert": "orders",
            "documents": [ { "_id": 1i32, "note": "conflict" } ],
            "$db": "alpha",
        })
        .await;
    let errors = duplicate.get_array("writeErrors").unwrap();
    assert_eq!(errors[0].as_document().unwrap().get_i32("code"), Ok(11000));

    // Update capture: merged view shows the edit, the base stays pinned.
    let update = alpha
        .command(&doc! {
            "update": "orders",
            "updates": [{ "q": { "_id": 1i32 }, "u": { "$set": { "note": "branch-edited" } } }],
            "$db": "alpha",
        })
        .await;
    assert_eq!(update.get_i32("n"), Ok(1), "update: {update:?}");
    let visible = alpha
        .command(&doc! { "find": "orders", "filter": { "_id": 1i32 }, "$db": "alpha" })
        .await;
    let shown = visible
        .get_document("cursor")
        .unwrap()
        .get_array("firstBatch")
        .unwrap();
    assert_eq!(
        shown[0].as_document().unwrap().get_str("note"),
        Ok("branch-edited"),
        "merged update: {visible:?}"
    );
    let base = root
        .command(&doc! { "find": "orders", "filter": { "_id": 1i32 }, "$db": GENERATION_DB })
        .await;
    let base_doc = base
        .get_document("cursor")
        .unwrap()
        .get_array("firstBatch")
        .unwrap();
    assert_eq!(
        base_doc[0].as_document().unwrap().get_str("note"),
        Ok("base-one"),
        "the base collection must stay untouched"
    );

    // Delete capture: a tombstone hides the base document.
    let removed = alpha
        .command(&doc! {
            "delete": "orders",
            "deletes": [{ "q": { "_id": 2i32 }, "limit": 1i32 }],
            "$db": "alpha",
        })
        .await;
    assert_eq!(removed.get_i32("n"), Ok(1), "delete: {removed:?}");
    let total = alpha
        .command(&doc! { "count": "orders", "$db": "alpha" })
        .await;
    // 4 base documents, one hidden by the tombstone, one inserted.
    assert_eq!(
        total.get_i32("n"),
        Ok(4),
        "count after insert/update/delete: {total:?}"
    );

    // Distinct and the count_documents aggregation run on the merged view.
    let distinct = alpha
        .command(&doc! { "distinct": "orders", "key": "customer_id", "$db": "alpha" })
        .await;
    // Document 2 (customer 20) is tombstoned; the branch insert is a 10.
    assert_eq!(
        distinct.get_array("values").unwrap(),
        &[bson::Bson::Int32(10), bson::Bson::Int32(30)],
        "distinct: {distinct:?}"
    );
    let counted = alpha
        .command(&doc! {
            "aggregate": "orders",
            "pipeline": [
                { "$match": { "tenant_id": 1i32 } },
                { "$group": { "_id": 1i32, "n": { "$sum": 1i32 } } },
            ],
            "cursor": {},
            "$db": "alpha",
        })
        .await;
    let groups = counted
        .get_document("cursor")
        .unwrap()
        .get_array("firstBatch")
        .unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].as_document().unwrap().get_i32("n"), Ok(2));

    // Cursor continuation: a bounded batch streams the rest via getMore.
    let paged = alpha
        .command(&doc! { "find": "orders", "batchSize": 2i32, "$db": "alpha" })
        .await;
    let cursor = paged.get_document("cursor").unwrap();
    let cursor_id = cursor.get_i64("id").unwrap();
    assert!(cursor_id > 0, "a bounded find must keep the cursor open");
    assert_eq!(cursor.get_array("firstBatch").unwrap().len(), 2);
    let more = alpha
        .command(&doc! { "getMore": cursor_id, "collection": "orders", "$db": "alpha" })
        .await;
    assert!(command_ok(&more), "getMore: {more:?}");
    let next = more.get_document("cursor").unwrap();
    assert_eq!(next.get_array("nextBatch").unwrap().len(), 2);
    assert_eq!(next.get_i64("id"), Ok(0), "the stream is exhausted");

    // Aggregations outside the admitted subset are typed refusals.
    let escape = alpha
        .command(&doc! {
            "aggregate": "orders",
            "pipeline": [ { "$out": "elsewhere" } ],
            "cursor": {},
            "$db": "alpha",
        })
        .await;
    assert_eq!(escape.get_f64("ok"), Ok(0.0));
    assert_eq!(escape.get_i32("code"), Ok(20), "refusal: {escape:?}");
    assert!(escape.get_str("errmsg").unwrap().contains("FG-2002"));

    // Branch beta owns a separate copy: its reads answer from that copy
    // (alpha's delta capture never reaches it), and its writes land there
    // natively — mongod's own reply shapes surface unchanged.
    let mut beta = RawClient::connect(&listen.to_string()).await.unwrap();
    beta.authenticate(BRANCH_USER, BRANCH_PASSWORD).await;
    let isolated = beta
        .command(&doc! { "find": "orders", "$db": "beta" })
        .await;
    assert!(command_ok(&isolated), "beta find: {isolated:?}");
    assert_eq!(
        isolated
            .get_document("cursor")
            .unwrap()
            .get_array("firstBatch")
            .unwrap()
            .len(),
        4,
        "branch isolation: {isolated:?}"
    );
    let beta_insert = beta
        .command(&doc! {
            "insert": "orders",
            "documents": [
                { "_id": 77, "tenant_id": 1, "customer_id": 10, "amount": 3.25, "note": "native" }
            ],
            "ordered": true,
            "$db": "beta",
        })
        .await;
    assert_eq!(
        beta_insert.get_i32("n"),
        Ok(1),
        "native insert: {beta_insert:?}"
    );
    let beta_update = beta
        .command(&doc! {
            "update": "orders",
            "updates": [{ "q": { "_id": 77 }, "u": { "$set": { "note": "native-edited" } } }],
            "$db": "beta",
        })
        .await;
    assert_eq!(
        beta_update.get_i32("n"),
        Ok(1),
        "native update: {beta_update:?}"
    );
    let beta_read = beta
        .command(&doc! { "find": "orders", "filter": { "_id": 77 }, "$db": "beta" })
        .await;
    let shown = beta_read
        .get_document("cursor")
        .unwrap()
        .get_array("firstBatch")
        .unwrap();
    assert_eq!(
        shown[0].as_document().unwrap().get_str("note"),
        Ok("native-edited"),
        "native read-your-write: {beta_read:?}"
    );
    // multi:true stays refused on materialized branches too (no
    // transactions: the pre-admitted bound could not be enforced).
    let multi = beta
        .command(&doc! {
            "update": "orders",
            "updates": [{ "q": {}, "u": { "$set": { "note": "x" } }, "multi": true }],
            "$db": "beta",
        })
        .await;
    assert_eq!(multi.get_f64("ok"), Ok(0.0), "multi refusal: {multi:?}");
    assert!(multi.get_str("errmsg").unwrap().contains("FG-2002"));

    // Real-driver evidence: pymongo drives a fresh branch end to end.
    let python = std::env::var("FG_SPIKE_PYTHON").unwrap_or_else(|_| "python3".into());
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/pymongo_branch_evidence.py"
    );
    let outcome = tokio::process::Command::new(python.clone())
        .arg(script)
        .arg(listen.port().to_string())
        .arg("gamma")
        .output()
        .await;
    match outcome {
        Ok(output) if output.status.success() => {
            println!("{}", String::from_utf8_lossy(&output.stdout));
        }
        Ok(output) if output.status.code() == Some(3) => {
            println!("pymongo branch evidence: SKIPPED (driver unavailable)");
        }
        other => {
            let detail = other
                .map(|output| {
                    format!(
                        "{}{}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    )
                })
                .unwrap_or_else(|error| format!("{error}"));
            panic!("pymongo branch evidence failed: {detail}");
        }
    }
    let _ = python;
    println!("branch data plane: merge, capture, isolation, cursoring, refusals: OK");
}

#[tokio::test]
async fn pymongo_style_passthrough_with_scram_termination() {
    let Some(mut root) = connect_root().await else {
        return;
    };
    // Create the spike account (idempotent: 51003 "already exists" is fine).
    let setup = |password: &str| {
        doc! {
            "createUser": SPIKE_USER,
            "pwd": password,
            "roles": [
                { "role": "readWrite", "db": "spike" },
            ],
            "$db": DB,
        }
    };
    let created = root.command(&setup(SPIKE_PASSWORD)).await;
    assert!(
        command_ok(&created) || created.get_i32("code").unwrap_or(0) == 51003,
        "createUser failed: {created:?}"
    );

    // Start the standalone passthrough fixture with 1:1 mirror accounts.
    let listener = tokio::net::TcpListener::bind(FRONTEND_LISTEN)
        .await
        .unwrap();
    let listen: SocketAddr = listener.local_addr().unwrap();
    let server_config = SpikeConfig {
        listen,
        backend: BACKEND.parse().unwrap(),
        backend_auth_db: DB.to_owned(),
        accounts: vec![Account {
            user: SPIKE_USER.to_owned(),
            password: SPIKE_PASSWORD.to_owned(),
        }],
    };
    // The spike serve binds internally; this test already owns the fixed
    // evidence listener, so run the accept loop directly.
    let server_config = std::sync::Arc::new(server_config);
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            stream.set_nodelay(true).unwrap();
            let config = server_config.clone();
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.into_split();
                let session = fg_proto_mongo::Session::new((*config).clone());
                session.run(&mut reader, &mut writer).await.ok();
            });
        }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = RawClient::connect(FRONTEND_LISTEN).await.unwrap();
    client.command(&doc! { "ping": 1i32, "$db": DB }).await;
    client.authenticate(SPIKE_USER, SPIKE_PASSWORD).await;
    let _ = client
        .command(&doc! { "drop": "orders", "$db": "spike" })
        .await;
    let insert = doc! {
        "insert": "orders",
        "documents": [ { "_id": 1i32, "tenant_id": 1i32, "amount": 10.50 } ],
        "$db": "spike",
    };
    let reply = client.command(&insert).await;
    assert!(
        (reply.get_f64("ok").unwrap_or(0.0) - 1.0).abs() < f64::EPSILON,
        "insert failed: {reply:?}"
    );
    let find = doc! {
        "find": "orders",
        "filter": { "_id": 1i32 },
        "$db": "spike",
    };
    let reply = client.command(&find).await;
    let batch = reply
        .get_document("cursor")
        .unwrap()
        .get_array("firstBatch")
        .unwrap();
    assert_eq!(batch.len(), 1, "expected one document, saw {batch:?}");
    println!("passthrough insert/find through the spike proxy: OK");

    // Real-driver evidence: pymongo against the still-running spike proxy.
    let python = std::env::var("FG_SPIKE_PYTHON").unwrap_or_else(|_| "python3".into());
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pymongo_evidence.py");
    let outcome = tokio::process::Command::new(python.clone())
        .arg(script)
        .arg(listen.port().to_string())
        .output()
        .await;
    match outcome {
        Ok(output) if output.status.success() => {
            println!("pymongo evidence: OK");
            println!("{}", String::from_utf8_lossy(&output.stdout));
        }
        Ok(output) if output.status.code() == Some(3) => {
            println!("pymongo evidence: SKIPPED (driver unavailable)");
        }
        other => {
            let detail = other
                .map(|output| String::from_utf8_lossy(&output.stderr).to_string())
                .unwrap_or_else(|error| format!("{error}"));
            panic!("pymongo evidence failed: {detail}");
        }
    }
    let _ = python;
}
