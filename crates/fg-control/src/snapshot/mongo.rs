//! Frozen-source native BSON backup, admission and byte-for-byte verification.

use std::{
    env, fs,
    io::{BufReader, Read, Write},
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::Command,
};

use base64::Engine as _;
use fg_meta::Metadata;
use fg_protocol_common::{
    CollectionManifest, DocumentSnapshot, SNAPSHOT_FORMAT_VERSION, SnapshotManifest,
};
use mongodb::{
    Client,
    bson::{Document, doc},
    options::{ClientOptions, Credential, ServerAddress, Tls, TlsOptions},
};
use percent_encoding::percent_decode_str;
use reqwest::Url;
use serde_json::json;

use super::{Capture, Options, SnapshotError, tools};
use crate::{
    grants::NativeRoles,
    native::{Native, NativeOptions},
};

pub(super) fn source(setting: &str) -> Result<bool, SnapshotError> {
    Ok(env::var(setting)
        .map_err(|_| SnapshotError::Setting("source_or_target_dsn"))?
        .starts_with("mongodb://"))
}

struct Endpoint {
    uri: String,
    host: String,
    port: u16,
    user: String,
    password: String,
    auth_db: String,
    ca: Option<PathBuf>,
}

impl Endpoint {
    fn from_env(setting: &str, ca_setting: &str) -> Result<Self, SnapshotError> {
        let uri = env::var(setting).map_err(|_| SnapshotError::Setting("source_or_target_dsn"))?;
        let url = Url::parse(&uri).map_err(|_| SnapshotError::Setting("mongo_source_dsn"))?;
        if url.scheme() != "mongodb" || url.query().is_some() || url.fragment().is_some() {
            return Err(SnapshotError::Setting("mongo_source_dsn"));
        }
        let host = url
            .host_str()
            .ok_or(SnapshotError::Setting("mongo_source_host"))?
            .to_owned();
        let decode = |value: &str| {
            percent_decode_str(value)
                .decode_utf8()
                .map(|s| s.into_owned())
                .map_err(|_| SnapshotError::Setting("mongo_source_dsn_encoding"))
        };
        let auth_db = decode(url.path().strip_prefix('/').unwrap_or_default())?;
        if auth_db.is_empty() || auth_db.contains('/') {
            return Err(SnapshotError::Setting("mongo_auth_database_required"));
        }
        let ca = env::var_os(ca_setting).map(PathBuf::from);
        if ca.as_ref().is_some_and(|ca| !ca.is_file())
            || (!matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1") && ca.is_none())
        {
            return Err(SnapshotError::Setting(
                "verified_source_or_target_ca_required",
            ));
        }
        let mut tool_uri = url.clone();
        tool_uri.set_path("/");
        tool_uri
            .query_pairs_mut()
            .append_pair("authSource", &auth_db);
        Ok(Self {
            host,
            port: url.port().unwrap_or(27017),
            user: decode(url.username())?,
            password: decode(url.password().unwrap_or_default())?,
            auth_db,
            ca,
            uri: tool_uri.into(),
        })
    }

    fn client(&self) -> Result<Client, SnapshotError> {
        let credential = Credential::builder()
            .username(self.user.clone())
            .password(self.password.clone())
            .source(self.auth_db.clone())
            .build();
        let options = ClientOptions::builder()
            .hosts(vec![ServerAddress::Tcp {
                host: self.host.clone(),
                port: Some(self.port),
            }])
            .credential(credential)
            .tls(
                self.ca
                    .as_ref()
                    .map(|ca| Tls::Enabled(TlsOptions::builder().ca_file_path(ca.clone()).build())),
            )
            .build();
        Ok(Client::with_options(options)?)
    }
}

async fn frozen(client: &Client) -> Result<(), SnapshotError> {
    let state = client
        .database("admin")
        .run_command(doc! {"currentOp":1})
        .await?;
    if state.get_bool("fsyncLock") != Ok(true) {
        return Err(SnapshotError::Setting(
            "mongodb_source_must_remain_externally_fsync_locked_until_capture_finishes",
        ));
    }
    Ok(())
}

fn require_frozen(options: &Options) -> Result<(), SnapshotError> {
    if options.consistency.as_deref() != Some("frozen_source") {
        return Err(SnapshotError::Setting(
            "mongodb_requires_explicit_consistency_frozen_source",
        ));
    }
    Ok(())
}

fn encode(document: &Document) -> Result<String, SnapshotError> {
    let bytes = mongodb::bson::to_vec(document)
        .map_err(|_| SnapshotError::Setting("mongo_metadata_bson"))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

fn decode(value: &str) -> Result<Document, SnapshotError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| SnapshotError::Setting("mongo_metadata_bson"))?;
    mongodb::bson::from_slice(&bytes).map_err(|_| SnapshotError::Setting("mongo_metadata_bson"))
}

fn validate_collection(collection: &CollectionManifest) -> Result<(), SnapshotError> {
    let options = decode(&collection.options_bson)?;
    for key in options.keys() {
        if !matches!(
            key.as_str(),
            "validator" | "validationLevel" | "validationAction" | "collation" | "storageEngine"
        ) {
            return Err(SnapshotError::Unsupported {
                object: collection.name.clone(),
                reason: "collection_option_not_preserved_by_snapshot_copy",
            });
        }
    }
    let mut index_names = std::collections::HashSet::new();
    for encoded in &collection.indexes_bson {
        let index = decode(encoded)?;
        if index.contains_key("expireAfterSeconds") {
            return Err(SnapshotError::Unsupported {
                object: collection.name.clone(),
                reason: "ttl_indexes_would_mutate_the_immutable_generation",
            });
        }
        let name = index
            .get_str("name")
            .map_err(|_| SnapshotError::Setting("mongo_index_name"))?;
        if name.is_empty()
            || !index_names.insert(name.to_owned())
            || index.get_document("key").is_err()
            || index.contains_key("ns")
        {
            return Err(SnapshotError::Setting("mongo_index_metadata"));
        }
    }
    if !index_names.contains("_id_") {
        return Err(SnapshotError::Setting("mongo_collection_requires_id_index"));
    }
    Ok(())
}

pub(super) fn validate(manifest: &SnapshotManifest) -> Result<(), SnapshotError> {
    manifest.validate()?;
    let document = manifest
        .document
        .as_ref()
        .ok_or(SnapshotError::Setting("mongo_manifest_required"))?;
    for collection in &document.collections {
        validate_collection(collection)?;
    }
    Ok(())
}

async fn read(
    client: &Client,
    physical: &str,
    logical: &str,
    name: &str,
) -> Result<SnapshotManifest, SnapshotError> {
    let version = client
        .database("admin")
        .run_command(doc! {"buildInfo":1})
        .await?;
    let version = version
        .get_str("version")
        .map_err(|_| SnapshotError::Setting("mongo_source_version"))?;
    if !version.starts_with("7.0.") {
        return Err(SnapshotError::Setting("mongodb_snapshot_requires_7_0"));
    }
    let database = client.database(physical);
    let mut cursor = database.list_collections().await?;
    let mut collections = Vec::new();
    while cursor.advance().await? {
        // CollectionSpecification's options retain all raw BSON fields. Use
        // the command below for source metadata so BSON numeric types/order
        // are not normalized through typed option structures.
        let spec = cursor.deserialize_current()?;
        if !fg_protocol_common::snapshot_identifier(&spec.name) {
            return Err(SnapshotError::Unsupported {
                object: spec.name,
                reason: "collection_name_not_admitted",
            });
        }
        let reply = database
            .run_command(doc! {"listCollections":1,"filter":{"name":&spec.name},"cursor":{}})
            .await?;
        let batch = reply
            .get_document("cursor")
            .and_then(|c| c.get_array("firstBatch"))
            .map_err(|_| SnapshotError::Setting("mongo_collection_reply"))?;
        let raw = batch
            .first()
            .and_then(|b| b.as_document())
            .ok_or(SnapshotError::Setting("mongo_collection_reply"))?;
        if raw.get_str("type") != Ok("collection") {
            return Err(SnapshotError::Unsupported {
                object: spec.name,
                reason: "views_and_timeseries_not_admitted",
            });
        }
        let options = raw
            .get_document("options")
            .map_err(|_| SnapshotError::Setting("mongo_collection_options"))?;
        let native = database.collection::<Document>(&spec.name);
        let rows = i64::try_from(native.count_documents(doc! {}).await?)
            .map_err(|_| SnapshotError::Setting("snapshot_row_count_overflow"))?;
        let mut indexes = Vec::new();
        // run_command cursor is deliberately raw; listIndexes IndexModel
        // would omit unknown options and lose their original BSON order.
        let mut reply = database
            .run_command(doc! {"listIndexes":&spec.name,"cursor":{"batchSize":100}})
            .await?;
        loop {
            let cursor = reply
                .get_document("cursor")
                .map_err(|_| SnapshotError::Setting("mongo_index_reply"))?;
            let batch = cursor
                .get_array("firstBatch")
                .or_else(|_| cursor.get_array("nextBatch"))
                .map_err(|_| SnapshotError::Setting("mongo_index_reply"))?;
            for index in batch {
                let mut index = index
                    .as_document()
                    .cloned()
                    .ok_or(SnapshotError::Setting("mongo_index_reply"))?;
                index.remove("ns");
                indexes.push((
                    index.get_str("name").unwrap_or_default().to_owned(),
                    encode(&index)?,
                ));
            }
            let id = cursor
                .get_i64("id")
                .map_err(|_| SnapshotError::Setting("mongo_index_cursor"))?;
            if id == 0 {
                break;
            }
            reply = database
                .run_command(doc! {"getMore":id,"collection":&spec.name,"batchSize":100})
                .await?;
        }
        indexes.sort_by(|a, b| a.0.cmp(&b.0));
        let collection = CollectionManifest {
            name: spec.name,
            rows,
            options_bson: encode(options)?,
            indexes_bson: indexes.into_iter().map(|(_, b)| b).collect(),
        };
        validate_collection(&collection)?;
        collections.push(collection);
    }
    collections.sort_by(|a, b| a.name.cmp(&b.name));
    let manifest = SnapshotManifest {
        format_version: SNAPSHOT_FORMAT_VERSION,
        engine: "mongodb".into(),
        name: name.into(),
        logical_schema: logical.into(),
        source_version: version.into(),
        tables: Vec::new(),
        document: Some(DocumentSnapshot {
            consistency: "frozen_source".into(),
            collections,
        }),
    };
    validate(&manifest)?;
    Ok(manifest)
}

pub(super) async fn inspect(options: Options) -> Result<(), SnapshotError> {
    require_frozen(&options)?;
    let endpoint = Endpoint::from_env(&options.source_env, "FG_SOURCE_CA")?;
    let client = endpoint.client()?;
    frozen(&client).await?;
    let manifest = read(&client, &options.schema, &options.schema, &options.name).await?;
    let storage_preflight = super::source_capacity(
        &mut Native::Mongo(client.clone()),
        &manifest,
        &options.output,
    )
    .await?;
    let versions = tools::versions(crate::native::Engine::MongoDb)?;
    frozen(&client).await?;
    tools::private_write(
        &options.output,
        &serde_json::to_vec_pretty(
            &json!({"status":"admitted","manifest":manifest,"tools":versions,"storage_preflight":storage_preflight}),
        )?,
    )?;
    println!(
        "{}",
        json!({"status":"admitted","engine":"mongodb","output":options.output})
    );
    Ok(())
}

pub(super) async fn capture(options: Options) -> Result<(), SnapshotError> {
    require_frozen(&options)?;
    let endpoint = Endpoint::from_env(&options.source_env, "FG_SOURCE_CA")?;
    let client = endpoint.client()?;
    let versions = tools::versions(crate::native::Engine::MongoDb)?;
    frozen(&client).await?;
    let manifest = read(&client, &options.schema, &options.schema, &options.name).await?;
    let storage_preflight = super::source_capacity(
        &mut Native::Mongo(client.clone()),
        &manifest,
        &options.output,
    )
    .await?;
    storage_preflight.ensure_capacity()?;
    fs::DirBuilder::new().mode(0o700).create(&options.output)?;
    native_tool(
        &endpoint,
        "mongodump",
        &[
            format!("--db={}", options.schema),
            format!(
                "--archive={}",
                options.output.join("source.archive.gz").display()
            ),
            "--gzip".into(),
            "--numParallelCollections=1".into(),
        ],
    )
    .await?;
    let witness = options.output.join("witness");
    fs::DirBuilder::new().mode(0o700).create(&witness)?;
    for collection in &manifest
        .document
        .as_ref()
        .ok_or(SnapshotError::Setting("mongo_manifest_required"))?
        .collections
    {
        let path = witness.join(format!("{}.bson", collection.name));
        tools::private_write(&path, &[])?;
        let mut file = fs::OpenOptions::new().append(true).open(path)?;
        let mut cursor = client
            .database(&options.schema)
            .collection::<Document>(&collection.name)
            .find(doc! {})
            .sort(doc! {"_id":1})
            .await?;
        let mut rows = 0i64;
        while cursor.advance().await? {
            file.write_all(cursor.current().as_bytes())?;
            rows += 1;
        }
        file.sync_all()?;
        if rows != collection.rows {
            return Err(SnapshotError::Setting(
                "frozen_source_document_count_changed",
            ));
        }
    }
    frozen(&client).await?;
    let observed = read(&client, &options.schema, &options.schema, &options.name).await?;
    if manifest != observed {
        return Err(SnapshotError::Setting("frozen_source_catalog_changed"));
    }
    tools::private_write(
        &options.output.join("manifest.json"),
        &serde_json::to_vec_pretty(&manifest)?,
    )?;
    tools::private_write(
        &options.output.join("capture.json"),
        &serde_json::to_vec_pretty(&Capture {
            format_version: 1,
            complete: true,
            engine: "mongodb".into(),
            tools: versions,
            postgres_locale: None,
            storage_preflight: Some(storage_preflight.clone()),
        })?,
    )?;
    println!(
        "{}",
        json!({"status":"captured","engine":"mongodb","collections":manifest.document.as_ref().ok_or(SnapshotError::Setting("mongo_manifest_required"))?.collections.len(),"output":options.output,"storage_preflight":storage_preflight})
    );
    Ok(())
}

async fn native_tool(
    endpoint: &Endpoint,
    tool: &'static str,
    args: &[String],
) -> Result<(), SnapshotError> {
    let private = tools::PrivateDir::new()?;
    let config = private.path().join("mongo.yml");
    // JSON strings are valid YAML scalars. The URI never enters argv or logs.
    tools::private_write(
        &config,
        format!("uri: {}\n", json!(endpoint.uri)).as_bytes(),
    )?;
    let mut command = Command::new(tool);
    command
        .arg("--config")
        .arg(&config)
        .arg("--quiet")
        .args(args);
    if let Some(ca) = &endpoint.ca {
        command.arg("--ssl").arg("--sslCAFile").arg(ca);
    }
    tools::execute(
        command,
        tool,
        if tool == "mongodump" {
            "capture"
        } else {
            "import"
        },
    )
    .await
}

async fn verify_data(
    client: &Client,
    physical: &str,
    manifest: &SnapshotManifest,
    input: &Path,
) -> Result<(), SnapshotError> {
    for collection in &manifest
        .document
        .as_ref()
        .ok_or(SnapshotError::Setting("mongo_manifest_required"))?
        .collections
    {
        let mut file = BufReader::new(fs::File::open(
            input
                .join("witness")
                .join(format!("{}.bson", collection.name)),
        )?);
        let mut cursor = client
            .database(physical)
            .collection::<Document>(&collection.name)
            .find(doc! {})
            .sort(doc! {"_id":1})
            .await?;
        let mut rows = 0i64;
        while cursor.advance().await? {
            let mut length = [0u8; 4];
            file.read_exact(&mut length)?;
            let size = i32::from_le_bytes(length);
            if !(5..=16 * 1024 * 1024).contains(&size) {
                return Err(SnapshotError::Setting("mongo_witness_document_size"));
            }
            let mut expected = vec![0u8; size as usize];
            expected[..4].copy_from_slice(&length);
            file.read_exact(&mut expected[4..])?;
            if cursor.current().as_bytes() != expected {
                return Err(SnapshotError::Setting("restored_bson_image_differs"));
            }
            rows += 1;
        }
        let mut trailing = [0u8; 1];
        if file.read(&mut trailing)? != 0 || rows != collection.rows {
            return Err(SnapshotError::Setting(
                "restored_bson_document_count_differs",
            ));
        }
    }
    Ok(())
}

pub(super) async fn import(
    metadata: &Metadata,
    options: &NativeOptions,
    roles: &NativeRoles,
    input: &Path,
    manifest: &SnapshotManifest,
) -> Result<(), SnapshotError> {
    validate(manifest)?;
    let _versions = tools::versions(crate::native::Engine::MongoDb)?;
    let storage_preflight = super::import_capacity(input, crate::native::Engine::MongoDb)?;
    storage_preflight.ensure_capacity()?;
    let endpoint = Endpoint::from_env("FG_BACKEND_ADMIN_DSN", "FG_BACKEND_CA")?;
    let cooldown = crate::parse_refresh_cooldown(
        env::var(crate::REFRESH_COOLDOWN_SECONDS).ok().as_deref(),
        env::var_os(fg_protocol_common::MANAGED_BACKEND_HOST).is_some(),
    )
    .map_err(|_| SnapshotError::Setting("refresh_cooldown"))?;
    if cooldown < crate::DEFAULT_REFRESH_COOLDOWN_SECONDS && !options.is_loopback() {
        return Err(SnapshotError::Setting(
            "short_refresh_cooldown_requires_loopback",
        ));
    }
    let _guard = metadata.lock_bootstrap().await?;
    if metadata.importing_generation().await?.is_some() {
        return Err(SnapshotError::Setting(
            "unfinished_import_requires_retry_cleanup",
        ));
    }
    let mut native = options
        .connect()
        .await
        .map_err(|_| SnapshotError::Setting("target_native_connection"))?;
    let Native::Mongo(client) = &native else {
        return Err(SnapshotError::Setting("snapshot_target_engine_mismatch"));
    };
    crate::mongo::verify(
        client,
        roles,
        metadata.active_generation_id("mongodb").await?.is_some(),
    )
    .await
    .map_err(|_| SnapshotError::Setting("target_role_grants"))?;
    let generation = metadata.allocate_snapshot(manifest, cooldown).await?;
    metadata
        .record_snapshot_storage_preflight(
            generation.id,
            &serde_json::to_value(&storage_preflight)?,
        )
        .await?;
    let result = async {
        crate::mongo::ensure_fresh(client, &generation)
            .await
            .map_err(|_| SnapshotError::Setting("target_namespace_already_exists"))?;
        metadata.claim_generation(generation.id).await?;
        metadata
            .snapshot_phase(generation.id, "loading", None)
            .await?;
        native_tool(
            &endpoint,
            "mongorestore",
            &[
                format!("--archive={}", input.join("source.archive.gz").display()),
                "--gzip".into(),
                "--stopOnError".into(),
                "--numParallelCollections=1".into(),
                format!("--nsInclude={}.*", manifest.logical_schema),
                format!("--nsFrom={}.*", manifest.logical_schema),
                format!("--nsTo={}.*", generation.schema),
            ],
        )
        .await?;
        metadata
            .snapshot_phase(generation.id, "verifying", None)
            .await?;
        let observed = read(
            client,
            &generation.schema,
            &manifest.logical_schema,
            &manifest.name,
        )
        .await?;
        if manifest.document != observed.document {
            return Err(SnapshotError::Setting(
                "restored_mongo_catalog_or_counts_differ",
            ));
        }
        verify_data(client, &generation.schema, manifest, input).await?;
        crate::mongo::initialize_manifest_delta(client, &generation, roles)
            .await
            .map_err(|_| SnapshotError::Setting("snapshot_native_grants_or_delta"))?;
        crate::mongo::verify(client, roles, true)
            .await
            .map_err(|_| SnapshotError::Setting("snapshot_native_grants"))?;
        metadata.finish_snapshot(generation.id, "mongodb").await?;
        Ok::<_, SnapshotError>(())
    }
    .await;
    if let Err(error) = result {
        if metadata
            .snapshot_generation_status(generation.id)
            .await
            .ok()
            .as_deref()
            == Some("importing")
            && super::cleanup(metadata, &mut native, roles, &generation)
                .await
                .is_err()
        {
            let _ = metadata
                .snapshot_phase(
                    generation.id,
                    "cleanup_pending",
                    Some("native_cleanup_unconfirmed"),
                )
                .await;
        }
        return Err(error);
    }
    println!(
        "{}",
        json!({"status":"active","generation_id":generation.id,"engine":"mongodb","snapshot":manifest.name,"storage_preflight":storage_preflight})
    );
    Ok(())
}
