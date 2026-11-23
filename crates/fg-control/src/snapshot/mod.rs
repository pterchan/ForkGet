//! Operator-owned native snapshot capture, admission and recoverable import.

pub(crate) mod ddl;
mod diagnostics;
mod inspect;
mod mongo;
mod tidb;
mod tools;

use std::{
    env, fs,
    io::{BufRead, BufReader},
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
};

use fg_meta::{BootstrapGeneration, Metadata};
use fg_protocol_common::{SnapshotManifest, UnsupportedTidbBackend, admit_tidb_backend};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    ControlError, bootstrap,
    grants::{self, NativeRoles},
    native::{Engine, Native, NativeOptions},
    verify,
};
use tools::Endpoint;

#[derive(Debug, thiserror::Error)]
pub(crate) enum SnapshotError {
    #[error(transparent)]
    UnsupportedTidb(#[from] UnsupportedTidbBackend),
    #[error(transparent)]
    Ddl(#[from] crate::native::DdlError),
    #[error("Snapshot setting refused: {0}")]
    Setting(&'static str),
    #[error("Snapshot object {object} refused: {reason}")]
    Unsupported {
        object: String,
        reason: &'static str,
    },
    #[error("Snapshot native operation failed ({}); inspect the snapshot job phase", crate::native_failure(.0))]
    Native(#[from] sqlx::Error),
    #[error("Snapshot MongoDB operation failed; inspect the snapshot job phase")]
    Mongo(#[from] mongodb::error::Error),
    #[error(transparent)]
    Capacity(#[from] crate::capacity::CapacityError),
    #[error("Snapshot filesystem operation failed")]
    Io(#[from] std::io::Error),
    #[error("Snapshot manifest is invalid")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Admission(#[from] fg_protocol_common::SnapshotAdmissionError),
    #[error(transparent)]
    Metadata(#[from] fg_meta::MetaError),
    #[error("Snapshot native tool {tool} failed during {phase} (exit {status:?})")]
    Tool {
        tool: &'static str,
        phase: &'static str,
        status: Option<i32>,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Capture {
    format_version: u32,
    complete: bool,
    engine: String,
    tools: serde_json::Value,
    #[serde(default)]
    postgres_locale: Option<PostgresLocale>,
    #[serde(default)]
    storage_preflight: Option<crate::capacity::StoragePreflight>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PostgresLocale {
    encoding: String,
    collate: String,
    ctype: String,
    provider: String,
    version: Option<String>,
}

async fn postgres_locale(native: &mut Native) -> Result<PostgresLocale, SnapshotError> {
    let json = inspect::text(native, "SELECT json_build_object('encoding',pg_encoding_to_char(encoding),'collate',datcollate,'ctype',datctype,'provider',datlocprovider::text,'version',pg_database_collation_actual_version(oid))::text FROM pg_database WHERE datname=current_database()").await?;
    let locale: PostgresLocale = serde_json::from_str(&json)?;
    if locale.encoding != "UTF8" || locale.provider != "c" {
        return Err(SnapshotError::Setting(
            "postgres_capture_requires_utf8_libc_locale",
        ));
    }
    Ok(locale)
}

struct Options {
    source_env: String,
    schema: String,
    name: String,
    output: PathBuf,
    consistency: Option<String>,
}

fn option<'a>(args: &'a [String], name: &str) -> Result<&'a str, SnapshotError> {
    let mut values = args.chunks_exact(2).filter(|pair| pair[0] == name);
    let value = values
        .next()
        .map(|pair| pair[1].as_str())
        .ok_or(SnapshotError::Setting("missing_snapshot_argument"))?;
    if values.next().is_some() {
        return Err(SnapshotError::Setting("duplicate_snapshot_argument"));
    }
    Ok(value)
}

fn options(args: &[String]) -> Result<Options, SnapshotError> {
    if !args.len().is_multiple_of(2)
        || args.chunks_exact(2).any(|pair| {
            !matches!(
                pair[0].as_str(),
                "--source-env" | "--schema" | "--name" | "--output" | "--consistency"
            )
        })
    {
        return Err(SnapshotError::Setting("snapshot_arguments"));
    }
    let source_env = option(args, "--source-env")?;
    if source_env.is_empty()
        || !source_env
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(SnapshotError::Setting("source_environment_name"));
    }
    let schema = option(args, "--schema")?;
    let name = option(args, "--name")?;
    if !fg_protocol_common::snapshot_identifier(schema)
        || !fg_protocol_common::valid_branch_name(name)
    {
        return Err(SnapshotError::Setting("snapshot_schema_or_name"));
    }
    Ok(Options {
        source_env: source_env.to_owned(),
        schema: schema.to_owned(),
        name: name.to_owned(),
        output: option(args, "--output")?.into(),
        consistency: args
            .chunks_exact(2)
            .find(|pair| pair[0] == "--consistency")
            .map(|pair| pair[1].clone()),
    })
}

pub(crate) async fn run(args: &[String]) -> Result<(), ControlError> {
    let (command, args) = args
        .split_first()
        .ok_or(ControlError::Config("snapshot subcommand required"))?;
    match command.as_str() {
        "inspect" => {
            let options = options(args)?;
            if mongo::source(&options.source_env)? {
                mongo::inspect(options).await?;
                return Ok(());
            }
            if options.consistency.is_some() {
                return Err(SnapshotError::Setting(
                    "consistency_argument_is_only_for_frozen_mongodb_sources",
                )
                .into());
            }
            let endpoint = Endpoint::from_env(&options.source_env, "FG_SOURCE_CA")?;
            let mut native = endpoint.connect().await?;
            inspect::source_visibility(&mut native, &options.schema).await?;
            let manifest =
                inspect::read(&mut native, &options.schema, &options.schema, &options.name).await?;
            let versions = tools::versions(endpoint.engine)?;
            let storage_preflight =
                source_capacity(&mut native, &manifest, &options.output).await?;
            tools::private_write(
                &options.output,
                &serde_json::to_vec_pretty(
                    &json!({"status":"admitted","manifest":manifest,"tools":versions,"storage_preflight":storage_preflight}),
                )
                .map_err(SnapshotError::Json)?,
            )?;
            println!(
                "{}",
                json!({"status":"admitted","output":options.output,"engine":endpoint.engine.name()})
            );
        }
        "capture" => capture(options(args)?).await?,
        "import" => {
            if args.len() != 2 || args[0] != "--input" {
                return Err(ControlError::Config("snapshot import --input <bundle>"));
            }
            let (metadata, native, roles) = crate::generation_settings().await?;
            import(&metadata, &native, &roles, Path::new(&args[1])).await?;
        }
        "status" | "retry-cleanup" => {
            let metadata = crate::metadata("FG_META_DSN", &crate::required("FG_META_DSN")?).await?;
            let selected = if args.is_empty() {
                None
            } else {
                if args.len() != 2 || args[0] != "--id" {
                    return Err(ControlError::Config("snapshot status [--id job]"));
                }
                Some(
                    args[1]
                        .parse::<i64>()
                        .ok()
                        .filter(|id| *id > 0)
                        .ok_or(ControlError::Config("positive snapshot job ID required"))?,
                )
            };
            let jobs = if let Some(id) = selected {
                vec![
                    metadata
                        .snapshot_job(id)
                        .await?
                        .ok_or(ControlError::Config("snapshot job not found"))?,
                ]
            } else {
                metadata.snapshot_jobs().await?
            };
            if command == "status" {
                println!(
                    "{}",
                    json!({"jobs":jobs.into_iter().filter(|job|selected.is_none_or(|id|id==job.id)).collect::<Vec<_>>()})
                );
            } else {
                let id = selected.ok_or(ControlError::Config("snapshot retry-cleanup --id job"))?;
                let job = jobs
                    .into_iter()
                    .find(|job| job.id == id)
                    .ok_or(ControlError::Config("snapshot job not found"))?;
                let generation = job
                    .generation_id
                    .ok_or(ControlError::Config("snapshot job has no generation"))?;
                let (metadata, options, roles) = crate::generation_settings().await?;
                let _guard = metadata.lock_bootstrap().await?;
                let target = generation_for(&metadata, generation, &job.engine).await?;
                let mut native = options.connect().await?;
                cleanup(&metadata, &mut native, &roles, &target).await?;
                println!(
                    "{}",
                    json!({"job_id":id,"generation_id":generation,"status":"cleaned"})
                );
            }
        }
        _ => {
            return Err(ControlError::Config(
                "snapshot subcommand: inspect, capture, import, status, retry-cleanup",
            ));
        }
    }
    Ok(())
}

async fn capture(options: Options) -> Result<(), SnapshotError> {
    if mongo::source(&options.source_env)? {
        return mongo::capture(options).await;
    }
    if options.consistency.is_some() {
        return Err(SnapshotError::Setting(
            "consistency_argument_is_only_for_frozen_mongodb_sources",
        ));
    }
    let endpoint = Endpoint::from_env(&options.source_env, "FG_SOURCE_CA")?;
    if endpoint.engine == Engine::TiDB {
        return tidb::capture(endpoint, options).await;
    }
    let mut native = endpoint.connect().await?;
    let versions = tools::versions(endpoint.engine)?;
    inspect::source_visibility(&mut native, &options.schema).await?;
    if endpoint.engine == Engine::Postgres {
        inspect::execute(
            &mut native,
            "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",
        )
        .await?;
    } else {
        inspect::execute(&mut native, "LOCK INSTANCE FOR BACKUP").await?;
    }
    let result=async{
        let mut manifest=inspect::read(&mut native,&options.schema,&options.schema,&options.name).await?;
        let locale=if endpoint.engine==Engine::Postgres{Some(postgres_locale(&mut native).await?)}else{None};
        let storage_preflight=source_capacity(&mut native,&manifest,&options.output).await?;
        storage_preflight.ensure_capacity()?;
        fs::DirBuilder::new().mode(0o700).create(&options.output)?;
        if endpoint.engine==Engine::Postgres{
            let token=inspect::text(&mut native,"SELECT pg_export_snapshot()").await?;
            tools::pg_dump(&endpoint,&options.schema,Some(&token),&options.output.join("source.dump")).await?;
        }else{
            let tables=manifest.tables.iter().map(|table|table.name.clone()).collect::<Vec<_>>();
            tools::mysql_dump(&endpoint,&options.schema,&tables,&options.output.join("data")).await?;
            mysql_counts(&options.output.join("data"),&mut manifest)?;
        }
        tools::private_write(&options.output.join("manifest.json"),&serde_json::to_vec_pretty(&manifest)?)?;
        tools::private_write(&options.output.join("capture.json"),&serde_json::to_vec_pretty(&Capture{format_version:1,complete:true,engine:manifest.engine.clone(),tools:versions,postgres_locale:locale,storage_preflight:Some(storage_preflight.clone())})?)?;
        println!("{}",json!({"status":"captured","engine":manifest.engine,"tables":manifest.tables.len(),"output":options.output,"storage_preflight":storage_preflight}));
        Ok(())
    }.await;
    let release = if endpoint.engine == Engine::Postgres {
        "ROLLBACK"
    } else {
        "UNLOCK INSTANCE"
    };
    // The connection is dropped right after this, releasing the lock or
    // instance; capture failures already surface through `result`.
    let _ = inspect::execute(&mut native, release).await;
    result
}

async fn source_capacity(
    native: &mut Native,
    manifest: &SnapshotManifest,
    output: &Path,
) -> Result<crate::capacity::StoragePreflight, SnapshotError> {
    let bytes =
        crate::capacity::manifest_estimate(native, manifest, &manifest.logical_schema).await?;
    Ok(crate::capacity::assess(
        bytes,
        "native_allocation_statistics_with_64KiB_minimum_per_relation",
        0,
        if native.engine() == Engine::Postgres {
            1
        } else {
            2
        },
        output,
    )?)
}

fn import_capacity(
    input: &Path,
    engine: Engine,
) -> Result<crate::capacity::StoragePreflight, SnapshotError> {
    let capture: Capture = serde_json::from_slice(&fs::read(input.join("capture.json"))?)?;
    let bytes = capture
        .storage_preflight
        .ok_or(SnapshotError::Setting(
            "bundle_requires_recapture_with_storage_estimate",
        ))?
        .estimated_native_bytes;
    Ok(crate::capacity::assess(
        bytes,
        "captured_native_allocation_statistics_with_64KiB_minimum_per_relation",
        if engine == Engine::Postgres { 2 } else { 1 },
        if engine == Engine::Postgres { 1 } else { 0 },
        &env::temp_dir(),
    )?)
}

fn mysql_counts(directory: &Path, manifest: &mut SnapshotManifest) -> Result<(), SnapshotError> {
    for table in &mut manifest.tables {
        let path = directory.join(format!("{}@{}.tsv", manifest.logical_schema, table.name));
        let mut reader = BufReader::new(fs::File::open(path)?);
        let mut bytes = Vec::new();
        let mut count = 0_i64;
        loop {
            bytes.clear();
            if reader.read_until(b'\n', &mut bytes)? == 0 {
                break;
            }
            count = count
                .checked_add(1)
                .ok_or(SnapshotError::Setting("snapshot_row_count_overflow"))?;
        }
        table.rows = count;
    }
    Ok(())
}

fn bundle(input: &Path) -> Result<SnapshotManifest, SnapshotError> {
    let capture: Capture = serde_json::from_slice(&fs::read(input.join("capture.json"))?)?;
    let manifest: SnapshotManifest =
        serde_json::from_slice(&fs::read(input.join("manifest.json"))?)?;
    if capture.format_version != 1 || !capture.complete || capture.engine != manifest.engine {
        return Err(SnapshotError::Setting("incomplete_or_mismatched_bundle"));
    }
    manifest.validate()?;
    for table in &manifest.tables {
        for check in &table.checks {
            inspect::validate_check(&check.expression, &table.columns)?;
        }
    }
    Ok(manifest)
}

async fn import(
    metadata: &Metadata,
    options: &NativeOptions,
    roles: &NativeRoles,
    input: &Path,
) -> Result<(), SnapshotError> {
    let manifest = bundle(input)?;
    if manifest.engine == Engine::TiDB.name() {
        admit_tidb_backend()?;
    }
    if !matches!(
        manifest.engine.as_str(),
        "mysql" | "postgresql" | "tidb" | "mongodb"
    ) || manifest.engine != options.engine().name()
    {
        return Err(SnapshotError::Setting("snapshot_target_engine_mismatch"));
    }
    if manifest.engine == "mongodb" {
        return mongo::import(metadata, options, roles, input, &manifest).await;
    }
    let endpoint = Endpoint::from_env("FG_BACKEND_ADMIN_DSN", "FG_BACKEND_CA")?;
    if manifest.engine == "postgresql" {
        tools::pg_validate_archive(&input.join("source.dump"), &manifest.logical_schema)?;
    }
    let _versions = tools::versions(endpoint.engine)?;
    let storage_preflight = import_capacity(input, endpoint.engine)?;
    storage_preflight.ensure_capacity()?;
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
    let mut native = options.connect().await.map_err(|error| match error {
        ControlError::UnsupportedTidb(error) => error.into(),
        _ => SnapshotError::Setting("target_native_connection"),
    })?;
    if native.engine() == Engine::Postgres {
        inspect::execute(&mut native, "SET client_min_messages=WARNING").await?;
        let capture: Capture = serde_json::from_slice(&fs::read(input.join("capture.json"))?)?;
        if capture.postgres_locale.as_ref() != Some(&postgres_locale(&mut native).await?) {
            return Err(SnapshotError::Setting(
                "target_postgres_locale_must_match_the_captured_source",
            ));
        }
    }
    if native.engine() == Engine::MySql
        && inspect::text(&mut native, "SELECT CAST(@@GLOBAL.local_infile AS CHAR)").await? != "1"
    {
        return Err(SnapshotError::Setting(
            "enable_local_infile_on_the_trusted_target_before_native_import",
        ));
    }
    verify::check_constraint_enforcement(&mut native)
        .await
        .map_err(|_| SnapshotError::Setting("target_constraint_enforcement"))?;
    let catalog = metadata.native_catalog(&manifest.engine).await?;
    grants::verify(&mut native, roles, &catalog, None)
        .await
        .map_err(|_| SnapshotError::Setting("target_role_grants"))?;
    let generation = metadata.allocate_snapshot(&manifest, cooldown).await?;
    metadata
        .record_snapshot_storage_preflight(
            generation.id,
            &serde_json::to_value(&storage_preflight)?,
        )
        .await?;
    tracing::info!(component="snapshot",generation_id=generation.id,engine=%manifest.engine,"snapshot import allocated");
    let result = install(
        metadata,
        &mut native,
        &endpoint,
        roles,
        &generation,
        &manifest,
        input,
    )
    .await;
    if let Err(error) = result {
        // Never remove a generation after an uncertain activation commit.
        if metadata
            .snapshot_generation_status(generation.id)
            .await
            .ok()
            .as_deref()
            == Some("importing")
            && let Err(cleanup_error) = cleanup(metadata, &mut native, roles, &generation).await
        {
            let _ = metadata
                .snapshot_phase(
                    generation.id,
                    "cleanup_pending",
                    Some("native_cleanup_unconfirmed"),
                )
                .await;
            tracing::warn!(component="snapshot",generation_id=generation.id,reason=%cleanup_error,"snapshot cleanup remains pending");
        }
        return Err(error);
    }
    println!(
        "{}",
        json!({"status":"active","generation_id":generation.id,"snapshot":manifest.name,"engine":manifest.engine,"storage_preflight":storage_preflight})
    );
    Ok(())
}

async fn install(
    metadata: &Metadata,
    native: &mut Native,
    endpoint: &Endpoint,
    roles: &NativeRoles,
    generation: &BootstrapGeneration,
    manifest: &SnapshotManifest,
    input: &Path,
) -> Result<(), SnapshotError> {
    let engine = native.engine();
    if verify::has_schema(native, &generation.schema)
        .await
        .map_err(|_| SnapshotError::Setting("target_namespace_check"))?
    {
        return Err(SnapshotError::Setting("target_namespace_already_exists"));
    }
    if engine == Engine::Postgres {
        let stage = stage_name(generation.id);
        if inspect::text(
            native,
            &format!(
                "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname='{}')::text",
                stage
            ),
        )
        .await?
            == "true"
        {
            return Err(SnapshotError::Setting("staging_database_already_exists"));
        }
    }
    metadata.claim_generation(generation.id).await?;
    metadata
        .snapshot_phase(generation.id, "staging", None)
        .await?;
    if engine == Engine::Postgres {
        postgres_install(native, endpoint, generation, manifest, input).await?;
    } else {
        inspect::execute(
            native,
            &format!(
                "CREATE SCHEMA {} CHARACTER SET utf8mb4",
                engine.quote(&generation.schema)
            ),
        )
        .await?;
        for index in manifest.validate()? {
            let table = &manifest.tables[index];
            inspect::execute(
                native,
                &ddl::table(
                    engine,
                    &engine.relation(&generation.schema, &table.name),
                    table,
                    false,
                )?,
            )
            .await?;
        }
        metadata
            .snapshot_phase(generation.id, "loading", None)
            .await?;
        if engine == Engine::TiDB {
            tidb::load(
                endpoint,
                &manifest.logical_schema,
                &generation.schema,
                &input.join("data"),
            )
            .await?;
        } else {
            tools::mysql_load(endpoint, &generation.schema, &input.join("data")).await?;
        }
        ddl::constraints(native, &generation.schema, manifest).await?;
    }
    metadata
        .snapshot_phase(generation.id, "verifying", None)
        .await?;
    let observed = inspect::read(
        native,
        &generation.schema,
        &manifest.logical_schema,
        &manifest.name,
    )
    .await?;
    compare(manifest, &observed)?;
    inspect::execute(
        native,
        &format!(
            "CREATE SCHEMA IF NOT EXISTS {}",
            engine.quote("forkget_delta")
        ),
    )
    .await?;
    for table in &generation.tables {
        let definition = manifest
            .tables
            .iter()
            .find(|definition| definition.name == table.logical_table)
            .ok_or(SnapshotError::Setting("registered_table_missing"))?;
        inspect::execute(
            native,
            &ddl::table(
                engine,
                &engine.relation(&table.delta_schema, &table.delta_table),
                definition,
                true,
            )?,
        )
        .await?;
    }
    if engine == Engine::Postgres {
        inspect::execute(
            native,
            &format!(
                "GRANT USAGE ON SCHEMA {},{} TO {}",
                engine.quote(&generation.schema),
                engine.quote("forkget_delta"),
                roles.service.account
            ),
        )
        .await?;
        inspect::execute(
            native,
            &format!(
                "GRANT USAGE ON SCHEMA {} TO {}",
                engine.quote("forkget_delta"),
                roles.collector.account
            ),
        )
        .await?;
        if let Some(admin) = &roles.branch_admin {
            inspect::execute(
                native,
                &format!(
                    "GRANT USAGE ON SCHEMA {} TO {}",
                    engine.quote(&generation.schema),
                    admin.account
                ),
            )
            .await?;
        }
    }
    for table in &generation.tables {
        grants::grant_table(native, table, roles)
            .await
            .map_err(|_| SnapshotError::Setting("snapshot_native_grants"))?;
    }
    let catalog = metadata.native_catalog(&manifest.engine).await?;
    grants::verify(native, roles, &catalog, Some(generation))
        .await
        .map_err(|_| SnapshotError::Setting("snapshot_native_grants"))?;
    if engine == Engine::Postgres {
        drop_stage(native, generation.id).await?;
    }
    metadata
        .finish_snapshot(generation.id, &manifest.engine)
        .await?;
    Ok(())
}

fn stage_name(generation: i64) -> String {
    format!("fg_stage_snapshot_{generation}")
}

async fn postgres_install(
    native: &mut Native,
    endpoint: &Endpoint,
    generation: &BootstrapGeneration,
    manifest: &SnapshotManifest,
    input: &Path,
) -> Result<(), SnapshotError> {
    let stage = stage_name(generation.id);
    let engine = Engine::Postgres;
    let locale = postgres_locale(native).await?;
    inspect::execute(
        native,
        &format!(
            "CREATE DATABASE {} TEMPLATE template0 ENCODING 'UTF8' LOCALE_PROVIDER libc LC_COLLATE {} LC_CTYPE {}",
            engine.quote(&stage), ddl::literal(&locale.collate), ddl::literal(&locale.ctype)
        ),
    )
    .await?;
    let stage_endpoint = endpoint.database(&stage);
    tools::pg_restore(&stage_endpoint, &input.join("source.dump")).await?;
    let mut staging = stage_endpoint.connect().await?;
    let observed = inspect::read(
        &mut staging,
        &manifest.logical_schema,
        &manifest.logical_schema,
        &manifest.name,
    )
    .await?;
    compare(manifest, &observed)?;
    inspect::execute(
        &mut staging,
        &format!(
            "ALTER SCHEMA {} RENAME TO {}",
            engine.quote(&manifest.logical_schema),
            engine.quote(&generation.schema)
        ),
    )
    .await?;
    let private = tools::PrivateDir::new()?;
    let remapped = private.path().join("remapped.dump");
    tools::pg_dump(&stage_endpoint, &generation.schema, None, &remapped).await?;
    tools::pg_restore(endpoint, &remapped).await
}

fn compare(expected: &SnapshotManifest, observed: &SnapshotManifest) -> Result<(), SnapshotError> {
    if expected.engine != observed.engine
        || expected.logical_schema != observed.logical_schema
        || expected.tables != observed.tables
    {
        diagnostics::record(expected, observed);
        return Err(SnapshotError::Setting(
            "restored_catalog_or_row_counts_differ",
        ));
    }
    Ok(())
}

async fn generation_for(
    metadata: &Metadata,
    id: i64,
    engine: &str,
) -> Result<BootstrapGeneration, SnapshotError> {
    let manifest = metadata
        .snapshot_manifest(id)
        .await?
        .ok_or(SnapshotError::Setting("snapshot_generation_not_registered"))?;
    if manifest.engine != engine {
        return Err(SnapshotError::Setting("snapshot_target_engine_mismatch"));
    }
    Ok(BootstrapGeneration {
        id,
        engine: engine.to_owned(),
        schema: format!("fg_g{id}"),
        native_claimed: metadata.snapshot_native_claimed(id).await?,
        tables: metadata.snapshot_registered_tables(id, engine).await?,
    })
}

async fn drop_stage(native: &mut Native, id: i64) -> Result<(), SnapshotError> {
    inspect::execute(
        native,
        &format!(
            "DROP DATABASE IF EXISTS {} WITH (FORCE)",
            Engine::Postgres.quote(&stage_name(id))
        ),
    )
    .await
}

async fn cleanup(
    metadata: &Metadata,
    native: &mut Native,
    roles: &NativeRoles,
    generation: &BootstrapGeneration,
) -> Result<(), SnapshotError> {
    if native.engine() == Engine::Postgres {
        inspect::execute(native, "SET client_min_messages=WARNING").await?;
    }
    let status = metadata.snapshot_generation_status(generation.id).await?;
    if !matches!(status.as_str(), "importing" | "failed") {
        return Err(SnapshotError::Setting(
            "active_or_retained_generation_cannot_be_cleaned",
        ));
    }
    metadata
        .snapshot_phase(generation.id, "cleanup_pending", Some("import_failed"))
        .await?;
    if metadata.snapshot_native_claimed(generation.id).await? {
        if native.engine() == Engine::Postgres {
            drop_stage(native, generation.id).await?;
        }
        bootstrap::remove_generation(native, generation, roles)
            .await
            .map_err(|_| SnapshotError::Setting("native_cleanup_unconfirmed"))?;
    }
    metadata.fail_generation(generation.id).await?;
    metadata
        .snapshot_phase(
            generation.id,
            "failed",
            Some("import_failed_cleanup_confirmed"),
        )
        .await?;
    Ok(())
}
