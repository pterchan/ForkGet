//! Genuine Dumpling snapshot export and Lightning logical import.

use std::{fs, os::unix::fs::DirBuilderExt, path::Path, process::Command};

use serde_json::json;

use super::{
    Capture, Options, SnapshotError, inspect,
    tools::{self, Endpoint},
};

pub(super) async fn capture(endpoint: Endpoint, options: Options) -> Result<(), SnapshotError> {
    let versions = tools::versions(crate::native::Engine::TiDB)?;
    let mut native = endpoint.connect().await?;
    let token = inspect::text(&mut native, "SELECT CAST(TIDB_CURRENT_TSO() AS CHAR)").await?;
    if token.is_empty() || !token.bytes().all(|b| b.is_ascii_digit()) {
        return Err(SnapshotError::Setting("tidb_snapshot_token"));
    }
    inspect::execute(&mut native, &format!("SET SESSION tidb_snapshot='{token}'")).await?;
    let manifest =
        inspect::read(&mut native, &options.schema, &options.schema, &options.name).await?;
    let storage_preflight = super::source_capacity(&mut native, &manifest, &options.output).await?;
    storage_preflight.ensure_capacity()?;
    fs::DirBuilder::new().mode(0o700).create(&options.output)?;
    let private = tools::PrivateDir::new()?;
    let config = private.path().join("dumpling.json");
    tools::private_write(
        &config,
        &serde_json::to_vec(
            &json!({"host":endpoint.host,"port":endpoint.port,"user":endpoint.user,"password":endpoint.password,"ca":endpoint.ca,"schema":options.schema,"tables":manifest.tables.iter().map(|t|&t.name).collect::<Vec<_>>(),"output":options.output.join("data"),"snapshot":token}),
        )?,
    )?;
    let mut command = Command::new("fg-dumpling-run");
    command.arg("--config").arg(&config);
    tools::execute(command, "fg-dumpling-run", "capture").await?;
    // The same historical timestamp remains pinned for the native metadata
    // and row-count witness; no source write can move these observations.
    let observed =
        inspect::read(&mut native, &options.schema, &options.schema, &options.name).await?;
    if manifest != observed {
        return Err(SnapshotError::Setting(
            "tidb_snapshot_catalog_or_count_changed",
        ));
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
            engine: "tidb".into(),
            tools: versions,
            postgres_locale: None,
            storage_preflight: Some(storage_preflight.clone()),
        })?,
    )?;
    println!(
        "{}",
        json!({"status":"captured","engine":"tidb","tables":manifest.tables.len(),"output":options.output,"storage_preflight":storage_preflight})
    );
    Ok(())
}

pub(super) async fn load(
    endpoint: &Endpoint,
    source: &str,
    target: &str,
    input: &Path,
) -> Result<(), SnapshotError> {
    let private = tools::PrivateDir::new()?;
    let config = private.path().join("lightning.toml");
    // JSON's escaped string syntax is also a TOML basic string. Every value
    // below is data in a private config file, never shell text or argv.
    let mut text = format!(
        "[lightning]\nlevel = \"error\"\nfile = {}\ncheck-requirements = true\nregion-concurrency = 1\ntable-concurrency = 1\nindex-concurrency = 1\n[tikv-importer]\nbackend = \"tidb\"\n[checkpoint]\nenable = false\n[tidb]\nhost = {}\nport = {}\nuser = {}\npassword = {}\ntls = {}\nsql-mode = \"STRICT_ALL_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION\"\n[tidb.session-vars]\ntime_zone = \"+00:00\"\n[mydumper]\ndata-source-dir = {}\nno-schema = true\ncase-sensitive = true\nfilter = [{}]\n[post-restore]\nchecksum = \"off\"\nanalyze = \"off\"\n[[routes]]\nschema-pattern = {}\ntarget-schema = {}\n",
        json!(private.path().join("lightning.log")),
        json!(endpoint.host),
        endpoint.port,
        json!(endpoint.user),
        json!(endpoint.password),
        json!(if endpoint.ca.is_some() {
            "cluster"
        } else {
            "false"
        }),
        json!(input),
        json!(format!("{source}.*")),
        json!(source),
        json!(target)
    );
    if let Some(ca) = &endpoint.ca {
        text.push_str(&format!("[security]\nca-path = {}\n", json!(ca)));
    }
    tools::private_write(&config, text.as_bytes())?;
    let mut command = Command::new("tidb-lightning");
    command.arg("--config").arg(config).arg("--redact-info-log");
    tools::execute(command, "tidb-lightning", "import").await
}
