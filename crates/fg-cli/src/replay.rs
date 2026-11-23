//! Complete artifacts and control-owned, exclusive replay jobs.
mod plan;

use clap::{Args, ValueEnum};
use fg_protocol_common::{
    ARTIFACT_LIMIT, ARTIFACT_VERSION, ArtifactHeader, ArtifactReader, ArtifactTable,
    ArtifactWriter, ReplayOrigin, TypedChange, valid_branch_name,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs::File,
    io::{BufReader, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::time::{sleep, timeout};
use tokio_util::io::ReaderStream;

use crate::{
    Control, Error, Outcome,
    dryrun::{Engine, Signals},
};

#[derive(Args)]
pub(super) struct Export {
    #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
    id: i64,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Args)]
pub(super) struct Replay {
    #[arg(long, value_enum)]
    engine: ReplayEngine,
    #[arg(
        long,
        required_unless_present_any = ["verify_job", "apply_job"],
        conflicts_with_all = ["verify_job", "apply_job"]
    )]
    input: Option<PathBuf>,
    #[arg(long, required_unless_present_any = ["check", "verify_job", "apply_job"], conflicts_with_all = ["verify_job", "apply_job"])]
    name: Option<String>,
    #[arg(long, conflicts_with_all = ["verify_job", "apply_job", "stage_only"])]
    check: bool,
    #[arg(long, conflicts_with_all = ["verify_job", "apply_job"], help = "Create a private target and wait for independent budget review without applying changes")]
    stage_only: bool,
    #[arg(long, value_parser = clap::value_parser!(i64).range(1..), conflicts_with = "apply_job")]
    verify_job: Option<i64>,
    #[arg(long, value_parser = clap::value_parser!(i64).range(1..), help = "Apply an existing staged job using its target's current authorization and budget")]
    apply_job: Option<i64>,
}

#[derive(Clone, Copy, ValueEnum)]
enum ReplayEngine {
    Mysql,
    Postgresql,
    #[value(hide = !fg_protocol_common::TIDB_BACKEND_AVAILABLE)]
    Tidb,
    Mongodb,
}
impl ReplayEngine {
    const fn name(self) -> &'static str {
        match self {
            Self::Mysql => "mysql",
            Self::Postgresql => "postgresql",
            Self::Tidb => "tidb",
            Self::Mongodb => "mongodb",
        }
    }
    fn sql(self) -> Result<Engine, Error> {
        match self {
            Self::Mysql => Ok(Engine::Mysql),
            Self::Postgresql => Ok(Engine::Postgresql),
            Self::Tidb => Ok(Engine::Tidb),
            Self::Mongodb => Err(Error::ReplayUnsupported),
        }
    }
}

pub(super) async fn export(control: &Control, options: Export) -> Result<Value, Error> {
    let url = control
        .base
        .join(&format!("v1/branches/{}/export", options.id))
        .map_err(|_| Error::Origin)?;
    let mut response = control
        .client
        .get(url)
        .bearer_auth(&control.token)
        .timeout(Duration::from_secs(350))
        .send()
        .await
        .map_err(|_| Error::Network)?;
    if !response.status().is_success() {
        return Err(Error::Status(response.status().as_u16()));
    }
    let parent = options
        .output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut output = tempfile::NamedTempFile::new_in(parent).map_err(|_| Error::Artifact)?;
    let mut bytes = 0u64;
    while let Some(chunk) = response.chunk().await.map_err(|_| Error::Network)? {
        bytes = bytes
            .checked_add(chunk.len() as u64)
            .filter(|count| *count <= ARTIFACT_LIMIT)
            .ok_or(Error::ReplayArtifact)?;
        output.write_all(&chunk).map_err(|_| Error::Artifact)?;
    }
    output.as_file().sync_all().map_err(|_| Error::Artifact)?;
    let mut reader = ArtifactReader::new(BufReader::new(
        output.reopen().map_err(|_| Error::Artifact)?,
    ))
    .map_err(|_| Error::ReplayArtifact)?;
    let header = reader.header().clone();
    if header.source_branch_id != options.id {
        return Err(Error::ReplayContext);
    }
    while reader
        .next_entry()
        .map_err(|_| Error::ReplayArtifact)?
        .is_some()
    {}
    let end = reader.end().ok_or(Error::ReplayArtifact)?.clone();
    output
        .persist_noclobber(&options.output)
        .map_err(|_| Error::Artifact)?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| Error::Artifact)?;
    Ok(
        json!({"branch_id":options.id,"generation_id":header.origin.generation_id,
        "engine":header.engine,"format_version":2,"complete":true,"changes":end.changes,
        "replayable":end.replayable,"replay_reasons":end.reasons,"bytes":bytes,"output":options.output}),
    )
}

pub(super) async fn run(control: &Control, options: Replay) -> Result<Outcome, Error> {
    if matches!(options.engine, ReplayEngine::Tidb) {
        fg_protocol_common::admit_tidb_backend()?;
    }
    if let Some(job) = options.verify_job {
        let result = action(control, job, "verify").await?;
        return Ok(outcome(result));
    }
    if let Some(job) = options.apply_job {
        let staged = control
            .request(reqwest::Method::GET, &format!("v1/replays/{job}"), None)
            .await?;
        require_staged(&staged)?;
        let branch = staged["branch_id"].as_i64().ok_or(Error::Response)?;
        return apply_staged(control, job, branch, &mut Signals::install()?).await;
    }
    let input = options.input.as_deref().ok_or(Error::ReplayArtifact)?;
    let name = options.name.as_deref().unwrap_or_default();
    if !options.check && !valid_branch_name(name) {
        return Err(Error::Name);
    }
    let normalized = normalize(input, options.engine)?;
    let url = control.base.join("v1/replays").map_err(|_| Error::Origin)?;
    let file = tokio::fs::File::from_std(normalized.reopen().map_err(|_| Error::Artifact)?);
    let response = control
        .client
        .post(url)
        .bearer_auth(&control.token)
        .timeout(Duration::from_secs(350))
        .header("x-forkget-replay-name", name)
        .header("x-forkget-check", options.check.to_string())
        .body(reqwest::Body::wrap_stream(ReaderStream::new(file)))
        .send()
        .await
        .map_err(|_| Error::Network)?;
    if !response.status().is_success() {
        return Err(Error::Status(response.status().as_u16()));
    }
    let staged: Value = response.json().await.map_err(|_| Error::Response)?;
    if options.check {
        return Ok(Outcome {
            success: true,
            value: staged,
        });
    }
    let job = staged["job"]["id"].as_i64().ok_or(Error::Response)?;
    let branch = staged["branch"]["id"].as_i64().ok_or(Error::Response)?;
    if options.stage_only {
        return match wait_active(control, branch).await {
            Ok(active) => Ok(Outcome {
                success: true,
                value: json!({"job_id":job,"branch_id":branch,"generation_id":staged["job"]["generation_id"],
                    "job":staged["job"],"branch":active,"staged":true,"verified":false,
                    "transaction":"not_started","cleanup":"retained", "next_action":"review the target budget, then replay --apply-job"}),
            }),
            Err(error) => Ok(provision_failure(job, branch, error)),
        };
    }
    apply_staged(control, job, branch, &mut Signals::install()?).await
}

fn require_staged(job: &Value) -> Result<(), Error> {
    if job["state"] != "staged" {
        return Err(Error::Rejected {
            code: "FG-2002".into(),
            message: "replay_job_not_staged: only a staged job may be applied; use --verify-job for failed or unknown results".into(),
        });
    }
    Ok(())
}

fn provision_failure(job: i64, branch: i64, error: Error) -> Outcome {
    Outcome {
        success: false,
        value: json!({"job_id":job,"branch_id":branch,"retained":true,"failure":error.to_string(),"phase":"provision"}),
    }
}

async fn apply_staged(
    control: &Control,
    job: i64,
    branch: i64,
    signals: &mut Signals,
) -> Result<Outcome, Error> {
    if let Err(error) = wait_active(control, branch).await {
        return Ok(provision_failure(job, branch, error));
    }
    let result = tokio::select! {
        biased;
        () = signals.cancelled() => {
            let cleanup = control.drop_id(branch).await.is_ok();
            return Ok(Outcome { success:false, value:json!({"job_id":job,"branch_id":branch,"cancelled":true,"cleanup_requested":cleanup,"verify_required":true}) });
        }
        result = action(control,job,"apply") => result,
    };
    match result {
        Ok(value) => Ok(outcome(value)),
        Err(_) => {
            // A lost response never grants permission to apply the plan again.
            match action(control, job, "verify").await {
                Ok(value) => Ok(outcome(value)),
                Err(_) => Ok(Outcome {
                    success: false,
                    value: json!({"job_id":job,"branch_id":branch,"transaction":"unknown","retained":true,"verify_required":true}),
                }),
            }
        }
    }
}

fn outcome(mut value: Value) -> Outcome {
    value["job_id"] = value["job"]["id"].clone();
    value["branch_id"] = value["job"]["branch_id"].clone();
    value["generation_id"] = value["job"]["generation_id"].clone();
    value["transaction"] = value["result"]["transaction"].clone();
    value["failure"] = value["result"]["failure"].clone();
    value["cleanup"] = json!("retained");
    Outcome {
        success: value["verified"] == true,
        value,
    }
}

async fn action(control: &Control, job: i64, action: &str) -> Result<Value, Error> {
    let url = control
        .base
        .join(&format!("v1/replays/{job}/{action}"))
        .map_err(|_| Error::Origin)?;
    let response = control
        .client
        .post(url)
        .bearer_auth(&control.token)
        .timeout(Duration::from_secs(350))
        .send()
        .await
        .map_err(|_| Error::Network)?;
    if !response.status().is_success() {
        return Err(Error::Status(response.status().as_u16()));
    }
    response.json().await.map_err(|_| Error::Response)
}

async fn wait_active(control: &Control, branch: i64) -> Result<Value, Error> {
    timeout(Duration::from_secs(300), async {
        loop {
            let status = control.branch(branch).await?;
            match status["status"].as_str() {
                Some("active") => return Ok(status),
                Some("provisioning") => sleep(Duration::from_millis(150)).await,
                _ => return Err(Error::ReplayContext),
            }
        }
    })
    .await
    .map_err(|_| Error::Network)?
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyArtifact {
    format_version: u8,
    engine: Engine,
    source_branch_id: i64,
    origin: ReplayOrigin,
    tables: Vec<plan::Table>,
    sql: Vec<String>,
}

fn normalize(path: &Path, engine: ReplayEngine) -> Result<tempfile::NamedTempFile, Error> {
    let source = File::open(path).map_err(|_| Error::ReplayArtifact)?;
    if source.metadata().map_err(|_| Error::ReplayArtifact)?.len() > ARTIFACT_LIMIT {
        return Err(Error::ReplayArtifact);
    }
    let is_v2 = ArtifactReader::new(BufReader::new(source)).is_ok();
    let mut output = tempfile::NamedTempFile::new().map_err(|_| Error::Artifact)?;
    if is_v2 {
        let mut reader = ArtifactReader::new(BufReader::new(
            File::open(path).map_err(|_| Error::ReplayArtifact)?,
        ))
        .map_err(|_| Error::ReplayArtifact)?;
        let header = reader.header().clone();
        if header.engine != engine.name() {
            return Err(Error::ReplayContext);
        }
        header.require_replay_source().map_err(|_|Error::Rejected {
            code:"FG-2002".into(),message:"source_snapshot_not_writable: retain the artifact; replay requires a writable generation".into(),
        })?;
        fg_protocol_common::replay_order(&header).map_err(|_| Error::ReplayUnsupported)?;
        while let Some(change) = reader.next_entry().map_err(|_| Error::ReplayArtifact)? {
            change
                .validate_replay(&header)
                .map_err(|_| Error::ReplayUnsupported)?;
        }
        std::io::copy(
            &mut File::open(path).map_err(|_| Error::ReplayArtifact)?,
            &mut output,
        )
        .map_err(|_| Error::Artifact)?;
    } else {
        legacy(path, engine.sql()?, &mut output)?;
    }
    output.as_file().sync_all().map_err(|_| Error::Artifact)?;
    Ok(output)
}

fn legacy(path: &Path, engine: Engine, output: &mut tempfile::NamedTempFile) -> Result<(), Error> {
    let file = File::open(path).map_err(|_| Error::ReplayArtifact)?;
    if file.metadata().map_err(|_| Error::ReplayArtifact)?.len() > 4 * 1024 * 1024 {
        return Err(Error::ReplayArtifact);
    }
    let legacy: LegacyArtifact =
        serde_json::from_reader(file).map_err(|_| Error::ReplayArtifact)?;
    if legacy.format_version != 1
        || legacy.engine != engine
        || legacy.sql != plan::statements(engine, &legacy.tables)?
    {
        return Err(Error::ReplayArtifact);
    }
    let mut tables = Vec::new();
    let mut changes = Vec::new();
    for table in &legacy.tables {
        let mut value = serde_json::to_value(table).map_err(|_| Error::ReplayArtifact)?;
        let rows = value
            .as_object_mut()
            .ok_or(Error::ReplayArtifact)?
            .remove("changes")
            .ok_or(Error::ReplayArtifact)?;
        let catalog: ArtifactTable =
            serde_json::from_value(value).map_err(|_| Error::ReplayArtifact)?;
        for row in rows.as_array().ok_or(Error::ReplayArtifact)? {
            let mut row = row.clone();
            row.as_object_mut()
                .ok_or(Error::ReplayArtifact)?
                .insert("table_id".into(), json!(catalog.id));
            changes.push(
                serde_json::from_value::<TypedChange>(row).map_err(|_| Error::ReplayArtifact)?,
            );
        }
        tables.push(catalog);
    }
    let header = ArtifactHeader {
        format_version: ARTIFACT_VERSION,
        engine: engine.name().into(),
        source_branch_id: legacy.source_branch_id,
        origin: legacy.origin,
        native_write: true,
        manifest: None,
        tables,
    };
    let mut writer = ArtifactWriter::new(output, header).map_err(|_| Error::ReplayArtifact)?;
    for change in changes {
        writer.change(change).map_err(|_| Error::ReplayArtifact)?;
    }
    writer
        .finish(Vec::new())
        .map_err(|_| Error::ReplayArtifact)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn staged_job_modes_accept_ids_without_reuploading_an_artifact() {
        for mode in ["--apply-job", "--verify-job"] {
            assert!(
                crate::Cli::try_parse_from([
                    "forkget",
                    "replay",
                    "--engine",
                    "postgresql",
                    mode,
                    "7"
                ])
                .is_ok()
            );
            assert!(
                crate::Cli::try_parse_from([
                    "forkget",
                    "replay",
                    "--engine",
                    "postgresql",
                    mode,
                    "7",
                    "--input",
                    "artifact.ndjson"
                ])
                .is_err()
            );
        }
        assert!(
            crate::Cli::try_parse_from([
                "forkget",
                "replay",
                "--engine",
                "mysql",
                "--input",
                "artifact.ndjson",
                "--name",
                "review-target",
                "--stage-only"
            ])
            .is_ok()
        );
        assert!(
            crate::Cli::try_parse_from([
                "forkget",
                "replay",
                "--engine",
                "mysql",
                "--input",
                "artifact.ndjson",
                "--check",
                "--stage-only"
            ])
            .is_err()
        );
        assert!(
            crate::Cli::try_parse_from([
                "forkget",
                "replay",
                "--engine",
                "mysql",
                "--apply-job",
                "7",
                "--verify-job",
                "7"
            ])
            .is_err()
        );
    }

    #[test]
    fn only_staged_jobs_can_request_apply() {
        assert!(require_staged(&json!({"state":"staged"})).is_ok());
        for state in ["running", "unknown", "failed", "verifying", "verified"] {
            assert!(matches!(
                require_staged(&json!({"state":state})),
                Err(Error::Rejected { message, .. }) if message.contains("replay_job_not_staged")
            ));
        }
        assert!(require_staged(&json!({})).is_err());
    }
}
