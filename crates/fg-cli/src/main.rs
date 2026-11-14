mod dryrun;
mod management;
mod replay;

use std::{
    env,
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use fg_protocol_common::{loopback_client, loopback_http, valid_branch_name};
use reqwest::{Client, Url};
use serde_json::{Value, json};

#[derive(Parser)]
#[command(about = "Manage local Forkget branches and policy")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Capabilities,
    Status {
        #[arg(long,value_parser=clap::value_parser!(i64).range(1..))]
        id: i64,
    },
    Renew {
        #[arg(long,value_parser=clap::value_parser!(i64).range(1..))]
        id: i64,
        #[arg(long,value_parser=clap::value_parser!(u32).range(1..=86400))]
        ttl_seconds: u32,
        #[arg(long,value_parser=clap::value_parser!(i64).range(1..))]
        expected_lease_version: i64,
    },
    Budget {
        #[command(subcommand)]
        command: management::BudgetCommand,
    },
    Github {
        #[command(subcommand)]
        command: management::GitHubCommand,
    },
    Fork {
        name: String,
        #[arg(long, value_enum, default_value = "dev")]
        class: Class,
        #[arg(long)]
        ttl_seconds: Option<u32>,
        #[arg(long, help = "Provision a writable copy of the current snapshot")]
        write: bool,
    },
    List,
    Drop {
        #[arg(required_unless_present = "id", conflicts_with = "id")]
        name: Option<String>,
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
        id: Option<i64>,
    },
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    Approval {
        #[command(subcommand)]
        command: ApprovalCommand,
    },
    Audit(AuditArgs),
    Diff {
        #[arg(required_unless_present = "id", conflicts_with = "id")]
        name: Option<String>,
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
        id: Option<i64>,
        #[arg(long)]
        output: PathBuf,
    },
    Dryrun(dryrun::Options),
    Export(replay::Export),
    Replay(replay::Replay),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Class {
    Dev,
    Ci,
    Agent,
    Staging,
}

impl Class {
    const fn name(self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Ci => "ci",
            Self::Agent => "agent",
            Self::Staging => "staging",
        }
    }
}

#[derive(Subcommand)]
enum PolicyCommand {
    Effective {
        #[arg(long,value_parser=clap::value_parser!(i64).range(1..))]
        id: i64,
    },
    Get {
        #[arg(value_enum)]
        class: Class,
    },
    Set {
        #[arg(value_enum)]
        class: Class,
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
        expected_version: i64,
        #[arg(long, value_parser = clap::value_parser!(i64).range(0..))]
        max_transaction_rows: i64,
        #[arg(long, value_parser = clap::value_parser!(i32).range(1..=10_000))]
        table_limit_bps: Option<i32>,
        #[arg(long, default_value_t = 1)]
        small_table_floor: u64,
        #[arg(long, value_parser = clap::value_parser!(i64).range(0..))]
        approval_after_rows: Option<i64>,
    },
}

#[derive(Subcommand)]
enum ApprovalCommand {
    List {
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
        id: i64,
    },
    Approve {
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
        id: i64,
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
        approval_id: i64,
    },
    Deny {
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
        id: i64,
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
        approval_id: i64,
    },
}

#[derive(Args)]
struct AuditArgs {
    #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
    id: i64,
    #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
    since: Option<i64>,
    #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
    until: Option<i64>,
    #[arg(long)]
    event_type: Option<String>,
    #[arg(long, value_parser = clap::value_parser!(i64).range(0..))]
    after: Option<i64>,
    #[arg(long, value_parser = clap::value_parser!(i64).range(1..=100))]
    limit: Option<i64>,
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("Set FG_OWNER_TOKEN to an owner API token")]
    Token,
    #[error("Set FG_CONTROL_URL to an HTTP origin on loopback")]
    Origin,
    #[error("The local control service is unavailable")]
    Network,
    #[error("The control service returned HTTP {0}")]
    Status(u16),
    #[error("[FORKGET {code}] {message}")]
    Rejected { code: String, message: String },
    #[error("The control service returned an invalid response")]
    Response,
    #[error("Use 3 to 63 lowercase letters, digits or hyphens, starting with a letter")]
    Name,
    #[error("No live branch with that name is visible to this owner")]
    Missing,
    #[error("Could not create a new private artifact at the requested path")]
    Artifact,
    #[error("The dry-run manifest is invalid or exceeds the supported limits")]
    Manifest,
    #[error("[FORKGET {code}] Dry-run {phase} statement {ordinal} is not supported")]
    ManifestStatement {
        phase: &'static str,
        ordinal: usize,
        code: &'static str,
    },
    #[error(
        "Set FG_DRYRUN_PROXY_DSN and FG_DRYRUN_PROXY_CA for the verified SQL proxy. A private endpoint requires FG_MANAGED_FRONTEND_HOST"
    )]
    ProxyConfig,
    #[error("Could not generate a temporary branch name")]
    Randomness,
    #[error("Could not install dry-run cancellation handlers")]
    Cancellation,
    #[error("[FORKGET FG-2002] The replay artifact is invalid or exceeds the supported limits")]
    ReplayArtifact,
    #[error(
        "[FORKGET FG-2002] The artifact contains a transition outside the admitted replay plan; inspect its replay_reasons"
    )]
    ReplayUnsupported,
    #[error(
        "[FORKGET FG-2003] Replay requires the same deployment, a complete retained source generation and the same catalog"
    )]
    ReplayContext,
}

struct Control {
    client: Client,
    base: Url,
    token: String,
}

impl Control {
    fn new() -> Result<Self, Error> {
        let base = env::var("FG_CONTROL_URL").unwrap_or_else(|_| "http://127.0.0.1:8081".into());
        let token = env::var("FG_OWNER_TOKEN").map_err(|_| Error::Token)?;
        if token.is_empty() {
            return Err(Error::Token);
        }
        Ok(Self {
            client: loopback_client(Duration::from_secs(5)).map_err(|_| Error::Network)?,
            base: loopback_http(&base).ok_or(Error::Origin)?,
            token,
        })
    }

    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, Error> {
        self.request_with_query(method, path, body, &[]).await
    }

    async fn request_with_query(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
        query: &[(&str, String)],
    ) -> Result<Value, Error> {
        let mut url = self.base.join(path).map_err(|_| Error::Origin)?;
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query);
        }
        let mut request = self.client.request(method, url).bearer_auth(&self.token);
        if path.ends_with("/diff") {
            request = request.timeout(Duration::from_secs(18));
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.map_err(|_| Error::Network)?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let problem = response.json::<Value>().await.ok();
            return Err(problem
                .as_ref()
                .and_then(rejection)
                .unwrap_or(Error::Status(status)));
        }
        if response.status() == reqwest::StatusCode::NO_CONTENT
            || response.status() == reqwest::StatusCode::ACCEPTED
                && response.content_length() == Some(0)
        {
            return Ok(json!({"status":"accepted"}));
        }
        response.json().await.map_err(|_| Error::Response)
    }

    async fn list(&self) -> Result<Value, Error> {
        self.request(reqwest::Method::GET, "v1/branches", None)
            .await
    }

    async fn fork(
        &self,
        name: &str,
        class: Class,
        ttl: Option<u32>,
        writable: bool,
    ) -> Result<Value, Error> {
        if !valid_branch_name(name) {
            return Err(Error::Name);
        }
        let mode = if writable {
            "native_write"
        } else {
            "read_only"
        };
        self.request(
            reqwest::Method::POST,
            "v1/branches",
            Some(json!({
                "name": name, "class": class.name(), "ttl_seconds": ttl, "mode": mode,
            })),
        )
        .await
    }

    async fn branch(&self, id: i64) -> Result<Value, Error> {
        self.request(reqwest::Method::GET, &format!("v1/branches/{id}"), None)
            .await
    }

    async fn drop_id(&self, id: i64) -> Result<Value, Error> {
        self.request(reqwest::Method::DELETE, &format!("v1/branches/{id}"), None)
            .await
    }

    async fn diff(&self, id: i64) -> Result<Value, Error> {
        self.request(
            reqwest::Method::GET,
            &format!("v1/branches/{id}/diff"),
            None,
        )
        .await
    }

    async fn audit(&self, id: i64, query: &[(&str, String)]) -> Result<Value, Error> {
        self.request_with_query(
            reqwest::Method::GET,
            &format!("v1/branches/{id}/audit"),
            None,
            query,
        )
        .await
    }

    async fn id_for(&self, name: &str) -> Result<i64, Error> {
        if !valid_branch_name(name) {
            return Err(Error::Name);
        }
        self.list()
            .await?
            .as_array()
            .ok_or(Error::Response)?
            .iter()
            .find(|item| item["name"] == name && item["status"] != "dropped")
            .and_then(|item| item["id"].as_i64())
            .ok_or(Error::Missing)
    }
}

fn rejection(problem: &Value) -> Option<Error> {
    let code = problem.get("code")?.as_str()?;
    let message = problem.get("message")?.as_str()?;
    if !valid_code(code) {
        return None;
    }
    Some(Error::Rejected {
        code: code.to_owned(),
        message: message.to_owned(),
    })
}

fn valid_code(code: &str) -> bool {
    code.strip_prefix("FG-").is_some_and(|digits| {
        digits.len() == 4 && digits.bytes().all(|digit| digit.is_ascii_digit())
    })
}

fn new_artifact(path: &Path) -> Result<File, Error> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| Error::Artifact)
}

fn write_artifact(mut output: File, report: &Value) -> Result<(), Error> {
    serde_json::to_writer_pretty(&mut output, report).map_err(|_| Error::Artifact)?;
    output
        .write_all(b"\n")
        .and_then(|()| output.sync_all())
        .map_err(|_| Error::Artifact)
}

struct Outcome {
    value: Value,
    success: bool,
}

async fn run(command: Command) -> Result<Outcome, Error> {
    let control = Control::new()?;
    let value = match command {
        Command::Capabilities => control.request(reqwest::Method::GET,"v1/capabilities",None).await?,
        Command::Status{id} => control.request(reqwest::Method::GET,&format!("v1/branches/{id}/status"),None).await?,
        Command::Renew{id,ttl_seconds,expected_lease_version} => control.request(reqwest::Method::POST,&format!("v1/branches/{id}/renew"),Some(json!({"ttl_seconds":ttl_seconds,"expected_lease_version":expected_lease_version}))).await?,
        Command::Budget{command} => management::budget(&control,command).await?,
        Command::Github{command} => management::github(&control,command).await?,
        Command::Fork {
            name,
            class,
            ttl_seconds,
            write,
        } => control.fork(&name, class, ttl_seconds, write).await?,
        Command::List => control.list().await?,
        Command::Drop { id, name } => {
            control
                .drop_id(branch_id(&control, id, name.as_deref()).await?)
                .await?
        }
        Command::Policy { command } => policy(&control, command).await?,
        Command::Approval { command } => approval(&control, command).await?,
        Command::Audit(args) => audit(&control, args).await?,
        Command::Diff { name, id, output } => {
            let id = branch_id(&control, id, name.as_deref()).await?;
            let report = control.diff(id).await?;
            let artifact = new_artifact(&output)?;
            write_artifact(artifact, &report)?;
            json!({"branch_id": id, "generation_id": report["generation_id"], "output": output})
        }
        Command::Dryrun(options) => return dryrun::run(&control, options).await,
        Command::Export(options) => replay::export(&control, options).await?,
        Command::Replay(options) => return replay::run(&control, options).await,
    };
    Ok(Outcome {
        value,
        success: true,
    })
}

async fn branch_id(control: &Control, id: Option<i64>, name: Option<&str>) -> Result<i64, Error> {
    match id {
        Some(id) => Ok(id),
        None => control.id_for(name.ok_or(Error::Name)?).await,
    }
}

async fn policy(control: &Control, command: PolicyCommand) -> Result<Value, Error> {
    match command {
        PolicyCommand::Effective{id} => control.request(reqwest::Method::GET,&format!("v1/branches/{id}/policy"),None).await,
        PolicyCommand::Get { class } => control.request(
            reqwest::Method::GET, &format!("v1/policies/{}", class.name()), None,
        ).await,
        PolicyCommand::Set {
            class, expected_version, max_transaction_rows, table_limit_bps, small_table_floor, approval_after_rows,
        } => control.request(
            reqwest::Method::PUT,
            &format!("v1/policies/{}", class.name()),
            Some(json!({ "expected_version": expected_version, "max_transaction_rows": max_transaction_rows,
                "table_limit_bps": table_limit_bps, "small_table_floor":small_table_floor,"approval_after_rows": approval_after_rows })),
        ).await,
    }
}

async fn approval(control: &Control, command: ApprovalCommand) -> Result<Value, Error> {
    match command {
        ApprovalCommand::List { id } => {
            control
                .request(
                    reqwest::Method::GET,
                    &format!("v1/branches/{id}/approvals"),
                    None,
                )
                .await
        }
        ApprovalCommand::Approve { id, approval_id } => {
            decide(control, id, approval_id, true).await
        }
        ApprovalCommand::Deny { id, approval_id } => decide(control, id, approval_id, false).await,
    }
}

async fn decide(
    control: &Control,
    id: i64,
    approval_id: i64,
    approve: bool,
) -> Result<Value, Error> {
    control
        .request(
            reqwest::Method::POST,
            &format!("v1/branches/{id}/approvals/{approval_id}"),
            Some(json!({ "approve": approve })),
        )
        .await
}

async fn audit(control: &Control, args: AuditArgs) -> Result<Value, Error> {
    let mut query: Vec<_> = [
        ("since", args.since),
        ("until", args.until),
        ("after", args.after),
        ("limit", args.limit),
    ]
    .into_iter()
    .filter_map(|(name, value)| value.map(|value| (name, value.to_string())))
    .collect();
    if let Some(event_type) = args.event_type {
        query.push(("event_type", event_type));
    }
    let report = control.audit(args.id, &query).await?;
    let Some(path) = args.output else {
        return Ok(report);
    };
    let events = report["events"].as_array().ok_or(Error::Response)?;
    let mut output = new_artifact(&path)?;
    for event in events {
        serde_json::to_writer(&mut output, event).map_err(|_| Error::Artifact)?;
        output.write_all(b"\n").map_err(|_| Error::Artifact)?;
    }
    output.sync_all().map_err(|_| Error::Artifact)?;
    Ok(
        json!({"branch_id": args.id, "events": events.len(), "next_after": report["next_after"], "output": path}),
    )
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse().command).await {
        Ok(outcome) => {
            println!("{:#}", outcome.value);
            if outcome.success {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
