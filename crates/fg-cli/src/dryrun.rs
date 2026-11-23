//! Apply a bounded manifest using the ordinary authenticated SQL frontend.

use std::{
    env,
    fs::File,
    future::poll_fn,
    io::Read,
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    time::Duration,
};

use clap::{Args, ValueEnum};
use fg_protocol_common::{TIDB_BACKEND_AVAILABLE, WireError, admit_tidb_backend};
use fg_rewrite::{Dialect, validate_dryrun_statement};
use rand::{RngCore, rngs::OsRng};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{
    Column, ConnectOptions, Connection, Executor, MySqlConnection, PgConnection, Row, TypeInfo,
    mysql::{MySqlConnectOptions, MySqlSslMode},
    postgres::{PgConnectOptions, PgSslMode},
};
use tokio::{
    signal::unix::{Signal, SignalKind, signal},
    time::{sleep, timeout},
};

use crate::{Class, Control, Error, Outcome, new_artifact, valid_code, write_artifact};

const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_CHANGES: usize = 1_000;
const MAX_CHECKS: usize = 100;
const POLL_INTERVAL: Duration = Duration::from_millis(150);
const ACTIVATION_TIMEOUT: Duration = Duration::from_secs(30);
const EXECUTION_TIMEOUT: Duration = Duration::from_secs(180);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(15);
const AUDIT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Args)]
pub(super) struct Options {
    #[arg(long, value_enum)]
    engine: Engine,
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, value_enum, default_value = "dev")]
    class: Class,
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=86_400))]
    ttl_seconds: Option<u32>,
    #[arg(long)]
    keep: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub(super) enum Engine {
    Mysql,
    Postgresql,
    #[value(hide = !TIDB_BACKEND_AVAILABLE)]
    Tidb,
}

impl Engine {
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Mysql => "mysql",
            Self::Postgresql => "postgresql",
            Self::Tidb => "tidb",
        }
    }

    pub(super) const fn dialect(self) -> Dialect {
        match self {
            Self::Mysql | Self::Tidb => Dialect::MySql,
            Self::Postgresql => Dialect::PostgreSql,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    changes: Vec<String>,
    #[serde(default)]
    checks: Vec<String>,
}

impl Manifest {
    fn load(path: &Path, dialect: Dialect) -> Result<Self, Error> {
        let mut bytes = Vec::new();
        File::open(path)
            .and_then(|file| file.take(MAX_MANIFEST_BYTES + 1).read_to_end(&mut bytes))
            .map_err(|_| Error::Manifest)?;
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(Error::Manifest);
        }
        let manifest: Self = serde_json::from_slice(&bytes).map_err(|_| Error::Manifest)?;
        if !(1..=MAX_CHANGES).contains(&manifest.changes.len())
            || manifest.checks.len() > MAX_CHECKS
        {
            return Err(Error::Manifest);
        }
        for (statements, phase) in [(&manifest.changes, "change"), (&manifest.checks, "check")] {
            for (index, sql) in statements.iter().enumerate() {
                validate_dryrun_statement(dialect, sql, phase == "change").map_err(|error| {
                    Error::ManifestStatement {
                        phase,
                        ordinal: index + 1,
                        code: error.code(),
                    }
                })?;
            }
        }
        Ok(manifest)
    }
}

#[derive(Deserialize)]
struct Branch {
    id: i64,
    generation_id: i64,
    created_by: String,
    expires_at: i64,
    status: String,
}

#[derive(Serialize)]
struct Report {
    format_version: u8,
    engine: &'static str,
    engine_version: Option<String>,
    tool_version: &'static str,
    branch_name: String,
    branch_id: Option<i64>,
    generation_id: Option<i64>,
    expires_at: Option<i64>,
    transaction: &'static str,
    cleanup: &'static str,
    cleanup_error: Option<String>,
    statements: Vec<StatementOutcome>,
    policy_decisions: Vec<Value>,
    rowdiff: Option<Value>,
    failure: Option<Failure>,
}

impl Report {
    fn new(engine: Engine, branch_name: String) -> Self {
        Self {
            format_version: 1,
            engine: engine.name(),
            engine_version: None,
            tool_version: env!("CARGO_PKG_VERSION"),
            branch_name,
            branch_id: None,
            generation_id: None,
            expires_at: None,
            transaction: "not_started",
            cleanup: "not_created",
            cleanup_error: None,
            statements: Vec::new(),
            policy_decisions: Vec::new(),
            rowdiff: None,
            failure: None,
        }
    }

    fn reject(&mut self, phase: &'static str, code: &str) {
        if self.failure.is_none() {
            self.failure = Some(Failure {
                phase,
                code: code.to_owned(),
            });
        }
    }

    fn statement(
        &mut self,
        phase: &'static str,
        index: usize,
        result: &Result<Option<u64>, SqlError>,
    ) {
        self.statements.push(StatementOutcome {
            phase,
            ordinal: index + 1,
            status: if result.is_ok() { "passed" } else { "failed" },
            affected: result.as_ref().ok().copied().flatten(),
            code: result.as_ref().err().map(|error| error.code().to_owned()),
        });
    }
}

#[derive(Serialize)]
struct Failure {
    phase: &'static str,
    code: String,
}

#[derive(Serialize)]
struct StatementOutcome {
    phase: &'static str,
    ordinal: usize,
    status: &'static str,
    affected: Option<u64>,
    code: Option<String>,
}

pub(super) async fn run(control: &Control, options: Options) -> Result<Outcome, Error> {
    if options.engine == Engine::Tidb {
        admit_tidb_backend()?;
    }
    let manifest = Manifest::load(&options.manifest, options.engine.dialect())?;
    let target = Target::load(options.engine)?;
    let mut report = Report::new(options.engine, temporary_name()?);
    let mut signals = Signals::install()?;
    let artifact = new_artifact(&options.output)?;
    match create(control, &options, &report.branch_name).await {
        Ok(branch) => {
            finish_branch(
                control,
                &target,
                &options,
                &manifest,
                branch,
                &mut report,
                &mut signals,
            )
            .await
        }
        Err(error) => {
            if uncertain_create(&error) {
                report.cleanup = "unknown";
            }
            report.reject("fork", control_code(&error));
        }
    }
    let success = report.failure.is_none();
    let value = json!({
        "status": if success { "passed" } else { "failed" },
        "branch_id": report.branch_id, "generation_id": report.generation_id,
        "branch_name": report.branch_name, "expires_at": report.expires_at,
        "cleanup": report.cleanup, "output": options.output,
    });
    write_artifact(
        artifact,
        &serde_json::to_value(report).map_err(|_| Error::Artifact)?,
    )?;
    Ok(Outcome { value, success })
}

fn temporary_name() -> Result<String, Error> {
    let mut bytes = [0; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| Error::Randomness)?;
    let suffix: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!("dryrun-{suffix}"))
}

async fn create(control: &Control, options: &Options, name: &str) -> Result<Branch, Error> {
    let result = control
        .fork(name, options.class, options.ttl_seconds, true)
        .await
        .and_then(parse_branch);
    match result {
        Err(error) if uncertain_create(&error) => {
            if let Ok(id) = control.id_for(name).await {
                return control.branch(id).await.and_then(parse_branch);
            }
            Err(error)
        }
        other => other,
    }
}

fn uncertain_create(error: &Error) -> bool {
    matches!(error, Error::Network | Error::Response)
        || matches!(error, Error::Status(status) if *status >= 500)
        || matches!(error, Error::Rejected { code, .. } if code == WireError::Backend.code())
}

fn parse_branch(response: Value) -> Result<Branch, Error> {
    let branch: Branch = serde_json::from_value(response).map_err(|_| Error::Response)?;
    if branch.id <= 0 || branch.generation_id <= 0 || branch.expires_at <= 0 {
        return Err(Error::Response);
    }
    Ok(branch)
}

async fn finish_branch(
    control: &Control,
    target: &Target,
    options: &Options,
    manifest: &Manifest,
    branch: Branch,
    report: &mut Report,
    signals: &mut Signals,
) {
    let id = branch.id;
    report.branch_id = Some(id);
    report.generation_id = Some(branch.generation_id);
    report.expires_at = Some(branch.expires_at);
    let ready = tokio::select! {
        biased;
        () = signals.cancelled() => Err(Error::Cancellation),
        result = async {
            if branch.status == "active" {
                Ok(())
            } else {
                wait_status(control, id, "active", ACTIVATION_TIMEOUT).await
            }
        } => result,
    };
    match ready {
        Ok(()) => {
            run_sql(target, &branch, manifest, report, signals).await;
            if report.transaction == "committed" {
                match control.diff(id).await {
                    Ok(diff) => report.rowdiff = Some(diff),
                    Err(error) => report.reject("rowdiff", control_code(&error)),
                }
            }
            let audit = timeout(AUDIT_TIMEOUT, decisions(control, id))
                .await
                .unwrap_or(Err(Error::Network));
            match audit {
                Ok(decisions) => report.policy_decisions = decisions,
                Err(error) => report.reject("audit", control_code(&error)),
            }
        }
        Err(Error::Cancellation) => report.reject("cancelled", WireError::Backend.code()),
        Err(error) => report.reject("activation", control_code(&error)),
    }
    if options.keep {
        report.cleanup = "kept";
    } else {
        cleanup(control, id, report).await;
    }
}

async fn wait_status(
    control: &Control,
    id: i64,
    expected: &str,
    bound: Duration,
) -> Result<(), Error> {
    timeout(bound, async {
        loop {
            let branch = control.branch(id).await.and_then(parse_branch)?;
            if branch.status == expected {
                return Ok(());
            }
            if expected == "active" && matches!(branch.status.as_str(), "dropping" | "dropped") {
                return Err(Error::Missing);
            }
            sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .map_err(|_| Error::Network)?
}

async fn cleanup(control: &Control, id: i64, report: &mut Report) {
    let initial = match control.drop_id(id).await {
        Ok(branch) => branch,
        Err(error) => {
            report.cleanup = "unknown";
            report.cleanup_error = Some(control_code(&error).to_owned());
            report.reject("cleanup", control_code(&error));
            return;
        }
    };
    if initial["status"] == "dropped" {
        report.cleanup = "dropped";
        return;
    }
    match wait_status(control, id, "dropped", CLEANUP_TIMEOUT).await {
        Ok(()) => report.cleanup = "dropped",
        Err(error) => {
            report.cleanup = "dropping";
            report.cleanup_error = Some(control_code(&error).to_owned());
            report.reject("cleanup", control_code(&error));
        }
    }
}

async fn decisions(control: &Control, id: i64) -> Result<Vec<Value>, Error> {
    let mut events = Vec::new();
    let mut after = 0;
    loop {
        let mut query = vec![
            ("event_type", "policy_decision".to_owned()),
            ("limit", "100".to_owned()),
        ];
        if after > 0 {
            query.push(("after", after.to_string()));
        }
        let page = control.audit(id, &query).await?;
        let received = page["events"].as_array().ok_or(Error::Response)?;
        events.extend(received.iter().cloned());
        if events.len() > MAX_CHANGES * 4 {
            return Err(Error::Response);
        }
        let Some(next) = page["next_after"].as_i64() else {
            return Ok(events);
        };
        if next <= after {
            return Err(Error::Response);
        }
        after = next;
    }
}

fn control_code(error: &Error) -> &str {
    match error {
        Error::Rejected { code, .. } => code,
        Error::Missing => WireError::Branch.code(),
        _ => WireError::Backend.code(),
    }
}

async fn run_sql(
    target: &Target,
    branch: &Branch,
    manifest: &Manifest,
    report: &mut Report,
    signals: &mut Signals,
) {
    let branch_name = report.branch_name.clone();
    tokio::select! {
        biased;
        () = signals.cancelled() => report.reject("cancelled", WireError::Backend.code()),
        result = timeout(EXECUTION_TIMEOUT, apply(target, &branch_name, branch, manifest, report)) => {
            if result.is_err() {
                report.reject("timeout", WireError::Backend.code());
            }
        }
    }
    report.transaction = match report.transaction {
        "open" => "rollback_pending",
        "committing" => "unknown",
        state => state,
    };
}

pub(super) struct Signals {
    interrupt: Signal,
    terminate: Signal,
}

impl Signals {
    pub(super) fn install() -> Result<Self, Error> {
        Ok(Self {
            interrupt: signal(SignalKind::interrupt()).map_err(|_| Error::Cancellation)?,
            terminate: signal(SignalKind::terminate()).map_err(|_| Error::Cancellation)?,
        })
    }

    pub(super) async fn cancelled(&mut self) {
        tokio::select! {
            _ = self.interrupt.recv() => (),
            _ = self.terminate.recv() => (),
        }
    }
}

async fn apply(
    target: &Target,
    name: &str,
    branch: &Branch,
    manifest: &Manifest,
    report: &mut Report,
) {
    let mut client = match target.connect(name, &branch.created_by).await {
        Ok(client) => client,
        Err(error) => {
            report.reject("connect", error.code());
            return;
        }
    };
    match client.text_scalar("SELECT VERSION()").await {
        Ok(version) => report.engine_version = Some(version),
        Err(error) => {
            report.reject("version", error.code());
            return;
        }
    }
    if let Err(error) = client.execute("BEGIN").await {
        report.reject("begin", error.code());
        return;
    }
    report.transaction = "open";
    if apply_statements(&mut client, manifest, report).await {
        report.transaction = "committing";
        match client.execute("COMMIT").await {
            Ok(_) => report.transaction = "committed",
            Err(error) => {
                report.reject("commit", error.code());
                if matches!(client, Client::Postgres(_)) && error.is_integrity_failure() {
                    report.transaction = "rolled_back";
                }
            }
        }
    } else if report.transaction != "rolled_back" {
        rollback(&mut client, report).await;
    }
}

async fn apply_statements(client: &mut Client, manifest: &Manifest, report: &mut Report) -> bool {
    for (index, sql) in manifest.changes.iter().enumerate() {
        let result = client.execute(sql).await.map(Some);
        report.statement("change", index, &result);
        if let Err(error) = result {
            report.reject("change", error.code());
            if error.confirms_policy_rollback() {
                report.transaction = "rolled_back";
            }
            return false;
        }
    }
    for (index, sql) in manifest.checks.iter().enumerate() {
        let result = client.check(sql).await.map(|()| None);
        report.statement("check", index, &result);
        if let Err(error) = result {
            report.reject("check", error.code());
            return false;
        }
    }
    true
}

async fn rollback(client: &mut Client, report: &mut Report) {
    report.transaction = if client.execute("ROLLBACK").await.is_ok() {
        "rolled_back"
    } else {
        "rollback_pending"
    };
}

pub(super) struct Target {
    engine: Engine,
    base: Url,
    ca: PathBuf,
}

impl Target {
    pub(super) fn load(engine: Engine) -> Result<Self, Error> {
        let input = env::var("FG_DRYRUN_PROXY_DSN").map_err(|_| Error::ProxyConfig)?;
        let base = Url::parse(&input).map_err(|_| Error::ProxyConfig)?;
        let managed = env::var_os("FG_MANAGED_FRONTEND_HOST")
            .map(|host| {
                host.to_str()
                    .and_then(|host| host.parse::<Ipv4Addr>().ok())
                    .filter(Ipv4Addr::is_private)
                    .ok_or(Error::ProxyConfig)
            })
            .transpose()?;
        let ca = env::var_os("FG_DRYRUN_PROXY_CA")
            .filter(|value| !value.is_empty())
            .ok_or(Error::ProxyConfig)?;
        let scheme = match base.scheme() {
            "mysql" => Engine::Mysql,
            "postgresql" | "postgres" => Engine::Postgresql,
            "tidb" => {
                admit_tidb_backend()?;
                Engine::Tidb
            }
            _ => return Err(Error::ProxyConfig),
        };
        if scheme != engine
            || base.query().is_some()
            || base.fragment().is_some()
            || base.username().is_empty()
            || base.password().is_none_or(str::is_empty)
            || !base
                .host_str()
                .is_some_and(|host| frontend_host_matches(host, managed))
        {
            return Err(Error::ProxyConfig);
        }
        Ok(Self {
            engine,
            base,
            ca: ca.into(),
        })
    }

    pub(super) async fn connect(&self, branch: &str, principal: &str) -> Result<Client, SqlError> {
        let mut url = self.base.clone();
        url.set_path(&format!("/{branch}"));
        // sqlx only parses mysql://; both schemes carry the branch in the path.
        let wire = match self.engine {
            Engine::Tidb => url.as_str().replacen("tidb://", "mysql://", 1),
            _ => url.as_str().to_owned(),
        };
        match self.engine {
            Engine::Mysql | Engine::Tidb => {
                let options = wire
                    .parse::<MySqlConnectOptions>()?
                    .ssl_mode(MySqlSslMode::VerifyIdentity)
                    .ssl_ca(&self.ca)
                    .timezone(None)
                    .set_names(false)
                    .pipes_as_concat(false)
                    .no_engine_substitution(false)
                    .disable_statement_logging();
                if options.get_username() != principal {
                    return Err(SqlError::Owner);
                }
                Ok(Client::MySql(
                    MySqlConnection::connect_with(&options).await?,
                ))
            }
            Engine::Postgresql => {
                let options = url
                    .as_str()
                    .parse::<PgConnectOptions>()?
                    .ssl_mode(PgSslMode::VerifyFull)
                    .ssl_root_cert(&self.ca)
                    .extra_float_digits(None)
                    .disable_statement_logging();
                if options.get_username() != principal {
                    return Err(SqlError::Owner);
                }
                Ok(Client::Postgres(
                    PgConnection::connect_with(&options).await?,
                ))
            }
        }
    }
}

fn frontend_host_matches(host: &str, managed: Option<Ipv4Addr>) -> bool {
    if let Some(expected) = managed {
        return host.parse::<Ipv4Addr>().ok() == Some(expected);
    }
    host == "localhost"
        || host
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

pub(super) enum Client {
    MySql(MySqlConnection),
    Postgres(PgConnection),
}

impl Client {
    pub(super) async fn text_scalar(&mut self, sql: &str) -> Result<String, SqlError> {
        match self {
            Self::MySql(connection) => Ok(connection.fetch_one(sql).await?.try_get_unchecked(0)?),
            Self::Postgres(connection) => {
                Ok(connection.fetch_one(sql).await?.try_get_unchecked(0)?)
            }
        }
    }

    pub(super) async fn execute(&mut self, sql: &str) -> Result<u64, SqlError> {
        match self {
            Self::MySql(connection) => Ok(connection.execute(sql).await?.rows_affected()),
            Self::Postgres(connection) => Ok(connection.execute(sql).await?.rows_affected()),
        }
    }

    async fn check(&mut self, sql: &str) -> Result<(), SqlError> {
        match self {
            Self::MySql(connection) => {
                let mut rows = connection.fetch(sql);
                let first = poll_fn(|context| rows.as_mut().poll_next(context))
                    .await
                    .transpose()?;
                let second = poll_fn(|context| rows.as_mut().poll_next(context))
                    .await
                    .transpose()?;
                check_value(first.as_ref(), second.is_some())
            }
            Self::Postgres(connection) => {
                let mut rows = connection.fetch(sql);
                let first = poll_fn(|context| rows.as_mut().poll_next(context))
                    .await
                    .transpose()?;
                let second = poll_fn(|context| rows.as_mut().poll_next(context))
                    .await
                    .transpose()?;
                check_value(first.as_ref(), second.is_some())
            }
        }
    }
}

fn check_value<R: Row>(row: Option<&R>, has_second: bool) -> Result<(), SqlError>
where
    usize: sqlx::ColumnIndex<R>,
    bool: for<'row> sqlx::Decode<'row, R::Database> + sqlx::Type<R::Database>,
    i16: for<'row> sqlx::Decode<'row, R::Database> + sqlx::Type<R::Database>,
    i32: for<'row> sqlx::Decode<'row, R::Database> + sqlx::Type<R::Database>,
    i64: for<'row> sqlx::Decode<'row, R::Database> + sqlx::Type<R::Database>,
{
    let row = row
        .filter(|row| row.len() == 1 && !has_second)
        .ok_or(SqlError::Check)?;
    let valid = match row.columns()[0].type_info().name() {
        "BOOL" | "BOOLEAN" => row.try_get_unchecked::<Option<bool>, _>(0)? == Some(true),
        "SMALLINT" | "INT2" => row.try_get_unchecked::<Option<i16>, _>(0)? == Some(1),
        "INT" | "INT4" => row.try_get_unchecked::<Option<i32>, _>(0)? == Some(1),
        "BIGINT" | "BIGINT UNSIGNED" | "INT8" => {
            row.try_get_unchecked::<Option<i64>, _>(0)? == Some(1)
        }
        _ => false,
    };
    if valid { Ok(()) } else { Err(SqlError::Check) }
}

pub(super) enum SqlError {
    Engine(sqlx::Error),
    Owner,
    Check,
}

impl From<sqlx::Error> for SqlError {
    fn from(error: sqlx::Error) -> Self {
        Self::Engine(error)
    }
}

impl SqlError {
    pub(super) fn code(&self) -> &str {
        match self {
            Self::Owner => WireError::Auth.code(),
            Self::Check => WireError::InvalidValue.code(),
            Self::Engine(error) => {
                let Some(database) = error.as_database_error() else {
                    return WireError::Backend.code();
                };
                database
                    .message()
                    .strip_prefix("[FORKGET ")
                    .and_then(|message| message.split_once(']'))
                    .map(|(code, _)| code)
                    .filter(|code| valid_code(code))
                    .unwrap_or_else(|| WireError::Native.code())
            }
        }
    }

    pub(super) fn is_integrity_failure(&self) -> bool {
        matches!(self, Self::Engine(error) if error.as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .is_some_and(|code| code.starts_with("23")))
    }

    pub(super) fn confirms_policy_rollback(&self) -> bool {
        let code = self.code();
        [WireError::RowLimit, WireError::Approval]
            .iter()
            .any(|error| error.code() == code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn failed_activation_keeps_identity_and_runs_cleanup()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            for (status, body) in [
                (
                    "503 Service Unavailable",
                    json!({"code":"FG-1004","message":"unavailable"}),
                ),
                ("202 Accepted", json!({"id":41,"status":"dropping"})),
                (
                    "200 OK",
                    json!({"id":41,"generation_id":7,"created_by":"alice","expires_at":i64::MAX,"name":"dryrun-case","status":"dropped"}),
                ),
            ] {
                let (mut socket, _) = listener.accept().await?;
                let mut bytes = [0u8; 4096];
                let count = socket.read(&mut bytes).await?;
                let request = String::from_utf8_lossy(&bytes[..count]);
                if status == "202 Accepted" {
                    assert!(request.starts_with("DELETE /v1/branches/41 "));
                }
                let body = body.to_string();
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await?;
            }
            Ok::<(), std::io::Error>(())
        });
        let control = Control {
            client: fg_protocol_common::loopback_client(Duration::from_secs(2))?,
            base: Url::parse(&format!("http://{address}/"))?,
            token: "test-token".into(),
        };
        let target = Target {
            engine: Engine::Mysql,
            base: Url::parse("mysql://alice:unused@127.0.0.1:1/base")?,
            ca: PathBuf::new(),
        };
        let options = Options {
            engine: Engine::Mysql,
            manifest: PathBuf::new(),
            output: PathBuf::new(),
            class: Class::Dev,
            ttl_seconds: None,
            keep: false,
        };
        let manifest = Manifest {
            changes: Vec::new(),
            checks: Vec::new(),
        };
        let branch = Branch {
            id: 41,
            generation_id: 7,
            created_by: "alice".into(),
            expires_at: i64::MAX,
            status: "provisioning".into(),
        };
        let mut report = Report::new(Engine::Mysql, "dryrun-case".into());
        let mut signals = Signals::install()?;
        finish_branch(
            &control,
            &target,
            &options,
            &manifest,
            branch,
            &mut report,
            &mut signals,
        )
        .await;
        assert_eq!(report.branch_id, Some(41));
        assert_eq!(report.generation_id, Some(7));
        assert_eq!(
            report.failure.as_ref().map(|failure| failure.phase),
            Some("activation")
        );
        assert_eq!(report.transaction, "not_started");
        assert_eq!(report.cleanup, "dropped");
        server.await??;
        Ok(())
    }

    #[test]
    fn managed_cli_target_requires_the_explicit_private_address() {
        let expected = Some(Ipv4Addr::new(10, 1, 2, 3));
        assert!(frontend_host_matches("10.1.2.3", expected));
        assert!(!frontend_host_matches("10.1.2.4", expected));
        assert!(!frontend_host_matches("127.0.0.1", expected));
        assert!(!frontend_host_matches("10.1.2.3", None));
        assert!(frontend_host_matches("[::1]", None));
    }

    #[test]
    fn manifest_statements_cannot_control_the_transaction() {
        for dialect in [Dialect::MySql, Dialect::PostgreSql] {
            assert!(
                validate_dryrun_statement(dialect, "INSERT INTO app.orders (id) VALUES (1)", true)
                    .is_ok()
            );
            assert!(validate_dryrun_statement(dialect, "SELECT 1", false).is_ok());
            assert!(validate_dryrun_statement(dialect, "SELECT 1; COMMIT", false).is_err());
            assert!(validate_dryrun_statement(dialect, "COMMIT", true).is_err());
            assert!(
                validate_dryrun_statement(dialect, "DELETE FROM app.orders WHERE id = 1", false)
                    .is_err()
            );
        }
    }
}
