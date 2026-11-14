//! Differential runner for the shared native-engine corpus.
//!
//! Executes corpus cases against two independent, equivalent datasets on one
//! engine. `reference-vs-reference` validates the harness. `reference-vs-proxy`
//! compares preseeded native tables and a persisted read branch. Endpoints and
//! credentials arrive through environment variables and stay out of reports.

mod mongo;
mod proxy;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use fg_diff::{
    CanonValue, CorpusCase, ENGINE_MONGODB, ENGINE_MYSQL, ENGINE_POSTGRESQL, Expectation,
    HarnessError, Observation, classify_error, compare_step, load_corpus, split_statements,
};
use serde::Serialize;
use sqlx::mysql::{MySqlDatabaseError, MySqlPoolOptions, MySqlRow};
use sqlx::postgres::{PgPoolOptions, PgRow};
use sqlx::{Column, MySqlPool, PgPool, Row, TypeInfo};

const DEFAULT_CORPUS: &str = "test/differential/corpus";
const DEFAULT_FIXTURES: &str = "test/differential/fixtures";
const DEFAULT_REPORT_ROOT: &str = "test/reports";
const MODE_REFERENCE_VS_REFERENCE: &str = "reference_vs_reference";
const RUN_KIND_LOCAL: &str = "local";
const REFERENCE_SIDE: &str = "reference";
const CANDIDATE_SIDE: &str = "candidate";
const NAMESPACE_REFERENCE: &str = "fg_diff_ref";
const NAMESPACE_CANDIDATE: &str = "fg_diff_cand";
const HONESTY_NOTE: &str = "reference_vs_reference mode validates the harness only; it cannot establish proxy support, capability promotion, or a release gate";

#[derive(Parser)]
#[command(name = "fg-diff", about = "Differential execution harness")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Exercise a live proxy session for the local deployment suite.
    Session {
        #[arg(long, value_enum)]
        engine: EngineArg,
        #[arg(long, value_enum)]
        action: proxy::SessionAction,
        /// Exact Forkget authentication or branch error expected on rejection.
        #[arg(long)]
        expected_fg: Option<String>,
    },
    /// Execute corpus cases against two independent equivalent datasets.
    Run {
        /// Engine under test.
        #[arg(long, value_enum)]
        engine: EngineArg,
        /// Execute a harness self-check or compare a preseeded read branch.
        #[arg(long, value_enum, default_value_t = ModeArg::ReferenceVsReference)]
        mode: ModeArg,
        /// Corpus tag to select; an empty selection is an error, never a pass.
        #[arg(long, default_value = "smoke")]
        tag: String,
        #[arg(long, default_value = DEFAULT_CORPUS)]
        corpus: PathBuf,
        #[arg(long, default_value = DEFAULT_FIXTURES)]
        fixtures: PathBuf,
        #[arg(long, default_value = DEFAULT_REPORT_ROOT)]
        report_root: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum EngineArg {
    Mysql,
    Postgres,
    Tidb,
    Mongodb,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum ModeArg {
    ReferenceVsReference,
    ReferenceVsProxy,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Engine {
    MySql,
    PostgreSql,
    TiDB,
    MongoDb,
}

impl Engine {
    fn name(self) -> &'static str {
        match self {
            Engine::MySql => "mysql",
            Engine::PostgreSql => "postgres",
            Engine::TiDB => "tidb",
            Engine::MongoDb => "mongodb",
        }
    }

    fn corpus_name(self) -> &'static str {
        match self {
            // TiDB shares the MySQL wire semantics, fixtures and corpus cases
            // The report still labels the engine "tidb".
            Engine::MySql | Engine::TiDB => ENGINE_MYSQL,
            Engine::PostgreSql => ENGINE_POSTGRESQL,
            Engine::MongoDb => ENGINE_MONGODB,
        }
    }

    fn env_keys(self) -> (&'static str, &'static str) {
        match self {
            Engine::MySql => ("FG_DIFF_MYSQL_REF_URL", "FG_DIFF_MYSQL_CAND_URL"),
            Engine::PostgreSql => ("FG_DIFF_PG_REF_URL", "FG_DIFF_PG_CAND_URL"),
            Engine::TiDB => ("FG_DIFF_TIDB_REF_URL", "FG_DIFF_TIDB_CAND_URL"),
            Engine::MongoDb => ("FG_DIFF_MONGO_REF_URL", "FG_DIFF_MONGO_CAND_URL"),
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Command::Session {
        engine,
        action,
        expected_fg,
    } = &cli.command
    {
        return match proxy::session((*engine).into(), *action, expected_fg.as_deref()).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("fg-diff: {error}");
                ExitCode::from(2)
            }
        };
    }
    let Command::Run {
        engine,
        mode,
        tag,
        corpus,
        fixtures,
        report_root,
    } = cli.command
    else {
        return ExitCode::from(2);
    };
    let engine = engine.into();
    let result = match mode {
        ModeArg::ReferenceVsReference => run(engine, &tag, &corpus, &fixtures, &report_root).await,
        ModeArg::ReferenceVsProxy => proxy::run(engine, &tag, &corpus, &report_root).await,
    };
    match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("fg-diff: {error}");
            ExitCode::from(2)
        }
    }
}

impl From<EngineArg> for Engine {
    fn from(engine: EngineArg) -> Self {
        match engine {
            EngineArg::Mysql => Self::MySql,
            EngineArg::Postgres => Self::PostgreSql,
            EngineArg::Tidb => Self::TiDB,
            EngineArg::Mongodb => Self::MongoDb,
        }
    }
}

/// Which execution path one statement takes; error expectations also use the
/// rows path so a database rejection surfaces as an observation.
#[derive(Clone, Copy)]
enum QueryShape {
    Rows,
    Affected,
}

pub(crate) fn shape_for(expectation: &Expectation) -> QueryShape {
    match expectation {
        Expectation::Rows { .. } | Expectation::Error { .. } | Expectation::ProxyRefusal { .. } => {
            QueryShape::Rows
        }
        Expectation::Affected { .. } => QueryShape::Affected,
    }
}

/// One side's connection inside a case namespace (database or schema).
enum SideClient {
    MySql(MySqlPool),
    PostgreSql(PgPool),
}

impl SideClient {
    async fn execute(&self, sql: &str, shape: QueryShape) -> Result<Observation, sqlx::Error> {
        match self {
            SideClient::MySql(pool) => observe_mysql(pool, sql, shape).await,
            SideClient::PostgreSql(pool) => observe_postgres(pool, sql, shape).await,
        }
    }
}

pub(crate) struct RunContext {
    pub(crate) engine: Engine,
    pub(crate) fixtures: PathBuf,
    pub(crate) reference_base_url: String,
    pub(crate) candidate_base_url: String,
}

async fn run(
    engine: Engine,
    tag: &str,
    corpus_dir: &Path,
    fixtures_dir: &Path,
    report_root: &Path,
) -> Result<ExitCode, HarnessError> {
    let corpus = load_corpus(corpus_dir)?;
    let selection: Vec<&CorpusCase> = corpus
        .iter()
        .filter(|case| {
            case.supports_engine(engine.corpus_name())
                && case.tags.iter().any(|candidate| candidate == tag)
        })
        .collect();
    if selection.is_empty() {
        return Err(HarnessError::Usage(format!(
            "tag '{tag}' selected no cases for engine {}; refusing to report a pass",
            engine.corpus_name()
        )));
    }
    // Each axis only speaks its own step language: a mixed selection is
    // a corpus authoring error, never a partial pass.
    for case in &selection {
        for (index, step) in case.steps.iter().enumerate() {
            if (engine == Engine::MongoDb) != matches!(step, fg_diff::Step::Command { .. }) {
                return Err(HarnessError::Usage(format!(
                    "case '{}' step {index}: {} steps are invalid for engine {}",
                    case.id,
                    if matches!(step, fg_diff::Step::Command { .. }) {
                        "mongo command"
                    } else {
                        "sql"
                    },
                    engine.corpus_name(),
                )));
            }
        }
        if engine == Engine::MongoDb && !case.setup.is_empty() {
            return Err(HarnessError::Usage(format!(
                "case '{}': mongodb cases carry no SQL setup; seed through the fixture",
                case.id,
            )));
        }
    }

    let (reference_key, candidate_key) = engine.env_keys();
    let context = RunContext {
        engine,
        fixtures: fixtures_dir.to_path_buf(),
        reference_base_url: endpoint_from_env(reference_key)?,
        candidate_base_url: endpoint_from_env(candidate_key)?,
    };

    let started_at = jiff::Zoned::now();
    let reference_version =
        engine_version(&context, &context.reference_base_url, REFERENCE_SIDE).await?;
    let candidate_version =
        engine_version(&context, &context.candidate_base_url, CANDIDATE_SIDE).await?;

    let mut reports = Vec::with_capacity(selection.len());
    for case in &selection {
        let report = run_case(&context, case).await?;
        if report.mismatches.is_empty() {
            println!("[PASS] {}", report.id);
        } else {
            println!("[FAIL] {}", report.id);
        }
        reports.push(report);
    }
    let finished_at = jiff::Zoned::now();

    let (report_dir, run_id) = write_report(ReportInputs {
        mode: MODE_REFERENCE_VS_REFERENCE,
        engine,
        tag,
        started_at: &started_at,
        finished_at: &finished_at,
        reference_version: &reference_version,
        candidate_version: &candidate_version,
        reports: &reports,
        report_root,
    })?;

    let failed = reports
        .iter()
        .filter(|report| !report.mismatches.is_empty())
        .count();
    println!(
        "run {run_id}: report written to {} ({} passed, {failed} failed)",
        report_dir.display(),
        reports.len() - failed
    );
    if failed == 0 {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}

fn endpoint_from_env(key: &str) -> Result<String, HarnessError> {
    let value = std::env::var(key).unwrap_or_default();
    if value.is_empty() {
        return Err(HarnessError::Usage(format!(
            "{key} is not set; point it at a running local engine (see test/local/README.md)"
        )));
    }
    Ok(value)
}

async fn engine_version(
    context: &RunContext,
    base_url: &str,
    side: &'static str,
) -> Result<String, HarnessError> {
    if context.engine == Engine::MongoDb {
        return mongo::engine_version(base_url).await;
    }
    let client = connect_side(context, base_url, side).await?;
    let observation = client
        .execute("SELECT VERSION()", QueryShape::Rows)
        .await
        .map_err(|error| HarnessError::Transport {
            side,
            message: error.to_string(),
        })?;
    let version = match observation {
        Observation::Rows { rows, .. } => {
            rows.first()
                .and_then(|row| row.first())
                .and_then(|value| match value {
                    CanonValue::Bytes(bytes) => Some(String::from_utf8_lossy(bytes).to_string()),
                    CanonValue::Null => None,
                })
        }
        _ => None,
    };
    version.ok_or_else(|| HarnessError::Transport {
        side,
        message: "could not read the engine version".to_string(),
    })
}

pub(crate) struct CaseReport {
    pub(crate) id: String,
    pub(crate) fixture: String,
    pub(crate) mismatches: Vec<String>,
}

async fn run_case(context: &RunContext, case: &CorpusCase) -> Result<CaseReport, HarnessError> {
    if context.engine == Engine::MongoDb {
        return mongo::run_case(
            context,
            case,
            &context.reference_base_url,
            &context.candidate_base_url,
        )
        .await;
    }
    let suffix = case_hash(&case.id);
    let reference_namespace = format!("{NAMESPACE_REFERENCE}_{suffix}");
    let candidate_namespace = format!("{NAMESPACE_CANDIDATE}_{suffix}");
    recreate_namespace(
        context,
        &context.reference_base_url,
        &reference_namespace,
        REFERENCE_SIDE,
    )
    .await?;
    recreate_namespace(
        context,
        &context.candidate_base_url,
        &candidate_namespace,
        CANDIDATE_SIDE,
    )
    .await?;
    let reference = connect_side(
        context,
        &namespace_url(context, &context.reference_base_url, &reference_namespace),
        REFERENCE_SIDE,
    )
    .await?;
    let candidate = connect_side(
        context,
        &namespace_url(context, &context.candidate_base_url, &candidate_namespace),
        CANDIDATE_SIDE,
    )
    .await?;

    let mut mismatches = Vec::new();
    let fixture_statements = fixture_statements(context, case)?;
    let fixture_ok = apply_to_both(
        &reference,
        &candidate,
        &fixture_statements,
        "fixture",
        &mut mismatches,
    )
    .await?;
    let setup_ok = if fixture_ok {
        apply_to_both(
            &reference,
            &candidate,
            &case.setup,
            "setup",
            &mut mismatches,
        )
        .await?
    } else {
        false
    };
    if setup_ok {
        for (index, step) in case.steps.iter().enumerate() {
            let fg_diff::Step::Sql { sql, expect } = step else {
                mismatches.push(format!(
                    "step {index}: mongo command steps are not supported by the SQL axis"
                ));
                continue;
            };
            let shape = shape_for(expect);
            let reference_observation =
                reference
                    .execute(sql, shape)
                    .await
                    .map_err(|error| HarnessError::Transport {
                        side: REFERENCE_SIDE,
                        message: error.to_string(),
                    })?;
            let candidate_observation =
                candidate
                    .execute(sql, shape)
                    .await
                    .map_err(|error| HarnessError::Transport {
                        side: CANDIDATE_SIDE,
                        message: error.to_string(),
                    })?;
            if let Err(mismatch) = compare_step(
                index,
                expect,
                &reference_observation,
                &candidate_observation,
            ) {
                mismatches.push(mismatch.detail);
            }
        }
    }

    reference.close().await;
    candidate.close().await;
    drop_namespaces(context, &reference_namespace, &candidate_namespace).await;

    Ok(CaseReport {
        id: case.id.clone(),
        fixture: case.fixture.clone(),
        mismatches,
    })
}

/// Apply statements to both sides; database failures become case mismatches
/// (the case is poisoned and later phases are skipped), transport failures
/// abort the run.
async fn apply_to_both(
    reference: &SideClient,
    candidate: &SideClient,
    statements: &[String],
    phase: &str,
    mismatches: &mut Vec<String>,
) -> Result<bool, HarnessError> {
    for statement in statements {
        for (side, client) in [(REFERENCE_SIDE, reference), (CANDIDATE_SIDE, candidate)] {
            let observed = client
                .execute(statement, QueryShape::Affected)
                .await
                .map_err(|error| HarnessError::Transport {
                    side,
                    message: error.to_string(),
                })?;
            if let Observation::Error { class, message, .. } = observed {
                mismatches.push(format!(
                    "{phase} statement failed on the {side} side: class {class}: {message}"
                ));
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn fixture_statements(
    context: &RunContext,
    case: &CorpusCase,
) -> Result<Vec<String>, HarnessError> {
    let path = context
        .fixtures
        .join(context.engine.corpus_name())
        .join(format!("{}.sql", case.fixture));
    let sql = fs::read_to_string(&path).map_err(|error| {
        HarnessError::Io(format!(
            "fixture {} at {}: {error}",
            case.fixture,
            path.display()
        ))
    })?;
    Ok(split_statements(&sql))
}

fn namespace_url(context: &RunContext, base_url: &str, namespace: &str) -> String {
    match context.engine {
        // MongoDB connections stay on the admin auth source; the working
        // database is selected per command, so no URL rewrite applies.
        Engine::MongoDb => base_url.to_owned(),
        Engine::MySql | Engine::TiDB => {
            format!("{}/{}", base_url.trim_end_matches('/'), namespace)
        }
        Engine::PostgreSql => {
            let separator = if base_url.contains('?') { '&' } else { '?' };
            format!("{base_url}{separator}options=-c%20search_path%3D{namespace}")
        }
    }
}

async fn connect_side(
    context: &RunContext,
    url: &str,
    side: &'static str,
) -> Result<SideClient, HarnessError> {
    match context.engine {
        Engine::MySql | Engine::TiDB => {
            let pool = MySqlPoolOptions::new()
                .max_connections(1)
                .connect(url)
                .await
                .map_err(|error| HarnessError::Transport {
                    side,
                    message: error.to_string(),
                })?;
            Ok(SideClient::MySql(pool))
        }
        Engine::PostgreSql => {
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(url)
                .await
                .map_err(|error| HarnessError::Transport {
                    side,
                    message: error.to_string(),
                })?;
            Ok(SideClient::PostgreSql(pool))
        }
        // The mongo axis connects through the driver in crate::mongo; this
        // SQL client never sees a mongodb deployment.
        Engine::MongoDb => Err(HarnessError::Transport {
            side,
            message: "mongo deployments connect through the mongo axis".to_owned(),
        }),
    }
}

impl SideClient {
    async fn close(&self) {
        match self {
            SideClient::MySql(pool) => pool.close().await,
            SideClient::PostgreSql(pool) => pool.close().await,
        }
    }
}

async fn recreate_namespace(
    context: &RunContext,
    base_url: &str,
    namespace: &str,
    side: &'static str,
) -> Result<(), HarnessError> {
    let client = connect_side(context, base_url, side).await?;
    let statements = match context.engine {
        Engine::MySql | Engine::TiDB => vec![
            format!("DROP DATABASE IF EXISTS `{namespace}`"),
            format!("CREATE DATABASE `{namespace}`"),
        ],
        Engine::PostgreSql => vec![
            format!("DROP SCHEMA IF EXISTS \"{namespace}\" CASCADE"),
            format!("CREATE SCHEMA \"{namespace}\""),
        ],
        // MongoDB recreates through crate::mongo (run_case bypasses this).
        Engine::MongoDb => Vec::new(),
    };
    for statement in statements {
        client
            .execute(&statement, QueryShape::Affected)
            .await
            .map_err(|error| HarnessError::Transport {
                side,
                message: error.to_string(),
            })?;
    }
    client.close().await;
    Ok(())
}

/// Best-effort cleanup after a case; failures print a warning and the next
/// case run recreates its namespace anyway.
async fn drop_namespaces(context: &RunContext, reference: &str, candidate: &str) {
    for (base_url, namespace) in [
        (&context.reference_base_url, reference),
        (&context.candidate_base_url, candidate),
    ] {
        let statement = match context.engine {
            Engine::MySql | Engine::TiDB => format!("DROP DATABASE IF EXISTS `{namespace}`"),
            Engine::PostgreSql => format!("DROP SCHEMA IF EXISTS \"{namespace}\" CASCADE"),
            Engine::MongoDb => continue,
        };
        match connect_side(context, base_url, "cleanup").await {
            Ok(client) => {
                if let Err(error) = client.execute(&statement, QueryShape::Affected).await {
                    eprintln!("fg-diff: namespace cleanup failed for {namespace}: {error}");
                }
                client.close().await;
            }
            Err(error) => eprintln!("fg-diff: namespace cleanup failed for {namespace}: {error}"),
        }
    }
}

/// Both engines observe through their non-prepared protocol path (MySQL
/// COM_QUERY text, PostgreSQL simple query): the canonical value is the raw
/// engine encoding, and NULL stays distinct from bytes.
async fn observe_mysql(
    pool: &MySqlPool,
    sql: &str,
    shape: QueryShape,
) -> Result<Observation, sqlx::Error> {
    match shape {
        QueryShape::Rows => match sqlx::raw_sql(sql).fetch_all(pool).await {
            Ok(rows) => {
                let columns = rows.first().map(row_columns_mysql).unwrap_or_default();
                let mut canonical_rows = Vec::with_capacity(rows.len());
                for row in &rows {
                    canonical_rows.push(canon_row_mysql(row)?);
                }
                Ok(Observation::Rows {
                    columns,
                    rows: canonical_rows,
                })
            }
            Err(error) => Ok(observed_error("mysql", error)),
        },
        QueryShape::Affected => match sqlx::raw_sql(sql).execute(pool).await {
            Ok(result) => Ok(Observation::Affected(result.rows_affected())),
            Err(error) => Ok(observed_error("mysql", error)),
        },
    }
}

async fn observe_postgres(
    pool: &PgPool,
    sql: &str,
    shape: QueryShape,
) -> Result<Observation, sqlx::Error> {
    match shape {
        QueryShape::Rows => match sqlx::raw_sql(sql).fetch_all(pool).await {
            Ok(rows) => {
                let columns = rows.first().map(row_columns_postgres).unwrap_or_default();
                let mut canonical_rows = Vec::with_capacity(rows.len());
                for row in &rows {
                    canonical_rows.push(canon_row_postgres(row)?);
                }
                Ok(Observation::Rows {
                    columns,
                    rows: canonical_rows,
                })
            }
            Err(error) => Ok(observed_error("postgresql", error)),
        },
        QueryShape::Affected => match sqlx::raw_sql(sql).execute(pool).await {
            Ok(result) => Ok(Observation::Affected(result.rows_affected())),
            Err(error) => Ok(observed_error("postgresql", error)),
        },
    }
}

fn row_columns_mysql(row: &MySqlRow) -> Vec<fg_diff::ColumnMeta> {
    row.columns()
        .iter()
        .map(|column| fg_diff::ColumnMeta {
            name: column.name().to_string(),
            type_name: column.type_info().name().to_string(),
        })
        .collect()
}

fn row_columns_postgres(row: &PgRow) -> Vec<fg_diff::ColumnMeta> {
    row.columns()
        .iter()
        .map(|column| fg_diff::ColumnMeta {
            name: column.name().to_string(),
            type_name: column.type_info().name().to_string(),
        })
        .collect()
}

/// Database errors are observations; anything else is a transport failure and
/// propagates as `Err`.
fn observed_error(engine: &'static str, error: sqlx::Error) -> Observation {
    match &error {
        sqlx::Error::Database(database) => {
            // MySQL SQLSTATE (for example 23000) cannot distinguish unique
            // from not-null violations; the granular error number can.
            let mysql_number = database
                .as_error()
                .downcast_ref::<MySqlDatabaseError>()
                .map(|error| error.number().to_string());
            let code = mysql_number.or_else(|| database.code().map(|code| code.to_string()));
            Observation::Error {
                class: classify_error(engine, code.as_deref()),
                code,
                message: database.message().to_string(),
            }
        }
        _ => Observation::Error {
            class: "transport_failure".to_string(),
            code: None,
            message: error.to_string(),
        },
    }
}

/// Raw engine bytes without a type gate (`try_get_unchecked`): the harness
/// compares encodings, it does not decode into Rust types.
fn canon_value_mysql(row: &MySqlRow, index: usize) -> Result<CanonValue, sqlx::Error> {
    let value: Option<Vec<u8>> = row.try_get_unchecked(index)?;
    Ok(match value {
        Some(bytes) => CanonValue::Bytes(bytes),
        None => CanonValue::Null,
    })
}

/// PostgreSQL simple-query values arrive as text; any column decodes as a
/// string and the canonical bytes are its UTF-8 form (bytea appears as its
/// `\x...` text representation, which compares exactly).
fn canon_value_postgres(row: &PgRow, index: usize) -> Result<CanonValue, sqlx::Error> {
    let value: Option<String> = row.try_get_unchecked(index)?;
    Ok(match value {
        Some(text) => CanonValue::Bytes(text.into_bytes()),
        None => CanonValue::Null,
    })
}

fn canon_row_mysql(row: &MySqlRow) -> Result<Vec<CanonValue>, sqlx::Error> {
    (0..row.columns().len())
        .map(|index| canon_value_mysql(row, index))
        .collect()
}

fn canon_row_postgres(row: &PgRow) -> Result<Vec<CanonValue>, sqlx::Error> {
    (0..row.columns().len())
        .map(|index| canon_value_postgres(row, index))
        .collect()
}

/// FNV-1a over the case id, rendered as eight hex characters; namespace names
/// stay well inside engine identifier limits.
pub(crate) fn case_hash(id: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in id.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:08x}")
}

#[derive(Serialize)]
struct CaseJson {
    id: String,
    fixture: String,
    status: &'static str,
    mismatches: Vec<String>,
}

#[derive(Serialize)]
struct ReportJson {
    run_id: String,
    run_kind: &'static str,
    mode: &'static str,
    engine: String,
    tag: String,
    started_at: String,
    finished_at: String,
    passed: usize,
    failed: usize,
    cases: Vec<CaseJson>,
    notes: Vec<&'static str>,
}

#[derive(Serialize)]
struct EnvJson {
    run_id: String,
    run_kind: &'static str,
    mode: &'static str,
    engine: String,
    source_revision: Option<String>,
    source_state: String,
    reference_engine_version: String,
    candidate_engine_version: String,
    platform: &'static str,
    architecture: &'static str,
    started_at: String,
    finished_at: String,
}

struct ReportInputs<'a> {
    mode: &'static str,
    engine: Engine,
    tag: &'a str,
    started_at: &'a jiff::Zoned,
    finished_at: &'a jiff::Zoned,
    reference_version: &'a str,
    candidate_version: &'a str,
    reports: &'a [CaseReport],
    report_root: &'a Path,
}

fn write_report(inputs: ReportInputs<'_>) -> Result<(PathBuf, String), HarnessError> {
    let date = inputs.started_at.strftime("%Y%m%d").to_string();
    let time = inputs.started_at.strftime("%H%M%S").to_string();
    let run_id = format!(
        "{date}-diff-{}-{}-{}",
        inputs.tag,
        inputs.engine.name(),
        time
    );
    let report_dir = inputs.report_root.join(&run_id);
    fs::create_dir_all(&report_dir)
        .map_err(|error| HarnessError::Io(format!("create {}: {error}", report_dir.display())))?;

    let failed = inputs
        .reports
        .iter()
        .filter(|report| !report.mismatches.is_empty())
        .count();
    let note = if inputs.mode == MODE_REFERENCE_VS_REFERENCE {
        HONESTY_NOTE
    } else {
        "read-only comparison with an independently materialized native reference"
    };
    let report = ReportJson {
        run_id: run_id.clone(),
        run_kind: RUN_KIND_LOCAL,
        mode: inputs.mode,
        engine: inputs.engine.corpus_name().to_string(),
        tag: inputs.tag.to_string(),
        started_at: inputs.started_at.to_string(),
        finished_at: inputs.finished_at.to_string(),
        passed: inputs.reports.len() - failed,
        failed,
        cases: inputs
            .reports
            .iter()
            .map(|report| CaseJson {
                id: report.id.clone(),
                fixture: report.fixture.clone(),
                status: if report.mismatches.is_empty() {
                    "passed"
                } else {
                    "failed"
                },
                mismatches: report.mismatches.clone(),
            })
            .collect(),
        notes: vec![
            note,
            "connection URLs contained credentials and are not recorded",
        ],
    };
    let (source_revision, source_state) = source_identity();
    let environment = EnvJson {
        run_id: run_id.clone(),
        run_kind: RUN_KIND_LOCAL,
        mode: inputs.mode,
        engine: inputs.engine.corpus_name().to_string(),
        source_revision: source_revision.clone(),
        source_state: source_state.clone(),
        reference_engine_version: inputs.reference_version.to_string(),
        candidate_engine_version: inputs.candidate_version.to_string(),
        platform: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        started_at: inputs.started_at.to_string(),
        finished_at: inputs.finished_at.to_string(),
    };

    write_json(&report_dir.join("report.json"), &report)?;
    write_json(&report_dir.join("env.json"), &environment)?;
    let summary = render_summary(&report, &source_revision, &source_state);
    fs::write(report_dir.join("summary.md"), summary)
        .map_err(|error| HarnessError::Io(format!("write summary: {error}")))?;
    Ok((report_dir, run_id))
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), HarnessError> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|error| HarnessError::Io(format!("serialize {}: {error}", path.display())))?;
    fs::write(path, text)
        .map_err(|error| HarnessError::Io(format!("write {}: {error}", path.display())))
}

fn render_summary(
    report: &ReportJson,
    source_revision: &Option<String>,
    source_state: &str,
) -> String {
    let revision = source_revision.as_deref().unwrap_or("none");
    let mut summary = format!(
        "# Differential run {}\n\n\
         - Mode: `{}` — {}\n\
         - Engine: `{}`\n\
         - Source: `{revision}` ({source_state})\n\
         - Result: **{} passed, {} failed** (tag `{}`)\n\n\
         ## Cases\n\n",
        report.run_id,
        report.mode,
        report.notes[0],
        report.engine,
        report.passed,
        report.failed,
        report.tag,
    );
    for case in &report.cases {
        if case.mismatches.is_empty() {
            summary.push_str(&format!(
                "- PASS `{}` (fixture `{}`)\n",
                case.id, case.fixture
            ));
        } else {
            summary.push_str(&format!(
                "- FAIL `{}` (fixture `{}`)\n",
                case.id, case.fixture
            ));
            for mismatch in &case.mismatches {
                summary.push_str(&format!("  - {mismatch}\n"));
            }
        }
    }
    summary.push_str("\n## Limitations\n\n- Empty result sets return no column metadata through this harness; both sides skip the column comparison identically.\n- Floating-point tolerance columns are not implemented; the engine-versus-itself byte comparison is exact.\n- Engine versions: see `env.json`.\n");
    summary
}

fn source_identity() -> (Option<String>, String) {
    let revision = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output();
    let Ok(output) = revision else {
        return (None, "no_git_repository".to_string());
    };
    if !output.status.success() {
        return (None, "no_git_repository".to_string());
    }
    let revision = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let status = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .output();
    let state = match status {
        Ok(output) if output.status.success() && output.stdout.is_empty() => "clean",
        Ok(_) => "dirty",
        Err(_) => "unknown",
    };
    (Some(revision), state.to_string())
}
