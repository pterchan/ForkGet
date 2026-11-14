//! Compare independently seeded reference tables with a real branch endpoint.

use std::{path::Path, process::ExitCode, time::Duration};

use clap::ValueEnum;
use fg_diff::{CorpusCase, Expectation, HarnessError, Observation, compare_step, load_corpus};
use sqlx::{
    Column, ConnectOptions, Connection, Executor, MySqlConnection, PgConnection, Row, Statement,
    TypeInfo,
    mysql::{MySqlConnectOptions, MySqlDatabaseError, MySqlPoolOptions, MySqlSslMode},
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};

use super::{
    CaseReport, Engine, QueryShape, ReportInputs, SideClient, endpoint_from_env, write_report,
};

const MODE: &str = "reference_vs_proxy";
const REF: &str = "reference";
const PROXY: &str = "proxy";

#[derive(Clone, Copy, ValueEnum)]
pub enum SessionAction {
    Probe,
    Reject,
    HoldClosed,
    HoldOpen,
}

const MYSQL_PREPARE: &str = "SELECT tenant_id, id FROM orders WHERE tenant_id = ? AND id = ?";
const PG_PREPARE: &str = "SELECT tenant_id, id FROM orders WHERE id = $2 AND tenant_id = $1";

pub async fn session(
    engine: Engine,
    action: SessionAction,
    expected: Option<&str>,
) -> Result<(), HarnessError> {
    let (_, key) = engine.env_keys();
    let url = endpoint_from_env(key)?;
    if matches!(action, SessionAction::Reject) {
        return rejected_login(engine, &url, expected).await;
    }
    let client = connect(engine, &url, "FG_DIFF_PROXY_CA", PROXY).await?;
    if matches!(action, SessionAction::Probe) {
        prepared_probe(&client)
            .await
            .map_err(|_| transport(PROXY))?;
        client.close().await;
        return Ok(());
    }
    let should_close = matches!(action, SessionAction::HoldClosed);
    let closed = match client {
        SideClient::MySql(pool) => {
            let mut tx = pool.begin().await.map_err(|_| transport(PROXY))?;
            sqlx::query(MYSQL_PREPARE)
                .bind(1_i32)
                .bind(1_i64)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|_| transport(PROXY))?;
            wait_for_parent()?;
            sqlx::query(MYSQL_PREPARE)
                .bind(1_i32)
                .bind(1_i64)
                .fetch_optional(&mut *tx)
                .await
                .is_err()
        }
        SideClient::PostgreSql(pool) => {
            let mut tx = pool.begin().await.map_err(|_| transport(PROXY))?;
            sqlx::query(PG_PREPARE)
                .bind(1_i32)
                .bind(1_i64)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|_| transport(PROXY))?;
            wait_for_parent()?;
            sqlx::query(PG_PREPARE)
                .bind(1_i32)
                .bind(1_i64)
                .fetch_optional(&mut *tx)
                .await
                .is_err()
        }
    };
    if closed == should_close {
        Ok(())
    } else {
        Err(HarnessError::Usage(
            "held session did not match expected drain state".into(),
        ))
    }
}

async fn rejected_login(
    engine: Engine,
    url: &str,
    expected: Option<&str>,
) -> Result<(), HarnessError> {
    let ca = endpoint_from_env("FG_DIFF_PROXY_CA")?;
    let login = async {
        match engine {
            Engine::MySql | Engine::TiDB => {
                let options = mysql_options(url, &ca)?;
                let result = MySqlConnection::connect_with(&options).await;
                Ok::<_, HarnessError>(result.err())
            }
            Engine::PostgreSql => {
                let options = pg_options(url, &ca, PROXY)?;
                let result = PgConnection::connect_with(&options).await;
                Ok(result.err())
            }
            // Reference-vs-proxy stays the SQL axis; MongoDB branch behavior
            // is checked separately by test/p2/mongo.py.
            Engine::MongoDb => Err(HarnessError::Usage(
                "mongo proxy sessions are not part of the differential harness".to_owned(),
            )),
        }
    };
    let failure = tokio::time::timeout(Duration::from_secs(6), login)
        .await
        .map_err(|_| transport(PROXY))??;
    let matches = match (expected, failure) {
        (Some(code), Some(sqlx::Error::Database(error))) => {
            error.message().starts_with(&format!("[FORKGET {code}]"))
        }
        (None, Some(sqlx::Error::Tls(_))) => true,
        (None, Some(sqlx::Error::Io(error))) => error.get_ref().is_some_and(|source| {
            matches!(
                source.downcast_ref::<rustls::Error>(),
                Some(rustls::Error::InvalidCertificate(_))
            )
        }),
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(HarnessError::Usage(format!(
            "branch login did not return the expected {}",
            expected.unwrap_or("TLS verification failure"),
        )))
    }
}

fn wait_for_parent() -> Result<(), HarnessError> {
    println!("ready");
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|_| transport(PROXY))?;
    Ok(())
}

async fn prepared_probe(client: &SideClient) -> Result<(), sqlx::Error> {
    match client {
        SideClient::MySql(pool) => {
            let statement = pool.prepare(MYSQL_PREPARE).await?;
            verify_columns(statement.columns())?;
            verify_parameter_count(statement.parameters())?;
            for (tenant, id) in [(1_i32, 2_i64), (2, 2)] {
                let row = sqlx::query(MYSQL_PREPARE)
                    .bind(tenant)
                    .bind(id)
                    .fetch_one(pool)
                    .await?;
                verify_values(row.try_get(0)?, row.try_get(1)?, tenant, id)?;
            }
            if sqlx::query(MYSQL_PREPARE)
                .bind(-1_i32)
                .bind(2_i64)
                .fetch_optional(pool)
                .await?
                .is_some()
            {
                return Err(sqlx::Error::Protocol(
                    "expected an empty prepared result".into(),
                ));
            }
        }
        SideClient::PostgreSql(pool) => {
            let statement = pool.prepare(PG_PREPARE).await?;
            verify_columns(statement.columns())?;
            verify_parameter_count(statement.parameters())?;
            for (tenant, id) in [(1_i32, 2_i64), (2, 2)] {
                let row = sqlx::query(PG_PREPARE)
                    .bind(tenant)
                    .bind(id)
                    .fetch_one(pool)
                    .await?;
                verify_values(row.try_get(0)?, row.try_get(1)?, tenant, id)?;
            }
            if sqlx::query(PG_PREPARE)
                .bind(-1_i32)
                .bind(2_i64)
                .fetch_optional(pool)
                .await?
                .is_some()
            {
                return Err(sqlx::Error::Protocol(
                    "expected an empty prepared result".into(),
                ));
            }
        }
    }
    Ok(())
}

fn verify_columns<C: Column>(columns: &[C]) -> Result<(), sqlx::Error> {
    if columns.len() == 2
        && columns[0].name() == "tenant_id"
        && columns[1].name() == "id"
        && matches!(columns[0].type_info().name(), "INT" | "INT4")
        && matches!(columns[1].type_info().name(), "BIGINT" | "INT8")
    {
        Ok(())
    } else {
        Err(sqlx::Error::Protocol(
            "unexpected logical column metadata".into(),
        ))
    }
}

fn verify_parameter_count<T>(
    parameters: Option<sqlx::Either<&[T], usize>>,
) -> Result<(), sqlx::Error> {
    let count = parameters.map(|parameters| match parameters {
        sqlx::Either::Left(types) => types.len(),
        sqlx::Either::Right(count) => count,
    });
    if count == Some(2) {
        Ok(())
    } else {
        Err(sqlx::Error::Protocol(
            "unexpected prepared parameter count".into(),
        ))
    }
}

fn verify_values(
    tenant: i32,
    id: i64,
    expected_tenant: i32,
    expected_id: i64,
) -> Result<(), sqlx::Error> {
    if (tenant, id) == (expected_tenant, expected_id) {
        Ok(())
    } else {
        Err(sqlx::Error::Protocol(
            "prepared parameters changed order".into(),
        ))
    }
}

pub async fn run(
    engine: Engine,
    tag: &str,
    corpus: &Path,
    report_root: &Path,
) -> Result<ExitCode, HarnessError> {
    let cases = load_corpus(corpus)?;
    let selection = cases
        .iter()
        .filter(|case| {
            case.supports_engine(engine.corpus_name()) && case.tags.iter().any(|item| item == tag)
        })
        .collect::<Vec<_>>();
    if selection.is_empty() || selection.iter().any(|case| !valid_case(case)) {
        return Err(HarnessError::Usage(
            "proxy comparison requires nonempty, externally seeded read or refusal cases".into(),
        ));
    }

    let (ref_key, proxy_key) = engine.env_keys();
    let started = jiff::Zoned::now();
    let reference = connect(engine, &endpoint_from_env(ref_key)?, "FG_DIFF_REF_CA", REF).await?;
    let proxy = connect(
        engine,
        &endpoint_from_env(proxy_key)?,
        "FG_DIFF_PROXY_CA",
        PROXY,
    )
    .await?;
    let reference_version = version(&reference, REF).await?;
    let candidate_version = version(&proxy, PROXY).await?;
    let mut reports = Vec::with_capacity(selection.len());
    for case in selection {
        let report = compare_case(&reference, &proxy, case).await?;
        println!(
            "[{}] {}",
            if report.mismatches.is_empty() {
                "PASS"
            } else {
                "FAIL"
            },
            report.id
        );
        reports.push(report);
    }
    reference.close().await;
    proxy.close().await;

    let (directory, _) = write_report(ReportInputs {
        mode: MODE,
        engine,
        tag,
        started_at: &started,
        finished_at: &jiff::Zoned::now(),
        reference_version: &reference_version,
        candidate_version: &candidate_version,
        reports: &reports,
        report_root,
    })?;
    println!(
        "Proxy differential report written to {}",
        directory.display()
    );
    Ok(if reports.iter().all(|case| case.mismatches.is_empty()) {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn valid_case(case: &CorpusCase) -> bool {
    case.setup.is_empty()
        && !case.steps.is_empty()
        && case.steps.iter().all(|step| {
            matches!(
                step.expect(),
                Expectation::Rows { .. } | Expectation::ProxyRefusal { .. }
            )
        })
}

async fn connect(
    engine: Engine,
    url: &str,
    ca_key: &str,
    side: &'static str,
) -> Result<SideClient, HarnessError> {
    let ca = endpoint_from_env(ca_key)?;
    match engine {
        Engine::MySql | Engine::TiDB => {
            let options = mysql_options(url, &ca)?;
            let pool = MySqlPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(Duration::from_secs(6))
                .connect_with(options)
                .await
                .map_err(|_| transport(side))?;
            Ok(SideClient::MySql(pool))
        }
        // Reference-vs-proxy stays the SQL axis.
        Engine::MongoDb => Err(transport("mongo proxy mode is not supported")),
        Engine::PostgreSql => {
            let options = pg_options(url, &ca, side)?;
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(Duration::from_secs(6))
                .connect_with(options)
                .await
                .map_err(|_| transport(side))?;
            Ok(SideClient::PostgreSql(pool))
        }
    }
}

fn mysql_options(url: &str, ca: &str) -> Result<MySqlConnectOptions, HarnessError> {
    Ok(url
        .parse::<MySqlConnectOptions>()
        .map_err(|_| transport("mysql"))?
        .ssl_mode(MySqlSslMode::VerifyIdentity)
        .ssl_ca(ca)
        .timezone(None)
        .set_names(false)
        .pipes_as_concat(false)
        .no_engine_substitution(false)
        .disable_statement_logging())
}

fn pg_options(url: &str, ca: &str, side: &'static str) -> Result<PgConnectOptions, HarnessError> {
    let options = url
        .parse::<PgConnectOptions>()
        .map_err(|_| transport(side))?
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(ca)
        .extra_float_digits(None)
        .disable_statement_logging();
    Ok(if side == REF {
        options.options([("search_path", "app")])
    } else {
        options
    })
}

async fn version(client: &SideClient, side: &'static str) -> Result<String, HarnessError> {
    let observation = client
        .execute("SELECT VERSION()", QueryShape::Rows)
        .await
        .map_err(|_| transport(side))?;
    let Observation::Rows { rows, .. } = observation else {
        return Err(transport(side));
    };
    match rows.first().and_then(|row| row.first()) {
        Some(fg_diff::CanonValue::Bytes(bytes)) => Ok(String::from_utf8_lossy(bytes).into_owned()),
        _ => Err(transport(side)),
    }
}

async fn compare_case(
    reference: &SideClient,
    candidate: &SideClient,
    case: &CorpusCase,
) -> Result<CaseReport, HarnessError> {
    let mut mismatches = Vec::new();
    for (index, step) in case.steps.iter().enumerate() {
        // Reference-vs-proxy stays the SQL axis; MongoDB command steps are
        // exercised in reference mode.
        let Some(sql) = (match step {
            fg_diff::Step::Sql { sql, .. } => Some(sql),
            fg_diff::Step::Command { .. } => None,
        }) else {
            mismatches.push(format!(
                "step {index}: mongo command steps are not supported in reference-vs-proxy mode"
            ));
            continue;
        };
        match &step.expect() {
            Expectation::ProxyRefusal {
                fg,
                sqlstate,
                errno,
            } => {
                if !refuses(candidate, sql, fg, sqlstate, *errno).await {
                    mismatches.push(format!(
                        "step {index}: expected {fg} and SQLSTATE {sqlstate}, errno {errno:?}"
                    ));
                }
            }
            expectation => {
                let left = reference
                    .execute(sql, QueryShape::Rows)
                    .await
                    .map_err(|_| transport(REF))?;
                let right = candidate
                    .execute(sql, QueryShape::Rows)
                    .await
                    .map_err(|_| transport(PROXY))?;
                if let Err(mismatch) = compare_step(index, expectation, &left, &right) {
                    mismatches.push(mismatch.detail);
                }
            }
        }
    }
    Ok(CaseReport {
        id: case.id.clone(),
        fixture: case.fixture.clone(),
        mismatches,
    })
}

async fn refuses(
    candidate: &SideClient,
    sql: &str,
    fg: &str,
    state: &str,
    errno: Option<u16>,
) -> bool {
    let result = match candidate {
        SideClient::MySql(pool) => sqlx::raw_sql(sql).execute(pool).await.map(drop),
        SideClient::PostgreSql(pool) => sqlx::raw_sql(sql).execute(pool).await.map(drop),
    };
    let Err(sqlx::Error::Database(error)) = result else {
        return false;
    };
    let number = error
        .as_error()
        .downcast_ref::<MySqlDatabaseError>()
        .map(MySqlDatabaseError::number);
    error.code().as_deref() == Some(state)
        && number == errno
        && error.message().starts_with(&format!("[FORKGET {fg}]"))
}

fn transport(side: &'static str) -> HarnessError {
    HarnessError::Transport {
        side,
        message: "TLS database connection or observation failed".into(),
    }
}
