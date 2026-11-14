//! SQLx wire client for local write differentials and session barriers.

#[path = "write_probe/load.rs"]
mod load;

use std::{
    env,
    io::{self, BufRead, Write},
    path::PathBuf,
    str::FromStr,
    time::{Duration, Instant},
};

use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{
    Column, ConnectOptions, Connection, Executor, MySqlConnection, PgConnection, Row, Statement,
    TypeInfo,
    mysql::{MySqlConnectOptions, MySqlDatabaseError, MySqlSslMode},
    postgres::{PgConnectOptions, PgSslMode},
};

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Text,
    Read,
    Prepare,
    Execute,
    Fetch,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Parameter {
    I32(i32),
    I64(i64),
    Text(String),
    NullText,
}

#[derive(Deserialize)]
struct Request {
    op: Operation,
    sql: String,
    #[serde(default)]
    params: Vec<Parameter>,
}

#[derive(Deserialize)]
struct Benchmark {
    setup: Option<String>,
    warmup: Vec<Request>,
    measure: Vec<Request>,
}

async fn benchmark(client: &mut Client) -> Result<Value, Box<dyn std::error::Error>> {
    let plan: Benchmark = serde_json::from_reader(io::stdin().lock())?;
    if plan.measure.is_empty() || plan.measure.len() > 1000 || plan.warmup.len() > 1000 {
        return Err("invalid benchmark sample size".into());
    }
    if let Some(sql) = plan.setup {
        client
            .query(Request {
                op: Operation::Text,
                sql,
                params: Vec::new(),
            })
            .await?;
    }
    for request in plan.warmup {
        match tokio::time::timeout(Duration::from_secs(5), client.query(request)).await {
            Ok(Ok(_)) => (),
            _ => return Err("benchmark warmup failed".into()),
        }
    }
    let requested = plan.measure.len();
    let mut latencies = Vec::with_capacity(requested);
    let mut errors = 0;
    let mut timeouts = 0;
    let total = Instant::now();
    for request in plan.measure {
        let start = Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(5), client.query(request)).await;
        latencies.push(start.elapsed().as_secs_f64() * 1000.0);
        match result {
            Ok(Ok(_)) => (),
            Ok(Err(_)) => errors += 1,
            Err(_) => {
                timeouts += 1;
                break;
            }
        }
    }
    let duration = total.elapsed().as_secs_f64();
    latencies.sort_by(f64::total_cmp);
    let quantile = |percentile: usize| latencies[(latencies.len() * percentile).div_ceil(100) - 1];
    Ok(json!({
        "requested": requested, "executed": latencies.len(),
        "errors": errors, "timeouts": timeouts, "seconds": duration,
        "qps": (latencies.len() - errors - timeouts) as f64 / duration,
        "p95_ms": quantile(95), "p99_ms": quantile(99),
    }))
}

enum Client {
    MySql(MySqlConnection),
    Postgres(PgConnection),
}

impl Client {
    async fn connect(url: &str, ca: PathBuf) -> Result<Self, sqlx::Error> {
        Self::connect_with_pem(url, std::fs::read(ca)?).await
    }

    async fn connect_with_pem(url: &str, ca: Vec<u8>) -> Result<Self, sqlx::Error> {
        // TiDB serves the MySQL wire protocol under the tidb:// scheme
        // SQLx only parses the mysql:// scheme.
        let wire = url.replacen("tidb://", "mysql://", 1);
        let url = wire.as_str();
        if url.starts_with("mysql://") {
            let options = MySqlConnectOptions::from_str(url)?
                .ssl_mode(MySqlSslMode::VerifyIdentity)
                .ssl_ca_from_pem(ca)
                .timezone(None)
                .set_names(false)
                .pipes_as_concat(false)
                .no_engine_substitution(false)
                .disable_statement_logging();
            MySqlConnection::connect_with(&options)
                .await
                .map(Self::MySql)
        } else {
            let options = PgConnectOptions::from_str(url)?
                .ssl_mode(PgSslMode::VerifyFull)
                .ssl_root_cert_from_pem(ca)
                .extra_float_digits(None)
                .disable_statement_logging();
            PgConnection::connect_with(&options)
                .await
                .map(Self::Postgres)
        }
    }

    async fn query(&mut self, request: Request) -> Result<Value, sqlx::Error> {
        match self {
            Self::MySql(connection) => mysql(connection, request).await,
            Self::Postgres(connection) => postgres(connection, request).await,
        }
    }
}

fn bind<'q, DB>(
    mut query: sqlx::query::Query<'q, DB, DB::Arguments<'q>>,
    parameters: Vec<Parameter>,
) -> sqlx::query::Query<'q, DB, DB::Arguments<'q>>
where
    DB: sqlx::Database,
    i32: sqlx::Encode<'q, DB> + sqlx::Type<DB>,
    i64: sqlx::Encode<'q, DB> + sqlx::Type<DB>,
    String: sqlx::Encode<'q, DB> + sqlx::Type<DB>,
    Option<String>: sqlx::Encode<'q, DB> + sqlx::Type<DB>,
{
    for parameter in parameters {
        query = match parameter {
            Parameter::I32(value) => query.bind(value),
            Parameter::I64(value) => query.bind(value),
            Parameter::Text(value) => query.bind(value),
            Parameter::NullText => query.bind(Option::<String>::None),
        };
    }
    query
}

fn statement<'q>(value: &impl Statement<'q>) -> Value {
    let parameters = match value.parameters() {
        Some(sqlx::Either::Left(types)) => {
            json!(types.iter().map(TypeInfo::name).collect::<Vec<_>>())
        }
        Some(sqlx::Either::Right(count)) => json!(count),
        None => Value::Null,
    };
    json!({"columns": columns(value.columns()), "parameters": parameters})
}

fn columns(values: &[impl Column]) -> Vec<(&str, &str)> {
    values
        .iter()
        .map(|column| (column.name(), column.type_info().name()))
        .collect()
}

fn rows<R>(rows: &[R]) -> Result<Value, sqlx::Error>
where
    R: Row,
    usize: sqlx::ColumnIndex<R>,
    Option<i32>: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    Option<i64>: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    Option<String>: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    let mut values = Vec::with_capacity(rows.len());
    for row in rows {
        let values_row: Result<Vec<_>, sqlx::Error> = row
            .columns()
            .iter()
            .map(|column| {
                let index = column.ordinal();
                Ok(match column.type_info().name() {
                    "INT" | "INT4" => json!(row.try_get::<Option<i32>, _>(index)?),
                    "BIGINT" | "BIGINT UNSIGNED" | "INT8" => {
                        json!(row.try_get_unchecked::<Option<i64>, _>(index)?)
                    }
                    _ => json!(row.try_get::<Option<String>, _>(index)?),
                })
            })
            .collect();
        values.push(values_row?);
    }
    Ok(json!({"columns": rows.first().map(|row| columns(row.columns())), "rows": values}))
}

async fn mysql(connection: &mut MySqlConnection, request: Request) -> Result<Value, sqlx::Error> {
    let sql = request.sql.as_str();
    let result = match request.op {
        Operation::Text => sqlx::raw_sql(sql).execute(connection).await?,
        Operation::Execute => {
            bind(sqlx::query(sql), request.params)
                .execute(connection)
                .await?
        }
        Operation::Read => return rows(&sqlx::raw_sql(sql).fetch_all(connection).await?),
        Operation::Fetch => {
            return rows(
                &bind(sqlx::query(sql), request.params)
                    .fetch_all(connection)
                    .await?,
            );
        }
        Operation::Prepare => return Ok(statement(&connection.prepare(sql).await?)),
    };
    Ok(json!({"affected": result.rows_affected(), "insert_id": result.last_insert_id()}))
}

async fn postgres(connection: &mut PgConnection, request: Request) -> Result<Value, sqlx::Error> {
    let sql = request.sql.as_str();
    let result = match request.op {
        Operation::Text => sqlx::raw_sql(sql).execute(connection).await?,
        Operation::Execute => {
            bind(sqlx::query(sql), request.params)
                .execute(connection)
                .await?
        }
        Operation::Read => return rows(&sqlx::raw_sql(sql).fetch_all(connection).await?),
        Operation::Fetch => {
            return rows(
                &bind(sqlx::query(sql), request.params)
                    .fetch_all(connection)
                    .await?,
            );
        }
        Operation::Prepare => return Ok(statement(&connection.prepare(sql).await?)),
    };
    Ok(json!({"affected": result.rows_affected()}))
}

fn failure(error: sqlx::Error) -> Value {
    let Some(error) = error.as_database_error() else {
        return json!({"transport": error.to_string()});
    };
    let errno = error
        .try_downcast_ref::<MySqlDatabaseError>()
        .map(MySqlDatabaseError::number);
    let message = error.message();
    let fg = message
        .strip_prefix("[FORKGET ")
        .and_then(|suffix| suffix.split_once(']'));
    let physical_leak = ["fg_b", "fg_g", "_fg_generated"]
        .iter()
        .any(|name| message.contains(name));
    let mut observed = json!({"sqlstate": error.code(), "errno": errno, "fg": fg.map(|(code, _)| code), "physical_leak": physical_leak});
    if message.starts_with("[FORKGET FG-5002] Transaction row budget exceeded:")
        || message.starts_with("[FORKGET FG-5002] Table row share budget exceeded:")
    {
        observed["policy_detail"] = json!(message);
    }
    observed
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mode = env::args().nth(1);
    match mode.as_deref() {
        Some("timed-load") => {
            println!("{}", load::run()?);
            return Ok(());
        }
        Some("revision") => {
            println!(
                "{}",
                option_env!("FG_GATE_BUILD_REVISION").unwrap_or("unavailable")
            );
            return Ok(());
        }
        _ => (),
    }
    let url = env::var("FG_WRITE_PROBE_URL")?;
    let ca = PathBuf::from(env::var_os("FG_WRITE_PROBE_CA").ok_or("missing TLS CA")?);
    let mut client = Client::connect(&url, ca)
        .await
        .map_err(|error| failure(error).to_string())?;
    if mode.as_deref() == Some("benchmark") {
        println!("{}", benchmark(&mut client).await?);
        return Ok(());
    }
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "ready")?;
    stdout.flush()?;
    for line in io::stdin().lock().lines() {
        let request: Request = serde_json::from_str(&line?)?;
        let value = client.query(request).await.unwrap_or_else(failure);
        writeln!(stdout, "{value}")?;
        stdout.flush()?;
    }
    Ok(())
}
