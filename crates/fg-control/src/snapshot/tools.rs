//! Native backup processes with credentials confined to private files/environment.

use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use fg_protocol_common::{TIDB_BACKEND_AVAILABLE, admit_tidb_backend, check_mysql_backend_version};
use percent_encoding::percent_decode_str;
use reqwest::Url;
use serde_json::json;
use sqlx::{
    ConnectOptions, Connection,
    mysql::{MySqlConnectOptions, MySqlSslMode},
    postgres::{PgConnectOptions, PgSslMode},
};

use super::SnapshotError;
use crate::native::{Engine, Native};

pub(super) struct Endpoint {
    pub engine: Engine,
    pub host: String,
    pub port: u16,
    pub database: String,
    pub(super) user: String,
    pub(super) password: String,
    pub(super) ca: Option<PathBuf>,
}

impl Endpoint {
    pub fn from_env(setting: &str, ca_setting: &str) -> Result<Self, SnapshotError> {
        let dsn = env::var(setting).map_err(|_| SnapshotError::Setting("source_or_target_dsn"))?;
        let url = Url::parse(&dsn).map_err(|_| SnapshotError::Setting("source_or_target_dsn"))?;
        let engine = match url.scheme() {
            "mysql" => Engine::MySql,
            "postgres" | "postgresql" => Engine::Postgres,
            "tidb" => {
                admit_tidb_backend()?;
                Engine::TiDB
            }
            _ => return Err(SnapshotError::Setting("unsupported_snapshot_engine")),
        };
        if url.query().is_some() || url.fragment().is_some() {
            return Err(SnapshotError::Setting("dsn_options_not_admitted"));
        }
        let decode = |value: &str| {
            percent_decode_str(value)
                .decode_utf8()
                .map(|value| value.into_owned())
                .map_err(|_| SnapshotError::Setting("dsn_encoding"))
        };
        let host = url
            .host_str()
            .ok_or(SnapshotError::Setting("dsn_host"))?
            .to_owned();
        let ca = env::var_os(ca_setting).map(PathBuf::from);
        let local = matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1");
        if ca.as_ref().is_some_and(|path| !path.is_file()) || (!local && ca.is_none()) {
            return Err(SnapshotError::Setting(
                "verified_source_or_target_ca_required",
            ));
        }
        let database = decode(url.path().strip_prefix('/').unwrap_or_default())?;
        if database.is_empty() || database.contains('/') {
            return Err(SnapshotError::Setting("dsn_database"));
        }
        Ok(Self {
            engine,
            host,
            port: url.port().unwrap_or(if engine == Engine::Postgres {
                5432
            } else if engine == Engine::TiDB {
                4000
            } else {
                3306
            }),
            database,
            user: decode(url.username())?,
            password: decode(url.password().unwrap_or_default())?,
            ca,
        })
    }

    pub async fn connect(&self) -> Result<Native, SnapshotError> {
        if self.engine == Engine::Postgres {
            let mut options = PgConnectOptions::new()
                .host(&self.host)
                .port(self.port)
                .username(&self.user)
                .password(&self.password)
                .database(&self.database)
                .disable_statement_logging();
            options = if let Some(ca) = &self.ca {
                options.ssl_mode(PgSslMode::VerifyFull).ssl_root_cert(ca)
            } else {
                options.ssl_mode(PgSslMode::Disable)
            };
            return Ok(Native::Postgres(
                sqlx::PgConnection::connect_with(&options).await?,
            ));
        }
        let mut options = MySqlConnectOptions::new()
            .host(&self.host)
            .port(self.port)
            .username(&self.user)
            .password(&self.password)
            .database(&self.database)
            .charset("utf8mb4")
            .disable_statement_logging();
        options = if let Some(ca) = &self.ca {
            options.ssl_mode(MySqlSslMode::VerifyIdentity).ssl_ca(ca)
        } else {
            options.ssl_mode(MySqlSslMode::Disabled)
        };
        let mut connection = sqlx::MySqlConnection::connect_with(&options).await?;
        if !TIDB_BACKEND_AVAILABLE {
            let version: String = sqlx::query_scalar("SELECT VERSION()")
                .fetch_one(&mut connection)
                .await?;
            check_mysql_backend_version(version.as_bytes())?;
        }
        Ok(if self.engine == Engine::TiDB {
            Native::TiDB(connection)
        } else {
            Native::MySql(connection)
        })
    }

    pub fn database(&self, database: &str) -> Self {
        Self {
            engine: self.engine,
            host: self.host.clone(),
            port: self.port,
            database: database.to_owned(),
            user: self.user.clone(),
            password: self.password.clone(),
            ca: self.ca.clone(),
        }
    }

    fn mysql_session(&self) -> serde_json::Value {
        let mut options = json!({"scheme":"mysql", "host":self.host, "port":self.port, "user":self.user, "password":self.password,
            "ssl-mode": if self.ca.is_some() { "VERIFY_IDENTITY" } else { "DISABLED" }});
        if let Some(ca) = &self.ca {
            options["ssl-ca"] = json!(ca);
        }
        options
    }

    fn postgres(&self, tool: &'static str) -> Result<Command, SnapshotError> {
        let mut command = Command::new(tool);
        command
            .env("PGHOST", &self.host)
            .env("PGPORT", self.port.to_string())
            .env("PGUSER", &self.user)
            .env("PGPASSWORD", &self.password)
            .env("PGDATABASE", &self.database)
            // PostgreSQL must notice an abruptly lost loader while a long
            // statement is still running, rather than only on its next write.
            .env("PGOPTIONS", "-c client_connection_check_interval=100ms")
            .env(
                "PGSSLMODE",
                if self.ca.is_some() {
                    "verify-full"
                } else {
                    "disable"
                },
            );
        if let Some(ca) = &self.ca {
            command.env("PGSSLROOTCERT", ca);
        }
        Ok(command)
    }
}

pub(super) struct PrivateDir(PathBuf);

impl PrivateDir {
    pub fn new() -> Result<Self, SnapshotError> {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| SnapshotError::Setting("clock"))?
            .as_nanos();
        let path = env::temp_dir().join(format!("forkget-snapshot-{}-{stamp}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(super) fn private_write(path: &Path, bytes: &[u8]) -> Result<(), SnapshotError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub(super) async fn execute(
    command: Command,
    tool: &'static str,
    phase: &'static str,
) -> Result<(), SnapshotError> {
    // The native loader must not outlive a crashed controller and race an
    // operator's retry-cleanup. util-linux sets Linux PR_SET_PDEATHSIG before
    // execing the tool; it adds no shell, credential argument or background
    // supervisor. Native profiles use a single process with worker threads.
    let mut supervised = Command::new("setpriv");
    supervised
        .args(["--pdeathsig", "KILL", "--"])
        .arg(command.get_program())
        .args(command.get_args());
    for (key, value) in command.get_envs() {
        if let Some(value) = value {
            supervised.env(key, value);
        } else {
            supervised.env_remove(key);
        }
    }
    if let Some(directory) = command.get_current_dir() {
        supervised.current_dir(directory);
    }
    // Tool text can include connection facts or source SQL. Keep it out of
    // application logs; return only a tool/phase/status classification.
    supervised
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    tokio::task::spawn_blocking(move || {
        let mut child = supervised.spawn().map_err(|_| SnapshotError::Tool {
            tool,
            phase,
            status: None,
        })?;
        let deadline = Instant::now() + TOOL_PHASE_LIMIT;
        loop {
            if let Some(status) = child.try_wait()? {
                return if status.success() {
                    Ok(())
                } else {
                    Err(SnapshotError::Tool {
                        tool,
                        phase,
                        status: status.code(),
                    })
                };
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(SnapshotError::Tool {
                    tool,
                    phase,
                    status: None,
                });
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    })
    .await
    .map_err(|_| SnapshotError::Setting("native_tool_task"))?
}

pub(super) fn versions(engine: Engine) -> Result<serde_json::Value, SnapshotError> {
    let names = if engine == Engine::Postgres {
        vec!["pg_dump", "pg_restore"]
    } else if engine == Engine::TiDB {
        vec!["fg-dumpling-run", "tidb-lightning"]
    } else if engine == Engine::MongoDb {
        vec!["mongodump", "mongorestore"]
    } else {
        vec!["mysqlsh"]
    };
    let mut result = serde_json::Map::new();
    for tool in names {
        let output = Command::new(tool)
            .arg(if tool == "tidb-lightning" {
                "-V"
            } else {
                "--version"
            })
            .output()
            .map_err(|_| SnapshotError::Tool {
                tool,
                phase: "version",
                status: None,
            })?;
        let version = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .trim()
        .to_owned();
        let supported = output.status.success()
            && if tool == "mysqlsh" {
                version.contains("Ver 8.0.36 ")
            } else if matches!(tool, "mongodump" | "mongorestore") {
                version.contains("version: 100.20.1")
            } else if matches!(tool, "fg-dumpling-run" | "tidb-lightning") {
                version.contains("v8.5.8")
            } else {
                version.contains("(PostgreSQL) 16.15 ")
            };
        if !supported {
            return Err(SnapshotError::Tool {
                tool,
                phase: "unsupported_version",
                status: output.status.code(),
            });
        }
        result.insert(tool.to_owned(), json!(version));
    }
    Ok(result.into())
}

pub(super) async fn mysql_dump(
    endpoint: &Endpoint,
    schema: &str,
    tables: &[String],
    output: &Path,
) -> Result<(), SnapshotError> {
    let options = json!({"consistent":true,"threads":1,"chunking":false,"compression":"none","dataOnly":true,"triggers":false,"showProgress":false,"tzUtc":true});
    mysql_script(
        endpoint,
        format!(
            "util.dump_tables({}, {}, {}, {})",
            python_json(json!(schema)),
            python_json(json!(tables)),
            python_json(json!(output)),
            python_json(options)
        ),
        "capture",
    )
    .await
}

pub(super) async fn mysql_load(
    endpoint: &Endpoint,
    schema: &str,
    input: &Path,
) -> Result<(), SnapshotError> {
    let options = json!({"schema":schema,"loadDdl":false,"loadData":true,"loadUsers":false,"loadIndexes":false,"ignoreExistingObjects":true,"threads":1,"showProgress":false,"progressFile":""});
    mysql_script(
        endpoint,
        format!(
            "util.load_dump({}, {})",
            python_json(json!(input)),
            python_json(options)
        ),
        "import",
    )
    .await
}

/// Wall-clock budget for one external snapshot tool phase. Sized for the
// local focused-evidence scope; the planned 200 GiB cloud refresh needs a
// raised, per-profile budget (support matrix: snapshot.* planned).
const TOOL_PHASE_LIMIT: Duration = Duration::from_secs(3600);

fn python_json(value: serde_json::Value) -> String {
    format!("json.loads({})", json!(value.to_string()))
}

async fn mysql_script(
    endpoint: &Endpoint,
    operation: String,
    phase: &'static str,
) -> Result<(), SnapshotError> {
    let private = PrivateDir::new()?;
    let script = private.path().join("operation.py");
    private_write(
        &script,
        format!(
            "import json\nshell.connect({})\n{operation}\n",
            python_json(endpoint.mysql_session())
        )
        .as_bytes(),
    )?;
    let mut command = Command::new("mysqlsh");
    command
        .args(["--no-defaults", "--py", "--quiet-start=2", "--file"])
        .arg(&script);
    execute(command, "mysqlsh", phase).await
}

pub(super) async fn pg_dump(
    endpoint: &Endpoint,
    schema: &str,
    snapshot: Option<&str>,
    output: &Path,
) -> Result<(), SnapshotError> {
    let mut command = endpoint.postgres("pg_dump")?;
    command
        .args([
            "--format=custom",
            "--no-owner",
            "--no-privileges",
            "--no-comments",
            "--no-security-labels",
            "--no-tablespaces",
            "--strict-names",
            "--schema",
        ])
        .arg(schema)
        .arg("--file")
        .arg(output);
    if let Some(snapshot) = snapshot {
        command.arg("--snapshot").arg(snapshot);
    }
    execute(command, "pg_dump", "capture").await
}

pub(super) async fn pg_restore(endpoint: &Endpoint, input: &Path) -> Result<(), SnapshotError> {
    let mut command = endpoint.postgres("pg_restore")?;
    command
        .args([
            "--exit-on-error",
            "--no-owner",
            "--no-privileges",
            "--no-comments",
            "--no-security-labels",
            "--no-tablespaces",
            "--dbname",
        ])
        .arg(&endpoint.database)
        .arg(input);
    execute(command, "pg_restore", "import").await
}

pub(super) fn pg_validate_archive(input: &Path, schema: &str) -> Result<(), SnapshotError> {
    let output = Command::new("pg_restore")
        .arg("--list")
        .arg(input)
        .output()
        .map_err(|_| SnapshotError::Tool {
            tool: "pg_restore",
            phase: "archive_admission",
            status: None,
        })?;
    if !output.status.success() {
        return Err(SnapshotError::Tool {
            tool: "pg_restore",
            phase: "archive_admission",
            status: output.status.code(),
        });
    }
    let listing = String::from_utf8(output.stdout)
        .map_err(|_| SnapshotError::Setting("archive_listing_encoding"))?;
    for line in listing
        .lines()
        .filter(|line| !line.starts_with(';') && !line.trim().is_empty())
    {
        let (_, entry) = line
            .split_once(';')
            .ok_or(SnapshotError::Setting("archive_listing_format"))?;
        let mut tokens = entry.split_whitespace();
        tokens.next();
        tokens.next();
        let description = tokens.collect::<Vec<_>>().join(" ");
        let Some((kind, rest)) = [
            "SEQUENCE OWNED BY",
            "SEQUENCE SET",
            "TABLE DATA",
            "FK CONSTRAINT",
            "CONSTRAINT",
            "SEQUENCE",
            "DEFAULT",
            "INDEX",
            "TABLE",
            "SCHEMA",
        ]
        .into_iter()
        .find_map(|kind| {
            description
                .strip_prefix(&format!("{kind} "))
                .map(|rest| (kind, rest))
        }) else {
            return Err(SnapshotError::Setting(
                "archive_contains_unadmitted_objects",
            ));
        };
        let mut names = rest.split_whitespace();
        let namespace = names.next().unwrap_or_default();
        let allowed = if kind == "SCHEMA" {
            namespace == "-" && names.next() == Some(schema)
        } else {
            namespace == schema
        };
        if !allowed {
            return Err(SnapshotError::Setting(
                "archive_contains_unadmitted_namespace",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ChildGuard(std::process::Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// Exercise the actual process runner against a real native connection.
    /// The helper is killed abruptly, without Rust destructors or cancellation.
    #[tokio::test]
    #[ignore = "requires an isolated native PostgreSQL DSN and installed native tools"]
    async fn native_parent_death() -> Result<(), Box<dyn std::error::Error>> {
        let endpoint = Endpoint::from_env("FG_SNAPSHOT_TEST_PG_DSN", "FG_SNAPSHOT_TEST_PG_CA")?;
        if env::var("FG_SNAPSHOT_TEST_PROCESS_HELPER").as_deref() == Ok("1") {
            let mut command = endpoint.postgres("psql")?;
            command
                .args(["--no-psqlrc", "--command", "SELECT pg_sleep(120)"])
                .env("PGAPPNAME", env::var("FG_SNAPSHOT_TEST_PROCESS_TAG")?);
            execute(command, "psql", "parent_death_test").await?;
            return Ok(());
        }
        let tag = format!("fg_native_parent_death_{}", std::process::id());
        let mut native = endpoint.connect().await?;
        let Native::Postgres(connection) = &mut native else {
            return Err("PostgreSQL test endpoint required".into());
        };
        let child = Command::new(env::current_exe()?)
            .args([
                "snapshot::tools::tests::native_parent_death",
                "--exact",
                "--ignored",
            ])
            .env("FG_SNAPSHOT_TEST_PROCESS_HELPER", "1")
            .env("FG_SNAPSHOT_TEST_PROCESS_TAG", &tag)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let mut helper = ChildGuard(child);
        let mut connected = false;
        for _ in 0..100 {
            let count:i64=sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE application_name=$1 AND query='SELECT pg_sleep(120)'")
                .bind(&tag).fetch_one(&mut *connection).await?;
            if count == 1 {
                connected = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if !connected {
            return Err("native helper never opened its connection".into());
        }
        let children = Command::new("ps")
            .args(["-o", "pid=", "--ppid", &helper.0.id().to_string()])
            .output()?;
        let children = String::from_utf8(children.stdout)?;
        let ids = children.split_whitespace().collect::<Vec<_>>();
        if ids.len() != 1 {
            return Err("expected one native child process".into());
        }
        let child_pid = ids[0].parse::<u32>()?;
        helper.0.kill()?;
        helper.0.wait()?;
        for _ in 0..100 {
            let count: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity WHERE application_name=$1",
            )
            .bind(&tag)
            .fetch_one(&mut *connection)
            .await?;
            let running = fs::read_to_string(format!("/proc/{child_pid}/stat"))
                .ok()
                .and_then(|stat| {
                    stat.split_once(')').map(|(_, rest)| {
                        !matches!(rest.trim_start().chars().next(), Some('Z' | 'X'))
                    })
                })
                .unwrap_or(false);
            if count == 0 && !running {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err("native process or connection outlived its killed controller".into())
    }
}
