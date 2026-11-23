//! Local control plane and native repository snapshot operations.

mod api;
mod bootstrap;
mod capacity;
mod console;
mod diagnostics;
mod gate_seed;
mod github;
mod grants;
mod mongo;
mod native;
mod recovery;
mod refresh;
mod seed;
mod snapshot;
mod verify;
mod writable;

use std::{
    env, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::ExitCode,
};

use fg_meta::{MetaError, Metadata};
use fg_protocol_common::{MANAGED_BACKEND_HOST, ManagedBackend, valid_managed_role};
use thiserror::Error;
use tracing_subscriber::{Layer, filter::Targets, layer::SubscriberExt, util::SubscriberInitExt};

use crate::{grants::NativeRoles, native::Engine, native::NativeOptions, seed::SeedVersion};

const SERVICE_USER: &str = "fg_service";
const GC_USER: &str = "fg_gc";
const REFRESH_COOLDOWN_SECONDS: &str = "FG_REFRESH_COOLDOWN_SECONDS";
const DEFAULT_REFRESH_COOLDOWN_SECONDS: u32 = 86_400;
const CONTROL_LISTEN: &str = "127.0.0.1:8081";
const PROXY_URL: &str = "http://127.0.0.1:8082";
const COMMANDS: &str = "command: migrate, bootstrap, refresh --snapshot v2|v3, \
    refresh --gate-orders <count>, retire --generation <id>, snapshot <subcommand>, \
    audit <subcommand>, doctor, status --json, serve, --revision";

#[derive(Debug, Error)]
enum ControlError {
    #[error(transparent)]
    UnsupportedTidb(#[from] fg_protocol_common::UnsupportedTidbBackend),
    #[error(transparent)]
    Ddl(#[from] native::DdlError),
    #[error(transparent)]
    Capacity(#[from] capacity::CapacityError),
    #[error(transparent)]
    Witness(#[from] writable::WitnessError),
    #[error(transparent)]
    Snapshot(#[from] snapshot::SnapshotError),
    #[error("Invalid or missing setting: {0}")]
    Config(&'static str),
    #[error("Native database operation failed ({})", native_failure(.0))]
    Native(#[from] sqlx::Error),
    #[error("MongoDB administrative operation failed; inspect the safe operation phase")]
    Mongo(#[from] mongodb::error::Error),
    #[error("{0}")]
    Meta(#[from] MetaError),
    #[error("Seed bootstrap refused: {0}")]
    Seed(&'static str),
    #[error("Writable branch provisioning refused: {0}")]
    Provision(&'static str),
    #[error(transparent)]
    Grants(#[from] grants::GrantError),
    #[error("Proxy drain is unavailable or native session cleanup is unconfirmed")]
    Drain,
    #[error("Local control listener failed")]
    Io(#[from] io::Error),
    #[error("Native database operation timed out")]
    NativeTimeout,
}

#[tokio::main]
async fn main() -> ExitCode {
    let filter = env::var("RUST_LOG")
        .ok()
        .and_then(|value| value.parse::<Targets>().ok())
        .unwrap_or_else(|| Targets::new().with_default(tracing::Level::INFO));
    let _ = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(io::stderr)
                .with_target(false)
                .without_time()
                .with_filter(filter),
        )
        .try_init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error = %error);
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), ControlError> {
    let mut args = env::args().skip(1);
    let command = args.next();
    if command.as_deref() == Some("snapshot") {
        return snapshot::run(&args.collect::<Vec<_>>()).await;
    }
    if command.as_deref() == Some("audit") {
        return audit_command(&args.collect::<Vec<_>>()).await;
    }
    let flag = args.next();
    let value = args.next();
    if args.next().is_some() {
        return Err(ControlError::Config(COMMANDS));
    }
    match (command.as_deref(), flag.as_deref(), value.as_deref()) {
        (Some("-h" | "--help"), None, None) => {
            println!("Usage: fg-control <command>\n{COMMANDS}");
            Ok(())
        }
        (Some("doctor"), None, None) => diagnostics::doctor().await,
        (Some("status"), Some("--json"), None) => diagnostics::status().await,
        (Some("--revision"), None, None) => {
            println!("{}", fg_protocol_common::BUILD_REVISION);
            Ok(())
        }
        (Some("migrate"), None, None) => migrate().await,
        (Some("bootstrap"), None, None) => bootstrap().await,
        (Some("refresh"), Some("--snapshot"), Some(version @ ("v2" | "v3"))) => {
            let version = SeedVersion::parse(version).ok_or(ControlError::Config(COMMANDS))?;
            refresh_generation(version).await
        }
        (Some("refresh"), Some("--gate-orders"), Some(count)) => {
            let version = SeedVersion::parse(&format!("gate-v2-{count}")).ok_or(
                ControlError::Config("gate order count must be between 1 and 20000000"),
            )?;
            refresh_generation(version).await
        }
        (Some("retire"), Some("--generation"), Some(id)) => {
            let id = id
                .parse::<i64>()
                .ok()
                .filter(|id| *id > 0)
                .ok_or(ControlError::Config(COMMANDS))?;
            retire_generation(id).await
        }
        (Some("serve"), None, None) => serve().await,
        _ => Err(ControlError::Config(COMMANDS)),
    }
}

async fn audit_command(args: &[String]) -> Result<(), ControlError> {
    if let [command, id_flag, id, drain] = args
        && command == "reconcile"
        && id_flag == "--id"
        && drain == "--drain"
    {
        return recovery::reconcile_operator(Some(parse_branch_id(id)?)).await;
    }
    if let [command, flag, value, operator_flag, operator] = args
        && operator_flag == "--operator"
    {
        return match (command.as_str(), flag.as_str()) {
            ("acknowledge-unknown", "--attempt") => {
                recovery::acknowledge_operator(value, operator).await
            }
            ("invalidate-storage", "--id") => {
                recovery::invalidate_operator(parse_branch_id(value)?, operator).await
            }
            _ => Err(ControlError::Config("audit operator command arguments")),
        };
    }
    if let [command, replacement, id_flag, id, operator_flag, operator] = args
        && command == "prepare"
        && replacement == "--replace-untrusted"
        && id_flag == "--id"
        && operator_flag == "--operator"
    {
        let (metadata, options, roles) = generation_settings().await?;
        recovery::require_upgrade_quiescence(&options).await?;
        return writable::Admin { options, roles }
            .replace_untrusted_witness(
                &metadata,
                writable::audit::Replacement {
                    branch_id: parse_branch_id(id)?,
                    operator,
                },
            )
            .await;
    }
    match args.first().map(String::as_str) {
        Some("prepare") if args.len() == 1 => {
            let (metadata, options, roles) = generation_settings().await?;
            recovery::require_upgrade_quiescence(&options).await?;
            writable::Admin { options, roles }
                .prepare_existing_witnesses(&metadata)
                .await
        }
        Some("reconcile") if args.len() == 1 => recovery::reconcile_operator(None).await,
        _ => Err(ControlError::Config(
            "audit prepare|reconcile|acknowledge-unknown|invalidate-storage: use the coordinated upgrade and audit recovery guide",
        )),
    }
}

fn parse_branch_id(value: &str) -> Result<i64, ControlError> {
    value
        .parse::<i64>()
        .ok()
        .filter(|id| *id > 0)
        .ok_or(ControlError::Config("branch ID must be positive"))
}

async fn migrate() -> Result<(), ControlError> {
    let (name, dsn) = match env::var("FG_META_MIGRATION_DSN") {
        Ok(value) if !value.is_empty() => ("FG_META_MIGRATION_DSN", value),
        _ => ("FG_META_DSN", required("FG_META_DSN")?),
    };
    metadata(name, &dsn).await?.migrate().await?;
    Ok(())
}

async fn bootstrap() -> Result<(), ControlError> {
    let (metadata, options, roles) = generation_settings().await?;
    let generation = bootstrap::run(&metadata, &options, &roles).await?;
    tracing::info!(
        generation_id = generation,
        engine = options.engine().name(),
        "generation activated"
    );
    Ok(())
}

/// The gate-orders fixture loads typed SQL rows (crate::gate_seed);
/// MongoDB generations use the named v1/v2/v3 document seeds instead.
fn gate_orders_refused(version: &SeedVersion, engine: Engine) -> bool {
    matches!(version, SeedVersion::Gate(_)) && engine == Engine::MongoDb
}

async fn refresh_generation(version: SeedVersion) -> Result<(), ControlError> {
    let cooldown = match env::var(REFRESH_COOLDOWN_SECONDS) {
        Ok(value) => Some(value),
        Err(env::VarError::NotPresent) => None,
        Err(_) => return Err(ControlError::Config(REFRESH_COOLDOWN_SECONDS)),
    };
    let cooldown_seconds = parse_refresh_cooldown(
        cooldown.as_deref(),
        env::var_os(MANAGED_BACKEND_HOST).is_some(),
    )?;
    let (metadata, options, roles) = generation_settings().await?;
    if gate_orders_refused(&version, options.engine()) {
        return Err(ControlError::Config(
            "gate-order snapshots are not available for MongoDB generations",
        ));
    }
    if cooldown_seconds < DEFAULT_REFRESH_COOLDOWN_SECONDS && !options.is_loopback() {
        return Err(ControlError::Config(
            "FG_REFRESH_COOLDOWN_SECONDS below 86400 requires a loopback backend",
        ));
    }
    let generation = refresh::run(
        &metadata,
        &options,
        &roles,
        refresh::Request {
            version,
            cooldown_seconds,
        },
    )
    .await?;
    tracing::info!(
        generation_id = generation,
        engine = options.engine().name(),
        snapshot = %version.name(),
        "generation activated"
    );
    Ok(())
}

async fn retire_generation(id: i64) -> Result<(), ControlError> {
    let (metadata, options, roles) = generation_settings().await?;
    refresh::retire(&metadata, &options, &roles, id).await?;
    tracing::info!(
        generation_id = id,
        engine = options.engine().name(),
        "generation retired"
    );
    Ok(())
}

async fn generation_settings() -> Result<(Metadata, NativeOptions, NativeRoles), ControlError> {
    let metadata = metadata("FG_META_DSN", &required("FG_META_DSN")?).await?;
    let managed = ManagedBackend::load().await.map_err(ControlError::Config)?;
    let options = native_options("FG_BACKEND_ADMIN_DSN", managed.as_ref())?;
    let (service, collector) = role_names(managed.is_some())?;
    let branch_admin = optional("FG_BRANCH_ADMIN_USER");
    if options.username() == service
        || options.username() == collector
        || branch_admin.as_deref() == Some(options.username())
    {
        return Err(ControlError::Config(
            "generation commands require a separate native administrator",
        ));
    }
    let roles = NativeRoles::new(
        options.engine(),
        &service,
        &collector,
        branch_admin.as_deref(),
    )?;
    Ok((metadata, options, roles))
}

async fn serve() -> Result<(), ControlError> {
    let metadata = metadata("FG_META_DSN", &required("FG_META_DSN")?).await?;
    let managed = ManagedBackend::load().await.map_err(ControlError::Config)?;
    let options = native_options("FG_BACKEND_GC_DSN", managed.as_ref())?;
    let (service, collector) = role_names(managed.is_some())?;
    if options.username() != collector || collector == service {
        return Err(ControlError::Config(
            "FG_BACKEND_GC_DSN must use the dedicated native GC role",
        ));
    }
    if !fg_protocol_common::TIDB_BACKEND_AVAILABLE && options.engine() == Engine::MySql {
        tokio::time::timeout(std::time::Duration::from_secs(5), options.connect())
            .await
            .map_err(|_| ControlError::NativeTimeout)??;
    }
    let address: SocketAddr = setting("FG_CONTROL_LISTEN", CONTROL_LISTEN)
        .parse()
        .map_err(|_| ControlError::Config("FG_CONTROL_LISTEN"))?;
    if !address.ip().is_loopback() {
        return Err(ControlError::Config("FG_CONTROL_LISTEN must be loopback"));
    }
    let branch_admin = branch_admin(&options, &service, &collector, managed.as_ref())?;
    if let Some(admin) = &branch_admin {
        admin.verify_startup(&metadata).await?;
    }
    let settings = api::Settings {
        accounts: required("FG_CONTROL_ACCOUNTS")?,
        token: required("FG_INTERNAL_TOKEN")?,
        proxy_url: setting("FG_PROXY_CONTROL_URL", PROXY_URL),
        branch_admin,
        github: github::GitHub::from_env()?,
    };
    api::serve(address, metadata, options, settings).await
}

fn branch_admin(
    gc: &NativeOptions,
    service: &str,
    collector: &str,
    managed: Option<&ManagedBackend>,
) -> Result<Option<writable::Admin>, ControlError> {
    if matches!(gc, NativeOptions::Mongo(_)) {
        if optional("FG_BRANCH_ADMIN_DSN").is_some() {
            return Err(ControlError::Config(
                "MongoDB deployments carry no branch administrator",
            ));
        }
        // The write-branch connection is the deployment administrator: mongo
        // provisioning creates databases, copies documents and merges role
        // privileges, which require the configured native administrator.
        let options = native_options("FG_BACKEND_ADMIN_DSN", managed)?;
        if !matches!(options, NativeOptions::Mongo(_)) {
            return Err(ControlError::Config("FG_BACKEND_ADMIN_DSN"));
        }
        let roles = NativeRoles::new(options.engine(), service, collector, None)?;
        return Ok(Some(writable::Admin { options, roles }));
    }
    let Some(dsn) = optional("FG_BRANCH_ADMIN_DSN") else {
        return Ok(None);
    };
    let ca = PathBuf::from(required("FG_BACKEND_CA")?);
    let options = NativeOptions::new(&dsn, &ca, managed)?;
    let username = options.username();
    let configured = optional("FG_BRANCH_ADMIN_USER");
    if username == service
        || username == collector
        || configured
            .as_deref()
            .is_some_and(|configured| configured != username)
        || managed.is_some() && configured.as_deref() != Some(username)
        || !options.same_backend(gc)
    {
        return Err(ControlError::Config(
            "FG_BRANCH_ADMIN_DSN must use the dedicated branch role on the serving backend",
        ));
    }
    let roles = NativeRoles::new(options.engine(), service, collector, Some(username))?;
    Ok(Some(writable::Admin { options, roles }))
}

fn native_options(
    name: &'static str,
    managed: Option<&ManagedBackend>,
) -> Result<NativeOptions, ControlError> {
    if required(name)?.starts_with("mongodb://") {
        let ca = optional("FG_BACKEND_CA").map(PathBuf::from);
        if managed.is_some() && ca.is_none() {
            return Err(ControlError::Config("FG_BACKEND_CA"));
        }
        if ca.as_ref().is_some_and(|ca| !ca.is_file()) {
            return Err(ControlError::Config("FG_BACKEND_CA"));
        }
        return NativeOptions::new(
            &required(name)?,
            ca.as_deref().unwrap_or(Path::new("unused-ca")),
            managed,
        );
    }
    let ca = PathBuf::from(required("FG_BACKEND_CA")?);
    NativeOptions::new(&required(name)?, &ca, managed)
}

async fn metadata(name: &'static str, dsn: &str) -> Result<Metadata, ControlError> {
    let ca = env::var_os("FG_META_CA").map(PathBuf::from);
    Metadata::connect(dsn, ca.as_deref())
        .await
        .map_err(|error| {
            tracing::error!(component = "metadata", setting = name, failure = %metadata_failure(&error),
            "metadata connection failed; check the metadata DSN, CA and role");
            error.into()
        })
}

fn metadata_failure(error: &MetaError) -> String {
    match error {
        MetaError::Database(error) => native_failure(error),
        _ => error.to_string(),
    }
}

fn parse_refresh_cooldown(value: Option<&str>, managed: bool) -> Result<u32, ControlError> {
    let seconds = match value {
        None => DEFAULT_REFRESH_COOLDOWN_SECONDS,
        Some(value) => value.parse::<u32>().map_err(|_| {
            ControlError::Config(
                "FG_REFRESH_COOLDOWN_SECONDS must be an integer between 0 and 4294967295",
            )
        })?,
    };
    if managed && seconds < DEFAULT_REFRESH_COOLDOWN_SECONDS {
        return Err(ControlError::Config(
            "FG_REFRESH_COOLDOWN_SECONDS must be at least 86400 on a managed backend",
        ));
    }
    Ok(seconds)
}

fn role_names(managed: bool) -> Result<(String, String), ControlError> {
    let service = if managed {
        required("FG_BACKEND_SERVICE_USER")?
    } else {
        setting("FG_BACKEND_SERVICE_USER", SERVICE_USER)
    };
    let collector = setting("FG_BACKEND_GC_USER", GC_USER);
    if managed
        && (!valid_managed_role(&service)
            || !valid_managed_role(&collector)
            || optional("FG_BRANCH_ADMIN_USER").is_some_and(|role| !valid_managed_role(&role)))
    {
        return Err(ControlError::Config(
            "Managed native service, GC and branch roles must be dedicated accounts",
        ));
    }
    Ok((service, collector))
}

fn required(name: &'static str) -> Result<String, ControlError> {
    optional(name).ok_or(ControlError::Config(name))
}

fn optional(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.is_empty())
}

fn setting(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_owned())
}

fn native_failure(error: &sqlx::Error) -> String {
    match error {
        sqlx::Error::Database(database) => {
            if let Some(mysql) = database.try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>() {
                return format!("MySQL errno {}", mysql.number());
            }
            database
                .code()
                .filter(|code| {
                    code.len() == 5
                        && code
                            .bytes()
                            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
                })
                .map_or_else(|| "database".to_owned(), |code| format!("SQLSTATE {code}"))
        }
        sqlx::Error::Tls(_) => "TLS".to_owned(),
        sqlx::Error::Io(_) => "I/O".to_owned(),
        sqlx::Error::ColumnDecode { index, .. }
            if index.len() <= 3 && index.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            format!("column decoding at ordinal {index}")
        }
        sqlx::Error::ColumnDecode { .. } => "column decoding".to_owned(),
        sqlx::Error::Protocol(_) => "protocol".to_owned(),
        _ => "connection or driver".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_interval_is_explicit_and_managed_minimum_is_preserved() -> Result<(), ControlError> {
        assert_eq!(parse_refresh_cooldown(None, false)?, 86_400);
        assert_eq!(parse_refresh_cooldown(Some("0"), false)?, 0);
        assert_eq!(parse_refresh_cooldown(Some("60"), false)?, 60);
        assert_eq!(parse_refresh_cooldown(None, true)?, 86_400);
        assert_eq!(parse_refresh_cooldown(Some("86400"), true)?, 86_400);
        assert!(parse_refresh_cooldown(Some("0"), true).is_err());
        for invalid in ["", "-1", "1.5", "4294967296", "later"] {
            assert!(parse_refresh_cooldown(Some(invalid), false).is_err());
        }
        Ok(())
    }

    #[test]
    fn gate_orders_are_refused_only_for_mongodb() -> Result<(), ControlError> {
        let gate = SeedVersion::parse("gate-v2-25000").ok_or(ControlError::Config(COMMANDS))?;
        assert!(gate_orders_refused(&gate, Engine::MongoDb));
        assert!(!gate_orders_refused(&gate, Engine::MySql));
        assert!(!gate_orders_refused(&gate, Engine::Postgres));
        assert!(!gate_orders_refused(&gate, Engine::TiDB));
        let snapshot = SeedVersion::parse("v2").ok_or(ControlError::Config(COMMANDS))?;
        assert!(!gate_orders_refused(&snapshot, Engine::MongoDb));
        Ok(())
    }
}
