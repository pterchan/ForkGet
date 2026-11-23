mod grants;
mod rowdiff;
mod settings;

use std::{process::ExitCode, sync::Arc, time::Duration};

use axum::{
    Json, Router as HttpRouter,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode, header},
    routing::{get, post},
};
use fg_protocol_common::{
    Router, TIDB_BACKEND_AVAILABLE, UnsupportedTidbBackend, WireError, bearer_matches,
    check_mysql_backend_version,
};
use mongodb::{
    Client,
    bson::{Document, doc},
    options::{ClientOptions, Credential, ServerAddress, Tls, TlsOptions},
};
use sqlx::{Connection, MySqlConnection, PgConnection};
use tokio::{
    net::TcpListener,
    sync::{Mutex, Semaphore},
    time::{sleep, timeout},
};

use settings::{Engine, MongoObserver, NativeOptions, Settings};

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("Invalid or missing proxy setting {0}")]
    Config(&'static str),
    #[error(transparent)]
    UnsupportedTidb(#[from] UnsupportedTidbBackend),
    #[error("Proxy socket failed: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Wire(#[from] WireError),
}

#[derive(Clone)]
struct Drain {
    router: Router,
    observer: Arc<NativeOptions>,
    observer_scan: Arc<Mutex<()>>,
    token: Arc<str>,
    diff_slots: Arc<Semaphore>,
    /// The deployment engine name; the observer wire protocol is MySQL for
    /// both MySQL and TiDB, so grants validation needs this explicitly.
    engine: &'static str,
}

#[tokio::main]
async fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("--revision") {
        println!("{}", fg_protocol_common::BUILD_REVISION);
        return ExitCode::SUCCESS;
    }
    let _ = tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .try_init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "local proxy stopped");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Error> {
    let settings = Settings::load().await?;
    let drain_socket = TcpListener::bind(settings.drain).await?;
    timeout(
        Duration::from_secs(15),
        wait_for_clean_start(&settings.observer),
    )
    .await
    .map_err(|_| WireError::Backend)??;
    timeout(Duration::from_secs(15), async {
        while settings.router.register_epoch().await.is_err() {
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| WireError::Backend)?;
    let frontend = TcpListener::bind(settings.frontend).await?;
    let audit_router = settings.router.clone();
    let state = Drain {
        router: settings.router.clone(),
        observer: Arc::new(settings.observer),
        observer_scan: Arc::new(Mutex::new(())),
        token: settings.token.into(),
        diff_slots: Arc::new(Semaphore::new(rowdiff::CONCURRENT_LIMIT)),
        engine: settings.engine.name(),
    };
    let api = HttpRouter::new()
        .route("/healthz", get(ready))
        .route("/internal/v1/audit-health", get(audit_health))
        .route("/internal/v1/branches/{id}/drain", post(drain))
        .route(
            "/internal/v1/native-sessions/{id}/quiescent",
            post(quiescent),
        )
        .route(
            "/internal/v1/native-sessions/quiescent",
            post(all_quiescent),
        )
        .route("/internal/v1/branches/{id}/diff", post(rowdiff::route))
        .route(
            "/internal/v1/branches/{id}/export",
            post(rowdiff::export_route),
        )
        .route(
            "/internal/v1/replays/{id}/apply",
            post(rowdiff::replay_apply_route).layer(DefaultBodyLimit::disable()),
        )
        .route(
            "/internal/v1/replays/{id}/verify",
            post(rowdiff::replay_verify_route).layer(DefaultBodyLimit::disable()),
        )
        .route(
            "/internal/v1/branches/{id}/verify-grants",
            post(grants::route),
        )
        .layer(DefaultBodyLimit::max(1024))
        .with_state(state);
    tracing::info!(sql = %frontend.local_addr()?, drain = %drain_socket.local_addr()?, "proxy ready");
    let wire = match settings.engine {
        // TiDB speaks the MySQL classic protocol end to end.
        Engine::MySql | Engine::TiDB => tokio::spawn(fg_proto_mysql::serve_branches(
            frontend,
            sql_config(settings.config)?,
            settings.accounts,
            settings.router,
        )),
        Engine::Postgres => tokio::spawn(fg_proto_pg::serve_branches(
            frontend,
            sql_config(settings.config)?,
            settings.accounts,
            settings.router,
        )),
        Engine::MongoDb => tokio::spawn(fg_proto_mongo::serve_branches(
            frontend,
            branch_config(
                settings.mongo.ok_or(Error::Config("FG_BACKEND_DSN"))?,
                settings.config,
            )?,
            settings.accounts,
            settings.router,
        )),
    };
    let audit_delivery = tokio::spawn(retry_audit_delivery(audit_router));
    let result = async {
        tokio::select! {
            result = axum::serve(drain_socket, api) => result?,
            result = wire => result.map_err(std::io::Error::other)??,
            result = tokio::signal::ctrl_c() => result?,
        }
        Ok(())
    }
    .await;
    audit_delivery.abort();
    result
}

async fn retry_audit_delivery(router: Router) {
    const RETRY_INTERVAL: Duration = Duration::from_secs(1);
    const RETRY_PASS_TIMEOUT: Duration = Duration::from_secs(5);
    let mut interval = tokio::time::interval(RETRY_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        if !matches!(
            timeout(RETRY_PASS_TIMEOUT, router.retry_audit_deliveries()).await,
            Ok(Ok(()))
        ) {
            tracing::debug!(
                component = "audit_delivery",
                "Audit outcome delivery remains pending"
            );
        }
    }
}

/// The SQL engines always load a TLS transport; a missing one is a settings
/// invariant violation surfaced as an explicit startup error.
fn sql_config(
    config: Option<fg_protocol_common::Config>,
) -> Result<fg_protocol_common::Config, Error> {
    config.ok_or(Error::Config("FG_BACKEND_DSN"))
}

fn branch_config(
    observer: MongoObserver,
    transport: Option<fg_protocol_common::Config>,
) -> Result<fg_proto_mongo::BranchConfig, Error> {
    Ok(fg_proto_mongo::BranchConfig {
        backend: observer.addr,
        transport,
        backend_auth_db: observer.auth_db,
        backend_account: fg_proto_mongo::Account {
            user: observer.user,
            password: observer.password,
        },
    })
}

async fn ready(State(state): State<Drain>) -> StatusCode {
    if state.router.control_ready().await && state.observe().await.is_ok() {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn drain(State(state): State<Drain>, Path(id): Path<i64>, headers: HeaderMap) -> StatusCode {
    if !internal_authorized(&headers, &state.token) {
        return StatusCode::UNAUTHORIZED;
    }
    if id <= 0 {
        return StatusCode::BAD_REQUEST;
    }
    match state.router.drain(id, || state.observe()).await {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

async fn quiescent(
    State(state): State<Drain>,
    Path(id): Path<u32>,
    headers: HeaderMap,
) -> StatusCode {
    if !internal_authorized(&headers, &state.token) {
        return StatusCode::UNAUTHORIZED;
    }
    if id == 0 {
        return StatusCode::BAD_REQUEST;
    }
    match state.observe().await {
        Ok(sessions) if !sessions.contains(&id) => StatusCode::NO_CONTENT,
        Ok(_) => StatusCode::CONFLICT,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

async fn all_quiescent(State(state): State<Drain>, headers: HeaderMap) -> StatusCode {
    if !internal_authorized(&headers, &state.token) {
        return StatusCode::UNAUTHORIZED;
    }
    match state.observe().await {
        Ok(sessions) if sessions.is_empty() => StatusCode::NO_CONTENT,
        Ok(_) => StatusCode::CONFLICT,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

impl Drain {
    async fn observe(&self) -> Result<Vec<u32>, WireError> {
        let _scan = self.observer_scan.lock().await;
        observe(&self.observer).await
    }
}

#[derive(serde::Serialize)]
struct AuditHealth {
    protected_writes_paused: bool,
}

async fn audit_health(
    State(state): State<Drain>,
    headers: HeaderMap,
) -> Result<Json<AuditHealth>, StatusCode> {
    if !internal_authorized(&headers, &state.token) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let protected_writes_paused = state
        .router
        .protected_writes_paused()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(Json(AuditHealth {
        protected_writes_paused,
    }))
}

fn internal_authorized(headers: &HeaderMap, expected: &str) -> bool {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    token.is_some_and(|candidate| bearer_matches(candidate, expected))
}

async fn wait_for_clean_start(options: &NativeOptions) -> Result<(), Error> {
    if !TIDB_BACKEND_AVAILABLE && let NativeOptions::MySql(options) = options {
        let mut native = MySqlConnection::connect_with(options)
            .await
            .map_err(|_| WireError::Backend)?;
        let version: String = sqlx::query_scalar("SELECT VERSION()")
            .fetch_one(&mut native)
            .await
            .map_err(|_| WireError::Backend)?;
        check_mysql_backend_version(version.as_bytes())?;
    }
    loop {
        if observe(options).await?.is_empty() {
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
    }
}

async fn observe(options: &NativeOptions) -> Result<Vec<u32>, WireError> {
    timeout(Duration::from_secs(5), native_sessions(options))
        .await
        .map_err(|_| WireError::Backend)?
        .map_err(|_| WireError::Backend)
}

async fn native_sessions(options: &NativeOptions) -> Result<Vec<u32>, WireError> {
    match options {
        NativeOptions::MySql(options) => {
            let result: Result<Vec<u32>, sqlx::Error> = async {
                let mut db = MySqlConnection::connect_with(options).await?;
                let identity: String = sqlx::query_scalar("SELECT CONVERT(CURRENT_USER() USING utf8mb4) COLLATE utf8mb4_unicode_ci")
                    .fetch_one(&mut db).await?;
                if identity != format!("{}@%", options.get_username()) {
                    return Err(sqlx::Error::Protocol("Native observation account is incompatible".into()));
                }
                let ids: Vec<u64> = sqlx::query_scalar(
                    "SELECT CAST(ID AS UNSIGNED) FROM information_schema.PROCESSLIST \
                     WHERE USER = SUBSTRING_INDEX(CURRENT_USER(), '@', 1) AND ID <> CONNECTION_ID()",
                )
                .fetch_all(&mut db)
                .await?;
                db.close().await?;
                ids.into_iter()
                    .map(|id| {
                        u32::try_from(id)
                            .map_err(|_| sqlx::Error::Protocol("Invalid MySQL connection ID".into()))
                    })
                    .collect()
            }
            .await;
            result.map_err(|_| WireError::Backend)
        }
        NativeOptions::Postgres(options) => {
            let result: Result<Vec<u32>, sqlx::Error> = async {
                let mut db = PgConnection::connect_with(options).await?;
                let identity: String = sqlx::query_scalar("SELECT current_user::text").fetch_one(&mut db).await?;
                if identity != options.get_username() {
                    return Err(sqlx::Error::Protocol("Native observation account is incompatible".into()));
                }
                let ids: Vec<i32> = sqlx::query_scalar(
                    "SELECT pid FROM pg_catalog.pg_stat_activity WHERE usename = current_user AND pid <> pg_backend_pid()",
                ).fetch_all(&mut db).await?;
                db.close().await?;
                Ok(ids.into_iter().map(i32::cast_unsigned).collect())
            }
            .await;
            result.map_err(|_| WireError::Backend)
        }
        NativeOptions::Mongo(options) => mongo_sessions(options).await,
    }
}

/// A single pooled driver connection lists every other service-user
/// connection mongod knows about.
/// The driver's SDAM monitor connection stays unauthenticated and is filtered
/// out by `allUsers: false`.
async fn mongo_sessions(options: &MongoObserver) -> Result<Vec<u32>, WireError> {
    let credential = Credential::builder()
        .username(options.user.clone())
        .password(options.password.clone())
        .source(options.auth_db.clone())
        .build();
    let client_options = ClientOptions::builder()
        .hosts(vec![ServerAddress::Tcp {
            host: options.host.clone(),
            port: Some(options.addr.port()),
        }])
        .credential(credential)
        .tls(
            options
                .tls_ca
                .as_ref()
                .map(|ca| Tls::Enabled(TlsOptions::builder().ca_file_path(ca.clone()).build())),
        )
        .max_pool_size(1)
        .build();
    let client = Client::with_options(client_options).map_err(|_| WireError::Backend)?;
    let admin = client.database("admin");
    let hello = admin
        .run_command(doc! { "hello": 1i32 })
        .await
        .map_err(|_| WireError::Backend)?;
    let own = mongo_connection_id(&hello).ok_or(WireError::Backend)?;
    let mut cursor = admin
        .aggregate(vec![
            doc! { "$currentOp": { "idleConnections": true, "allUsers": false } },
            doc! { "$match": { "connectionId": { "$ne": own } } },
        ])
        .await
        .map_err(|_| WireError::Backend)?;
    let mut sessions = Vec::new();
    while cursor.advance().await.map_err(|_| WireError::Backend)? {
        let document = cursor
            .deserialize_current()
            .map_err(|_| WireError::Backend)?;
        if let Some(id) = mongo_connection_id(&document) {
            sessions.push(id);
        }
    }
    Ok(sessions)
}

/// mongod reports `connectionId` as NumberInt on some versions and NumberLong
/// on others; accept both.
fn mongo_connection_id(document: &Document) -> Option<u32> {
    let id = match document.get_i32("connectionId") {
        Ok(id) => i64::from(id),
        Err(_) => document.get_i64("connectionId").ok()?,
    };
    u32::try_from(id).ok()
}
