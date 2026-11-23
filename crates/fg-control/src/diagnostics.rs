//! Read-only operator diagnostics never return connection strings or raw errors.

use std::{env, path::Path, process::Command};

use serde_json::{Value, json};

const AUDIT_HEALTH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

pub(crate) async fn audit_pause_state(
    client: &reqwest::Client,
    proxy_url: &reqwest::Url,
    token: &str,
) -> Option<bool> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct AuditHealth {
        protected_writes_paused: bool,
    }
    tokio::time::timeout(AUDIT_HEALTH_TIMEOUT, async {
        let response = client
            .get(proxy_url.join("internal/v1/audit-health").ok()?)
            .bearer_auth(token)
            .send()
            .await
            .ok()?
            .error_for_status()
            .ok()?;
        Some(
            response
                .json::<AuditHealth>()
                .await
                .ok()?
                .protected_writes_paused,
        )
    })
    .await
    .ok()
    .flatten()
}

async fn proxy_audit_health() -> Option<bool> {
    let token = env::var("FG_INTERNAL_TOKEN").ok()?;
    let proxy_url = fg_protocol_common::loopback_http(
        &env::var("FG_PROXY_CONTROL_URL").unwrap_or_else(|_| crate::PROXY_URL.to_owned()),
    )?;
    let client = fg_protocol_common::loopback_client(AUDIT_HEALTH_TIMEOUT).ok()?;
    audit_pause_state(&client, &proxy_url, &token).await
}

use crate::{
    ControlError, metadata,
    native::{Native, NativeOptions},
    required,
};

pub(crate) async fn status() -> Result<(), ControlError> {
    let metadata = metadata("FG_META_DSN", &required("FG_META_DSN")?).await?;
    let mut report = metadata.deployment_status(engine()?).await?;
    report["storage_assurance"] = crate::capacity::assurance();
    report["audit"]["protected_writes_paused"] = json!(proxy_audit_health().await);
    report["known_limitations"] = known_limitations(engine()?);
    println!("{report}");
    Ok(())
}

pub(crate) async fn doctor() -> Result<(), ControlError> {
    let engine = engine()?;
    let mut checks = Vec::new();
    for name in [
        "FG_META_DSN",
        "FG_BACKEND_DSN",
        "FG_BACKEND_GC_DSN",
        "FG_FRONTEND_ACCOUNTS",
        "FG_CONTROL_ACCOUNTS",
        "FG_INTERNAL_TOKEN",
    ] {
        let configured = env::var(name).is_ok_and(|value| !value.is_empty());
        checks.push(json!({"component":name,"ok":configured,"reason":if configured{"configured"}else{"missing_setting"}}));
    }
    let tls_required = engine != "mongodb"
        || env::var_os("FG_TLS_CERT").is_some()
        || env::var_os("FG_TLS_KEY").is_some();
    if tls_required {
        for name in ["FG_BACKEND_CA", "FG_TLS_CERT", "FG_TLS_KEY"] {
            let available = env::var_os(name).is_some_and(|value| Path::new(&value).is_file());
            checks.push(json!({"component":name,"ok":available,"reason":if available{"file_available"}else{"missing_file"}}));
        }
    }
    let metadata_check = match env::var("FG_META_DSN") {
        Ok(dsn) => match metadata("FG_META_DSN", &dsn).await {
            Ok(metadata) => match metadata.deployment_status(engine).await {
                Ok(status) => {
                    let active = status["generations"]
                        .as_array()
                        .is_some_and(|items| items.iter().any(|item| item["status"] == "active"));
                    json!({"component":"metadata","ok":active,"status":status,
                        "reason":if active{"active_snapshot_available"}else{"no_active_snapshot"},
                        "hint":if active{"ready"}else{"import a snapshot before serving branches"}})
                }
                Err(_) => {
                    json!({"component":"metadata","ok":false,"reason":"schema_or_runtime_grants_unavailable","hint":"run migrate with the migration account and install runtime grants"})
                }
            },
            Err(_) => {
                json!({"component":"metadata","ok":false,"reason":"connection_unavailable","hint":"check metadata endpoint, role and CA"})
            }
        },
        Err(_) => json!({"component":"metadata","ok":false,"reason":"missing_setting"}),
    };
    checks.push(metadata_check);
    let paused = proxy_audit_health().await;
    checks.push(json!({"component":"proxy_audit_delivery","ok":paused==Some(false),
        "protected_writes_paused":paused,"reason":match paused { Some(false)=>"audit_delivery_current", Some(true)=>"protected_writes_paused",None=>"audit_delivery_state_unavailable" }}));
    checks.push(backend().await);
    let tools: &[&str] = match engine {
        "postgresql" => &["pg_dump", "pg_restore"],
        "mysql" => &["mysqlsh"],
        "tidb" => &["fg-dumpling-run", "tidb-lightning"],
        _ => &["mongodump", "mongorestore"],
    };
    let native_tools = tools.iter().map(|name| tool(name)).collect::<Vec<_>>();
    let supervisor = tool("setpriv");
    checks.push(
        json!({"component":"native_tool_supervisor","ok":supervisor["available"],
        "reason":if supervisor["available"]==true {"setpriv_available"} else {"setpriv_missing"},
        "details":supervisor}),
    );
    let runtime_ok = checks.iter().all(|check| check["ok"] == true);
    println!(
        "{}",
        json!({"engine":engine,"runtime_ok":runtime_ok,"checks":checks,"snapshot_tools":native_tools,
        "storage_assurance":crate::capacity::assurance(),
        "known_limitations":known_limitations(engine),
        "control_topology":"loopback; use an authenticated SSH tunnel for remote owner commands",
        "tool_check_scope":"availability; actual versions are recorded by each snapshot capture"})
    );
    if runtime_ok {
        Ok(())
    } else {
        Err(ControlError::Config(
            "doctor found failed checks; see the structured report",
        ))
    }
}

async fn backend() -> Value {
    let check = async {
        let dsn = required("FG_BACKEND_GC_DSN")?;
        let ca = env::var("FG_BACKEND_CA").unwrap_or_default();
        let managed = fg_protocol_common::ManagedBackend::load()
            .await
            .map_err(ControlError::Config)?;
        let options = NativeOptions::new(&dsn, Path::new(&ca), managed.as_ref())?;
        let expected = env::var("FG_BACKEND_GC_USER").unwrap_or_else(|_| "fg_gc".into());
        if options.username() != expected {
            return Err(ControlError::Config("native_gc_role_mismatch"));
        }
        let mut native = options.connect().await?;
        if let Native::Mongo(client) = &mut native {
            client
                .database("admin")
                .run_command(bson::doc! {"ping":1})
                .await?;
            Ok(())
        } else {
            native.execute("SELECT 1").await
        }
    }
    .await;
    match check {
        Ok(()) => json!({"component":"native_gc_connection","ok":true}),
        Err(ControlError::UnsupportedTidb(error)) => {
            json!({"component":"native_gc_connection","ok":false,
            "reason":"unsupported_backend_engine","hint":error.to_string()})
        }
        Err(_) => json!({"component":"native_gc_connection","ok":false,
            "reason":"native_endpoint_role_or_tls_unavailable","hint":"check FG_BACKEND_GC_DSN, FG_BACKEND_GC_USER and FG_BACKEND_CA"}),
    }
}

fn engine() -> Result<&'static str, ControlError> {
    let dsn = env::var("FG_BACKEND_DSN")
        .or_else(|_| env::var("FG_BACKEND_GC_DSN"))
        .map_err(|_| ControlError::Config("FG_BACKEND_DSN"))?;
    match dsn.split(':').next() {
        Some("mysql") => Ok("mysql"),
        Some("postgres" | "postgresql") => Ok("postgresql"),
        Some("tidb") => {
            fg_protocol_common::admit_tidb_backend()?;
            Ok("tidb")
        }
        Some("mongodb") => Ok("mongodb"),
        _ => Err(ControlError::Config("native DSN scheme")),
    }
}

fn tool(name: &str) -> Value {
    match Command::new(name)
        .arg(if name == "tidb-lightning" {
            "-V"
        } else {
            "--version"
        })
        .output()
    {
        Ok(output) if output.status.success() => json!({"tool":name,"available":true,
            "version":String::from_utf8_lossy(&output.stdout).lines().next().unwrap_or_default().chars().take(160).collect::<String>()}),
        _ => {
            json!({"tool":name,"available":false,"hint":"install the documented pinned native snapshot tool"})
        }
    }
}

pub(crate) fn known_limitations(engine: &str) -> Value {
    if engine == "tidb" {
        json!([{"reason":"tidb_native_foreign_key_concurrency","verification":"failed",
            "observed_version":"v8.5.8","scope":"concurrent parent deletion and child insertion",
            "observation":"native and proxied transactions can both commit an orphan child; reproduced with TiKV and unistore",
            "action":"use the validated MySQL or PostgreSQL path when concurrent foreign-key integrity is required; the TiDB compatibility gate remains blocked"}])
    } else {
        json!([])
    }
}
