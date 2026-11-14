//! Isolated executable used by the native driver compatibility matrix.

use std::{
    env,
    net::{Ipv4Addr, SocketAddr},
    process::ExitCode,
    sync::Arc,
};

use fg_proto_mongo::{Account, SpikeConfig};
use fg_protocol_common::Config;
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    crypto::ring::default_provider,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
    version::{TLS12, TLS13},
};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const FRONTEND_USER: &str = "p1_user";
const BACKEND_USER: &str = "p1_service";
const BACKEND_DATABASE: &str = "p1_native";
const BACKEND_NAME: &str = "localhost";
const CERT_SETTING: &str = "FG_P1_TLS_CERT";
const KEY_SETTING: &str = "FG_P1_TLS_KEY";
const CA_SETTING: &str = "FG_P1_BACKEND_CA";

#[derive(Clone, Copy, PartialEq)]
enum Engine {
    MySql,
    Postgres,
    TiDB,
    MongoDb,
}

impl Engine {
    fn argument() -> Result<Self, FixtureError> {
        let mut args = env::args_os().skip(1);
        let engine = match args.next().as_deref().and_then(std::ffi::OsStr::to_str) {
            Some("mysql") => Self::MySql,
            Some("postgresql") => Self::Postgres,
            Some("tidb") => Self::TiDB,
            Some("mongodb") => Self::MongoDb,
            _ => return Err(FixtureError::Usage),
        };
        if args.next().is_some() {
            return Err(FixtureError::Usage);
        }
        Ok(engine)
    }

    const fn name(self) -> &'static str {
        match self {
            Self::MySql => "mysql",
            Self::Postgres => "postgresql",
            Self::TiDB => "tidb",
            Self::MongoDb => "mongodb",
        }
    }

    const fn ports(self) -> (u16, u16) {
        match self {
            Self::MySql => (13_306, 3306),
            Self::Postgres => (15_432, 5432),
            // TiDB listens on 4000.
            Self::TiDB => (13_306, 4000),
            // The MongoDB fixture uses frontend port 28017.
            Self::MongoDb => (28_017, 27_017),
        }
    }
}

#[derive(Debug, Error)]
enum FixtureError {
    #[error("usage: fg-protocol-fixture mysql|postgresql|tidb")]
    Usage,
    #[error("set {0} to a nonempty value")]
    Missing(&'static str),
    #[error("set {0} to a valid TCP port")]
    Port(&'static str),
    #[error("cannot load TLS configuration from {0}")]
    Tls(&'static str),
    #[error("fixture listener failed: {0}")]
    Listener(#[from] std::io::Error),
}

#[tokio::main]
async fn main() -> ExitCode {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .try_init();
    if let Err(error) = run().await {
        tracing::error!(%error, "fixture stopped");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

async fn run() -> Result<(), FixtureError> {
    let engine = Engine::argument()?;
    let (frontend_port, backend_port) = engine.ports();
    let frontend = loopback(port("FG_P1_LISTEN_PORT", frontend_port, true)?);
    let backend = loopback(port("FG_P1_BACKEND_PORT", backend_port, false)?);
    // MongoDB serves the spike frontend: plaintext wire with SCRAM
    // termination against the mirror account; this fixture has no control
    // plane, so the fixture uses a one-to-one frontend/native account mapping.
    // Its serve() binds its own listener.
    if engine == Engine::MongoDb {
        let password = required("FG_P1_FRONTEND_PASSWORD")?;
        println!("ready mongodb {frontend}");
        return fg_proto_mongo::serve(SpikeConfig {
            listen: frontend,
            backend,
            backend_auth_db: "admin".to_owned(),
            accounts: vec![Account {
                user: FRONTEND_USER.to_owned(),
                password,
            }],
        })
        .await
        .map_err(FixtureError::from);
    }
    let listener = TcpListener::bind(frontend).await?;
    println!("ready {} {}", engine.name(), listener.local_addr()?);
    match engine {
        // TiDB speaks the MySQL wire protocol end to end.
        Engine::MySql | Engine::TiDB => {
            let config = load_config(backend)?;
            fg_proto_mysql::serve(listener, config).await?
        }
        Engine::Postgres => {
            let config = load_config(backend)?;
            fg_proto_pg::serve(listener, config).await?
        }
        Engine::MongoDb => unreachable!("handled above"),
    }
    Ok(())
}

fn load_config(backend: SocketAddr) -> Result<Config, FixtureError> {
    let backend_name =
        ServerName::try_from(BACKEND_NAME).map_err(|_| FixtureError::Tls(CA_SETTING))?;
    Ok(Config {
        backend,
        backend_name,
        frontend_tls: load_acceptor()?,
        backend_tls: load_connector()?,
        frontend_user: FRONTEND_USER.to_owned(),
        frontend_password: required("FG_P1_FRONTEND_PASSWORD")?,
        backend_user: BACKEND_USER.to_owned(),
        backend_password: required("FG_P1_BACKEND_PASSWORD")?,
        backend_database: BACKEND_DATABASE.to_owned(),
    })
}

fn load_acceptor() -> Result<TlsAcceptor, FixtureError> {
    let certs = read_certs(CERT_SETTING)?;
    let key = PrivateKeyDer::from_pem_file(required(KEY_SETTING)?)
        .map_err(|_| FixtureError::Tls(KEY_SETTING))?;
    let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&TLS13, &TLS12])
        .map_err(|_| FixtureError::Tls(CERT_SETTING))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| FixtureError::Tls(KEY_SETTING))?;
    // SCRAM without channel binding should use a fresh TLS connection
    // (RFC 7677, Section 4).
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn load_connector() -> Result<TlsConnector, FixtureError> {
    let mut roots = RootCertStore::empty();
    for cert in read_certs(CA_SETTING)? {
        roots.add(cert).map_err(|_| FixtureError::Tls(CA_SETTING))?;
    }
    let mut config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&TLS13, &TLS12])
        .map_err(|_| FixtureError::Tls(CA_SETTING))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    Ok(TlsConnector::from(Arc::new(config)))
}

fn read_certs(setting: &'static str) -> Result<Vec<CertificateDer<'static>>, FixtureError> {
    let certs = CertificateDer::pem_file_iter(required(setting)?)
        .map_err(|_| FixtureError::Tls(setting))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| FixtureError::Tls(setting))?;
    if certs.is_empty() {
        return Err(FixtureError::Tls(setting));
    }
    Ok(certs)
}

fn required(setting: &'static str) -> Result<String, FixtureError> {
    env::var(setting)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or(FixtureError::Missing(setting))
}

fn port(setting: &'static str, default: u16, allow_ephemeral: bool) -> Result<u16, FixtureError> {
    let Some(value) = env::var_os(setting) else {
        return Ok(default);
    };
    let port = value
        .to_str()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| allow_ephemeral || *port != 0)
        .ok_or(FixtureError::Port(setting))?;
    Ok(port)
}

fn loopback(port: u16) -> SocketAddr {
    (Ipv4Addr::LOCALHOST, port).into()
}
