use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use fg_protocol_common::{
    Config, FrontendAccount, ManagedBackend, Router, admit_tidb_backend, loopback_http,
    valid_managed_role,
};
use percent_encoding::percent_decode_str;
use reqwest::Url;
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    crypto::ring::default_provider,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
};
use sqlx::{
    ConnectOptions,
    mysql::{MySqlConnectOptions, MySqlSslMode},
    postgres::{PgConnectOptions, PgSslMode},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::Error;

const BACKEND_DSN: &str = "FG_BACKEND_DSN";
const BACKEND_CA: &str = "FG_BACKEND_CA";
const BACKEND_SERVICE_USER: &str = "FG_BACKEND_SERVICE_USER";
const BACKEND_GC_USER: &str = "FG_BACKEND_GC_USER";
const BRANCH_ADMIN_USER: &str = "FG_BRANCH_ADMIN_USER";
const FRONTEND_ACCOUNTS: &str = "FG_FRONTEND_ACCOUNTS";

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Engine {
    MySql,
    Postgres,
    TiDB,
    MongoDb,
}

impl Engine {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::MySql => "mysql",
            Self::Postgres => "postgresql",
            Self::TiDB => "tidb",
            Self::MongoDb => "mongodb",
        }
    }

    /// Default backend port implied by the DSN scheme (TiDB listens on 4000).
    fn backend_port(self) -> u16 {
        match self {
            Self::MySql => 3306,
            Self::Postgres => 5432,
            Self::TiDB => 4000,
            Self::MongoDb => 27017,
        }
    }

    /// Default frontend listener port; TiDB serves the MySQL wire protocol.
    fn frontend_port(self) -> u16 {
        match self {
            Self::MySql | Self::TiDB => 3306,
            Self::Postgres => 5432,
            Self::MongoDb => 28017,
        }
    }

    fn listen_key(self) -> &'static str {
        match self {
            Self::MySql | Self::TiDB => "FG_LISTEN_MYSQL",
            Self::Postgres => "FG_LISTEN_PG",
            Self::MongoDb => "FG_LISTEN_MONGO",
        }
    }
}

pub enum NativeOptions {
    MySql(MySqlConnectOptions),
    Postgres(PgConnectOptions),
    /// MongoDB observation runs over the official driver;
    /// the data path keeps the hand-rolled OP_MSG frontend.
    Mongo(MongoObserver),
}

/// Connection facts shared by MongoDB observation and row differences.
/// Private endpoints require a verified CA.
#[derive(Clone)]
pub struct MongoObserver {
    pub addr: SocketAddr,
    pub host: String,
    pub user: String,
    pub password: String,
    pub auth_db: String,
    pub tls_ca: Option<std::path::PathBuf>,
}

pub struct Settings {
    pub engine: Engine,
    pub frontend: SocketAddr,
    pub drain: SocketAddr,
    /// None only for MongoDB's loopback plaintext development mode.
    pub config: Option<Config>,
    pub mongo: Option<MongoObserver>,
    pub observer: NativeOptions,
    pub accounts: Vec<FrontendAccount>,
    pub router: Router,
    pub token: String,
}

impl Settings {
    pub async fn load() -> Result<Self, Error> {
        let dsn = required(BACKEND_DSN)?;
        let managed = ManagedBackend::load().await.map_err(Error::Config)?;
        let endpoint = Backend::parse(&dsn, managed.as_ref())?;
        if managed.is_some() {
            check_managed_role(&endpoint.user)?;
        }
        let token = required("FG_INTERNAL_TOKEN")?;
        let control = origin("FG_CONTROL_URL", "http://127.0.0.1:8081")?;
        let engine = endpoint.engine;
        // All private endpoints use verified TLS on both hops.
        let ca =
            (engine != Engine::MongoDb || managed.is_some() || optional(BACKEND_CA)?.is_some())
                .then(|| required(BACKEND_CA))
                .transpose()?;
        let observer = endpoint.observer(ca.as_deref());
        let mongo =
            matches!(engine, Engine::MongoDb).then(|| endpoint.mongo_observer(ca.as_deref()));
        let config = ca
            .map(|ca: String| endpoint.clone().transport(&ca))
            .transpose()?;
        Ok(Self {
            engine,
            frontend: address(
                engine.listen_key(),
                engine.frontend_port(),
                managed.is_some(),
            )?,
            drain: address("FG_PROXY_CONTROL_LISTEN", 8082, false)?,
            config,
            mongo,
            observer,
            accounts: accounts()?,
            router: Router::new(control, token.clone(), engine.name())?,
            token,
        })
    }
}

#[derive(Clone)]
struct Backend {
    engine: Engine,
    addr: SocketAddr,
    host: String,
    user: String,
    password: String,
    database: String,
}

impl Backend {
    fn parse(dsn: &str, managed: Option<&ManagedBackend>) -> Result<Self, Error> {
        let invalid = || Error::Config(BACKEND_DSN);
        let url = Url::parse(dsn).map_err(|_| invalid())?;
        let engine = match url.scheme() {
            "mysql" => Engine::MySql,
            "postgres" | "postgresql" => Engine::Postgres,
            "tidb" => {
                admit_tidb_backend()?;
                Engine::TiDB
            }
            "mongodb" => Engine::MongoDb,
            _ => return Err(invalid()),
        };
        if url.query().is_some() || url.fragment().is_some() {
            return Err(invalid());
        }
        let port = url.port().unwrap_or_else(|| engine.backend_port());
        let (addr, host) = match managed {
            Some(managed) if managed.matches_url(&url) => {
                (managed.address(port), managed.hostname())
            }
            Some(_) => return Err(invalid()),
            None => loopback_backend(&url, port).ok_or_else(invalid)?,
        };
        let database = url
            .path()
            .strip_prefix('/')
            .filter(|path| !path.contains('/'))
            .ok_or_else(invalid)?;
        Ok(Self {
            engine,
            addr,
            host: host.to_owned(),
            user: decode(url.username())?,
            password: decode(url.password().ok_or_else(invalid)?)?,
            database: decode(database)?,
        })
    }

    fn transport(self, ca: &str) -> Result<Config, Error> {
        Ok(Config {
            backend: self.addr,
            backend_name: ServerName::try_from(self.host)
                .map_err(|_| Error::Config(BACKEND_DSN))?,
            frontend_tls: acceptor()?,
            backend_tls: connector(ca)?,
            frontend_user: String::new(),
            frontend_password: String::new(),
            backend_user: self.user,
            backend_password: self.password,
            backend_database: self.database,
        })
    }

    fn observer(&self, ca: Option<&str>) -> NativeOptions {
        match self.engine {
            // TiDB speaks the MySQL wire protocol; observation SQL is shared.
            Engine::MySql | Engine::TiDB => NativeOptions::MySql(
                MySqlConnectOptions::new()
                    .host(&self.host)
                    .port(self.addr.port())
                    .username(&self.user)
                    .password(&self.password)
                    .database(&self.database)
                    .ssl_mode(MySqlSslMode::VerifyIdentity)
                    .ssl_ca(ca.unwrap_or_default())
                    .disable_statement_logging(),
            ),
            Engine::Postgres => NativeOptions::Postgres(
                PgConnectOptions::new_without_pgpass()
                    .host(&self.host)
                    .port(self.addr.port())
                    .username(&self.user)
                    .password(&self.password)
                    .database(&self.database)
                    .ssl_mode(PgSslMode::VerifyFull)
                    .ssl_root_cert(ca.unwrap_or_default())
                    .disable_statement_logging(),
            ),
            Engine::MongoDb => NativeOptions::Mongo(self.mongo_observer(ca)),
        }
    }

    fn mongo_observer(&self, ca: Option<&str>) -> MongoObserver {
        MongoObserver {
            addr: self.addr,
            host: self.host.clone(),
            user: self.user.clone(),
            password: self.password.clone(),
            auth_db: self.database.clone(),
            tls_ca: ca.map(std::path::PathBuf::from),
        }
    }
}

fn loopback_backend(url: &Url, port: u16) -> Option<(SocketAddr, &str)> {
    let host = url.host_str()?.trim_matches(['[', ']']);
    let ip = if host == "localhost" {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        host.parse::<IpAddr>().ok().filter(IpAddr::is_loopback)?
    };
    Some(((ip, port).into(), host))
}

fn check_managed_role(backend_user: &str) -> Result<(), Error> {
    let service = required(BACKEND_SERVICE_USER)?;
    let collector = optional(BACKEND_GC_USER)?.unwrap_or_else(|| "fg_gc".to_owned());
    let branch_admin = optional(BRANCH_ADMIN_USER)?;
    if !matches_service_role(backend_user, &service, &collector, branch_admin.as_deref()) {
        return Err(Error::Config(BACKEND_SERVICE_USER));
    }
    Ok(())
}

fn matches_service_role(
    backend_user: &str,
    service: &str,
    collector: &str,
    admin: Option<&str>,
) -> bool {
    backend_user == service
        && service != collector
        && Some(service) != admin
        && valid_managed_role(service)
        && valid_managed_role(collector)
        && admin.is_none_or(valid_managed_role)
}

fn decode(value: &str) -> Result<String, Error> {
    let decoded = percent_decode_str(value)
        .decode_utf8()
        .map_err(|_| Error::Config(BACKEND_DSN))?;
    if decoded.is_empty() || decoded.contains('\0') {
        return Err(Error::Config(BACKEND_DSN));
    }
    Ok(decoded.into_owned())
}

fn accounts() -> Result<Vec<FrontendAccount>, Error> {
    let invalid = Error::Config(FRONTEND_ACCOUNTS);
    let accounts: Vec<FrontendAccount> = serde_json::from_str(&required(FRONTEND_ACCOUNTS)?)
        .map_err(|_| Error::Config(FRONTEND_ACCOUNTS))?;
    let mut users = std::collections::HashSet::new();
    if accounts.is_empty()
        || accounts.len() > 32
        || accounts.iter().any(|account| {
            account.user.is_empty()
                || account.user.len() > 63
                || !account
                    .user
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                || account.password.is_empty()
                || account.password.len() > 128
                || !account.password.bytes().all(|byte| byte.is_ascii_graphic())
                || account.expires_at <= 0
                || !users.insert(&account.user)
        })
    {
        return Err(invalid);
    }
    Ok(accounts)
}

fn acceptor() -> Result<TlsAcceptor, Error> {
    let certs = certificates(&required("FG_TLS_CERT")?, "FG_TLS_CERT")?;
    let key = PrivateKeyDer::from_pem_file(required("FG_TLS_KEY")?)
        .map_err(|_| Error::Config("FG_TLS_KEY"))?;
    let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|_| Error::Config("FG_TLS_CERT"))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| Error::Config("FG_TLS_KEY"))?;
    // The PostgreSQL frontend advertises SCRAM without channel binding.
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn connector(ca: &str) -> Result<TlsConnector, Error> {
    let mut roots = RootCertStore::empty();
    for cert in certificates(ca, BACKEND_CA)? {
        roots.add(cert).map_err(|_| Error::Config(BACKEND_CA))?;
    }
    let mut config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|_| Error::Config(BACKEND_CA))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    Ok(TlsConnector::from(Arc::new(config)))
}

fn certificates(path: &str, setting: &'static str) -> Result<Vec<CertificateDer<'static>>, Error> {
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(|_| Error::Config(setting))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Error::Config(setting))?;
    if certs.is_empty() {
        return Err(Error::Config(setting));
    }
    Ok(certs)
}

fn required(setting: &'static str) -> Result<String, Error> {
    env::var(setting)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or(Error::Config(setting))
}

fn optional(setting: &'static str) -> Result<Option<String>, Error> {
    match env::var(setting) {
        Ok(value) if !value.is_empty() => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        _ => Err(Error::Config(setting)),
    }
}

fn address(setting: &'static str, port: u16, allow_private: bool) -> Result<SocketAddr, Error> {
    match env::var(setting) {
        Ok(value) => value
            .parse::<SocketAddr>()
            .ok()
            .filter(|addr| allowed_listener(addr.ip(), allow_private))
            .ok_or(Error::Config(setting)),
        Err(env::VarError::NotPresent) => Ok((Ipv4Addr::LOCALHOST, port).into()),
        Err(_) => Err(Error::Config(setting)),
    }
}

fn allowed_listener(ip: IpAddr, allow_private: bool) -> bool {
    ip.is_loopback() || (allow_private && matches!(ip, IpAddr::V4(ip) if ip.is_private()))
}

fn origin(setting: &'static str, default: &str) -> Result<Url, Error> {
    let value = env::var(setting).unwrap_or_else(|_| default.to_owned());
    loopback_http(&value).ok_or(Error::Config(setting))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admits_tidb_dsn_only_in_experimental_build() {
        let result = Backend::parse("tidb://fg_service:pw@127.0.0.1/app", None);
        if fg_protocol_common::TIDB_BACKEND_AVAILABLE {
            assert!(matches!(result, Ok(backend) if backend.engine == Engine::TiDB));
        } else {
            assert!(matches!(result, Err(Error::UnsupportedTidb(_))));
        }
    }

    #[test]
    fn accepts_explicit_private_listener_only_in_managed_mode() {
        let private = IpAddr::from([10, 1, 2, 3]);
        assert!(!allowed_listener(private, false));
        assert!(allowed_listener(private, true));
        assert!(allowed_listener(IpAddr::V4(Ipv4Addr::LOCALHOST), false));
        for ip in [
            [0, 0, 0, 0],
            [8, 8, 8, 8],
            [169, 254, 1, 1],
            [100, 64, 0, 1],
        ] {
            assert!(!allowed_listener(IpAddr::from(ip), true));
        }
    }

    #[test]
    fn mongodb_dsn_resolves_loopback_endpoints_and_ports() -> Result<(), &'static str> {
        let backend = Backend::parse("mongodb://fg_service:pw@127.0.0.1:27017/admin", None)
            .map_err(|_| "parse")?;
        assert_eq!(backend.engine, Engine::MongoDb);
        assert_eq!(backend.engine.name(), "mongodb");
        assert_eq!(backend.engine.backend_port(), 27017);
        assert_eq!(backend.engine.frontend_port(), 28017);
        assert_eq!(backend.engine.listen_key(), "FG_LISTEN_MONGO");
        assert_eq!(backend.addr.port(), 27017);
        assert_eq!(backend.database, "admin");
        // Query strings stay rejected for every engine; the auth database is
        // the DSN path, so no authSource parameter is accepted.
        assert!(Backend::parse("mongodb://u:p@127.0.0.1:27017/admin?tls=false", None).is_err());
        assert!(Backend::parse("mongodb://u:p@10.0.0.1:27017/admin", None).is_err());
        Ok(())
    }

    #[test]
    fn managed_proxy_requires_its_dedicated_service_role() {
        assert!(matches_service_role(
            "proxy_role",
            "proxy_role",
            "gc_role",
            Some("ddl_role")
        ));
        assert!(!matches_service_role(
            "gc_role",
            "proxy_role",
            "gc_role",
            None
        ));
        assert!(!matches_service_role(
            "proxy_role",
            "proxy_role",
            "proxy_role",
            None
        ));
        assert!(!matches_service_role(
            "proxy_role",
            "proxy_role",
            "gc_role",
            Some("proxy_role")
        ));
        assert!(!matches_service_role(
            "postgres", "postgres", "gc_role", None
        ));
    }
}
