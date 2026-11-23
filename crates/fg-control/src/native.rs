//! Native administration and branch cleanup use separate authenticated roles.

mod ddl;
pub(crate) use ddl::{DdlError, mysql_table_checks};

use std::{net::IpAddr, path::Path, str::FromStr};

use fg_protocol_common::{
    CatalogEntry, ManagedBackend, TIDB_BACKEND_AVAILABLE, admit_tidb_backend,
    check_mysql_backend_version,
};
use mongodb::{
    Client,
    options::{ClientOptions, Credential, ServerAddress, Tls, TlsOptions},
};
use percent_encoding::percent_decode_str;
use reqwest::Url;
use sqlx::{
    ConnectOptions, Connection, Executor, MySqlConnection, PgConnection,
    mysql::{MySqlConnectOptions, MySqlSslMode},
    postgres::{PgConnectOptions, PgSslMode},
};

use crate::ControlError;

const CLEANUP_BATCH: i64 = 1_000;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Engine {
    MySql,
    Postgres,
    TiDB,
    MongoDb,
}

impl Engine {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::MySql => "mysql",
            Self::Postgres => "postgresql",
            Self::TiDB => "tidb",
            Self::MongoDb => "mongodb",
        }
    }

    pub(crate) fn quote(self, identifier: &str) -> String {
        let quote = match self {
            Self::MySql | Self::TiDB => '`',
            Self::Postgres => '"',
            // MongoDB names are unquoted; relation() never reaches a Mongo
            // connection because every Mongo path is command-based.
            Self::MongoDb => return identifier.to_owned(),
        };
        let escaped = identifier.replace(quote, &format!("{quote}{quote}"));
        format!("{quote}{escaped}{quote}")
    }

    pub(crate) fn relation(self, schema: &str, table: &str) -> String {
        format!("{}.{}", self.quote(schema), self.quote(table))
    }
}

/// Connection facts for one admitted mongod administration endpoint.
#[derive(Clone)]
pub(crate) struct MongoOptions {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) user: String,
    pub(crate) password: String,
    pub(crate) auth_db: String,
    tls_ca: Option<std::path::PathBuf>,
}

impl MongoOptions {
    fn parse(dsn: &str, managed: Option<&ManagedBackend>, ca: &Path) -> Result<Self, ControlError> {
        let invalid = || ControlError::Config("native DSN scheme");
        let url = Url::parse(dsn).map_err(|_| invalid())?;
        if url.query().is_some() || url.fragment().is_some() {
            return Err(invalid());
        }
        let host = url
            .host_str()
            .map(str::to_owned)
            .filter(|host| {
                is_loopback_host(host) || managed.is_some_and(|endpoint| endpoint.matches_url(&url))
            })
            .ok_or_else(invalid)?;
        let database = url
            .path()
            .strip_prefix('/')
            .filter(|path| !path.is_empty() && !path.contains('/'))
            .ok_or_else(invalid)?;
        Ok(Self {
            host,
            port: url.port().unwrap_or(27017),
            user: decode_component(url.username())?,
            password: decode_component(url.password().ok_or_else(invalid)?)?,
            auth_db: decode_component(database)?,
            tls_ca: (managed.is_some() || ca.is_file()).then(|| ca.to_path_buf()),
        })
    }

    fn client_options(&self) -> ClientOptions {
        let credential = Credential::builder()
            .username(self.user.clone())
            .password(self.password.clone())
            .source(self.auth_db.clone())
            .build();
        ClientOptions::builder()
            .hosts(vec![ServerAddress::Tcp {
                host: self.host.clone(),
                port: Some(self.port),
            }])
            .credential(credential)
            .tls(
                self.tls_ca
                    .as_ref()
                    .map(|ca| Tls::Enabled(TlsOptions::builder().ca_file_path(ca.clone()).build())),
            )
            .build()
    }
}

fn decode_component(value: &str) -> Result<String, ControlError> {
    percent_decode_str(value)
        .decode_utf8()
        .map(|decoded| decoded.into_owned())
        .map_err(|_| ControlError::Config("native DSN scheme"))
}

pub(crate) enum NativeOptions {
    MySql(MySqlConnectOptions),
    Postgres(PgConnectOptions),
    /// TiDB speaks the MySQL wire protocol; only engine-gated behavior
    /// (version gates, grant hygiene, clone DDL) distinguishes it.
    TiDB(MySqlConnectOptions),
    /// MongoDB control-plane administration runs over the official driver
    /// for one admitted endpoint, with verified TLS when configured.
    Mongo(MongoOptions),
}

impl NativeOptions {
    pub(crate) fn new(
        dsn: &str,
        ca: &Path,
        managed: Option<&ManagedBackend>,
    ) -> Result<Self, ControlError> {
        let managed_endpoint = managed
            .map(|endpoint| checked_managed_endpoint(dsn, endpoint))
            .transpose()?;
        if dsn.starts_with("mongodb://") {
            // Only one verified private endpoint is admitted; URI overrides
            // and topology discovery remain outside the supported subset.
            return Ok(Self::Mongo(MongoOptions::parse(dsn, managed, ca)?));
        }
        if dsn.starts_with("mysql://") {
            let mut options = MySqlConnectOptions::from_str(dsn)?
                .ssl_mode(MySqlSslMode::VerifyIdentity)
                .ssl_ca(ca)
                .disable_statement_logging();
            if let Some((host, port)) = managed_endpoint {
                options = options.host(host).port(port.unwrap_or(3306));
            }
            return Ok(Self::MySql(options));
        }
        if dsn.starts_with("tidb://") {
            admit_tidb_backend()?;
            // sqlx only parses the mysql:// scheme; the engine identity stays
            // TiDB so its version and privilege checks still apply.
            let wire_dsn = dsn.replacen("tidb://", "mysql://", 1);
            let mut options = MySqlConnectOptions::from_str(wire_dsn.as_str())?
                .ssl_mode(MySqlSslMode::VerifyIdentity)
                .ssl_ca(ca)
                .disable_statement_logging();
            if let Some((host, port)) = managed_endpoint {
                options = options.host(host).port(port.unwrap_or(4000));
            }
            return Ok(Self::TiDB(options));
        }
        if dsn.starts_with("postgres://") || dsn.starts_with("postgresql://") {
            let mut options = PgConnectOptions::from_str(dsn)?
                .ssl_mode(PgSslMode::VerifyFull)
                .ssl_root_cert(ca)
                .disable_statement_logging();
            if let Some((host, port)) = managed_endpoint {
                options = options.host(host).port(port.unwrap_or(5432));
            }
            return Ok(Self::Postgres(options));
        }
        Err(ControlError::Config("native DSN scheme"))
    }

    pub(crate) const fn engine(&self) -> Engine {
        match self {
            Self::MySql(_) => Engine::MySql,
            Self::Postgres(_) => Engine::Postgres,
            Self::TiDB(_) => Engine::TiDB,
            Self::Mongo(_) => Engine::MongoDb,
        }
    }

    pub(crate) fn username(&self) -> &str {
        match self {
            Self::MySql(options) | Self::TiDB(options) => options.get_username(),
            Self::Postgres(options) => options.get_username(),
            Self::Mongo(options) => &options.user,
        }
    }

    pub(crate) fn same_backend(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::MySql(first) | Self::TiDB(first), Self::MySql(second) | Self::TiDB(second)) => {
                first.get_host() == second.get_host()
                    && first.get_port() == second.get_port()
                    && first.get_socket() == second.get_socket()
            }
            (Self::Postgres(first), Self::Postgres(second)) => {
                first.get_host() == second.get_host()
                    && first.get_port() == second.get_port()
                    && first.get_socket() == second.get_socket()
                    && first.get_database().is_some()
                    && first.get_database() == second.get_database()
            }
            (Self::Mongo(first), Self::Mongo(second)) => {
                first.host == second.host && first.port == second.port
            }
            _ => false,
        }
    }

    pub(crate) fn is_loopback(&self) -> bool {
        match self {
            Self::MySql(options) | Self::TiDB(options) => {
                options.get_socket().is_some() || is_loopback_host(options.get_host())
            }
            Self::Postgres(options) => {
                options.get_socket().is_some() || is_loopback_host(options.get_host())
            }
            // Use the validated endpoint rather than inferring engine locality.
            Self::Mongo(options) => is_loopback_host(&options.host),
        }
    }

    pub(crate) async fn connect(&self) -> Result<Native, ControlError> {
        if let Self::Mongo(options) = self {
            return Client::with_options(options.client_options())
                .map(Native::Mongo)
                .map_err(|error| {
                    tracing::error!(component = "native", engine = self.engine().name(),
                        role = self.username(), failure = %error,
                        "native connection failed; check the role and auth database in the backend DSN setting");
                    ControlError::Mongo(error)
                });
        }
        let result = match self {
            Self::MySql(options) => MySqlConnection::connect_with(options)
                .await
                .map(Native::MySql),
            Self::TiDB(options) => MySqlConnection::connect_with(options)
                .await
                .map(Native::TiDB),
            Self::Postgres(options) => PgConnection::connect_with(options)
                .await
                .map(Native::Postgres),
            Self::Mongo(_) => unreachable!("handled above"),
        };
        let mut native = result.map_err(|error| {
            tracing::error!(component = "native", engine = self.engine().name(),
                role = self.username(), failure = %crate::native_failure(&error),
                "native connection failed; check the role, database and CA in the backend DSN setting");
            ControlError::Native(error)
        })?;
        if !TIDB_BACKEND_AVAILABLE && let Native::MySql(connection) = &mut native {
            let version: String = sqlx::query_scalar("SELECT VERSION()")
                .fetch_one(connection)
                .await?;
            check_mysql_backend_version(version.as_bytes())?;
        }
        Ok(native)
    }
}

fn is_loopback_host(host: &str) -> bool {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn checked_managed_endpoint<'a>(
    dsn: &str,
    endpoint: &'a ManagedBackend,
) -> Result<(&'a str, Option<u16>), ControlError> {
    let invalid = || {
        ControlError::Config(
            "Managed native DSN must use FG_MANAGED_BACKEND_HOST and explicit credentials and database settings",
        )
    };
    let url = Url::parse(dsn).map_err(|_| invalid())?;
    let postgres_database_missing = matches!(url.scheme(), "postgres" | "postgresql")
        && !url
            .path()
            .strip_prefix('/')
            .is_some_and(|name| !name.is_empty() && !name.contains('/'));
    if !endpoint.matches_url(&url)
        || url.username().is_empty()
        || url.password().is_none_or(str::is_empty)
        || postgres_database_missing
    {
        return Err(invalid());
    }
    Ok((endpoint.hostname(), url.port()))
}

pub(crate) enum Native {
    MySql(MySqlConnection),
    Postgres(PgConnection),
    TiDB(MySqlConnection),
    Mongo(Client),
}

pub(crate) async fn require_service_quiescence(
    options: &NativeOptions,
) -> Result<(), ControlError> {
    let mut native = options.connect().await?;
    let identity: String = match &mut native {
        Native::MySql(connection) | Native::TiDB(connection) => {
            sqlx::query_scalar(
                "SELECT CONVERT(CURRENT_USER() USING utf8mb4) COLLATE utf8mb4_unicode_ci",
            )
            .fetch_one(connection)
            .await?
        }
        Native::Postgres(connection) => {
            sqlx::query_scalar("SELECT current_user::text")
                .fetch_one(connection)
                .await?
        }
        Native::Mongo(_) => {
            return Err(ControlError::Config(
                "SQL witness preparation requires a SQL backend",
            ));
        }
    };
    let expected = match native.engine() {
        Engine::MySql | Engine::TiDB => format!("{}@%", options.username()),
        _ => options.username().to_owned(),
    };
    if identity != expected {
        return Err(ControlError::Config(
            "service observation authenticated as an unexpected native account",
        ));
    }
    let active: i64 = match &mut native {
        Native::MySql(connection) | Native::TiDB(connection) => sqlx::query_scalar(
            "SELECT CAST(COUNT(*) AS SIGNED) FROM information_schema.PROCESSLIST WHERE USER=SUBSTRING_INDEX(CURRENT_USER(),'@',1) AND ID<>CONNECTION_ID()",
        ).fetch_one(connection).await?,
        Native::Postgres(connection) => sqlx::query_scalar(
            "SELECT COUNT(*) FROM pg_catalog.pg_stat_activity WHERE usename=current_user AND pid<>pg_backend_pid()",
        ).fetch_one(connection).await?,
        Native::Mongo(_) => return Err(ControlError::Config("SQL witness preparation requires a SQL backend")),
    };
    if active != 0 {
        return Err(crate::writable::WitnessError::Quiescence.into());
    }
    Ok(())
}

impl Native {
    pub(crate) const fn engine(&self) -> Engine {
        match self {
            Self::MySql(_) => Engine::MySql,
            Self::Postgres(_) => Engine::Postgres,
            Self::TiDB(_) => Engine::TiDB,
            Self::Mongo(_) => Engine::MongoDb,
        }
    }

    pub(crate) async fn execute(&mut self, sql: &str) -> Result<(), ControlError> {
        match self {
            Self::MySql(connection) | Self::TiDB(connection) => {
                connection.execute(sql).await?;
            }
            Self::Postgres(connection) => {
                connection.execute(sql).await?;
            }
            // Every Mongo administration path is command-based (crate::
            // mongo); a SQL statement reaching a Mongo connection is a
            // dispatch bug, not a diagnosable backend failure.
            Self::Mongo(_) => {
                return Err(ControlError::Config(
                    "MongoDB administration does not accept SQL statements",
                ));
            }
        }
        Ok(())
    }

    pub(crate) async fn delete_branch(
        &mut self,
        branch: i64,
        tables: &[CatalogEntry],
    ) -> Result<(), ControlError> {
        if let Self::Mongo(client) = self {
            return crate::mongo::delete_branch(client, branch, tables).await;
        }
        let engine = self.engine();
        for table in tables {
            let name = engine.relation(&table.delta_schema, &table.delta_table);
            self.delete_delta(branch, &name).await?;
        }
        Ok(())
    }

    async fn delete_delta(&mut self, branch: i64, table: &str) -> Result<(), ControlError> {
        match self {
            // TiDB accepts the same bounded DELETE ... LIMIT shape as MySQL.
            Self::MySql(connection) | Self::TiDB(connection) => {
                let sql = format!("DELETE FROM {table} WHERE _fg_branch = ? LIMIT ?");
                loop {
                    let deleted = sqlx::query(&sql)
                        .bind(branch)
                        .bind(CLEANUP_BATCH)
                        .execute(&mut *connection)
                        .await?;
                    if deleted.rows_affected() == 0 {
                        break;
                    }
                }
            }
            Self::Postgres(connection) => {
                let sql = format!(
                    "WITH batch AS (SELECT ctid FROM {table} WHERE _fg_branch = $1 LIMIT $2) DELETE FROM {table} AS delta USING batch WHERE delta.ctid = batch.ctid"
                );
                loop {
                    let deleted = sqlx::query(&sql)
                        .bind(branch)
                        .bind(CLEANUP_BATCH)
                        .execute(&mut *connection)
                        .await?;
                    if deleted.rows_affected() == 0 {
                        break;
                    }
                }
            }
            // The branch purge lands in the Mongo administration module;
            // delete_branch dispatches there before this SQL arm is reached.
            Self::Mongo(_) => {
                return Err(ControlError::Config(
                    "MongoDB administration does not accept SQL statements",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{NativeOptions, is_loopback_host};

    #[test]
    fn admits_tidb_dsn_only_in_experimental_build() {
        let result = NativeOptions::new(
            "tidb://role:unused@127.0.0.1/app",
            Path::new("/unused-ca"),
            None,
        );
        if fg_protocol_common::TIDB_BACKEND_AVAILABLE {
            assert!(matches!(result, Ok(NativeOptions::TiDB(_))));
        } else {
            assert!(matches!(
                result,
                Err(crate::ControlError::UnsupportedTidb(_))
            ));
        }
    }

    #[test]
    fn shortened_refresh_cooldown_is_confined_to_local_endpoints() {
        for host in [
            "localhost",
            "LOCALHOST",
            "127.0.0.1",
            "127.10.20.30",
            "::1",
            "[::1]",
        ] {
            assert!(is_loopback_host(host));
        }
        for host in [
            "db.example.com",
            "localhost.example.com",
            "10.0.0.1",
            "0.0.0.0",
            "::",
        ] {
            assert!(!is_loopback_host(host));
        }
    }

    #[test]
    fn ipv6_loopback_dsn_supports_local_refresh_override() -> Result<(), crate::ControlError> {
        for dsn in [
            "mysql://role:unused@[::1]/app",
            "postgres://role:unused@[::1]/app",
        ] {
            let options = NativeOptions::new(dsn, Path::new("/unused-ca"), None)?;
            assert!(options.is_loopback());
        }
        Ok(())
    }
}
