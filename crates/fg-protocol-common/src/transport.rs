use std::{net::SocketAddr, time::Duration};

use rustls::pki_types::ServerName;
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub const BRANCH: &str = "p1-fixture";
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const IO_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_SESSIONS: usize = 16;

/// One isolated fixture endpoint and its independent backend login.
pub struct Config {
    pub backend: SocketAddr,
    pub backend_name: ServerName<'static>,
    pub frontend_tls: TlsAcceptor,
    pub backend_tls: TlsConnector,
    pub frontend_user: String,
    pub frontend_password: String,
    pub backend_user: String,
    pub backend_password: String,
    pub backend_database: String,
}
