//! PostgreSQL v3 endpoint backed by a pinned native session.
//!
//! Wire behavior is based on the public PostgreSQL 16 protocol specification.
//! The endpoint admits fixed protocol fixtures or statements compiled against a branch catalog.

mod admission;
mod backend;
mod scram;
mod session;
mod wire;

use std::{collections::HashMap, io, sync::Arc};

use fg_protocol_common::{
    BRANCH, BranchSession, Config, FrontendAccount, HANDSHAKE_TIMEOUT, MAX_SESSIONS, Router,
    WireError, credential_current,
};
use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    time::timeout,
};
use tokio_rustls::server::TlsStream;

use crate::{
    scram::{MECHANISM, ServerExchange, Verifier},
    session::Cancellations,
    wire::{
        CANCEL_REQUEST, GSS_REQUEST, SSL_REQUEST, VERSION, backend_error, cstring, end,
        protocol_error, public_parameter_status, read_frame, read_startup, take, take_string,
        take_u32, write_error, write_frame,
    },
};

type Frontend = TlsStream<TcpStream>;

/// Serves the PostgreSQL protocol fixture on an already bound loopback listener.
///
/// # Errors
///
/// Returns an error if the listener or backend is not on loopback, the fixture
/// credential cannot be initialized, or the listener fails to accept sockets.
pub async fn serve(listener: TcpListener, mut config: Config) -> io::Result<()> {
    if !listener.local_addr()?.ip().is_loopback() || !config.backend.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "The PostgreSQL protocol fixture requires loopback endpoints",
        ));
    }
    let account = AccountVerifier {
        verifier: Verifier::new(&std::mem::take(&mut config.frontend_password))?,
        expires_at: None,
    };
    let accounts = HashMap::from([(config.frontend_user.clone(), account)]);
    serve_inner(listener, config, accounts, None).await
}

/// Serves the admitted read subset against a catalog obtained from control.
pub async fn serve_branches(
    listener: TcpListener,
    config: Config,
    accounts: Vec<FrontendAccount>,
    router: Router,
) -> io::Result<()> {
    serve_inner(listener, config, account_verifiers(accounts)?, Some(router)).await
}

fn account_verifiers(
    accounts: Vec<FrontendAccount>,
) -> io::Result<HashMap<String, AccountVerifier>> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid PostgreSQL account configuration",
        )
    };
    let mut result = HashMap::new();
    for account in accounts {
        if account.user.is_empty() || account.password.is_empty() || account.user.contains('\0') {
            return Err(invalid());
        }
        let verifier = AccountVerifier {
            verifier: Verifier::new(&account.password)?,
            expires_at: Some(account.expires_at),
        };
        if result.insert(account.user, verifier).is_some() {
            return Err(invalid());
        }
    }
    if result.is_empty() {
        return Err(invalid());
    }
    Ok(result)
}

async fn serve_inner(
    listener: TcpListener,
    config: Config,
    accounts: HashMap<String, AccountVerifier>,
    router: Option<Router>,
) -> io::Result<()> {
    let fake_verifier = Verifier::new("")?;
    let state = Arc::new(State {
        config,
        accounts,
        router,
        fake_verifier,
        cancellations: Cancellations::default(),
        sessions: Arc::new(Semaphore::new(MAX_SESSIONS)),
    });
    let handshakes = Arc::new(Semaphore::new(MAX_SESSIONS));
    loop {
        let (stream, address) = listener.accept().await?;
        stream.set_nodelay(true).ok();
        if state.router.is_none() && !address.ip().is_loopback() {
            continue;
        }
        let Ok(permit) = Arc::clone(&handshakes).try_acquire_owned() else {
            continue;
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(error) = handle(stream, &state, permit).await {
                tracing::debug!(engine = "postgresql", kind = ?error.kind(), "PostgreSQL session closed");
            }
        });
    }
}

struct State {
    config: Config,
    accounts: HashMap<String, AccountVerifier>,
    router: Option<Router>,
    fake_verifier: Verifier,
    cancellations: Cancellations,
    sessions: Arc<Semaphore>,
}

struct AccountVerifier {
    verifier: Verifier,
    expires_at: Option<i64>,
}

impl AccountVerifier {
    fn is_current(&self) -> bool {
        self.expires_at.is_none_or(credential_current)
    }
}

struct Admitted {
    frontend: Frontend,
    backend: backend::Backend,
    principal: String,
    branch: Option<BranchSession>,
    _permit: OwnedSemaphorePermit,
}

async fn handle(
    socket: TcpStream,
    state: &State,
    handshake: OwnedSemaphorePermit,
) -> io::Result<()> {
    let admission = timeout(HANDSHAKE_TIMEOUT, admit(socket, state))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "PostgreSQL handshake timed out"))??;
    drop(handshake);
    let Some(Admitted {
        frontend,
        backend,
        principal,
        branch,
        _permit,
    }) = admission
    else {
        return Ok(());
    };
    run_connected(
        frontend,
        backend,
        &state.cancellations,
        &principal,
        branch.as_ref(),
    )
    .await
}

async fn run_connected(
    mut frontend: Frontend,
    backend: backend::Backend,
    cancellations: &Cancellations,
    principal: &str,
    branch: Option<&BranchSession>,
) -> io::Result<()> {
    let registration = cancellations.insert(backend.key)?;
    timeout(
        HANDSHAKE_TIMEOUT,
        startup_complete(
            &mut frontend,
            backend.parameters,
            registration.frontend_key,
            principal,
        ),
    )
    .await
    .map_err(|_| backend_error())??;
    session::run(frontend, backend.stream, &registration, principal, branch).await
}

async fn admit(socket: TcpStream, state: &State) -> io::Result<Option<Admitted>> {
    let Some((mut frontend, startup)) = negotiate(socket, state).await? else {
        return Ok(None);
    };
    let startup = match Startup::parse(&startup) {
        Ok(startup) => startup,
        Err(_) => {
            write_error(&mut frontend, WireError::Protocol, true).await?;
            return Ok(None);
        }
    };
    let account = state.accounts.get(startup.user);
    if !authenticate(&mut frontend, account, &state.fake_verifier).await? {
        write_error(&mut frontend, WireError::Auth, true).await?;
        return Ok(None);
    }
    if startup.unsupported {
        write_error(&mut frontend, WireError::Unsupported, true).await?;
        return Ok(None);
    }
    let Ok(permit) = Arc::clone(&state.sessions).try_acquire_owned() else {
        write_error(&mut frontend, WireError::Backend, true).await?;
        return Ok(None);
    };
    let pending = match &state.router {
        Some(router) => {
            let Some(expires_at) = account.and_then(|account| account.expires_at) else {
                write_error(&mut frontend, WireError::Auth, true).await?;
                return Ok(None);
            };
            match router.begin(startup.user, startup.branch, expires_at).await {
                Ok(pending) => Some(pending),
                Err(error) => {
                    write_error(&mut frontend, error, true).await?;
                    return Ok(None);
                }
            }
        }
        None if startup.branch == BRANCH => None,
        None => {
            write_error(&mut frontend, WireError::Branch, true).await?;
            return Ok(None);
        }
    };
    let backend = match backend::Backend::connect(&state.config, pending.is_some()).await {
        Ok(backend) => backend,
        Err(_) => {
            write_error(&mut frontend, WireError::Backend, true).await?;
            return Ok(None);
        }
    };
    let branch = match pending {
        Some(pending) => match pending.activate(backend.connection_id()) {
            Ok(branch) => Some(branch),
            Err(error) => {
                drop(backend);
                write_error(&mut frontend, error, true).await?;
                return Ok(None);
            }
        },
        None => None,
    };
    Ok(Some(Admitted {
        frontend,
        backend,
        principal: startup.user.to_owned(),
        branch,
        _permit: permit,
    }))
}

async fn negotiate(
    mut socket: TcpStream,
    state: &State,
) -> io::Result<Option<(Frontend, Vec<u8>)>> {
    let mut startup = read_startup(&mut socket).await?;
    if startup == GSS_REQUEST.to_be_bytes() {
        socket.write_all(b"N").await?;
        startup = read_startup(&mut socket).await?;
    }
    if let Some(key) = cancellation_key(&startup)? {
        state.cancellations.cancel(&state.config, key).await?;
        return Ok(None);
    }
    if startup != SSL_REQUEST.to_be_bytes() {
        write_error(&mut socket, WireError::Auth, true).await?;
        return Ok(None);
    }
    socket.write_all(b"S").await?;
    let mut frontend = state.config.frontend_tls.accept(socket).await?;
    let startup = read_startup(&mut frontend).await?;
    if let Some(key) = cancellation_key(&startup)? {
        state.cancellations.cancel(&state.config, key).await?;
        return Ok(None);
    }
    Ok(Some((frontend, startup)))
}

fn cancellation_key(mut startup: &[u8]) -> io::Result<Option<[u8; 8]>> {
    if take_u32(&mut startup)? != CANCEL_REQUEST {
        return Ok(None);
    }
    let key = take(&mut startup)?;
    end(startup)?;
    Ok(Some(key))
}

struct Startup<'a> {
    user: &'a str,
    branch: &'a str,
    unsupported: bool,
}

impl<'a> Startup<'a> {
    fn parse(mut body: &'a [u8]) -> io::Result<Self> {
        if take_u32(&mut body)? != VERSION {
            return Err(protocol_error());
        }
        let mut user = None;
        let mut branch = None;
        let mut unsupported = false;
        loop {
            let field = take_string(&mut body)?;
            if field.is_empty() {
                end(body)?;
                break;
            }
            let value = take_string(&mut body)?;
            match field {
                "user" if user.is_none() => user = Some(value),
                "database" if branch.is_none() => branch = Some(value),
                "application_name" => (),
                "client_encoding" if value.eq_ignore_ascii_case("UTF8") => (),
                "DateStyle"
                    if value.eq_ignore_ascii_case("ISO")
                        || value.eq_ignore_ascii_case("ISO, MDY") => {}
                "TimeZone" if matches!(value, "UTC" | "Etc/UTC" | "GMT") => (),
                "extra_float_digits" if matches!(value, "2" | "3") => (),
                _ => unsupported = true,
            }
        }
        Ok(Self {
            user: user.unwrap_or(""),
            branch: branch.unwrap_or(""),
            unsupported,
        })
    }
}

async fn authenticate(
    frontend: &mut Frontend,
    account: Option<&AccountVerifier>,
    fake_verifier: &Verifier,
) -> io::Result<bool> {
    let mut mechanisms = Vec::new();
    cstring(&mut mechanisms, MECHANISM);
    mechanisms.push(0);
    auth_frame(frontend, 10, &mechanisms).await?;

    let verifier = account.map_or(fake_verifier, |account| &account.verifier);
    let initial = read_frame(frontend).await?;
    if initial.tag != b'p' {
        return Ok(false);
    }
    let exchange = match ServerExchange::start(verifier, &initial.body) {
        Ok(exchange) => exchange,
        Err(_) => return Ok(false),
    };
    auth_frame(frontend, 11, exchange.challenge()).await?;
    let final_frame = read_frame(frontend).await?;
    if final_frame.tag != b'p' {
        return Ok(false);
    }
    let signature = match exchange.finish(&final_frame.body) {
        Ok(Some(signature)) if account.is_some_and(AccountVerifier::is_current) => signature,
        _ => return Ok(false),
    };
    auth_frame(frontend, 12, signature.as_bytes()).await?;
    Ok(true)
}

async fn auth_frame(
    stream: &mut (impl AsyncWrite + Unpin),
    code: u32,
    details: &[u8],
) -> io::Result<()> {
    let mut body = code.to_be_bytes().to_vec();
    body.extend_from_slice(details);
    write_frame(stream, b'R', &body).await
}

async fn startup_complete(
    frontend: &mut Frontend,
    parameters: Vec<wire::Frame>,
    key: [u8; 8],
    frontend_user: &str,
) -> io::Result<()> {
    auth_frame(frontend, 0, &[]).await?;
    for mut parameter in parameters {
        if public_parameter_status(&mut parameter.body, frontend_user)? {
            write_frame(frontend, parameter.tag, &parameter.body).await?;
        }
    }
    write_frame(frontend, b'K', &key).await?;
    write_frame(frontend, b'Z', b"I").await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn does_not_accept_startup_controls_from_client() -> io::Result<()> {
        let mut packet = VERSION.to_be_bytes().to_vec();
        for field in [
            "user",
            "fixture-user",
            "database",
            BRANCH,
            "options",
            "-c role=root",
        ] {
            cstring(&mut packet, field);
        }
        packet.push(0);
        let parsed = Startup::parse(&packet)?;
        assert_eq!(parsed.user, "fixture-user");
        assert_eq!(parsed.branch, BRANCH);
        assert!(parsed.unsupported);
        Ok(())
    }

    #[test]
    fn cancel_request_has_exact_length() -> io::Result<()> {
        let mut packet = CANCEL_REQUEST.to_be_bytes().to_vec();
        packet.extend_from_slice(&[7; 8]);
        assert_eq!(cancellation_key(&packet)?, Some([7; 8]));
        packet.push(0);
        assert!(cancellation_key(&packet).is_err());
        Ok(())
    }
}
