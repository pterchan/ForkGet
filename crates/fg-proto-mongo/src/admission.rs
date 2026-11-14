//! Branch admission session: SCRAM-SHA-256 termination against the
//! configured frontend accounts, branch binding through the control plane,
//! and the admitted-command dispatcher with drain/cancel integration. The
//! backend data path authenticates with the deployment service account, not
//! with any frontend identity.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};

use fg_protocol_common::{Config, FrontendAccount, HANDSHAKE_TIMEOUT, MAX_SESSIONS, Router};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::backend::{Backend, binary_payload, read_message, write_message};
use crate::command;
use crate::scram::{self, Verifier};
use crate::session::{
    Account, auth_error, error_document, hello_document, reply, sasl_reply, scram_user,
    unauthorized_error,
};
use crate::wire::{self, command_name, kind_zero_document};
use crate::{Error, OPCODE_MSG};

/// Loopback backend facts plus the service account for the data path (the
/// deployment-wide account, never per-client mirrors).
pub struct BranchConfig {
    pub backend: SocketAddr,
    /// Verified TLS on both hops; None is restricted to loopback development.
    pub transport: Option<Config>,
    /// Mongo auth database holding the service account (admin).
    pub backend_auth_db: String,
    pub backend_account: Account,
}

/// The per-client phases. SCRAM exchanges hold the started server exchange
/// and the matched frontend account index; the authenticated phase carries
/// the control-plane principal and the account expiry.
enum Auth {
    None,
    Started(scram::ServerExchange, usize),
    Authenticated { principal: String, expires_at: i64 },
}

/// Per-connection state shared behind the accept loop.
struct State {
    config: BranchConfig,
    accounts: Vec<FrontendAccount>,
    router: Router,
}

static NEXT_CONNECTION_ID: AtomicI32 = AtomicI32::new(1);

async fn run(
    state: Arc<State>,
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
) -> Result<(), Error> {
    let connection_id = NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
    let mut auth = Auth::None;
    let mut backend: Option<Backend> = None;
    let mut bound: Option<command::BoundSession> = None;
    loop {
        let request = match bound.as_ref() {
            // A cancelled branch closes the frontend socket instead of
            // answering more commands, exactly like the SQL frontends.
            Some(bound) => {
                tokio::select! {
                    request = read_message(reader) => {
                        match request {
                            Ok(request) => request,
                            Err(Error::Io(error))
                                if error.kind() == io::ErrorKind::UnexpectedEof =>
                            {
                                return Ok(());
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    _ = bound.session.cancelled() => return Ok(()),
                }
            }
            None => match read_message(reader).await {
                Ok(request) => request,
                Err(Error::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    return Ok(());
                }
                Err(error) => return Err(error),
            },
        };
        if request.opcode != OPCODE_MSG {
            if request.opcode == crate::OPCODE_QUERY {
                let query = wire::parse_op_query(&request.body)?;
                let name = command_name(&query.document).unwrap_or_default();
                if matches!(name, "hello" | "ismaster" | "isMaster") {
                    let document = hello_document(i64::from(connection_id));
                    let response = wire::Message {
                        request_id: connection_id,
                        response_to: request.request_id,
                        opcode: crate::OPCODE_REPLY,
                        body: wire::op_reply_body(&document)?,
                    }
                    .into_bytes();
                    write_message(writer, &response).await?;
                    continue;
                }
            }
            let refusal = reply(
                connection_id,
                request.request_id,
                &error_document("This proxy accepts only OP_MSG.", 20),
            )?;
            write_message(writer, &refusal).await?;
            return Ok(());
        }
        let op_msg = wire::parse_op_msg(&request.body)?;
        // Driver bulk writes carry documents/updates/deletes in kind-1
        // sections; materialize them before dispatch (the interception layer
        // reads the whole command, mongod accepts inline arrays).
        let mut document = kind_zero_document(&op_msg.sections)?;
        for (identifier, documents) in wire::document_sequences(&op_msg)? {
            document.insert(identifier, documents);
        }
        let name = command_name(&document).unwrap_or_default().to_owned();

        // Handshake and auth are intercepted; authenticated traffic goes
        // through the admission dispatcher. Auth failures reply with an
        // auth error and keep the connection open (auth reset).
        let reply_bytes = match (name.as_str(), &mut auth) {
            ("hello" | "ismaster" | "isMaster", _) => reply(
                connection_id,
                request.request_id,
                &hello_document(i64::from(connection_id)),
            )?,
            ("saslStart", auth @ Auth::None) => {
                match sasl_start(
                    state.as_ref(),
                    connection_id,
                    request.request_id,
                    &document,
                    auth,
                ) {
                    Ok(reply) => reply,
                    Err(_) => reply(connection_id, request.request_id, &auth_error())?,
                }
            }
            ("saslContinue", auth @ Auth::Started(..)) => {
                let Auth::Started(exchange, account_index) = std::mem::replace(auth, Auth::None)
                else {
                    return Err(Error::Invalid);
                };
                match sasl_continue(
                    state.as_ref(),
                    connection_id,
                    request.request_id,
                    &document,
                    exchange,
                    &mut backend,
                )
                .await
                {
                    // The session is authenticated from here on; only a
                    // backend failure keeps it closed.
                    Ok(reply) => {
                        let account = &state.accounts[account_index];
                        *auth = Auth::Authenticated {
                            principal: account.user.clone(),
                            expires_at: account.expires_at,
                        };
                        reply
                    }
                    Err(_) => reply(connection_id, request.request_id, &auth_error())?,
                }
            }
            (
                _,
                Auth::Authenticated {
                    principal,
                    expires_at,
                },
            ) if !name.starts_with("sasl") => {
                let Some(backend) = backend.as_mut() else {
                    return Err(Error::Invalid);
                };
                command::dispatch(
                    &state.router,
                    backend,
                    &mut bound,
                    command::CommandContext {
                        request: &request,
                        op_msg: &op_msg,
                        document: &document,
                        name: &name,
                        principal,
                        expires_at: *expires_at,
                        connection_id,
                    },
                )
                .await?
            }
            _ => reply(connection_id, request.request_id, &unauthorized_error())?,
        };
        write_message(writer, &reply_bytes).await?;
    }
}

fn sasl_start(
    state: &State,
    connection_id: i32,
    request_id: i32,
    document: &bson::Document,
    auth: &mut Auth,
) -> Result<Vec<u8>, ()> {
    if document.get_str("mechanism") != Ok(scram::MECHANISM) {
        return Err(());
    }
    let payload = binary_payload(document).map_err(|_| ())?;
    let user = scram_user(&payload).ok_or(())?;
    let account_index = state
        .accounts
        .iter()
        .position(|account| account.user == user)
        .ok_or(())?;
    let password = state.accounts[account_index].password.clone();
    let verifier = Verifier::new(&password).map_err(|_| ())?;
    let (exchange, challenge) =
        scram::ServerExchange::start(&verifier, &payload).map_err(|_| ())?;
    *auth = Auth::Started(exchange, account_index);
    reply(
        connection_id,
        request_id,
        &sasl_reply(challenge.as_bytes(), false),
    )
    .map_err(|_| ())
}

async fn sasl_continue(
    state: &State,
    connection_id: i32,
    request_id: i32,
    document: &bson::Document,
    exchange: scram::ServerExchange,
    backend: &mut Option<Backend>,
) -> Result<Vec<u8>, ()> {
    let payload = binary_payload(document).map_err(|_| ())?;
    let server_final = exchange.finish(&payload).map_err(|_| ())?;
    // The proxy authenticates to mongod with its own service account; the
    // frontend identity only ever names the control-plane principal.
    let connected = match state.config.transport.as_ref() {
        Some(transport) => Backend::connect_tls(transport, &state.config.backend_auth_db).await,
        None => {
            Backend::connect(
                state.config.backend,
                &state.config.backend_auth_db,
                &state.config.backend_account.user,
                &state.config.backend_account.password,
            )
            .await
        }
    };
    *backend = Some(connected.map_err(|_| ())?);
    reply(
        connection_id,
        request_id,
        &sasl_reply(server_final.as_bytes(), true),
    )
    .map_err(|_| ())
}

/// Accept frontend connections until stopped; one task per session and one
/// backend connection per authenticated session, so branch identity and native
/// cancellation remain bound to that connection.
pub async fn serve_branches(
    listener: TcpListener,
    config: BranchConfig,
    accounts: Vec<FrontendAccount>,
    router: Router,
) -> io::Result<()> {
    if config.transport.is_none()
        && (!listener.local_addr()?.ip().is_loopback() || !config.backend.ip().is_loopback())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "MongoDB branching requires loopback endpoints",
        ));
    }
    let state = Arc::new(State {
        config,
        accounts,
        router,
    });
    let permits = Arc::new(Semaphore::new(MAX_SESSIONS));
    tracing::info!(listen = %listener.local_addr()?, "mongo branch frontend ready");
    loop {
        let permit = Arc::clone(&permits)
            .acquire_owned()
            .await
            .map_err(io::Error::other)?;
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true).ok();
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let _permit = permit;
            let result = match state.config.transport.as_ref() {
                Some(transport) => {
                    match timeout(HANDSHAKE_TIMEOUT, transport.frontend_tls.accept(stream)).await {
                        Ok(Ok(stream)) => run_stream(Arc::clone(&state), stream).await,
                        Ok(Err(error)) => Err(Error::Io(error)),
                        Err(_) => Err(Error::Io(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "MongoDB frontend TLS timed out",
                        ))),
                    }
                }
                None => run_stream(state, stream).await,
            };
            if let Err(error) = result {
                tracing::info!(%error, "mongo session closed abnormally");
            }
        });
    }
}

async fn run_stream(
    state: Arc<State>,
    stream: impl AsyncRead + AsyncWrite + Unpin,
) -> Result<(), Error> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    run(state, &mut reader, &mut writer).await
}
