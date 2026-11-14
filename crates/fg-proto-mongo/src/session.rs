//! Per-client session state machine for the standalone passthrough fixture:
//! handshake interception, SCRAM termination, backend authentication, then
//! command passthrough. Deployment traffic goes through `admission.rs`.

use std::io;
use std::sync::atomic::{AtomicI32, Ordering};

use tokio::net::tcp;

use crate::backend::{Backend, binary_payload, read_message, write_message};
use crate::scram::{self, Verifier};
use crate::wire::{self, Message, command_name, kind_zero_document, op_msg_body};
use crate::{Error, OPCODE_MSG};

/// A frontend account; the spike maps it 1:1 to a mongod account with the
/// same password in the backend auth database.
#[derive(Clone)]
pub struct Account {
    pub user: String,
    pub password: String,
}

#[derive(Clone)]
pub struct SpikeConfig {
    pub listen: std::net::SocketAddr,
    pub backend: std::net::SocketAddr,
    /// Mongo auth database holding the backend accounts (admin).
    pub backend_auth_db: String,
    pub accounts: Vec<Account>,
}

pub(crate) fn hello_document(connection_id: i64) -> bson::Document {
    bson::doc! {
        "ok": 1.0,
        "helloOk": true,
        "isWritablePrimary": true,
        "secondary": false,
        "connectionId": connection_id,
        // Without this, drivers default to SCRAM-SHA-1 for compatibility
        // with pre-4.0 servers; the proxy terminates SHA-256 only.
        "saslSupportedMechs": ["SCRAM-SHA-256"],
        // Omitting logicalSessionTimeoutMinutes disables driver sessions;
        // omitting setName/msg makes drivers classify this as a standalone
        // server, which disables transactions, retryable writes and change
        // streams on the driver side without further negotiation.
        "minWireVersion": crate::MIN_WIRE_VERSION,
        "maxWireVersion": crate::MAX_WIRE_VERSION,
        "maxBsonObjectSize": crate::MAX_BSON_OBJECT_SIZE,
        "maxMessageSizeBytes": 48_000_000i32,
        "maxWriteBatchSize": 100_000i32,
    }
}

/// Encode `ok` as a BSON double to match native mongod replies; the
/// errmsg text carries the FG mapping so users can act on refusals.
pub(crate) fn error_document(message: &str, code: i32) -> bson::Document {
    bson::doc! { "ok": 0.0, "errmsg": message, "code": code }
}

pub(crate) fn auth_error() -> bson::Document {
    error_document("Authentication failed.", 18)
}

pub(crate) fn unauthorized_error() -> bson::Document {
    error_document("Command requires authentication.", 13)
}

pub(crate) fn ok_document() -> bson::Document {
    bson::doc! { "ok": 1.0 }
}

pub(crate) fn reply(
    connection_id: i32,
    request_id: i32,
    document: &bson::Document,
) -> Result<Vec<u8>, Error> {
    Ok(Message {
        request_id: connection_id,
        response_to: request_id,
        opcode: OPCODE_MSG,
        body: op_msg_body(0, document)?,
    }
    .into_bytes())
}

pub(crate) fn sasl_reply(payload: &[u8], done: bool) -> bson::Document {
    bson::doc! {
        "conversationId": 1i32,
        "done": done,
        "payload": bson::Binary {
            bytes: payload.to_vec(),
            subtype: bson::spec::BinarySubtype::Generic,
        },
        "ok": 1.0,
    }
}

pub(crate) fn scram_user(payload: &[u8]) -> Option<&str> {
    let payload = std::str::from_utf8(payload).ok()?;
    payload
        .split(',')
        .find_map(|part| part.strip_prefix("n="))
        .filter(|user| !user.is_empty())
}

/// The per-client auth phases.
enum Auth {
    None,
    Started(scram::ServerExchange, usize),
    Authenticated,
}

pub struct Session {
    config: SpikeConfig,
    connection_id: i32,
}

static NEXT_CONNECTION_ID: AtomicI32 = AtomicI32::new(1);

impl Session {
    pub fn new(config: SpikeConfig) -> Self {
        Self {
            config,
            connection_id: NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed),
        }
    }

    pub async fn run(
        self,
        reader: &mut tcp::OwnedReadHalf,
        writer: &mut tcp::OwnedWriteHalf,
    ) -> Result<(), Error> {
        let mut auth = Auth::None;
        let mut backend: Option<Backend> = None;
        loop {
            let request = match read_message(reader).await {
                Ok(request) => request,
                Err(Error::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            if request.opcode != OPCODE_MSG {
                // The legacy handshake (OP_QUERY hello/ismaster) still comes
                // from some drivers before they switch to OP_MSG (mongosh's
                // Node driver); mongod accepts both, so answer it and keep
                // the session open. Any other legacy opcode stays rejected.
                let parsed = match request.opcode {
                    crate::OPCODE_QUERY => wire::parse_op_query(&request.body),
                    opcode => Err(Error::Opcode(opcode)),
                };
                let Ok(op_query) = parsed else {
                    tracing::info!(opcode = request.opcode, "rejecting non-OP_MSG opcode");
                    let refusal = reply(
                        self.connection_id,
                        request.request_id,
                        &error_document("This proxy accepts only OP_MSG.", 20),
                    )?;
                    write_message(writer, &refusal).await?;
                    return Ok(());
                };
                let command = command_name(&op_query.document).unwrap_or_default();
                if !matches!(command, "hello" | "ismaster" | "isMaster") {
                    tracing::info!(command = %command, "rejecting legacy non-hello command");
                    let refusal = reply(
                        self.connection_id,
                        request.request_id,
                        &error_document("This proxy accepts only OP_MSG.", 20),
                    )?;
                    write_message(writer, &refusal).await?;
                    return Ok(());
                }
                let mut reply_document = hello_document(i64::from(self.connection_id));
                reply_document.insert("ok", 1.0);
                let bytes = Message {
                    request_id: self.connection_id,
                    response_to: request.request_id,
                    opcode: crate::OPCODE_REPLY,
                    body: wire::op_reply_body(&reply_document)?,
                }
                .into_bytes();
                write_message(writer, &bytes).await?;
                continue;
            }
            let op_msg = wire::parse_op_msg(&request.body)?;
            let document = kind_zero_document(&op_msg.sections)?;
            let name = command_name(&document).unwrap_or_default().to_owned();

            // Handshake and auth are intercepted; everything else passes
            // through to the backend once authenticated. Auth failures reply
            // with an auth error and keep the connection open (auth reset).
            let reply_bytes = match (name.as_str(), &mut auth) {
                ("hello" | "ismaster" | "isMaster", _) => reply(
                    self.connection_id,
                    request.request_id,
                    &hello_document(i64::from(self.connection_id)),
                )?,
                ("saslStart", auth @ Auth::None) => {
                    match self.sasl_start(request.request_id, &document, auth) {
                        Ok(reply) => reply,
                        Err(_) => reply(self.connection_id, request.request_id, &auth_error())?,
                    }
                }
                ("saslContinue", auth @ Auth::Started(..)) => {
                    let Auth::Started(exchange, account_index) =
                        std::mem::replace(auth, Auth::None)
                    else {
                        return Err(Error::Invalid);
                    };
                    match self
                        .sasl_continue(
                            request.request_id,
                            &document,
                            exchange,
                            account_index,
                            &mut backend,
                        )
                        .await
                    {
                        // The session is authenticated from here on; only a
                        // backend failure keeps it closed.
                        Ok(reply) => {
                            *auth = Auth::Authenticated;
                            reply
                        }
                        Err(_) => reply(self.connection_id, request.request_id, &auth_error())?,
                    }
                }
                (_, Auth::Authenticated) if !name.starts_with("sasl") => {
                    let Some(backend) = backend.as_mut() else {
                        return Err(Error::Invalid);
                    };
                    backend.forward(&request, &op_msg).await?
                }
                _ => reply(
                    self.connection_id,
                    request.request_id,
                    &unauthorized_error(),
                )?,
            };
            write_message(writer, &reply_bytes).await?;
        }
    }

    fn sasl_start(
        &self,
        request_id: i32,
        document: &bson::Document,
        auth: &mut Auth,
    ) -> Result<Vec<u8>, ()> {
        if document.get_str("mechanism") != Ok(scram::MECHANISM) {
            return Err(());
        }
        let payload = binary_payload(document).map_err(|_| ())?;
        let user = scram_user(&payload).ok_or(())?;
        let account_index = self
            .config
            .accounts
            .iter()
            .position(|account| account.user == user)
            .ok_or(())?;
        let password = self.config.accounts[account_index].password.clone();
        let verifier = Verifier::new(&password).map_err(|_| ())?;
        let (exchange, challenge) =
            scram::ServerExchange::start(&verifier, &payload).map_err(|_| ())?;
        *auth = Auth::Started(exchange, account_index);
        reply(
            self.connection_id,
            request_id,
            &sasl_reply(challenge.as_bytes(), false),
        )
        .map_err(|_| ())
    }

    async fn sasl_continue(
        &self,
        request_id: i32,
        document: &bson::Document,
        exchange: scram::ServerExchange,
        account_index: usize,
        backend: &mut Option<Backend>,
    ) -> Result<Vec<u8>, ()> {
        let payload = binary_payload(document).map_err(|_| ())?;
        let server_final = exchange.finish(&payload).map_err(|_| ())?;
        let account = self.config.accounts[account_index].clone();
        *backend = Some(
            Backend::connect(
                self.config.backend,
                &self.config.backend_auth_db,
                &account.user,
                &account.password,
            )
            .await
            .map_err(|_| ())?,
        );
        reply(
            self.connection_id,
            request_id,
            &sasl_reply(server_final.as_bytes(), true),
        )
        .map_err(|_| ())
    }
}

/// Accept frontend connections until stopped; the spike keeps one task per
/// session and one backend connection per authenticated session, retaining
/// native connection identity across the authenticated command stream.
pub async fn serve(config: SpikeConfig) -> io::Result<()> {
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    tracing::info!(listen = %config.listen, backend = %config.backend,
        accounts = config.accounts.len(), "mongo spike ready");
    loop {
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true).ok();
        let config = config.clone();
        tokio::spawn(async move {
            let (mut reader, mut writer) = stream.into_split();
            if let Err(error) = Session::new(config).run(&mut reader, &mut writer).await {
                tracing::info!(%error, "mongo spike session ended");
            }
        });
    }
}
