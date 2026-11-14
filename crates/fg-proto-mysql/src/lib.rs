//! MySQL classic protocol endpoint backed by one native session per client.
//!
//! Packet, connection, authentication, command and response behavior derives
//! from Oracle's public MySQL classic protocol documentation. This endpoint
//! admits fixed local fixtures or compiles SQL against a pinned branch catalog.

mod admission;
mod guard;
mod handshake;
mod packet;
mod result;

use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use fg_protocol_common::{
    BRANCH, BranchSession, Config, FrontendAccount, HANDSHAKE_TIMEOUT, IO_TIMEOUT, MAX_SESSIONS,
    Router, WireError, WriteOperation,
};
use fg_rewrite::{
    BoundCompiler, CompiledExplain, CompiledRead, CompiledStatement, CompiledWrite, Dialect,
    GeneratedIds, OutputColumn, PlanMapping, QueryMode,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, split};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::handshake::{Authenticated, BackStream, FOUND_ROWS, OK, send_error};
use crate::packet::{Fields, MESSAGE_LIMIT};
use crate::result::Relay;

const QUIT: u8 = 0x01;
const INIT_DB: u8 = 0x02;
const QUERY: u8 = 0x03;
const PING: u8 = 0x0e;
const PREPARE: u8 = 0x16;
const EXECUTE: u8 = 0x17;
const SEND_LONG_DATA: u8 = 0x18;
const CLOSE: u8 = 0x19;
const RESET: u8 = 0x1a;
const MAX_STATEMENTS: usize = 256;
const MAX_PREFETCH_BYTES: usize = 64 * 1024;
// The parser and native lexer must agree on quotes and backslashes.
const FIXED_SQL_MODE: &[u8] = b"SET SESSION sql_mode = 'ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION'";
const FIXED_MESSAGE_LOCALE: &[u8] = b"SET SESSION lc_messages = 'en_US'";
type Statements = HashMap<u32, Prepared>;

struct Prepared {
    output: Option<Vec<OutputColumn>>,
    write: Option<PreparedWrite>,
    explain: Option<PlanMapping>,
}

#[derive(Clone, Copy)]
struct PreparedWrite {
    operation: WriteOperation,
    generated: Option<GeneratedIds>,
}

/// Serve one loopback MySQL fixture against the configured loopback backend.
///
/// This listener accepts only the fixture principal and branch over TLS.
pub async fn serve(listener: TcpListener, config: Config) -> io::Result<()> {
    if !listener.local_addr()?.ip().is_loopback() || !config.backend.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "MySQL fixture requires loopback endpoints",
        ));
    }
    serve_inner(listener, config, None).await
}

/// Serves the admitted read subset against a catalog obtained from control.
pub async fn serve_branches(
    listener: TcpListener,
    config: Config,
    accounts: Vec<FrontendAccount>,
    router: Router,
) -> io::Result<()> {
    serve_inner(listener, config, Some(Routing { accounts, router })).await
}

struct Routing {
    accounts: Vec<FrontendAccount>,
    router: Router,
}

struct State {
    config: Config,
    routing: Option<Routing>,
}

async fn serve_inner(
    listener: TcpListener,
    config: Config,
    routing: Option<Routing>,
) -> io::Result<()> {
    validate_config(&config, routing.as_ref())?;
    let state = Arc::new(State { config, routing });
    let permits = Arc::new(Semaphore::new(MAX_SESSIONS));
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
            if let Err(error) = session(stream, &state).await {
                // Abnormal session endings are rare and operationally
                // relevant; normal QUIT/Ping endings return Ok and stay quiet.
                tracing::info!(kind = ?error.kind(), source = %error,
                    "MySQL session closed abnormally");
            }
        });
    }
}

fn validate_config(config: &Config, routing: Option<&Routing>) -> io::Result<()> {
    let native = [
        &config.backend_user,
        &config.backend_password,
        &config.backend_database,
    ];
    let valid = |value: &str| !value.is_empty() && !value.as_bytes().contains(&0);
    let frontend = match routing {
        Some(routing) => {
            !routing.accounts.is_empty()
                && routing
                    .accounts
                    .iter()
                    .all(|account| valid(&account.user) && valid(&account.password))
        }
        None => valid(&config.frontend_user) && valid(&config.frontend_password),
    };
    if !frontend || !native.iter().all(|value| valid(value)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "MySQL credentials and database must be nonempty and NUL-free",
        ));
    }
    Ok(())
}

async fn session(stream: TcpStream, state: &State) -> io::Result<()> {
    let config = &state.config;
    let accounts = state
        .routing
        .as_ref()
        .map(|routing| routing.accounts.as_slice());
    let mut frontend = timeout(
        HANDSHAKE_TIMEOUT,
        handshake::frontend(stream, config, accounts),
    )
    .await??;
    let pending = match &state.routing {
        Some(routing) => {
            let Some(expires_at) = frontend.expires_at else {
                return reject_login(&mut frontend, WireError::Auth).await;
            };
            match routing
                .router
                .begin(&frontend.principal, &frontend.branch, expires_at)
                .await
            {
                Ok(pending) => Some(pending),
                Err(error) => return reject_login(&mut frontend, error).await,
            }
        }
        None if frontend.branch == BRANCH => None,
        None => return reject_login(&mut frontend, WireError::Branch).await,
    };

    let (backend, accepted, native_id) = match timeout(
        HANDSHAKE_TIMEOUT,
        connect_backend(
            config,
            frontend.flags,
            pending.is_some(),
            pending
                .as_ref()
                .is_some_and(|pending| pending.binding().write_schema.is_some()),
            // TiDB does not implement lc_messages; the writable
            // counting contract only needs the English info text.
            match &state.routing {
                Some(routing) if routing.router.engine() == "tidb" => None,
                _ => Some(FIXED_MESSAGE_LOCALE),
            },
        ),
    )
    .await
    {
        Ok(Ok(backend)) => backend,
        _ => return reject_login(&mut frontend, WireError::Backend).await,
    };
    let branch = match pending {
        Some(pending) => match pending.activate(native_id) {
            Ok(branch) => Some(branch),
            Err(error) => {
                drop(backend);
                return reject_login(&mut frontend, error).await;
            }
        },
        None => None,
    };
    run_connected(frontend, backend, accepted, branch.as_ref()).await
}

async fn connect_backend(
    config: &Config,
    flags: u32,
    is_branch: bool,
    is_writable: bool,
    locale: Option<&'static [u8]>,
) -> io::Result<(BackStream, Vec<u8>, u32)> {
    let (mut backend, accepted, native_id) = handshake::backend(config, flags).await?;
    let settings = [
        is_branch.then_some(FIXED_SQL_MODE),
        is_writable.then_some(locale).flatten(),
    ];
    for sql in settings.into_iter().flatten() {
        let mut command = Vec::with_capacity(sql.len() + 1);
        command.push(QUERY);
        command.extend_from_slice(sql);
        let mut sequence = 0;
        packet::write(&mut backend, &mut sequence, &command).await?;
        let reply = packet::read(&mut backend, &mut sequence, MESSAGE_LIMIT).await?;
        if reply.first() != Some(&OK) {
            return Err(packet::invalid());
        }
    }
    Ok((backend, accepted, native_id))
}

async fn reject_login(frontend: &mut Authenticated, error: WireError) -> io::Result<()> {
    timeout(
        IO_TIMEOUT,
        send_error(&mut frontend.stream, &mut frontend.sequence, error),
    )
    .await?
}

async fn run_connected(
    mut frontend: Authenticated,
    mut backend: BackStream,
    accepted: Vec<u8>,
    branch: Option<&BranchSession>,
) -> io::Result<()> {
    let compiler = match branch
        .map(|branch| BoundCompiler::new(Dialect::MySql, branch.binding()))
        .transpose()
    {
        Ok(compiler) => compiler,
        Err(error) => return reject_login(&mut frontend, error.wire()).await,
    };
    let mut session = Session {
        compiler,
        has_found_rows: frontend.flags & FOUND_ROWS != 0,
        ..Session::default()
    };
    let exchange = async {
        timeout(
            IO_TIMEOUT,
            packet::write(&mut frontend.stream, &mut frontend.sequence, &accepted),
        )
        .await??;
        let (mut reader, mut writer) = split(frontend.stream);
        session
            .exchange(&mut reader, &mut writer, &mut backend, branch)
            .await
    };
    let result = match branch {
        Some(branch) => tokio::select! {
            biased;
            _ = branch.cancelled() => Ok(()),
            result = exchange => result,
        },
        None => exchange.await,
    };
    if let Err(error) = &result {
        tracing::info!(kind = ?error.kind(), source = %error,
            command_kind = ?session.last_command.get(), "MySQL session ended abnormally");
    }
    drop(backend);
    if let Some(branch) = branch {
        session.transaction.close(branch).await;
    }
    result
}

#[derive(Default)]
struct Session<'a> {
    compiler: Option<BoundCompiler<'a>>,
    statements: Statements,
    transaction: guard::Transaction,
    has_found_rows: bool,
    /// Keep only the wire command tag; SQL bytes can contain parameter values.
    last_command: std::cell::Cell<Option<u8>>,
}

impl Session<'_> {
    async fn exchange(
        &mut self,
        reader: &mut (impl AsyncRead + Unpin),
        writer: &mut (impl AsyncWrite + Unpin),
        backend: &mut BackStream,
        branch: Option<&BranchSession>,
    ) -> io::Result<()> {
        let is_writable = branch.is_some_and(|branch| branch.binding().write_schema.is_some());
        let mut prefetched = Vec::new();
        let mut metadata = packet::MetadataBatch::new();
        loop {
            let mut sequence = 0;
            let result = timeout(
                IO_TIMEOUT,
                read_command(reader, &mut prefetched, &mut sequence),
            )
            .await?;
            let command = match result {
                Ok(command) => {
                    self.last_command.set(command.first().copied());
                    command
                }
                Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                    sequence = sequence.max(1);
                    timeout(
                        IO_TIMEOUT,
                        send_error(writer, &mut sequence, WireError::Protocol),
                    )
                    .await??;
                    return Err(error);
                }
                Err(error) => return Err(error),
            };

            let mut relay = Relay {
                backend,
                frontend: writer,
                metadata: &mut metadata,
                back_sequence: 0,
                front_sequence: sequence,
                is_branch: branch.is_some(),
                is_writable,
                has_found_rows: self.has_found_rows,
            };
            let exchange = run_with_disconnect(
                reader,
                &mut prefetched,
                is_writable,
                dispatch(&mut relay, self, &command, branch),
            );
            // An approval can outlast packet I/O deadlines, which still apply
            // individually to every native read and write.
            let flow = if is_writable {
                exchange.await?
            } else {
                timeout(IO_TIMEOUT, exchange).await??
            };
            if matches!(flow, Flow::Close) {
                return Ok(());
            }
        }
    }
}

async fn read_command(
    reader: &mut (impl AsyncRead + Unpin),
    prefetched: &mut Vec<u8>,
    sequence: &mut u8,
) -> io::Result<Vec<u8>> {
    let mut prefix = prefetched.as_slice();
    let result = packet::read(&mut (&mut prefix).chain(reader), sequence, MESSAGE_LIMIT).await;
    let consumed = prefetched.len() - prefix.len();
    prefetched.drain(..consumed);
    result
}

async fn run_with_disconnect(
    reader: &mut (impl AsyncRead + Unpin),
    prefetched: &mut Vec<u8>,
    is_writable: bool,
    exchange: impl Future<Output = io::Result<Flow>>,
) -> io::Result<Flow> {
    tokio::pin!(exchange);
    let mut next = [0; 4096];
    let read_limit = if is_writable { next.len() } else { 1 };
    loop {
        tokio::select! {
            biased;
            read = reader.read(&mut next[..read_limit]) => {
                let count = read?;
                if count == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "MySQL client disconnected"));
                }
                if prefetched.len() + count > MAX_PREFETCH_BYTES {
                    return Err(packet::invalid());
                }
                prefetched.extend_from_slice(&next[..count]);
                if !is_writable {
                    return exchange.await;
                }
            }
            result = &mut exchange => return result,
        }
    }
}

#[derive(Clone, Copy)]
enum Flow {
    Continue,
    Close,
}

async fn dispatch(
    relay: &mut Relay<'_, impl AsyncWrite + Unpin>,
    session: &mut Session<'_>,
    command: &[u8],
    branch: Option<&BranchSession>,
) -> io::Result<Flow> {
    let Some((&kind, data)) = command.split_first() else {
        return refuse(relay, WireError::Protocol, Flow::Close).await;
    };
    if kind != QUIT
        && let Some(branch) = branch
        && let Err(error) = branch.authorize().await
    {
        return refuse(relay, error, Flow::Close).await;
    }
    let branch_name = branch.map_or(BRANCH, |branch| branch.binding().name.as_str());
    if session.transaction.is_aborted()
        && kind != QUIT
        && !(kind == QUERY && data.eq_ignore_ascii_case(b"ROLLBACK"))
    {
        return refuse(relay, WireError::TransactionAborted, Flow::Continue).await;
    }
    match kind {
        QUIT if data.is_empty() => {
            relay.start(command).await?;
            return Ok(Flow::Close);
        }
        PING if data.is_empty() => ping(relay).await?,
        INIT_DB if data == branch_name.as_bytes() => ping(relay).await?,
        INIT_DB => return refuse(relay, WireError::Branch, Flow::Continue).await,
        QUERY if admission::use_branch(data) == Some(branch_name.as_bytes()) => ping(relay).await?,
        QUERY if branch.is_some() && admission::use_branch(data).is_some() => {
            return refuse(relay, WireError::Branch, Flow::Continue).await;
        }
        QUERY => {
            return query(
                relay,
                &mut session.transaction,
                data,
                CompileContext {
                    branch,
                    compiler: session.compiler.as_ref(),
                },
            )
            .await;
        }
        PREPARE => {
            prepare(
                relay,
                &mut session.statements,
                data,
                CompileContext {
                    branch,
                    compiler: session.compiler.as_ref(),
                },
            )
            .await?
        }
        EXECUTE | RESET | CLOSE => return statement_command(relay, session, command, branch).await,
        // SEND_LONG_DATA has no normal response. Close after the refusal so a
        // client cannot interpret it as the response to a later EXECUTE.
        SEND_LONG_DATA => return refuse(relay, WireError::Unsupported, Flow::Close).await,
        _ => return refuse(relay, WireError::Unsupported, Flow::Continue).await,
    }
    Ok(Flow::Continue)
}

async fn ping(relay: &mut Relay<'_, impl AsyncWrite + Unpin>) -> io::Result<()> {
    relay.start(&[PING]).await?;
    relay.simple().await
}

async fn query(
    relay: &mut Relay<'_, impl AsyncWrite + Unpin>,
    transaction: &mut guard::Transaction,
    sql: &[u8],
    context: CompileContext<'_>,
) -> io::Result<Flow> {
    let branch = context.branch;
    let admitted = match Admitted::compile(sql, QueryMode::Text, context) {
        Ok(admitted) => admitted,
        Err(error) => return refuse(relay, error, Flow::Continue).await,
    };
    match admitted {
        Admitted::Explain(plan) => {
            start_sql(relay, QUERY, plan.read.sql.as_bytes()).await?;
            relay
                .query_plan(Some(&plan.read.columns), &plan.mapping, false)
                .await?;
            Ok(Flow::Continue)
        }
        Admitted::Write(write) => match branch {
            Some(branch) => {
                guard::execute(relay, transaction, branch, guard::Write::Text(write)).await
            }
            None => Err(packet::invalid()),
        },
        admitted => {
            if relay.is_writable
                && let Some(branch) = branch
                && transaction.control(relay, branch, admitted.sql()).await?
            {
                return Ok(Flow::Continue);
            }
            start_sql(relay, QUERY, admitted.sql()).await?;
            relay.query(admitted.output()).await?;
            Ok(Flow::Continue)
        }
    }
}

async fn prepare(
    relay: &mut Relay<'_, impl AsyncWrite + Unpin>,
    statements: &mut Statements,
    sql: &[u8],
    context: CompileContext<'_>,
) -> io::Result<()> {
    if statements.len() >= MAX_STATEMENTS {
        return relay.error(WireError::Unsupported).await;
    }
    let admitted = match Admitted::compile(sql, QueryMode::Prepared, context) {
        Ok(admitted) => admitted,
        Err(error) => return relay.error(error).await,
    };
    start_sql(relay, PREPARE, admitted.sql()).await?;
    if let Some(id) = relay.prepare(admitted.prepared_metadata()).await? {
        statements.insert(id, admitted.into_prepared());
    }
    Ok(())
}

enum Admitted {
    Native(&'static [u8]),
    Rewritten(CompiledRead),
    Write(CompiledWrite),
    Savepoint(String),
    Explain(CompiledExplain),
}

#[derive(Clone, Copy)]
struct CompileContext<'a> {
    branch: Option<&'a BranchSession>,
    compiler: Option<&'a BoundCompiler<'a>>,
}

impl Admitted {
    fn compile(
        sql: &[u8],
        mode: QueryMode,
        context: CompileContext<'_>,
    ) -> Result<Self, WireError> {
        let Some(branch) = context.branch else {
            return match mode {
                QueryMode::Text => admission::text(sql),
                QueryMode::Prepared => admission::prepared(sql),
            }
            .map(Self::Native)
            .ok_or(WireError::Unsupported);
        };
        if let Some(sql) = admission::session(sql)
            .filter(|_| mode == QueryMode::Text)
            .or_else(|| {
                branch.binding().write_schema.as_ref()?;
                admission::write_session(sql, mode == QueryMode::Text)
            })
        {
            return Ok(Self::Native(sql));
        }
        let sql = str::from_utf8(sql).map_err(|_| WireError::SqlSyntax)?;
        context
            .compiler
            .ok_or(WireError::Backend)?
            .compile_statement(mode, sql)
            .map(|statement| match statement {
                CompiledStatement::Read(read) => Self::Rewritten(read),
                CompiledStatement::Write(write) => Self::Write(write),
                CompiledStatement::Savepoint(sql) => Self::Savepoint(sql),
                CompiledStatement::Explain(plan) => Self::Explain(plan),
            })
            .map_err(|error| error.wire_at(Dialect::MySql, sql))
    }

    fn sql(&self) -> &[u8] {
        match self {
            Self::Native(sql) => sql,
            Self::Rewritten(read) => read.sql.as_bytes(),
            Self::Write(write) => write.sql.as_bytes(),
            Self::Savepoint(sql) => sql.as_bytes(),
            Self::Explain(plan) => plan.read.sql.as_bytes(),
        }
    }

    fn output(&self) -> Option<&[OutputColumn]> {
        match self {
            Self::Native(_) | Self::Write(_) | Self::Savepoint(_) => None,
            Self::Rewritten(read) => Some(&read.columns),
            Self::Explain(plan) => Some(&plan.read.columns),
        }
    }

    fn prepared_metadata(&self) -> Option<(usize, &[OutputColumn])> {
        match self {
            Self::Native(_) => None,
            Self::Rewritten(read) => Some((read.parameter_count, &read.columns)),
            Self::Write(write) => Some((write.parameter_count, &write.columns)),
            Self::Savepoint(_) => Some((0, &[])),
            Self::Explain(plan) => Some((plan.read.parameter_count, &plan.read.columns)),
        }
    }

    fn into_prepared(self) -> Prepared {
        let explain = match &self {
            Self::Explain(plan) => Some(plan.mapping.clone()),
            _ => None,
        };
        let (output, write) = match self {
            Self::Native(_) | Self::Savepoint(_) => (None, None),
            Self::Rewritten(read) => (Some(read.columns), None),
            Self::Explain(plan) => (Some(plan.read.columns), None),
            Self::Write(write) => (
                None,
                Some(PreparedWrite {
                    operation: write.operation,
                    generated: write.generated,
                }),
            ),
        };
        Prepared {
            output,
            write,
            explain,
        }
    }
}

async fn start_sql(
    relay: &mut Relay<'_, impl AsyncWrite + Unpin>,
    kind: u8,
    sql: &[u8],
) -> io::Result<()> {
    let mut command = Vec::with_capacity(sql.len() + 1);
    command.push(kind);
    command.extend_from_slice(sql);
    relay.start(&command).await
}

async fn statement_command(
    relay: &mut Relay<'_, impl AsyncWrite + Unpin>,
    session: &mut Session<'_>,
    command: &[u8],
    branch: Option<&BranchSession>,
) -> io::Result<Flow> {
    let kind = command[0];
    let mut fields = Fields(&command[1..]);
    let Ok(id) = fields.u32() else {
        return refuse(relay, WireError::Protocol, Flow::Continue).await;
    };
    if kind == CLOSE && fields.0.is_empty() {
        if session.statements.remove(&id).is_some() {
            relay.start(command).await?;
        }
        return Ok(Flow::Continue);
    }
    let Some(statement) = session.statements.get(&id) else {
        return refuse(relay, WireError::Protocol, Flow::Continue).await;
    };
    match kind {
        EXECUTE if matches!(fields.0, [0, 1, 0, 0, 0, ..]) => {
            if let Some(write) = statement.write {
                let Some(branch) = branch else {
                    return Err(packet::invalid());
                };
                let write = guard::Write::Prepared {
                    command,
                    operation: write.operation,
                    generated: write.generated,
                };
                return guard::execute(relay, &mut session.transaction, branch, write).await;
            }
            relay.start(command).await?;
            if let Some(mapping) = &statement.explain {
                relay
                    .query_plan(statement.output.as_deref(), mapping, true)
                    .await
            } else {
                relay.query(statement.output.as_deref()).await
            }
        }
        EXECUTE if fields.0.len() >= 5 && fields.0[0] != 0 => {
            relay.error(WireError::Unsupported).await
        }
        RESET if fields.0.is_empty() => {
            relay.start(command).await?;
            relay.simple().await
        }
        _ => relay.error(WireError::Protocol).await,
    }?;
    Ok(Flow::Continue)
}

async fn refuse(
    relay: &mut Relay<'_, impl AsyncWrite + Unpin>,
    error: WireError,
    flow: Flow,
) -> io::Result<Flow> {
    relay.error(error).await?;
    Ok(flow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn approval_wait_observes_disconnect_even_after_prefetching() -> io::Result<()> {
        let (mut client, mut reader) = tokio::io::duplex(8);
        client.write_all(b"queued").await?;
        drop(client);
        let mut prefetched = Vec::new();
        let result =
            run_with_disconnect(&mut reader, &mut prefetched, true, std::future::pending()).await;
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::UnexpectedEof));
        assert_eq!(prefetched, b"queued");
        Ok(())
    }
}
