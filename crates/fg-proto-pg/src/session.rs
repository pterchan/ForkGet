use std::{
    collections::HashMap,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use fg_protocol_common::{
    BranchSession, Config, IO_TIMEOUT, NativeErrorClass, TransactionBudget, TransactionOutcome,
    WireError, WriteOperation,
};
use fg_rewrite::{BoundCompiler, Dialect, PlanMapping};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{Mutex as AsyncMutex, mpsc, oneshot, watch},
    task::JoinHandle,
    time::timeout,
};

#[path = "guard.rs"]
mod guard;
#[path = "handles.rs"]
mod handles;
#[path = "witness.rs"]
mod witness;

use crate::{
    admission::{self, Admission, BindWithGenerated, GeneratedBind},
    backend, scram,
    wire::{
        Frame, backend_error, cstring, end, public_parameter_status, read_frame,
        strip_row_identity, take_string, write_error, write_frame,
    },
};

const FRONTEND_QUEUE: usize = 8;
const MAX_NAMED_HANDLES: usize = 256;
const FAILED_PARSE_NAME: &str = "_fg_abort";
const SYNTHETIC_PID_BIT: u8 = 1 << 6;
// An engine parse failure preserves the native transaction boundary when
// refusing client SQL. The offending client SQL is never sent to PostgreSQL.
const INVALID_NATIVE_QUERY: &str = "SELECT )";

type Key = [u8; 8];

#[derive(Default)]
pub(crate) struct Cancellations(Mutex<HashMap<Key, Arc<CancelSlot>>>);

impl Cancellations {
    pub(crate) fn insert(&self, backend_key: Key) -> io::Result<Registration<'_>> {
        let mut entries = self.0.lock().map_err(|_| backend_error())?;
        let slot = Arc::new(CancelSlot {
            backend_key,
            active: AtomicBool::new(false),
            guarded: AtomicBool::new(false),
            cancellation: watch::channel(()).0,
            fence: AsyncMutex::new(()),
        });
        loop {
            let mut frontend_key = scram::random::<8>()?;
            // Reserve an ID range above the native Linux backend PID limit.
            frontend_key[0] = (frontend_key[0] & 0x3f) | SYNTHETIC_PID_BIT;
            if frontend_key != backend_key && !entries.contains_key(&frontend_key) {
                entries.insert(frontend_key, Arc::clone(&slot));
                return Ok(Registration {
                    registry: self,
                    frontend_key,
                    slot,
                });
            }
        }
    }

    fn find(&self, frontend_key: Key) -> io::Result<Option<Arc<CancelSlot>>> {
        Ok(self
            .0
            .lock()
            .map_err(|_| backend_error())?
            .get(&frontend_key)
            .cloned())
    }

    pub(crate) async fn cancel(&self, config: &Config, frontend_key: Key) -> io::Result<()> {
        let Some(slot) = self.find(frontend_key)? else {
            return Ok(());
        };
        let _fence = slot.fence.lock().await;
        if slot.guarded.load(Ordering::Acquire) {
            slot.cancellation.send_replace(());
        }
        if slot.active.load(Ordering::Acquire) {
            backend::cancel(config, slot.backend_key).await?;
        }
        Ok(())
    }
}

struct CancelSlot {
    backend_key: Key,
    active: AtomicBool,
    guarded: AtomicBool,
    cancellation: watch::Sender<()>,
    fence: AsyncMutex<()>,
}

pub(crate) struct Registration<'a> {
    registry: &'a Cancellations,
    pub(crate) frontend_key: Key,
    slot: Arc<CancelSlot>,
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        self.slot.active.store(false, Ordering::Release);
        if let Ok(mut entries) = self.registry.0.lock() {
            entries.remove(&self.frontend_key);
        }
    }
}

pub(crate) async fn run(
    mut frontend: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    backend: backend::Stream,
    registration: &Registration<'_>,
    frontend_user: &str,
    branch: Option<&BranchSession>,
) -> io::Result<()> {
    let compiler = match branch
        .map(|branch| BoundCompiler::new(Dialect::PostgreSql, branch.binding()))
        .transpose()
    {
        Ok(compiler) => compiler,
        Err(error) => {
            bounded(write_error(&mut frontend, error.wire(), true)).await??;
            return Ok(());
        }
    };
    let (input, mut output) = tokio::io::split(frontend);
    let (send, mut receive) = mpsc::channel(FRONTEND_QUEUE);
    let (close, mut disconnected) = oneshot::channel();
    let _reader = AbortOnDrop(tokio::spawn(read_frontend(input, send, close)));
    let mut session = Session {
        backend,
        slot: &registration.slot,
        frontend_user,
        branch,
        compiler,
        transaction: b'I',
        explicit: false,
        local_sync: false,
        skip_until_sync: false,
        statements: HashMap::new(),
        portals: HashMap::new(),
        explain_statements: HashMap::new(),
        explain_portals: HashMap::new(),
        handles: handles::Handles::default(),
        budget: TransactionBudget::default(),
        guarded_work: false,
        commit_in_flight: false,
    };
    let branch_closed = async {
        if let Some(branch) = branch {
            branch.cancelled().await;
        } else {
            std::future::pending::<()>().await;
        }
    };
    let result = tokio::select! {
        biased;
        _ = branch_closed => Ok(()),
        result = &mut disconnected => result.unwrap_or(Ok(())),
        result = session.exchange(&mut receive, &mut output) => result,
    };
    drop(session.backend);
    registration.slot.active.store(false, Ordering::Release);
    registration.slot.guarded.store(false, Ordering::Release);
    if let (Some(branch), Some(attempt)) = (branch, session.budget.take_attempt()) {
        let outcome = if session.commit_in_flight {
            TransactionOutcome::Unknown
        } else {
            TransactionOutcome::RolledBack
        };
        let _ = branch.audit_outcome(&attempt, outcome).await;
    }
    result
}

struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn read_frontend(
    mut input: impl AsyncRead + Unpin,
    send: mpsc::Sender<Frame>,
    close: oneshot::Sender<io::Result<()>>,
) {
    loop {
        match read_frame(&mut input).await {
            Ok(frame) => {
                if send.try_send(frame).is_err() {
                    let _ = close.send(Err(crate::wire::protocol_error()));
                    break;
                }
            }
            Err(error) => {
                let result = match error.kind() {
                    io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset => Ok(()),
                    _ => Err(error),
                };
                let _ = close.send(result);
                break;
            }
        }
    }
}

struct Session<'a> {
    backend: backend::Stream,
    slot: &'a CancelSlot,
    frontend_user: &'a str,
    branch: Option<&'a BranchSession>,
    compiler: Option<BoundCompiler<'a>>,
    transaction: u8,
    explicit: bool,
    local_sync: bool,
    skip_until_sync: bool,
    statements: HashMap<String, Option<StatementPolicy>>,
    portals: HashMap<String, Option<PortalPolicy>>,
    explain_statements: HashMap<String, PlanMapping>,
    explain_portals: HashMap<String, PlanMapping>,
    handles: handles::Handles,
    budget: TransactionBudget,
    guarded_work: bool,
    commit_in_flight: bool,
}

#[derive(Clone, Copy)]
enum Command {
    Write(WriteOperation),
    Begin,
    Commit,
    Rollback,
}

#[derive(Clone, Copy)]
struct StatementPolicy {
    command: Command,
    generated: Option<GeneratedBind>,
}

struct PortalPolicy {
    command: Command,
    executed: bool,
}

#[derive(Default)]
struct Response {
    refusal: Option<WireError>,
    hidden_type: Option<u16>,
    control: Option<Command>,
    explain: Option<PlanMapping>,
}

impl Session<'_> {
    async fn exchange(
        &mut self,
        receive: &mut mpsc::Receiver<Frame>,
        frontend: &mut (impl AsyncWrite + Unpin),
    ) -> io::Result<()> {
        loop {
            let Some(mut frame) = bounded(receive.recv()).await? else {
                return Ok(());
            };
            let tag = frame.tag;
            if self.skip_until_sync && !matches!(tag, b'S' | b'X') {
                continue;
            }
            if tag != b'X'
                && let Some(branch) = self.branch
                && let Err(error) = branch.authorize().await
            {
                bounded(write_error(frontend, error, true)).await??;
                return Ok(());
            }
            if tag == b'S' && self.local_sync {
                self.local_sync = false;
                self.skip_until_sync = false;
                bounded(write_frame(frontend, b'Z', &[self.transaction])).await??;
                continue;
            }
            if tag == b'Q' && self.guarded_work && !self.explicit {
                // A simple message cannot cross a guarded extended transaction.
                bounded(write_error(frontend, WireError::Protocol, true)).await??;
                return Ok(());
            }
            if tag == b'Q' || (tag == b'P' && frame.body.first() == Some(&0)) {
                self.statements.remove("");
                self.explain_statements.remove("");
                if tag == b'Q' {
                    self.portals.remove("");
                    self.explain_portals.remove("");
                }
            }
            match admission::admit(&mut frame, self.compiler.as_ref()) {
                Ok(_) if tag == b'X' => {
                    let _ = bounded(write_frame(&mut self.backend, tag, &frame.body)).await?;
                    return Ok(());
                }
                Ok(admitted) => self.admitted(frontend, frame, admitted).await?,
                Err(WireError::Protocol) if self.branch.is_some() => {
                    // A local protocol error cannot leave a live native
                    // transaction behind a synthetic recovery state.
                    bounded(write_error(frontend, WireError::Protocol, true)).await??;
                    return Ok(());
                }
                Err(error) => self.reject(frontend, frame, error).await?,
            }
        }
    }

    async fn admitted(
        &mut self,
        frontend: &mut (impl AsyncWrite + Unpin),
        frame: Frame,
        admitted: Admission,
    ) -> io::Result<()> {
        let control = match admitted {
            Admission::Explain(mapping) => return self.explain(frontend, frame, mapping).await,
            Admission::WriteText(write) => {
                let mut frame = frame;
                let Some(branch) = self.branch else {
                    return Err(backend_error());
                };
                let sql = if let Some(ids) = write.generated {
                    let start = match branch.allocate(ids.table_id, ids.count).await {
                        Ok(start) => start,
                        Err(error) => return self.reject(frontend, frame, error).await,
                    };
                    write.text_sql(start)
                } else {
                    write.sql
                };
                frame.body.clear();
                cstring(&mut frame.body, &sql);
                return self.guard_write(frontend, frame, write.operation).await;
            }
            Admission::WriteParse(operation, generated) => {
                return self
                    .parse(
                        frontend,
                        frame,
                        Some(StatementPolicy {
                            command: Command::Write(operation),
                            generated,
                        }),
                    )
                    .await;
            }
            Admission::Ready => transaction_control(&frame)?,
        };
        match frame.tag {
            b'P' => {
                return self
                    .parse(
                        frontend,
                        frame,
                        control.map(|command| StatementPolicy {
                            command,
                            generated: None,
                        }),
                    )
                    .await;
            }
            b'B' => return self.bind(frontend, frame).await,
            b'E' => return self.execute(frontend, frame).await,
            b'C' | b'D' if frame.body.first() == Some(&b'S') => {
                return self.target_statement(frontend, frame).await;
            }
            b'C' if frame.body.first() == Some(&b'P') => {
                let name = admission::name(&mut &frame.body[1..])?.to_owned();
                if self.forward(frontend, frame, Response::default()).await? {
                    self.portals.remove(&name);
                    self.explain_portals.remove(&name);
                }
                return Ok(());
            }
            _ => (),
        }
        let deallocate = frame.tag == b'Q' && frame.body == b"DEALLOCATE ALL\0";
        if self
            .forward(
                frontend,
                frame,
                Response {
                    control,
                    ..Response::default()
                },
            )
            .await?
            && deallocate
        {
            self.statements.clear();
            self.explain_statements.clear();
            self.handles.clear_statements();
        }
        Ok(())
    }

    async fn explain(
        &mut self,
        frontend: &mut (impl AsyncWrite + Unpin),
        frame: Frame,
        mapping: PlanMapping,
    ) -> io::Result<()> {
        if frame.tag == b'P' {
            let name = admission::name(&mut frame.body.as_slice())?.to_owned();
            if at_handle_capacity(&self.statements, &name) {
                return self.reject_handle_capacity(frontend).await;
            }
            if self.forward(frontend, frame, Response::default()).await? {
                self.statements.insert(name.clone(), None);
                self.explain_statements.insert(name, mapping);
            }
        } else {
            self.forward(
                frontend,
                frame,
                Response {
                    explain: Some(mapping),
                    ..Response::default()
                },
            )
            .await?;
        }
        Ok(())
    }

    async fn parse(
        &mut self,
        frontend: &mut (impl AsyncWrite + Unpin),
        frame: Frame,
        policy: Option<StatementPolicy>,
    ) -> io::Result<()> {
        let name = admission::name(&mut frame.body.as_slice())?.to_owned();
        if at_handle_capacity(&self.statements, &name) {
            return self.reject_handle_capacity(frontend).await;
        }
        if self.forward(frontend, frame, Response::default()).await? {
            self.explain_statements.remove(&name);
            self.statements.insert(name, policy);
        }
        Ok(())
    }

    async fn bind(
        &mut self,
        frontend: &mut (impl AsyncWrite + Unpin),
        frame: Frame,
    ) -> io::Result<()> {
        let name = admission::name(&mut frame.body.as_slice())?.to_owned();
        if at_handle_capacity(&self.portals, &name) {
            return self.reject_handle_capacity(frontend).await;
        }
        let explain = self
            .explain_statements
            .get(admission::bind_statement(&frame.body)?)
            .cloned();
        let policy = self
            .statements
            .get(admission::bind_statement(&frame.body)?)
            .copied()
            .flatten();
        let success = if let Some(generated) = policy.and_then(|policy| policy.generated) {
            self.bind_generated(frontend, frame, generated).await?
        } else {
            self.forward(frontend, frame, Response::default()).await?
        };
        if success {
            if let Some(mapping) = explain {
                self.explain_portals.insert(name.clone(), mapping);
            } else {
                self.explain_portals.remove(&name);
            }
            self.portals.insert(
                name,
                policy.map(|policy| PortalPolicy {
                    command: policy.command,
                    executed: false,
                }),
            );
        }
        Ok(())
    }

    async fn execute(
        &mut self,
        frontend: &mut (impl AsyncWrite + Unpin),
        frame: Frame,
    ) -> io::Result<()> {
        let (name, maximum) = admission::execute_target(&frame.body)?;
        let explain = self.explain_portals.get(name).cloned();
        let control = self
            .portals
            .get_mut(name)
            .and_then(Option::as_mut)
            .map(|portal| {
                let was_executed = portal.executed;
                portal.executed = true;
                (portal.command, was_executed)
            });
        match control {
            Some((Command::Write(_), true)) => {
                self.deny_write(frontend, b'E', WireError::Unsupported)
                    .await
            }
            Some((Command::Write(operation), false)) => {
                if maximum != 0 {
                    return self
                        .deny_write(frontend, b'E', WireError::Unsupported)
                        .await;
                }
                self.guard_write(frontend, frame, operation).await
            }
            _ => {
                self.forward(
                    frontend,
                    frame,
                    Response {
                        control: control.map(|(command, _)| command),
                        explain,
                        ..Response::default()
                    },
                )
                .await?;
                Ok(())
            }
        }
    }

    async fn bind_generated(
        &mut self,
        frontend: &mut (impl AsyncWrite + Unpin),
        mut frame: Frame,
        bind: GeneratedBind,
    ) -> io::Result<bool> {
        let Some(branch) = self.branch else {
            return Err(backend_error());
        };
        let prepared = BindWithGenerated::parse(&frame.body, bind.client_count);
        let (body, refusal) = match prepared {
            Ok(prepared) => match branch.allocate(bind.ids.table_id, bind.ids.count).await {
                Ok(start) => (prepared.with_start(start), None),
                Err(error) => (admission::refuse_generated_bind(&frame.body)?, Some(error)),
            },
            Err(_) => (
                admission::refuse_generated_bind(&frame.body)?,
                Some(WireError::Protocol),
            ),
        };
        frame.body = body;
        self.forward(
            frontend,
            frame,
            Response {
                refusal,
                ..Response::default()
            },
        )
        .await
    }

    async fn target_statement(
        &mut self,
        frontend: &mut (impl AsyncWrite + Unpin),
        frame: Frame,
    ) -> io::Result<()> {
        let name = admission::name(&mut &frame.body[1..])?.to_owned();
        let is_close = frame.tag == b'C';
        let hidden_type = self
            .statements
            .get(&name)
            .filter(|_| !is_close)
            .copied()
            .flatten()
            .and_then(|policy| policy.generated)
            .map(|bind| bind.client_count);
        if self
            .forward(
                frontend,
                frame,
                Response {
                    hidden_type,
                    refusal: None,
                    control: None,
                    explain: None,
                },
            )
            .await?
            && is_close
        {
            self.statements.remove(&name);
            self.explain_statements.remove(&name);
        }
        Ok(())
    }

    async fn reject_handle_capacity(
        &mut self,
        frontend: &mut (impl AsyncWrite + Unpin),
    ) -> io::Result<()> {
        // Sync must see a native failure so an earlier guarded Execute cannot commit.
        self.forward(
            frontend,
            failing_parse(),
            Response {
                refusal: Some(WireError::ResourceLimit),
                ..Response::default()
            },
        )
        .await?;
        Ok(())
    }

    async fn reject(
        &mut self,
        frontend: &mut (impl AsyncWrite + Unpin),
        frame: Frame,
        error: WireError,
    ) -> io::Result<()> {
        let tag = frame.tag;
        if matches!(
            error,
            WireError::Unsupported
                | WireError::SqlAt { .. }
                | WireError::SqlLimit { .. }
                | WireError::SqlSyntax
                | WireError::SqlObject
                | WireError::SqlFunction
                | WireError::IdsExhausted
                | WireError::Backend
                | WireError::Policy
        ) && matches!(tag, b'Q' | b'P')
        {
            let safe = refusal_frame(&frame)?;
            self.forward(
                frontend,
                safe,
                Response {
                    refusal: Some(error),
                    ..Response::default()
                },
            )
            .await?;
            return Ok(());
        }
        bounded(write_error(frontend, error, false)).await??;
        if tag == b'Q' {
            bounded(write_frame(frontend, b'Z', &[self.transaction])).await??;
        } else {
            self.skip_until_sync = true;
        }
        Ok(())
    }

    async fn forward(
        &mut self,
        frontend: &mut (impl AsyncWrite + Unpin),
        mut frame: Frame,
        response: Response,
    ) -> io::Result<bool> {
        let handle_change = self.handles.prepare(&mut frame)?;
        let tag = frame.tag;
        let committing = self.guarded_work
            && commits_guarded_work(
                tag,
                response.control,
                self.explicit,
                self.skip_until_sync,
                self.transaction,
            );
        let slot = self.slot;
        let cancel = slot.cancellation.subscribe();
        let _commit_guard = committing.then(|| guard::GuardCancellation::new(slot));
        if committing {
            if !self.ensure_witness().await? {
                let error = if guard::cancellation_pending(&cancel) {
                    WireError::Cancelled
                } else {
                    WireError::Backend
                };
                self.deny_write(frontend, if tag == b'S' { b'Q' } else { tag }, error)
                    .await?;
                return Ok(false);
            }
            if let Some(branch) = self.branch
                && let Err(error) = self.budget.fence_for_commit(branch).await
            {
                self.deny_write(frontend, if tag == b'S' { b'Q' } else { tag }, error)
                    .await?;
                return Ok(false);
            }
            let cancelled = {
                let _fence = self.slot.fence.lock().await;
                guard::cancellation_pending(&cancel)
            };
            if cancelled {
                self.deny_write(
                    frontend,
                    if tag == b'S' { b'Q' } else { tag },
                    WireError::Cancelled,
                )
                .await?;
                return Ok(false);
            }
            self.commit_in_flight = true;
        }
        bounded(write_frame(&mut self.backend, tag, &frame.body)).await??;
        if tag == b'H' {
            return Ok(true);
        }
        let cancelable = matches!(tag, b'Q' | b'E');
        if cancelable {
            self.slot.active.store(true, Ordering::Release);
        }
        let result = self.drain(frontend, tag, response).await;
        if matches!(result, Ok(true)) {
            self.handles.complete(handle_change);
        }
        if cancelable {
            let _fence = self.slot.fence.lock().await;
            self.slot.active.store(false, Ordering::Release);
        }
        if result.is_ok() {
            self.commit_in_flight = false;
        }
        result
    }

    async fn drain(
        &mut self,
        frontend: &mut (impl AsyncWrite + Unpin),
        tag: u8,
        response: Response,
    ) -> io::Result<bool> {
        if !matches!(tag, b'Q' | b'S') {
            // Extended replies may remain in the server's output buffer.
            bounded(write_frame(&mut self.backend, b'H', &[])).await??;
        }
        let mut success = true;
        let had_error = self.skip_until_sync;
        loop {
            let mut frame = bounded(read_frame(&mut self.backend)).await??;
            let received = frame.tag;
            if received == b'C' {
                self.observe_control(response.control, &frame.body).await;
            }
            if received == b'Z' && frame.body == b"I" {
                self.explicit = false;
                self.portals.clear();
                self.explain_portals.clear();
                self.handles.clear_portals();
                if self.guarded_work {
                    let outcome = if success && !had_error {
                        TransactionOutcome::Committed
                    } else {
                        TransactionOutcome::RolledBack
                    };
                    self.finish_work(outcome).await;
                }
            }
            if received == b't'
                && let Some(count) = response.hidden_type
            {
                admission::strip_generated_type(&mut frame.body, count)?;
            }
            if let Some(refusal) = response.refusal.filter(|_| received == b'E') {
                bounded(write_error(frontend, refusal, false)).await??;
            } else {
                if received == b'D'
                    && let Some(mapping) = &response.explain
                {
                    sanitize_plan_row(&mut frame.body, mapping)?;
                }
                self.relay(frontend, &mut frame).await?;
            }
            if received == b'E' {
                success = false;
                if !matches!(tag, b'Q' | b'S') {
                    self.skip_until_sync = true;
                    return Ok(false);
                }
            }
            if response_complete(tag, received) {
                return Ok(success);
            }
        }
    }

    async fn relay(
        &mut self,
        frontend: &mut (impl AsyncWrite + Unpin),
        frame: &mut Frame,
    ) -> io::Result<()> {
        match frame.tag {
            b'Z' if matches!(frame.body.as_slice(), b"I" | b"T" | b"E") => {
                self.transaction = frame.body[0];
                self.skip_until_sync = false;
            }
            b'T' => strip_row_identity(&mut frame.body)?,
            b'E' => {
                let is_writable = self
                    .branch
                    .is_some_and(|branch| branch.binding().write_schema.is_some());
                return relay_error(frontend, &frame.body, is_writable).await;
            }
            // Suppress native notices because they can carry physical identities
            // and application values outside the typed error boundary.
            b'N' => return Ok(()),
            b'S' => {
                if !public_parameter_status(&mut frame.body, self.frontend_user)? {
                    return Ok(());
                }
            }
            b'1' | b'2' | b'3' | b'C' | b'D' | b'H' | b'I' | b'c' | b'd' | b'n' | b's' | b't' => (),
            _ => return Err(backend_error()),
        }
        bounded(write_frame(frontend, frame.tag, &frame.body)).await?
    }
}

fn sanitize_plan_row(body: &mut Vec<u8>, mapping: &PlanMapping) -> io::Result<()> {
    if body.len() < 6 || body[..2] != 1u16.to_be_bytes() {
        return Err(backend_error());
    }
    let length = i32::from_be_bytes(body[2..6].try_into().map_err(|_| backend_error())?);
    if usize::try_from(length).ok() != Some(body.len() - 6) {
        return Err(backend_error());
    }
    let json = mapping.sanitize(&body[6..]).map_err(|_| backend_error())?;
    body.clear();
    body.extend(1u16.to_be_bytes());
    body.extend((json.len() as u32).to_be_bytes());
    body.extend(json);
    Ok(())
}

fn at_handle_capacity<T>(handles: &HashMap<String, T>, name: &str) -> bool {
    let unnamed = usize::from(handles.contains_key(""));
    !name.is_empty() && handles.len() >= MAX_NAMED_HANDLES + unnamed && !handles.contains_key(name)
}

fn failing_parse() -> Frame {
    let mut body = Vec::new();
    cstring(&mut body, FAILED_PARSE_NAME);
    cstring(&mut body, INVALID_NATIVE_QUERY);
    body.extend_from_slice(&[0, 0]);
    Frame { tag: b'P', body }
}

fn transaction_control(frame: &Frame) -> io::Result<Option<Command>> {
    if !matches!(frame.tag, b'P' | b'Q') {
        return Ok(None);
    }
    let mut body = frame.body.as_slice();
    if frame.tag == b'P' {
        admission::name(&mut body)?;
    }
    let sql = take_string(&mut body)?;
    let normalized = sql.to_ascii_uppercase();
    Ok(
        if normalized == "BEGIN"
            || normalized.starts_with("BEGIN ")
            || normalized.starts_with("START TRANSACTION")
        {
            Some(Command::Begin)
        } else if normalized == "COMMIT" {
            Some(Command::Commit)
        } else if normalized == "ROLLBACK" {
            Some(Command::Rollback)
        } else {
            None
        },
    )
}

fn commits_guarded_work(
    tag: u8,
    control: Option<Command>,
    explicit: bool,
    skipping: bool,
    transaction: u8,
) -> bool {
    transaction != b'E'
        && ((matches!(tag, b'Q' | b'E') && matches!(control, Some(Command::Commit)))
            || (tag == b'S' && !explicit && !skipping))
}

fn refusal_frame(frame: &Frame) -> io::Result<Frame> {
    let mut body = Vec::new();
    if frame.tag == b'P' {
        let statement = admission::name(&mut frame.body.as_slice())?;
        // PostgreSQL drops an earlier unnamed statement on a new unnamed Parse.
        cstring(&mut body, statement);
    }
    cstring(&mut body, INVALID_NATIVE_QUERY);
    if frame.tag == b'P' {
        body.extend_from_slice(&[0, 0]);
    }
    Ok(Frame {
        tag: frame.tag,
        body,
    })
}

fn response_complete(request: u8, response: u8) -> bool {
    match request {
        b'Q' | b'S' => response == b'Z',
        b'P' => response == b'1',
        b'B' => response == b'2',
        b'C' => response == b'3',
        b'D' => matches!(response, b'T' | b'n'),
        b'E' => matches!(response, b'C' | b'I' | b's'),
        _ => false,
    }
}

async fn relay_error(
    frontend: &mut (impl AsyncWrite + Unpin),
    mut body: &[u8],
    is_writable: bool,
) -> io::Result<()> {
    let mut code = WireError::Native.postgres();
    while let Some((&tag, rest)) = body.split_first() {
        body = rest;
        if tag == 0 {
            end(body)?;
            break;
        }
        let value = take_string(&mut body)?;
        if tag == b'C'
            && value.len() == 5
            && value
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        {
            code = value;
        }
    }
    let error = classify_native_error(code, is_writable);
    let message = error.to_string();
    let mut safe = Vec::new();
    for (tag, value) in [
        (b'S', "ERROR"),
        (b'V', "ERROR"),
        (b'C', code),
        (b'M', message.as_str()),
    ] {
        safe.push(tag);
        cstring(&mut safe, value);
    }
    safe.push(0);
    bounded(write_frame(frontend, b'E', &safe)).await?
}

fn classify_native_error(sqlstate: &str, is_writable: bool) -> WireError {
    match sqlstate {
        "25P02" => WireError::NativeClass(NativeErrorClass::TransactionAborted),
        "40P01" => WireError::NativeClass(NativeErrorClass::Deadlock),
        "55P03" => WireError::NativeClass(NativeErrorClass::LockTimeout),
        "42501" => WireError::NativeClass(NativeErrorClass::Permission),
        code if code.starts_with("08") => WireError::NativeClass(NativeErrorClass::Connection),
        code if code.starts_with("53") => WireError::NativeClass(NativeErrorClass::Resource),
        "23505" => WireError::Unique,
        "23503" if is_writable => WireError::ForeignKey,
        "22001" | "22003" | "22007" | "22008" | "22018" | "22021" | "22P02" | "22P03" | "23502"
        | "23514" | "42804"
            if is_writable =>
        {
            WireError::InvalidValue
        }
        _ => WireError::Native,
    }
}

async fn bounded<T>(operation: impl Future<Output = T>) -> io::Result<T> {
    timeout(IO_TIMEOUT, operation)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "PostgreSQL fixture I/O timed out"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_fixture_and_read_branch_error_categories() {
        for (sqlstate, writable) in [
            ("22P02", WireError::InvalidValue),
            ("23514", WireError::InvalidValue),
            ("23503", WireError::ForeignKey),
        ] {
            assert_eq!(classify_native_error(sqlstate, false), WireError::Native);
            assert_eq!(classify_native_error(sqlstate, true), writable);
        }
        assert_eq!(classify_native_error("23505", false), WireError::Unique);
        assert_eq!(classify_native_error("22012", true), WireError::Native);
        for writable in [false, true] {
            assert_eq!(
                classify_native_error("25P02", writable),
                WireError::NativeClass(NativeErrorClass::TransactionAborted)
            );
        }
    }

    #[tokio::test]
    async fn native_aborted_transaction_keeps_sqlstate_and_safe_rollback_guidance() -> io::Result<()>
    {
        let (mut frontend, mut writer) = tokio::io::duplex(4096);
        relay_error(
            &mut writer,
            b"SERROR\0C25P02\0Mprivate-value in fg_b901\0\0",
            true,
        )
        .await?;
        let frame = read_frame(&mut frontend).await?;
        assert_eq!(frame.tag, b'E');
        let body = String::from_utf8_lossy(&frame.body);
        assert!(body.contains("C25P02\0"));
        assert!(body.contains("[FORKGET FG-1005]"));
        assert!(body.contains("native_transaction_aborted"));
        assert!(body.contains("issue ROLLBACK"));
        for private in ["private-value", "fg_b901", "FG-5001"] {
            assert!(!body.contains(private));
        }
        Ok(())
    }

    #[test]
    fn native_cancellation_credentials_are_never_frontend_credentials() -> io::Result<()> {
        let map = Cancellations::default();
        let native_a = [1; 8];
        let native_b = [2; 8];
        let a = map.insert(native_a)?;
        let b = map.insert(native_b)?;
        let frontend_a = a.frontend_key;
        let mut forged = a.frontend_key;
        forged[7] ^= 1;
        assert!(map.find(native_a)?.is_none());
        assert!(map.find(native_b)?.is_none());
        assert!(map.find(forged)?.is_none());
        assert_eq!(
            map.find(frontend_a)?.map(|slot| slot.backend_key),
            Some(native_a)
        );
        assert_eq!(
            map.find(b.frontend_key)?.map(|slot| slot.backend_key),
            Some(native_b)
        );
        drop(a);
        assert!(map.find(frontend_a)?.is_none());
        assert!(map.find(b.frontend_key)?.is_some());
        Ok(())
    }

    #[test]
    fn refusal_preserves_unnamed_parse_lifetime_without_forwarding_sql() -> io::Result<()> {
        let rejected = Frame {
            tag: b'P',
            body: b"\0DROP TABLE fixture_items\0\0\0".to_vec(),
        };
        let frame = refusal_frame(&rejected)?;
        assert_eq!(frame.tag, b'P');
        assert_eq!(frame.body, b"\0SELECT )\0\0\0");
        Ok(())
    }

    #[test]
    fn handle_capacity_allows_unnamed_and_existing_handles() {
        let mut handles: HashMap<_, _> = (0..MAX_NAMED_HANDLES)
            .map(|index| (format!("statement_{index}"), ()))
            .collect();
        handles.insert(String::new(), ());
        assert!(at_handle_capacity(&handles, "new_statement"));
        assert!(!at_handle_capacity(&handles, "statement_0"));
        assert!(!at_handle_capacity(&handles, ""));
        handles.remove("statement_0");
        assert!(!at_handle_capacity(&handles, "new_statement"));
    }

    #[test]
    fn terminal_responses_distinguish_sync_from_portal_suspension() {
        assert!(!response_complete(b'S', b'E'));
        assert!(response_complete(b'S', b'Z'));
        assert!(!response_complete(b'Q', b'C'));
        assert!(response_complete(b'E', b's'));
        assert!(response_complete(b'D', b'n'));
        assert!(!response_complete(b'D', b't'));
    }

    #[test]
    fn witnesses_only_real_commit_boundaries_never_parse_or_flush() {
        for tag in [b'P', b'B', b'D', b'H'] {
            assert!(!commits_guarded_work(
                tag,
                Some(Command::Commit),
                false,
                false,
                b'T'
            ));
        }
        for tag in [b'Q', b'E'] {
            assert!(commits_guarded_work(
                tag,
                Some(Command::Commit),
                true,
                false,
                b'T'
            ));
            assert!(!commits_guarded_work(
                tag,
                Some(Command::Commit),
                true,
                false,
                b'E'
            ));
        }
        assert!(commits_guarded_work(b'S', None, false, false, b'I'));
        assert!(!commits_guarded_work(b'S', None, true, false, b'T'));
        assert!(!commits_guarded_work(b'S', None, false, true, b'I'));
        assert!(!commits_guarded_work(
            b'Q',
            Some(Command::Rollback),
            true,
            false,
            b'T'
        ));
    }
}
