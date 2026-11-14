//! Bound the native write response until its transaction is authorized.

use std::io;

use fg_protocol_common::{
    TransactionOutcome, WireError, WriteKind, WriteOperation, witness_insert_sql,
};
use tokio::io::AsyncWrite;

use super::{
    CancelSlot, Command, Frame, INVALID_NATIVE_QUERY, Session, backend_error, bounded, cstring,
    failing_parse, read_frame, response_complete, take_string, write_error, write_frame,
};

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_RESPONSE_FRAMES: usize = 8192;

impl Session<'_> {
    pub(super) async fn guard_write(
        &mut self,
        frontend: &mut (impl AsyncWrite + Unpin),
        mut frame: Frame,
        operation: WriteOperation,
    ) -> io::Result<()> {
        let branch = self.branch.ok_or_else(backend_error)?;
        let tag = frame.tag;
        let policy = match branch.policy().await {
            Ok(policy) => policy,
            Err(error) => return self.deny_write(frontend, tag, error).await,
        };
        let hidden = tag == b'Q' && !self.explicit;
        if hidden {
            self.internal_query("BEGIN", b'T').await?;
        }
        let slot = self.slot;
        let mut cancel = slot.cancellation.subscribe();
        let guard = GuardCancellation::new(slot);
        self.handles.prepare(&mut frame)?;
        let mut captured = self.capture(frame, true).await?;
        if captured.has_error() {
            drop(guard);
            self.budget.native_error(branch, &policy, operation).await;
            self.guarded_work = self.budget.attempt().is_some();
            return self
                .native_write_failure(frontend, tag, hidden, captured)
                .await;
        }
        let rows = captured.rows(operation.kind)?;
        self.guarded_work = true;
        let explicit = self.explicit;
        let mut allowed = tokio::select! {
            biased;
            _ = cancel.changed() => Err(WireError::Cancelled),
            result = async {
                if explicit {
                    self.budget.evaluate(branch, &policy, operation, rows).await
                } else {
                    self.budget.evaluate_autocommit(branch, &policy, operation, rows).await
                }
            } => result,
        };
        {
            let _fence = slot.fence.lock().await;
            if cancellation_pending(&cancel) {
                allowed = Err(WireError::Cancelled);
            }
        }
        if let Err(error) = allowed {
            return self.deny_write(frontend, tag, error).await;
        }
        if hidden {
            if !self.ensure_witness().await? {
                let error = if cancellation_pending(&cancel) {
                    WireError::Cancelled
                } else {
                    WireError::Backend
                };
                return self.deny_write(frontend, tag, error).await;
            }
            if let Err(error) = self.budget.fence_for_commit(branch).await {
                return self.deny_write(frontend, tag, error).await;
            }
            {
                let _fence = slot.fence.lock().await;
                if cancellation_pending(&cancel) {
                    allowed = Err(WireError::Cancelled);
                }
            }
            if let Err(error) = allowed {
                return self.deny_write(frontend, tag, error).await;
            }
            self.commit_in_flight = true;
            let commit = self.capture(query("COMMIT"), false).await;
            let commit = match commit {
                Ok(commit) => commit,
                Err(error) => {
                    self.finish_work(TransactionOutcome::Unknown).await;
                    return Err(error);
                }
            };
            let outcome = if commit.has_error() {
                TransactionOutcome::RolledBack
            } else {
                TransactionOutcome::Committed
            };
            self.finish_work(outcome).await;
            if commit.has_error() {
                return self.relay_captured(frontend, commit).await;
            }
            captured.replace_ready(commit.ready().ok_or_else(backend_error)?)?;
        }
        drop(guard);
        self.relay_captured(frontend, captured).await
    }

    async fn native_write_failure(
        &mut self,
        frontend: &mut (impl AsyncWrite + Unpin),
        tag: u8,
        hidden: bool,
        mut captured: Captured,
    ) -> io::Result<()> {
        if hidden {
            self.internal_query("ROLLBACK", b'I').await?;
            self.finish_work(TransactionOutcome::RolledBack).await;
            captured.replace_ready(b'I')?;
        } else if tag == b'E' {
            self.skip_until_sync = true;
        }
        self.relay_captured(frontend, captured).await
    }

    pub(super) async fn deny_write(
        &mut self,
        frontend: &mut (impl AsyncWrite + Unpin),
        tag: u8,
        error: WireError,
    ) -> io::Result<()> {
        let explicit = self.explicit;
        if tag == b'E' {
            if !explicit {
                // Sync alone would commit previously completed Execute messages.
                if !self.capture(failing_parse(), false).await?.has_error() {
                    return Err(backend_error());
                }
            }
            let sync = self
                .capture(
                    Frame {
                        tag: b'S',
                        body: Vec::new(),
                    },
                    false,
                )
                .await?;
            if !explicit && sync.ready() != Some(b'I') {
                return Err(backend_error());
            }
        }
        if explicit || tag == b'Q' {
            self.internal_query("ROLLBACK", b'I').await?;
        }
        self.finish_work(TransactionOutcome::RolledBack).await;
        if explicit {
            // Preserve PostgreSQL's failed-transaction recovery contract while
            // ensuring all guarded work has already been rolled back. Drivers
            // can now issue their ordinary ROLLBACK without losing the original
            // policy refusal to a connection failure.
            self.internal_query("BEGIN", b'T').await?;
            let failed = self.capture(query(INVALID_NATIVE_QUERY), false).await?;
            if !failed.has_error() || failed.ready() != Some(b'E') {
                return Err(backend_error());
            }
        }
        self.transaction = if explicit { b'E' } else { b'I' };
        self.explicit = explicit;
        self.portals.clear();
        self.explain_portals.clear();
        self.handles.clear_portals();
        bounded(write_error(frontend, error, false)).await??;
        if tag == b'Q' {
            bounded(write_frame(frontend, b'Z', &[self.transaction])).await??;
        } else {
            self.local_sync = true;
            self.skip_until_sync = true;
        }
        Ok(())
    }

    pub(super) async fn finish_work(&mut self, outcome: TransactionOutcome) {
        self.commit_in_flight = false;
        let attempt = self.budget.take_attempt();
        self.budget.reset();
        self.guarded_work = false;
        if let (Some(branch), Some(attempt)) = (self.branch, attempt) {
            // Native facts survive audit transport failures. The metadata
            // intent and witness remain recoverable and block unsafe cleanup.
            let _ = branch.audit_outcome(&attempt, outcome).await;
        }
    }

    pub(super) async fn ensure_witness(&mut self) -> io::Result<bool> {
        let Some(attempt) = self.budget.attempt() else {
            return Ok(true);
        };
        let branch = self.branch.ok_or_else(backend_error)?;
        let Ok(sql) = witness_insert_sql(branch.binding(), attempt) else {
            return Ok(false);
        };
        self.slot.active.store(true, super::Ordering::Release);
        let result = super::witness::insert(&mut self.backend, &sql).await;
        let _fence = self.slot.fence.lock().await;
        self.slot.active.store(false, super::Ordering::Release);
        result
    }

    pub(super) async fn observe_control(&mut self, command: Option<Command>, tag: &[u8]) {
        match (command, tag) {
            (Some(Command::Begin), b"BEGIN\0" | b"START TRANSACTION\0") => self.explicit = true,
            (Some(Command::Commit), b"COMMIT\0") => {
                self.finish_work(TransactionOutcome::Committed).await;
                self.explicit = false;
                self.portals.clear();
                self.explain_portals.clear();
                self.handles.clear_portals();
            }
            (Some(Command::Rollback | Command::Commit), b"ROLLBACK\0") => {
                self.finish_work(TransactionOutcome::RolledBack).await;
                self.explicit = false;
                self.portals.clear();
                self.explain_portals.clear();
                self.handles.clear_portals();
            }
            _ => (),
        }
    }

    async fn internal_query(&mut self, sql: &str, expected: u8) -> io::Result<()> {
        let response = self.capture(query(sql), false).await?;
        if response.has_error() || response.ready() != Some(expected) {
            return Err(backend_error());
        }
        Ok(())
    }

    async fn capture(&mut self, frame: Frame, cancelable: bool) -> io::Result<Captured> {
        if cancelable {
            self.slot.active.store(true, super::Ordering::Release);
        }
        let result = self.capture_frames(frame).await;
        if cancelable {
            let _fence = self.slot.fence.lock().await;
            self.slot.active.store(false, super::Ordering::Release);
        }
        result
    }

    async fn capture_frames(&mut self, frame: Frame) -> io::Result<Captured> {
        let tag = frame.tag;
        bounded(write_frame(&mut self.backend, tag, &frame.body)).await??;
        let expects_ready = matches!(tag, b'Q' | b'S');
        if !expects_ready {
            bounded(write_frame(&mut self.backend, b'H', &[])).await??;
        }
        let mut bytes = 0;
        let mut frames = Vec::new();
        while frames.len() < MAX_RESPONSE_FRAMES {
            let next = bounded(read_frame(&mut self.backend)).await??;
            bytes += next.body.len();
            if bytes > MAX_RESPONSE_BYTES {
                return Err(backend_error());
            }
            let done = response_complete(tag, next.tag) || (next.tag == b'E' && !expects_ready);
            frames.push(next);
            if done {
                return Ok(Captured(frames));
            }
        }
        Err(backend_error())
    }

    async fn relay_captured(
        &mut self,
        frontend: &mut (impl AsyncWrite + Unpin),
        captured: Captured,
    ) -> io::Result<()> {
        for mut frame in captured.0 {
            self.relay(frontend, &mut frame).await?;
        }
        Ok(())
    }
}

fn query(sql: &str) -> Frame {
    let mut body = Vec::new();
    cstring(&mut body, sql);
    Frame { tag: b'Q', body }
}

struct Captured(Vec<Frame>);

impl Captured {
    fn has_error(&self) -> bool {
        self.0.iter().any(|frame| frame.tag == b'E')
    }

    fn ready(&self) -> Option<u8> {
        let frame = self.0.last()?;
        (frame.tag == b'Z' && frame.body.len() == 1).then(|| frame.body[0])
    }

    fn replace_ready(&mut self, ready: u8) -> io::Result<()> {
        let frame = self.0.last_mut().ok_or_else(backend_error)?;
        if frame.tag != b'Z' || frame.body.len() != 1 {
            return Err(backend_error());
        }
        frame.body[0] = ready;
        Ok(())
    }

    fn rows(&self, kind: WriteKind) -> io::Result<u64> {
        let completion = self
            .0
            .iter()
            .find(|frame| frame.tag == b'C')
            .ok_or_else(backend_error)?;
        let tag = take_string(&mut completion.body.as_slice())?;
        let prefix = match kind {
            WriteKind::Insert => "INSERT 0 ",
            WriteKind::Update => "UPDATE ",
            WriteKind::Delete => "DELETE ",
        };
        tag.strip_prefix(prefix)
            .and_then(|count| count.parse().ok())
            .ok_or_else(backend_error)
    }
}

pub(super) struct GuardCancellation<'a>(&'a CancelSlot);

impl<'a> GuardCancellation<'a> {
    pub(super) fn new(slot: &'a CancelSlot) -> Self {
        slot.guarded.store(true, super::Ordering::Release);
        Self(slot)
    }
}

pub(super) fn cancellation_pending(receiver: &tokio::sync::watch::Receiver<()>) -> bool {
    !matches!(receiver.has_changed(), Ok(false))
}

impl Drop for GuardCancellation<'_> {
    fn drop(&mut self) {
        self.0.guarded.store(false, super::Ordering::Release);
    }
}
