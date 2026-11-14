//! Hold a native write until the policy decision can no longer roll it back.

use std::io;

use fg_protocol_common::{
    BranchSession, MAX_GENERATED_ROWS, Policy, TransactionBudget, TransactionOutcome, WireError,
    WriteKind, WriteOperation, witness_insert_sql,
};
use fg_rewrite::{CompiledWrite, GeneratedIds, MYSQL_GENERATED_START};
use tokio::io::AsyncWrite;

use crate::{
    Flow, PING, QUERY,
    handshake::{ERR, OK},
    packet::{self, Fields},
    result::Relay,
    start_sql,
};

const IN_TRANSACTION: u16 = 0x0001;
const AUTOCOMMIT: u16 = 0x0002;
const IN_READ_ONLY_TRANSACTION: u16 = 0x2000;
const TRANSACTION_FLAGS: u16 = IN_TRANSACTION | AUTOCOMMIT | IN_READ_ONLY_TRANSACTION;

#[derive(Default)]
pub(crate) struct Transaction {
    budget: TransactionBudget,
    has_write: bool,
    commit_pending: bool,
    autocommit: bool,
    is_aborted: bool,
}

impl Transaction {
    async fn finish(&mut self, branch: &BranchSession, outcome: TransactionOutcome) {
        let attempt = self.budget.take_attempt();
        self.budget.reset();
        self.commit_pending = false;
        self.is_aborted = false;
        self.has_write = false;
        if let Some(attempt) = attempt {
            // A failed delivery leaves a durable intent and applies write
            // backpressure. It cannot turn a known native commit into rollback.
            let _ = branch.audit_outcome(&attempt, outcome).await;
        }
    }

    pub(crate) async fn close(&mut self, branch: &BranchSession) {
        let outcome = self.interrupted_outcome();
        self.finish(branch, outcome).await;
    }

    fn interrupted_outcome(&self) -> TransactionOutcome {
        if self.commit_pending {
            TransactionOutcome::Unknown
        } else {
            TransactionOutcome::RolledBack
        }
    }

    pub(crate) fn is_aborted(&self) -> bool {
        self.is_aborted
    }

    pub(crate) async fn control(
        &mut self,
        relay: &mut Relay<'_, impl AsyncWrite + Unpin>,
        branch: &BranchSession,
        sql: &[u8],
    ) -> io::Result<bool> {
        let outcome = match sql {
            b"BEGIN" | b"START TRANSACTION" | b"COMMIT" => Some(TransactionOutcome::Committed),
            b"SET AUTOCOMMIT=1" | b"SET AUTOCOMMIT = 1" | b"SET @@session.autocommit = ON" => {
                (!self.autocommit).then_some(TransactionOutcome::Committed)
            }
            b"SET AUTOCOMMIT=0" | b"SET AUTOCOMMIT = 0" | b"SET @@session.autocommit = OFF" => None,
            b"ROLLBACK" => Some(TransactionOutcome::RolledBack),
            _ => return Ok(false),
        };
        self.commit_pending =
            self.has_write && matches!(outcome, Some(TransactionOutcome::Committed));
        if self.commit_pending && !self.ensure_witness(relay, branch).await? {
            self.rollback(relay, branch).await?;
            relay.error(WireError::Backend).await?;
            return Ok(true);
        }
        // The attempt-bound fence checks fresh lease and policy authority
        // after the witness, even when ordinary authorization is cached.
        if self.commit_pending
            && let Err(error) = self.budget.fence_for_commit(branch).await
        {
            self.rollback(relay, branch).await?;
            relay.error(error).await?;
            return Ok(true);
        }
        let reply = internal_query(relay, sql).await?;
        if reply.first() == Some(&ERR) {
            if self.commit_pending {
                let status = ping_status(relay).await?;
                self.autocommit = status.autocommit();
                if !status.in_transaction() {
                    self.finish(branch, TransactionOutcome::Unknown).await;
                }
                self.commit_pending = false;
            }
            relay.native_error(&reply).await?;
        } else {
            let status = NativeOk::parse(&reply)?.status;
            self.autocommit = status.autocommit();
            // SET autocommit=1 has no commit effect if it was already enabled.
            if let Some(outcome) = outcome
                && (!sql.starts_with(b"SET ") || !status.in_transaction())
            {
                self.finish(branch, outcome).await;
            }
            self.commit_pending = false;
            relay.write(&reply).await?;
        }
        Ok(true)
    }

    async fn rollback(
        &mut self,
        relay: &mut Relay<'_, impl AsyncWrite + Unpin>,
        branch: &BranchSession,
    ) -> io::Result<()> {
        end_owned_transaction(relay, b"ROLLBACK").await?;
        self.finish(branch, TransactionOutcome::RolledBack).await;
        Ok(())
    }

    async fn ensure_witness(
        &self,
        relay: &mut Relay<'_, impl AsyncWrite + Unpin>,
        branch: &BranchSession,
    ) -> io::Result<bool> {
        let Some(attempt) = self.budget.attempt() else {
            return Ok(true);
        };
        let Ok(sql) = witness_insert_sql(branch.binding(), attempt) else {
            return Ok(false);
        };
        let reply = internal_query(relay, sql.as_bytes()).await?;
        if reply.first() == Some(&ERR) {
            return Ok(false);
        }
        let response = NativeOk::parse(&reply)?;
        if response.affected != 1 || !response.status.in_transaction() {
            return Err(packet::invalid());
        }
        Ok(true)
    }

    async fn deny(
        &mut self,
        relay: &mut Relay<'_, impl AsyncWrite + Unpin>,
        branch: &BranchSession,
        owns_transaction: bool,
        error: WireError,
    ) -> io::Result<Flow> {
        self.rollback(relay, branch).await?;
        // Preserve the refusal for drivers that automatically roll back after
        // a failed flush. Requiring their rollback also prevents a caller from
        // silently starting new work inside a transaction we already aborted.
        self.is_aborted = !owns_transaction;
        relay.error(error).await?;
        Ok(Flow::Continue)
    }
}

pub(crate) enum Write<'a> {
    Text(CompiledWrite),
    Prepared {
        command: &'a [u8],
        operation: WriteOperation,
        generated: Option<GeneratedIds>,
    },
}

impl Write<'_> {
    fn operation(&self) -> WriteOperation {
        match self {
            Self::Text(write) => write.operation,
            Self::Prepared { operation, .. } => *operation,
        }
    }

    async fn allocate(&self, branch: &BranchSession) -> Result<Option<i64>, WireError> {
        let generated = match self {
            Self::Text(write) => write.generated,
            Self::Prepared { generated, .. } => *generated,
        };
        match generated {
            Some(ids) => branch.allocate(ids.table_id, ids.count).await.map(Some),
            None => Ok(None),
        }
    }

    async fn start(
        self,
        relay: &mut Relay<'_, impl AsyncWrite + Unpin>,
        allocation: Option<i64>,
    ) -> io::Result<()> {
        match self {
            Self::Text(write) => {
                let sql = match allocation {
                    Some(start) => write.text_sql(start),
                    None => write.sql,
                };
                start_sql(relay, QUERY, sql.as_bytes()).await
            }
            Self::Prepared { command, .. } => {
                if let Some(start) = allocation {
                    let set = format!("SET {MYSQL_GENERATED_START} = CAST({start} AS SIGNED)");
                    start_sql(relay, QUERY, set.as_bytes()).await?;
                    relay.internal_ok().await?;
                }
                relay.start(command).await
            }
        }
    }
}

pub(crate) async fn execute(
    relay: &mut Relay<'_, impl AsyncWrite + Unpin>,
    transaction: &mut Transaction,
    branch: &BranchSession,
    write: Write<'_>,
) -> io::Result<Flow> {
    let operation = write.operation();
    let status = ping_status(relay).await?;
    transaction.autocommit = status.autocommit();
    let owns_transaction = status.autocommit() && !status.in_transaction();
    if !status.in_transaction() {
        // A native automatic rollback cannot have committed guarded work. Only
        // a previously dispatched commit boundary can leave its fact unknown.
        transaction.close(branch).await;
    }
    let policy = match branch.policy().await {
        Ok(policy) => policy,
        Err(error) => {
            return transaction
                .deny(relay, branch, owns_transaction, error)
                .await;
        }
    };
    let allocation = match write.allocate(branch).await {
        Ok(allocation) => allocation,
        Err(error) => {
            relay.error(error).await?;
            return Ok(Flow::Continue);
        }
    };
    if owns_transaction {
        begin_owned_transaction(relay).await?;
    }
    transaction.has_write = true;
    write.start(relay, allocation).await?;
    let mut reply = relay.read().await?;
    let measured = match reply.first() {
        Some(&ERR) => {
            transaction
                .budget
                .native_error(branch, &policy, operation)
                .await;
            if owns_transaction {
                transaction.rollback(relay, branch).await?;
            } else if !ping_status(relay).await?.in_transaction() {
                transaction
                    .finish(branch, TransactionOutcome::RolledBack)
                    .await;
            }
            relay.native_error(&reply).await?;
            return Ok(Flow::Continue);
        }
        Some(&OK) => NativeOk::parse(&reply)
            .and_then(|reply| reply.measure(operation.kind, relay.has_found_rows)),
        _ => return Err(packet::invalid()),
    };
    let rows = match measured {
        Ok(rows) => rows,
        Err(error) => {
            transaction.rollback(relay, branch).await?;
            return Err(error);
        }
    };
    let protected = ProtectedWrite {
        branch,
        policy,
        operation,
        rows,
        owns_transaction,
    };
    protected.finish(relay, transaction, &mut reply).await
}

struct ProtectedWrite<'a> {
    branch: &'a BranchSession,
    policy: Policy,
    operation: WriteOperation,
    rows: u64,
    owns_transaction: bool,
}

impl ProtectedWrite<'_> {
    async fn finish(
        self,
        relay: &mut Relay<'_, impl AsyncWrite + Unpin>,
        transaction: &mut Transaction,
        reply: &mut [u8],
    ) -> io::Result<Flow> {
        let evaluation = if self.owns_transaction {
            transaction
                .budget
                .evaluate_autocommit(self.branch, &self.policy, self.operation, self.rows)
                .await
        } else {
            transaction
                .budget
                .evaluate(self.branch, &self.policy, self.operation, self.rows)
                .await
        };
        if let Err(error) = evaluation {
            return transaction
                .deny(relay, self.branch, self.owns_transaction, error)
                .await;
        }
        if self.owns_transaction {
            if !transaction.ensure_witness(relay, self.branch).await? {
                return transaction
                    .deny(relay, self.branch, true, WireError::Backend)
                    .await;
            }
            if let Err(error) = transaction.budget.fence_for_commit(self.branch).await {
                return transaction
                    .deny(relay, self.branch, self.owns_transaction, error)
                    .await;
            }
            transaction.commit_pending = true;
            let commit = internal_query(relay, b"COMMIT").await?;
            if commit.first() == Some(&ERR) {
                transaction.commit_pending = false;
                transaction.rollback(relay, self.branch).await?;
                relay.native_error(&commit).await?;
                return Ok(Flow::Continue);
            }
            let status = NativeOk::parse(&commit)?.status;
            if status.in_transaction() {
                return Err(packet::invalid());
            }
            transaction
                .finish(self.branch, TransactionOutcome::Committed)
                .await;
            NativeOk::replace_transaction_status(reply, status)?;
        }
        relay.write(reply).await?;
        Ok(Flow::Continue)
    }
}

async fn internal_query(
    relay: &mut Relay<'_, impl AsyncWrite + Unpin>,
    sql: &[u8],
) -> io::Result<Vec<u8>> {
    start_sql(relay, QUERY, sql).await?;
    relay.read().await
}

async fn ping_status(relay: &mut Relay<'_, impl AsyncWrite + Unpin>) -> io::Result<Status> {
    relay.start(&[PING]).await?;
    NativeOk::parse(&relay.read().await?).map(|reply| reply.status)
}

async fn begin_owned_transaction(relay: &mut Relay<'_, impl AsyncWrite + Unpin>) -> io::Result<()> {
    let reply = internal_query(relay, b"START TRANSACTION").await?;
    if !NativeOk::parse(&reply)?.status.in_transaction() {
        return Err(packet::invalid());
    }
    Ok(())
}

async fn end_owned_transaction(
    relay: &mut Relay<'_, impl AsyncWrite + Unpin>,
    sql: &[u8],
) -> io::Result<Status> {
    let reply = internal_query(relay, sql).await?;
    let status = NativeOk::parse(&reply)?.status;
    if status.in_transaction() {
        return Err(packet::invalid());
    }
    Ok(status)
}

#[derive(Clone, Copy)]
struct Status(u16);

impl Status {
    fn in_transaction(self) -> bool {
        self.0 & IN_TRANSACTION != 0
    }

    fn autocommit(self) -> bool {
        self.0 & AUTOCOMMIT != 0
    }
}

struct NativeOk<'a> {
    affected: u64,
    status: Status,
    status_offset: usize,
    info: &'a [u8],
}

impl<'a> NativeOk<'a> {
    fn parse(packet: &'a [u8]) -> io::Result<Self> {
        let mut fields = Fields(packet);
        if fields.byte()? != OK {
            return Err(packet::invalid());
        }
        let affected = fields.lenenc_u64()?;
        fields.lenenc_u64()?;
        let status_offset = packet.len() - fields.0.len();
        let status = Status(fields.u16()?);
        fields.u16()?;
        Ok(Self {
            affected,
            status,
            status_offset,
            info: fields.0,
        })
    }

    fn measure(&self, kind: WriteKind, has_found_rows: bool) -> io::Result<u64> {
        let rows = match kind {
            WriteKind::Insert if (1..=u64::from(MAX_GENERATED_ROWS)).contains(&self.affected) => {
                Ok(self.affected)
            }
            WriteKind::Delete if self.affected <= 1 => Ok(self.affected),
            WriteKind::Update => self.measure_update(has_found_rows),
            _ => Err(packet::invalid()),
        };
        if let Ok(rows) = rows
            && rows > 0
            && !self.status.in_transaction()
        {
            tracing::warn!(
                affected = self.affected,
                status = self.status.0,
                "write accounting refused a reply outside an explicit transaction"
            );
            return Err(packet::invalid());
        }
        rows
    }

    fn measure_update(&self, has_found_rows: bool) -> io::Result<u64> {
        let mut payload = Fields(self.info);
        // MySQL 8.0.43 sends a length-encoded info field for both QUERY and
        // COM_STMT_EXECUTE. The writable native session fixes lc_messages.
        let text = str::from_utf8(payload.lenbytes()?)
            .map_err(|_| packet::invalid())
            .inspect_err(|_| {
                tracing::warn!(info = ?String::from_utf8_lossy(self.info).get(..64),
                    "update info field is not valid UTF-8");
            })?;
        let words = text.split_ascii_whitespace().collect::<Vec<_>>();
        let [
            "Rows",
            "matched:",
            matched,
            "Changed:",
            changed,
            "Warnings:",
            warnings,
        ] = words.as_slice()
        else {
            tracing::warn!(info = %text, "update info field does not match the accounting contract");
            return Err(packet::invalid());
        };
        let matched = matched.parse::<u64>().map_err(|_| packet::invalid())?;
        let changed = changed.parse::<u64>().map_err(|_| packet::invalid())?;
        let expected_affected = if has_found_rows { matched } else { changed };
        // TiDB counts cascaded foreign-key rows in Changed (matched 1,
        // changed 2 for one cascaded child), unlike MySQL; a no-op update has
        // changed 0 below matched. The budget then takes the conservative
        // maximum; the forwarded affected byte stays the engine's own report.
        if !payload.0.is_empty()
            || warnings.parse::<u16>().is_err()
            || matched > 1
            || self.affected != expected_affected
        {
            tracing::warn!(
                matched,
                changed,
                affected = self.affected,
                has_found_rows,
                trailing = payload.0.len(),
                "update accounting mismatch"
            );
            return Err(packet::invalid());
        }
        Ok(matched.max(changed))
    }

    fn replace_transaction_status(packet: &mut [u8], final_status: Status) -> io::Result<()> {
        let reply = NativeOk::parse(packet)?;
        let status = (reply.status.0 & !TRANSACTION_FLAGS) | (final_status.0 & TRANSACTION_FLAGS);
        let offset = reply.status_offset;
        packet[offset..offset + 2].copy_from_slice(&status.to_le_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_transaction_end_is_unknown_only_after_a_commit_boundary() {
        let mut transaction = Transaction::default();
        assert_eq!(
            transaction.interrupted_outcome(),
            TransactionOutcome::RolledBack
        );
        transaction.has_write = true;
        assert_eq!(
            transaction.interrupted_outcome(),
            TransactionOutcome::RolledBack
        );
        transaction.is_aborted = true;
        assert_eq!(
            transaction.interrupted_outcome(),
            TransactionOutcome::RolledBack
        );
        assert!(transaction.is_aborted());
        transaction.commit_pending = true;
        assert_eq!(
            transaction.interrupted_outcome(),
            TransactionOutcome::Unknown
        );
    }

    #[test]
    fn noop_updates_charge_native_matched_rows_for_both_client_capabilities() -> io::Result<()> {
        for affected in [0, 1] {
            let mut reply = vec![OK, affected, 0, 3, 0, 0, 0];
            packet::put_lenbytes(&mut reply, b"Rows matched: 1  Changed: 0  Warnings: 0");
            let response = NativeOk::parse(&reply)?;
            let has_found_rows = affected == 1;
            assert_eq!(response.measure(WriteKind::Update, has_found_rows)?, 1);
            assert!(
                response
                    .measure(WriteKind::Update, !has_found_rows)
                    .is_err()
            );
            assert_eq!(response.affected, u64::from(affected));
        }
        let mut inconsistent = vec![OK, 1, 0, 3, 0, 0, 0];
        packet::put_lenbytes(
            &mut inconsistent,
            b"Rows matched: 0  Changed: 0  Warnings: 0",
        );
        assert!(
            NativeOk::parse(&inconsistent)?
                .measure(WriteKind::Update, true)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn commit_status_replacement_keeps_insert_id_and_statement_flags() -> io::Result<()> {
        let mut reply = vec![OK, 1, 0xfe];
        reply.extend((1_u64 << 62).to_le_bytes());
        reply.extend([0x23, 0, 2, 0]);
        let original = reply.clone();
        NativeOk::replace_transaction_status(&mut reply, Status(AUTOCOMMIT))?;
        assert_eq!(&reply[..11], &original[..11]);
        assert_eq!(&reply[11..], &[0x22, 0, 2, 0]);
        Ok(())
    }
}
