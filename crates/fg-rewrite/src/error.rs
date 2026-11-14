use fg_protocol_common::{INVALID_CONTEXT_CODE, UNSUPPORTED_TABLE_CODE};
use thiserror::Error;

/// Stable library errors; wire adapters encode protocol-specific error packets.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum RewriteError {
    #[error("[FORKGET {INVALID_CONTEXT_CODE}] Branch ID must be a positive metadata BIGINT")]
    InvalidBranchId,
    #[error(
        "[FORKGET {INVALID_CONTEXT_CODE}] Reload catalog metadata: identifiers must be nonempty and contain no NUL"
    )]
    InvalidIdentifier,
    #[error(
        "[FORKGET {INVALID_CONTEXT_CODE}] Reload catalog metadata: a table needs an explicit column list"
    )]
    EmptyProjection,
    #[error(
        "[FORKGET {INVALID_CONTEXT_CODE}] Reload catalog metadata: projected columns must be distinct"
    )]
    DuplicateColumn,
    #[error(
        "[FORKGET {INVALID_CONTEXT_CODE}] Reload catalog metadata: primary-key columns must be distinct projected columns"
    )]
    InvalidPrimaryKey,
    #[error(
        "[FORKGET {UNSUPPORTED_TABLE_CODE}] Tables without a primary key are unsupported; register a table with a non-null primary key"
    )]
    MissingPrimaryKey,
    #[error(
        "[FORKGET {UNSUPPORTED_TABLE_CODE}] Columns starting with _fg_ are reserved; rename them before registering this table"
    )]
    ReservedColumn,
}

impl RewriteError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::MissingPrimaryKey | Self::ReservedColumn => UNSUPPORTED_TABLE_CODE,
            _ => INVALID_CONTEXT_CODE,
        }
    }
}
