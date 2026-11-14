use thiserror::Error;

pub const UNSUPPORTED_TABLE_CODE: &str = "FG-2002";
pub const INVALID_CONTEXT_CODE: &str = "FG-2003";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqlErrorKind {
    Syntax,
    Unsupported,
    Object,
    Function,
}

impl SqlErrorKind {
    const fn wire(self) -> WireError {
        match self {
            Self::Syntax => WireError::SqlSyntax,
            Self::Unsupported => WireError::Unsupported,
            Self::Object => WireError::SqlObject,
            Self::Function => WireError::SqlFunction,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqlLimit {
    Bytes,
    Tokens,
    BindParameters,
    BulkRows,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeErrorClass {
    TransactionAborted,
    Deadlock,
    LockTimeout,
    Permission,
    Connection,
    Resource,
}

impl NativeErrorClass {
    const fn reason(self) -> &'static str {
        match self {
            Self::TransactionAborted => "native_transaction_aborted",
            Self::Deadlock => "native_deadlock",
            Self::LockTimeout => "native_lock_timeout",
            Self::Permission => "native_permission_denied",
            Self::Connection => "native_connection_failure",
            Self::Resource => "native_resource_limit",
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::TransactionAborted => {
                "[FORKGET FG-1005] Native transaction is aborted; issue ROLLBACK before continuing"
            }
            Self::Deadlock => {
                "[FORKGET FG-1005] Native deadlock; roll back and retry the whole transaction"
            }
            Self::LockTimeout => {
                "[FORKGET FG-1005] Native lock wait timed out; roll back before retrying"
            }
            Self::Permission => {
                "[FORKGET FG-1005] Native permission denied; ask the operator to check backend role grants"
            }
            Self::Connection => {
                "[FORKGET FG-1005] Native connection failed; reconnect after backend readiness recovers"
            }
            Self::Resource => {
                "[FORKGET FG-1005] Native resource limit reached; ask the operator to check backend capacity"
            }
        }
    }
}

impl SqlLimit {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Bytes => "sql_bytes",
            Self::Tokens => "sql_tokens",
            Self::BindParameters => "bind_parameters",
            Self::BulkRows => "insert_rows",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("{} (reason={})", self.message(), self.reason())]
pub enum WireError {
    Auth,
    Branch,
    Unsupported,
    Protocol,
    Backend,
    Native,
    NativeClass(NativeErrorClass),
    ResourceLimit,
    Unique,
    ForeignKey,
    IdsExhausted,
    InvalidValue,
    SqlSyntax,
    SqlObject,
    SqlFunction,
    Policy,
    ReadOnly,
    AuditStorageUnprepared,
    TransactionAborted,
    #[error("{} (reason={}, statement_line={line}, statement_column={column}, position_scope=statement_start)", kind.wire().message(), kind.wire().reason())]
    SqlAt {
        kind: SqlErrorKind,
        line: u32,
        column: u32,
    },
    #[error("[FORKGET FG-2002] SQL capability limit exceeded (reason=sql_capability_limit, capability={}, actual={actual}, limit={limit}); split the operation within the published limits", kind.name())]
    SqlLimit {
        kind: SqlLimit,
        actual: u64,
        limit: u64,
    },
    RowLimit,
    #[error(
        "[FORKGET {}] Transaction row budget exceeded: cumulative rows {rows} > max_transaction_rows {limit}; request a temporary branch budget (reason=transaction_row_budget)",
        self.code()
    )]
    TransactionRowLimit {
        rows: u64,
        limit: u64,
    },
    #[error(
        "[FORKGET {}] Table row share budget exceeded: cumulative table rows {rows} > limit {limit} (baseline_rows={baseline}, table_limit_bps={bps}); request a temporary branch budget (reason=table_row_budget)",
        self.code()
    )]
    TableRowLimit {
        rows: u64,
        limit: u128,
        baseline: u64,
        bps: u16,
    },
    Approval,
    Cancelled,
}

impl WireError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::SqlAt { kind, .. } => kind.wire().code(),
            Self::SqlLimit { .. } => UNSUPPORTED_TABLE_CODE,
            Self::Auth => "FG-1002",
            Self::Protocol => "FG-1003",
            Self::Backend => "FG-1004",
            Self::Native | Self::NativeClass(_) => "FG-1005",
            Self::ResourceLimit => "FG-1006",
            Self::SqlSyntax => "FG-2001",
            Self::Unsupported => UNSUPPORTED_TABLE_CODE,
            Self::Branch | Self::SqlObject => INVALID_CONTEXT_CODE,
            Self::SqlFunction => "FG-2004",
            Self::Unique => "FG-3001",
            Self::ForeignKey => "FG-3002",
            Self::IdsExhausted => "FG-3003",
            Self::InvalidValue => "FG-3004",
            Self::Policy
            | Self::ReadOnly
            | Self::AuditStorageUnprepared
            | Self::TransactionAborted => "FG-5001",
            Self::RowLimit | Self::TransactionRowLimit { .. } | Self::TableRowLimit { .. } => {
                "FG-5002"
            }
            Self::Approval | Self::Cancelled => "FG-5003",
        }
    }

    pub const fn mysql(self) -> (u16, &'static str) {
        match self {
            Self::SqlAt { kind, .. } => kind.wire().mysql(),
            Self::SqlLimit { .. } => WireError::Unsupported.mysql(),
            Self::Auth => (1045, "28000"),
            Self::Branch => (1044, "42000"),
            Self::Unsupported => (1235, "42000"),
            Self::Protocol => (1043, "08S01"),
            Self::Backend => (1040, "08004"),
            Self::Native | Self::NativeClass(_) => (1105, "HY000"),
            Self::ResourceLimit => (1461, "42000"),
            Self::Unique => (1062, "23000"),
            Self::ForeignKey => (1452, "23000"),
            Self::IdsExhausted => (1467, "HY000"),
            Self::InvalidValue => (1264, "22003"),
            Self::SqlSyntax => (1064, "42000"),
            Self::SqlObject => (1146, "42S02"),
            Self::SqlFunction => (1235, "42000"),
            Self::Policy | Self::ReadOnly | Self::AuditStorageUnprepared => (1142, "42000"),
            Self::TransactionAborted => (1644, "45000"),
            Self::RowLimit
            | Self::TransactionRowLimit { .. }
            | Self::TableRowLimit { .. }
            | Self::Approval => (1644, "45000"),
            Self::Cancelled => (1317, "70100"),
        }
    }

    pub const fn postgres(self) -> &'static str {
        match self {
            Self::SqlAt { kind, .. } => kind.wire().postgres(),
            Self::SqlLimit { .. } => WireError::Unsupported.postgres(),
            Self::Auth => "28P01",
            Self::Branch => "3D000",
            Self::Unsupported => "0A000",
            Self::Protocol => "08P01",
            Self::Backend => "08006",
            Self::NativeClass(NativeErrorClass::TransactionAborted) => "25P02",
            Self::Native | Self::NativeClass(_) => "XX000",
            Self::Unique => "23505",
            Self::ForeignKey => "23503",
            Self::IdsExhausted => "2200H",
            Self::InvalidValue => "22003",
            Self::SqlSyntax => "42601",
            Self::SqlObject => "42P01",
            Self::SqlFunction => "0A000",
            Self::Policy | Self::ReadOnly | Self::AuditStorageUnprepared | Self::Approval => {
                "42501"
            }
            Self::TransactionAborted => "25P02",
            Self::RowLimit
            | Self::TransactionRowLimit { .. }
            | Self::TableRowLimit { .. }
            | Self::ResourceLimit => "54000",
            Self::Cancelled => "57014",
        }
    }

    /// Mongo numeric codes from the mongod error registry; the
    /// FG code itself rides the errmsg text so users can act on refusals.
    pub const fn mongo(self) -> i32 {
        match self {
            Self::SqlAt { kind, .. } => kind.wire().mongo(),
            Self::SqlLimit { .. } => WireError::Unsupported.mongo(),
            Self::Auth => 18,                          // AuthenticationFailed
            Self::Branch | Self::SqlObject => 26,      // NamespaceNotFound: a branch is a database
            Self::Unique => 11000,                     // DuplicateKey
            Self::InvalidValue => 2,                   // BadValue
            Self::Protocol | Self::Backend => 6,       // HostUnreachable
            Self::Native | Self::NativeClass(_) => 76, // ClientOperationFailed
            Self::ForeignKey
            | Self::IdsExhausted
            | Self::ResourceLimit
            | Self::RowLimit
            | Self::TransactionRowLimit { .. }
            | Self::TableRowLimit { .. }
            | Self::Unsupported
            | Self::SqlSyntax
            | Self::SqlFunction
            | Self::Policy
            | Self::ReadOnly
            | Self::AuditStorageUnprepared
            | Self::TransactionAborted
            | Self::Approval
            | Self::Cancelled => 20, // IllegalOperation
        }
    }

    pub const fn message(self) -> &'static str {
        match self {
            Self::SqlAt { kind, .. } => kind.wire().message(),
            Self::SqlLimit { .. } => "[FORKGET FG-2002] SQL capability limit exceeded",
            Self::Auth => "[FORKGET FG-1002] Authentication failed",
            Self::Branch => "[FORKGET FG-2003] Branch is unavailable for this principal",
            Self::Unsupported => "[FORKGET FG-2002] Use a supported statement or protocol command",
            Self::Protocol => "[FORKGET FG-1003] Invalid protocol message",
            Self::Backend => "[FORKGET FG-1004] Branch service or backend is unavailable",
            Self::Native => "[FORKGET FG-1005] Statement failed in the native engine",
            Self::NativeClass(class) => class.message(),
            Self::ResourceLimit => "[FORKGET FG-1006] Close unused statement or portal handles",
            Self::Unique => "[FORKGET FG-3001] Duplicate key",
            Self::ForeignKey => "[FORKGET FG-3002] Foreign key constraint failed",
            Self::IdsExhausted => "[FORKGET FG-3003] Generated key range exhausted",
            Self::InvalidValue => "[FORKGET FG-3004] Value violates the registered write layout",
            Self::SqlSyntax => "[FORKGET FG-2001] Use one statement in the supported SQL dialect",
            Self::SqlObject => "[FORKGET FG-2003] Use a registered logical table and column",
            Self::SqlFunction => "[FORKGET FG-2004] Use a supported read-only SQL function",
            Self::Policy => "[FORKGET FG-5001] The branch policy denied the operation",
            Self::ReadOnly => {
                "[FORKGET FG-5001] This branch is read-only; create a writable branch with --write"
            }
            Self::AuditStorageUnprepared => {
                "[FORKGET FG-5001] Write audit storage is unprepared; ask the operator to run fg-control audit prepare for this branch"
            }
            Self::TransactionAborted => {
                "[FORKGET FG-5001] The transaction was rolled back; issue ROLLBACK before continuing"
            }
            Self::RowLimit => {
                "[FORKGET FG-5002] The write exceeds a transaction or table row budget"
            }
            Self::TransactionRowLimit { .. } => {
                "[FORKGET FG-5002] The write exceeds max_transaction_rows"
            }
            Self::TableRowLimit { .. } => "[FORKGET FG-5002] The write exceeds table_limit_bps",
            Self::Approval => "[FORKGET FG-5003] Approval was denied, expired, or invalidated",
            Self::Cancelled => "[FORKGET FG-5003] The guarded operation was cancelled",
        }
    }

    /// Stable, value-free refusal reasons for native clients and diagnostics.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::SqlAt { kind, .. } => kind.wire().reason(),
            Self::SqlLimit { .. } => "sql_capability_limit",
            Self::Auth => "authentication_failed",
            Self::Branch => "branch_unavailable",
            Self::Unsupported => "unsupported_statement_or_command",
            Self::Protocol => "invalid_protocol",
            Self::Backend => "dependency_unavailable",
            Self::Native => "native_statement_failure",
            Self::NativeClass(class) => class.reason(),
            Self::ResourceLimit => "session_handle_limit",
            Self::Unique => "native_unique_constraint",
            Self::ForeignKey => "native_foreign_key_constraint",
            Self::IdsExhausted => "generated_key_exhausted",
            Self::InvalidValue => "native_value_constraint",
            Self::SqlSyntax => "invalid_sql_shape",
            Self::SqlObject => "unregistered_logical_object",
            Self::SqlFunction => "unsupported_sql_function",
            Self::Policy => "policy_context_denied",
            Self::ReadOnly => "branch_read_only",
            Self::AuditStorageUnprepared => "audit_storage_unprepared",
            Self::TransactionAborted => "transaction_requires_rollback",
            Self::RowLimit => "direct_row_budget",
            Self::TransactionRowLimit { .. } => "transaction_row_budget",
            Self::TableRowLimit { .. } => "table_row_budget",
            Self::Approval => "approval_unavailable",
            Self::Cancelled => "operation_cancelled",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{INVALID_CONTEXT_CODE, UNSUPPORTED_TABLE_CODE, WireError};

    #[test]
    fn existing_error_codes_match_wire_messages() {
        assert!(WireError::Branch.message().contains(INVALID_CONTEXT_CODE));
        assert!(
            WireError::Unsupported
                .message()
                .contains(UNSUPPORTED_TABLE_CODE)
        );
    }

    #[test]
    fn row_limit_details_preserve_registered_wire_codes() {
        let transaction = WireError::TransactionRowLimit { rows: 3, limit: 2 };
        let table = WireError::TableRowLimit {
            rows: 2,
            limit: 1,
            baseline: 4,
            bps: 1000,
        };
        for error in [transaction, table] {
            assert_eq!(error.code(), WireError::RowLimit.code());
            assert_eq!(error.mysql(), WireError::RowLimit.mysql());
            assert_eq!(error.postgres(), WireError::RowLimit.postgres());
            assert!(error.to_string().contains(error.code()));
        }
        assert!(
            transaction
                .to_string()
                .contains("cumulative rows 3 > max_transaction_rows 2")
        );
        assert!(
            table
                .to_string()
                .contains("cumulative table rows 2 > limit 1")
        );
        assert!(
            table
                .to_string()
                .contains("baseline_rows=4, table_limit_bps=1000")
        );
    }

    #[test]
    fn diagnostics_distinguish_access_native_category_and_capability_limits() {
        use super::{NativeErrorClass, SqlErrorKind, SqlLimit};
        assert_eq!(WireError::ReadOnly.code(), WireError::Policy.code());
        assert!(
            WireError::ReadOnly
                .to_string()
                .contains("reason=branch_read_only")
        );
        assert!(
            WireError::TransactionAborted
                .to_string()
                .contains("issue ROLLBACK")
        );
        let native = WireError::NativeClass(NativeErrorClass::Deadlock);
        assert_eq!(native.code(), WireError::Native.code());
        assert!(native.to_string().contains("reason=native_deadlock"));
        let aborted = WireError::NativeClass(NativeErrorClass::TransactionAborted);
        assert_eq!(aborted.code(), "FG-1005");
        assert_eq!(aborted.postgres(), "25P02");
        assert!(
            aborted
                .to_string()
                .contains("reason=native_transaction_aborted")
        );
        assert!(aborted.to_string().contains("issue ROLLBACK"));
        assert_eq!(WireError::TransactionAborted.code(), "FG-5001");
        assert_eq!(
            WireError::TransactionAborted.reason(),
            "transaction_requires_rollback"
        );
        let positioned = WireError::SqlAt {
            kind: SqlErrorKind::Object,
            line: 2,
            column: 7,
        };
        assert_eq!(positioned.postgres(), WireError::SqlObject.postgres());
        assert!(
            positioned
                .to_string()
                .contains("statement_line=2, statement_column=7")
        );
        let limit = WireError::SqlLimit {
            kind: SqlLimit::BindParameters,
            actual: 16_385,
            limit: 16_384,
        };
        assert_eq!(limit.mysql(), WireError::Unsupported.mysql());
        assert!(
            limit
                .to_string()
                .contains("capability=bind_parameters, actual=16385, limit=16384")
        );
    }
}
