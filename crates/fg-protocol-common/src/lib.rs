//! Shared wire errors, transport inputs, and local branch routing.

mod errors;
pub use errors::{
    INVALID_CONTEXT_CODE, NativeErrorClass, SqlErrorKind, SqlLimit, UNSUPPORTED_TABLE_CODE,
    WireError,
};

#[cfg(feature = "routing")]
mod snapshot;
#[cfg(feature = "routing")]
pub use snapshot::{
    CheckSpec, CollectionManifest, ColumnDefault, ColumnSpec, DocumentSnapshot, ForeignKeySpec,
    IndexSpec, ReferentialAction, SNAPSHOT_FORMAT_VERSION, SnapshotAdmissionError,
    SnapshotManifest, SnapshotType, TableManifest, snapshot_identifier,
};

#[cfg(feature = "routing")]
mod write_target;
#[cfg(feature = "routing")]
pub use write_target::{MYSQL_WRITE_SCHEMA, WriteTarget};
#[cfg(feature = "routing")]
mod witness;
#[cfg(feature = "routing")]
pub use witness::{
    TXN_WITNESS_FORMAT, TXN_WITNESS_TABLE, valid_witness_identity, witness_insert_sql,
};

pub const GENERATED_ID_START: i64 = 1_i64 << 62;
pub const GENERATED_ID_MAX: i64 = i64::MAX - 1;
pub const MAX_GENERATED_ROWS: u16 = 1024;
pub const BUILD_REVISION: &str = match option_env!("FG_GATE_BUILD_REVISION") {
    Some(revision) => revision,
    None => "unavailable",
};

#[cfg(feature = "transport")]
mod transport;
#[cfg(feature = "transport")]
pub use transport::{BRANCH, Config, HANDSHAKE_TIMEOUT, IO_TIMEOUT, MAX_SESSIONS};

#[cfg(feature = "routing")]
mod managed;
#[cfg(feature = "routing")]
pub use managed::{MANAGED_BACKEND_HOST, ManagedBackend, valid_managed_role};
#[cfg(feature = "routing")]
mod artifact;
#[cfg(feature = "routing")]
mod audit;
#[cfg(feature = "routing")]
mod branch;
#[cfg(feature = "routing")]
mod policy;
#[cfg(feature = "routing")]
pub use artifact::{
    ARTIFACT_LIMIT, ARTIFACT_RECORD_LIMIT, ARTIFACT_VERSION, ArtifactEnd, ArtifactEntry,
    ArtifactHeader, ArtifactReader, ArtifactRecord, ArtifactTable, ArtifactWriter, ChangeOperation,
    DocumentChange, ReplayIds, ReplayPermit, ReplayResolve, ReplaySession, ReplayStatement,
    TypedChange, bson_document, bson_key, encode_bson, native_type, replay_order, replay_statement,
    validate_document_change, validate_replay_change,
};
#[cfg(feature = "routing")]
pub use audit::{
    AUDIT_WITNESS_VERSION, AuditAttempt, AuditAttemptContext, AuditMode, AuditStatus,
    AuditStatusRequest, AuditedDecisionRequest, AuditedDecisionResponse, AuditedOutcomeRequest,
    MongoObservationState, MongoStepAck, MongoStepRequest, MongoWriteObservation,
    NativeWitnessBinding, OutcomeAck, WriteFenceRequest, WriteFenceResponse,
};
#[cfg(feature = "routing")]
mod routing;
#[cfg(feature = "routing")]
pub use branch::{BRANCH_PROTOCOL_VERSION, BranchAccess, BranchLayout, ReadStrategy};
#[cfg(feature = "routing")]
pub use policy::{
    ApprovalContext, ApprovalState, BranchClass, CreateBudgetRequest, DecisionRequest,
    DecisionResponse, DecisionVerdict, OutcomeRequest, Policy, PolicyContext, ProxyEpoch,
    TransactionBudget, TransactionOutcome, UpdatePolicy, WriteKind, WriteOperation,
};
#[cfg(feature = "routing")]
pub use routing::{
    AllocateIds, AllocatedIds, BranchBinding, BranchGrantCheck, BranchSession, CatalogColumn,
    CatalogEntry, CheckBranch, DiffRequest, FrontendAccount, PendingSession, ReplayOrigin,
    ResolveBranch, Router, bearer_matches, credential_current, gate_order_count, loopback_client,
    loopback_http, valid_branch_name,
};
