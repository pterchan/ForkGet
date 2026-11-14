//! Differential execution and result comparison for the shared corpus.
//!
//! Pure logic only: the corpus model, statement splitting, canonical
//! observations, error classification, and the comparator. The binary in this
//! package drives the engines. `reference-versus-reference` mode validates the
//! harness itself; its evidence cannot establish proxy support, capability
//! promotion, or a release gate.

mod compare;
mod corpus;
mod observe;
mod split;

pub use compare::{Mismatch, StepOutcome, compare_step};
pub use corpus::{
    CorpusCase, ENGINE_MONGODB, ENGINE_MYSQL, ENGINE_POSTGRESQL, Expectation, RowOrder, Step,
    load_corpus,
};
pub use observe::{CanonValue, ColumnMeta, Observation, classify_error};
pub use split::split_statements;

/// Harness-level failures that are never a test observation: bad input files,
/// unusable selections, or transport-level engine failures.
#[derive(Debug, thiserror::Error)]
pub enum HarnessError {
    #[error("corpus file {path} is invalid: {message}")]
    InvalidCorpus { path: String, message: String },
    #[error("{0}")]
    Usage(String),
    #[error("engine transport failure on the {side} side: {message}")]
    Transport { side: &'static str, message: String },
    #[error("I/O failure: {0}")]
    Io(String),
}
