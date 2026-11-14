//! MongoDB OP_MSG frontend that terminates the handshake, answers `hello` with a
//! standalone topology, verifies SCRAM-SHA-256 against the configured
//! frontend accounts, and serves the admitted branch command subset
//! over a service-account backend connection.

use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid MongoDB wire message")]
    Invalid,
    #[error("message exceeded {0} bytes")]
    Oversize(usize),
    #[error("unsupported wire opcode {0}")]
    Opcode(i32),
    #[error("io: {0}")]
    Io(#[from] io::Error),
}

pub const OPCODE_MSG: i32 = 2013;
pub const OPCODE_QUERY: i32 = 2004;
pub const OPCODE_REPLY: i32 = 1;
/// MongoDB 7.0 wire version; declared so drivers enable the modern feature
/// set while the proxy omits sessions and compression.
pub const MAX_WIRE_VERSION: i32 = 21;
pub const MIN_WIRE_VERSION: i32 = 0;
pub const MAX_BSON_OBJECT_SIZE: i32 = 16_777_216;
pub const MAX_MESSAGE_SIZE: usize = 48_000_000;
pub const MAX_READ_BUFFER: usize = 64 * 1024 * 1024;

mod admission;
mod backend;
mod command;
pub mod observation;
pub mod read;
pub mod scram;
mod session;
pub mod wire;
mod write;

pub use admission::{BranchConfig, serve_branches};
pub use session::{Account, Session, SpikeConfig, serve};
pub use wire::{
    Message, kind_zero_document, op_msg_body, op_reply_body, parse_op_msg, parse_op_query,
};
