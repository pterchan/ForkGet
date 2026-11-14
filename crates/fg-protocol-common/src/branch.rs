use serde::{Deserialize, Serialize};

/// Drain native sessions before upgrading the coordinated write protocol.
pub const BRANCH_PROTOCOL_VERSION: u32 = 3;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BranchAccess {
    #[default]
    ReadOnly,
    ReadWrite,
}

impl BranchAccess {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::ReadWrite => "read_write",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "read_only" => Some(Self::ReadOnly),
            "read_write" => Some(Self::ReadWrite),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BranchLayout {
    #[default]
    SparseDelta,
    NativeCopy,
}

impl BranchLayout {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SparseDelta => "sparse_delta",
            Self::NativeCopy => "native_copy",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "sparse_delta" => Some(Self::SparseDelta),
            "native_copy" => Some(Self::NativeCopy),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadStrategy {
    #[default]
    Merge,
    BaseOnly,
}

impl ReadStrategy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Merge => "merge",
            Self::BaseOnly => "base_only",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "merge" => Some(Self::Merge),
            "base_only" => Some(Self::BaseOnly),
            _ => None,
        }
    }
}
