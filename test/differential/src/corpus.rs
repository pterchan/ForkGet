//! Typed JSON corpus model for SQL statements and MongoDB commands.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::HarnessError;

pub const ENGINE_MYSQL: &str = "mysql";
pub const ENGINE_POSTGRESQL: &str = "postgresql";
pub const ENGINE_MONGODB: &str = "mongodb";

/// One differential scenario. `capabilities` may be empty: reference-mode
/// engine-semantics cases verify the harness, not a Forkget capability, and
/// must not claim capability evidence.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CorpusCase {
    pub id: String,
    pub tags: Vec<String>,
    pub engines: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    pub fixture: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub setup: Vec<String>,
    pub steps: Vec<Step>,
}

impl CorpusCase {
    pub fn supports_engine(&self, engine: &str) -> bool {
        self.engines.iter().any(|candidate| candidate == engine)
    }
}

/// One executed step. SQL engines take a statement; MongoDB takes a
/// command body: the runner assembles `{command: <collection>,
/// ...document, $db: <namespace>}`. The untagged form keeps existing SQL
/// corpus files byte-identical.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Step {
    Sql {
        sql: String,
        expect: Expectation,
    },
    Command {
        command: String,
        collection: String,
        #[serde(default)]
        document: serde_json::Value,
        expect: Expectation,
    },
}

impl Step {
    pub fn expect(&self) -> &Expectation {
        match self {
            Step::Sql { expect, .. } | Step::Command { expect, .. } => expect,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Expectation {
    /// Compare result rows (column names, types, values, duplicate counts).
    Rows { order: RowOrder },
    /// Compare the affected-row count.
    Affected { count: u64 },
    /// Expect an engine rejection and compare its stable class.
    Error { class: String },
    /// A Forkget refusal. The reference engine does not execute this SQL.
    ProxyRefusal {
        fg: String,
        sqlstate: String,
        #[serde(default)]
        errno: Option<u16>,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RowOrder {
    /// The statement guarantees a deterministic total order.
    Total,
    /// Compare row multisets; duplicate multiplicity is preserved.
    Multiset,
}

/// Load every `*.json` corpus file under `directory` (sorted by path) and
/// reject duplicate case ids so selection is unambiguous.
pub fn load_corpus(directory: &Path) -> Result<Vec<CorpusCase>, HarnessError> {
    let mut paths = Vec::new();
    collect_json_files(directory, &mut paths)?;
    paths.sort();
    if paths.is_empty() {
        return Err(HarnessError::InvalidCorpus {
            path: directory.display().to_string(),
            message: "no corpus files found".to_string(),
        });
    }

    let mut cases = Vec::new();
    let mut seen = std::collections::BTreeMap::new();
    for path in paths {
        let text = fs::read_to_string(&path).map_err(|error| HarnessError::InvalidCorpus {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
        let parsed: Vec<CorpusCase> =
            serde_json::from_str(&text).map_err(|error| HarnessError::InvalidCorpus {
                path: path.display().to_string(),
                message: error.to_string(),
            })?;
        for case in parsed {
            if seen
                .insert(case.id.clone(), path.display().to_string())
                .is_some()
            {
                return Err(HarnessError::InvalidCorpus {
                    path: path.display().to_string(),
                    message: format!("duplicate case id '{}'", case.id),
                });
            }
            cases.push(case);
        }
    }
    Ok(cases)
}

fn collect_json_files(
    directory: &Path,
    paths: &mut Vec<std::path::PathBuf>,
) -> Result<(), HarnessError> {
    let entries = fs::read_dir(directory).map_err(|error| HarnessError::InvalidCorpus {
        path: directory.display().to_string(),
        message: error.to_string(),
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| HarnessError::InvalidCorpus {
            path: directory.display().to_string(),
            message: error.to_string(),
        })?;
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            paths.push(path);
        }
    }
    Ok(())
}
