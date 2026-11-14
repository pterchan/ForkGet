//! Canonical observations and engine error classification.

/// Column metadata captured from the result set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColumnMeta {
    pub name: String,
    pub type_name: String,
}

/// Canonical value: engine bytes or NULL. The encoding preserves the
/// type/NULL/length boundaries long enough for an engine-versus-itself
/// comparison; NULL is never a byte string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CanonValue {
    Null,
    Bytes(Vec<u8>),
}

/// What one executed statement produced on one side.
#[derive(Clone, Debug)]
pub enum Observation {
    Rows {
        columns: Vec<ColumnMeta>,
        rows: Vec<Vec<CanonValue>>,
    },
    Affected(u64),
    Error {
        class: String,
        code: Option<String>,
        message: String,
    },
}

impl Observation {
    pub(crate) fn describe(&self) -> String {
        match self {
            Observation::Rows { columns, rows } => {
                format!("rows ({} columns, {} rows)", columns.len(), rows.len())
            }
            Observation::Affected(count) => format!("affected rows ({count})"),
            Observation::Error { class, .. } => format!("error (class {class})"),
        }
    }
}

/// Map an engine error code to a stable, engine-independent class so shared
/// corpus cases can expect one name. Unknown codes keep a unique class so an
/// engine-versus-itself comparison still detects mismatches.
pub fn classify_error(engine: &str, code: Option<&str>) -> String {
    let Some(code) = code else {
        return "unclassified".to_string();
    };
    let mapped = match engine {
        "mysql" => match code {
            "1048" | "1044" => Some("not_null_violation"),
            "1062" => Some("unique_violation"),
            "1064" | "1149" => Some("syntax_error"),
            "1146" => Some("undefined_table"),
            "1054" => Some("undefined_column"),
            "1365" => Some("division_by_zero"),
            "3819" => Some("check_violation"),
            "1452" | "1451" => Some("foreign_key_violation"),
            _ => None,
        },
        "postgresql" => match code {
            "23502" => Some("not_null_violation"),
            "23505" => Some("unique_violation"),
            "42601" => Some("syntax_error"),
            "42P01" => Some("undefined_table"),
            "42703" => Some("undefined_column"),
            "22012" => Some("division_by_zero"),
            "23514" => Some("check_violation"),
            "23503" => Some("foreign_key_violation"),
            "25P02" => Some("in_failed_transaction"),
            _ => None,
        },
        "mongodb" => match code {
            "2" => Some("bad_value"),
            "11000" => Some("unique_violation"),
            _ => None,
        },
        _ => None,
    };
    mapped.map_or_else(|| format!("unclassified_{code}"), ToOwned::to_owned)
}
