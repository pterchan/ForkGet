//! Owned snapshot descriptions shared by import, reflection and replay.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

pub const SNAPSHOT_FORMAT_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotManifest {
    pub format_version: u32,
    pub engine: String,
    pub name: String,
    pub logical_schema: String,
    pub source_version: String,
    pub tables: Vec<TableManifest>,
    #[serde(default)]
    pub document: Option<DocumentSnapshot>,
}

/// BSON metadata stays in its original byte order rather than JSON object order.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentSnapshot {
    pub consistency: String,
    pub collections: Vec<CollectionManifest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionManifest {
    pub name: String,
    pub rows: i64,
    pub options_bson: String,
    pub indexes_bson: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TableManifest {
    pub name: String,
    pub columns: Vec<ColumnSpec>,
    pub primary_key: Vec<String>,
    #[serde(default)]
    pub primary_key_name: Option<String>,
    pub generated_key: Option<String>,
    pub rows: i64,
    pub indexes: Vec<IndexSpec>,
    pub foreign_keys: Vec<ForeignKeySpec>,
    pub checks: Vec<CheckSpec>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ColumnSpec {
    pub name: String,
    pub sql_type: SnapshotType,
    pub nullable: bool,
    pub collation: Option<String>,
    pub default: Option<ColumnDefault>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SnapshotType {
    Integer { bits: u8 },
    Decimal { precision: u16, scale: u16 },
    Text { length: Option<u32> },
    Binary { length: Option<u32> },
    Boolean,
    Date,
    Timestamp { precision: u8, timezone: bool },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ColumnDefault {
    Null,
    Number(String),
    Text(String),
    Boolean(bool),
    CurrentTimestamp,
    CurrentTimestampPrecision(u8),
    Generated,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IndexSpec {
    pub name: String,
    pub columns: Vec<String>,
    pub unique: bool,
    #[serde(default)]
    pub is_constraint: bool,
    #[serde(default)]
    pub deferrable: bool,
    #[serde(default)]
    pub initially_deferred: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ForeignKeySpec {
    pub name: String,
    pub columns: Vec<String>,
    pub referenced_table: String,
    pub referenced_columns: Vec<String>,
    pub on_update: ReferentialAction,
    pub on_delete: ReferentialAction,
    pub deferrable: bool,
    pub initially_deferred: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferentialAction {
    NoAction,
    Restrict,
    Cascade,
    SetNull,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckSpec {
    pub name: String,
    /// Admitted by the importer before execution; never raw client DDL.
    pub expression: String,
}

#[derive(Debug, thiserror::Error)]
#[error("[FORKGET FG-2002] Snapshot object {object}: {reason}")]
pub struct SnapshotAdmissionError {
    pub object: String,
    pub reason: &'static str,
}

pub fn snapshot_identifier(value: &str) -> bool {
    (1..=63).contains(&value.len())
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphabetic() || byte == b'_' || (index > 0 && byte.is_ascii_digit())
        })
        && !value.to_ascii_lowercase().starts_with("_fg_")
        && !value.to_ascii_lowercase().starts_with("fg_")
}

impl SnapshotManifest {
    pub fn validate(&self) -> Result<Vec<usize>, SnapshotAdmissionError> {
        let reject = |object: &str, reason| SnapshotAdmissionError {
            object: object.to_owned(),
            reason,
        };
        if self.format_version != SNAPSHOT_FORMAT_VERSION
            || !matches!(
                self.engine.as_str(),
                "mysql" | "postgresql" | "tidb" | "mongodb"
            )
            || !crate::valid_branch_name(&self.name)
            || !snapshot_identifier(&self.logical_schema)
        {
            return Err(reject("manifest", "invalid_snapshot_context"));
        }
        if self.engine == "mongodb" {
            let document = self
                .document
                .as_ref()
                .ok_or_else(|| reject("manifest", "document_manifest_required"))?;
            if document.consistency != "frozen_source"
                || document.collections.is_empty()
                || !self.tables.is_empty()
            {
                return Err(reject("manifest", "frozen_document_snapshot_required"));
            }
            let mut names = HashSet::new();
            for collection in &document.collections {
                if !snapshot_identifier(&collection.name)
                    || !names.insert(&collection.name)
                    || collection.rows < 0
                    || collection.options_bson.is_empty()
                    || collection.indexes_bson.len() > 64
                {
                    return Err(reject(&collection.name, "invalid_document_collection"));
                }
            }
            return Ok(Vec::new());
        }
        if self.tables.is_empty() || self.document.is_some() {
            return Err(reject("manifest", "sql_tables_required"));
        }
        let mut names = HashSet::new();
        for table in &self.tables {
            if !snapshot_identifier(&table.name) || !names.insert(table.name.as_str()) {
                return Err(reject(&table.name, "invalid_or_duplicate_table"));
            }
            table.validate()?;
        }
        let by_name: HashMap<_, _> = self
            .tables
            .iter()
            .enumerate()
            .map(|(index, table)| (table.name.as_str(), index))
            .collect();
        let mut done = HashSet::new();
        let mut ordered = Vec::new();
        while ordered.len() < self.tables.len() {
            let before = ordered.len();
            for (index, table) in self.tables.iter().enumerate() {
                if done.contains(&index) {
                    continue;
                }
                let mut ready = true;
                for key in &table.foreign_keys {
                    let parent = by_name
                        .get(key.referenced_table.as_str())
                        .ok_or_else(|| reject(&key.name, "foreign_key_target_not_registered"))?;
                    let target = &self.tables[*parent];
                    if key
                        .referenced_columns
                        .iter()
                        .any(|name| !target.has_column(name))
                    {
                        return Err(reject(&key.name, "foreign_key_column_not_registered"));
                    }
                    ready &= done.contains(parent);
                }
                if ready {
                    done.insert(index);
                    ordered.push(index);
                }
            }
            if before == ordered.len() {
                return Err(reject("foreign_keys", "cyclic_dependency_not_supported"));
            }
        }
        Ok(ordered)
    }
}

impl TableManifest {
    pub fn has_column(&self, name: &str) -> bool {
        self.columns.iter().any(|column| column.name == name)
    }

    fn validate(&self) -> Result<(), SnapshotAdmissionError> {
        let reject = |reason| SnapshotAdmissionError {
            object: self.name.clone(),
            reason,
        };
        let mut names = HashSet::new();
        if self.rows < 0 || self.columns.is_empty() || self.primary_key.is_empty() {
            return Err(reject("table_requires_columns_and_primary_key"));
        }
        if self
            .primary_key_name
            .as_deref()
            .is_some_and(|name| !snapshot_identifier(name))
        {
            return Err(reject("invalid_primary_key_name"));
        }
        for column in &self.columns {
            if !snapshot_identifier(&column.name) || !names.insert(column.name.as_str()) {
                return Err(reject("invalid_or_duplicate_column"));
            }
            if !column.sql_type.is_valid() {
                return Err(reject("unsupported_column_type"));
            }
            if matches!(column.default, Some(ColumnDefault::Generated))
                && self.generated_key.as_deref() != Some(column.name.as_str())
            {
                return Err(reject("generated_default_requires_registered_primary_key"));
            }
            if matches!(column.default,Some(ColumnDefault::CurrentTimestampPrecision(value)) if value>6)
            {
                return Err(reject("unsupported_default_time_precision"));
            }
            if let Some(ColumnDefault::Number(value)) = &column.default
                && !numeric_literal(value)
            {
                return Err(reject("invalid_numeric_default"));
            }
        }
        let mut keys = HashSet::new();
        for name in &self.primary_key {
            let column = self
                .columns
                .iter()
                .find(|column| &column.name == name)
                .ok_or_else(|| reject("primary_key_column_not_registered"))?;
            if column.nullable
                || !keys.insert(name)
                || !matches!(column.sql_type, SnapshotType::Integer { .. })
            {
                return Err(reject("primary_key_requires_nonnullable_integers"));
            }
        }
        if let Some(name) = &self.generated_key {
            let valid = self.primary_key == [name.clone()]
                && self.columns.iter().any(|column| {
                    column.name == *name && column.sql_type == SnapshotType::Integer { bits: 64 }
                });
            if !valid {
                return Err(reject("generated_key_requires_single_bigint_primary_key"));
            }
        }
        let mut constraints = HashSet::new();
        let mut index_names = HashSet::new();
        if let Some(name) = &self.primary_key_name {
            constraints.insert(name.as_str());
        }
        for index in &self.indexes {
            if !snapshot_identifier(&index.name)
                || !index_names.insert(index.name.as_str())
                || (index.is_constraint && !constraints.insert(index.name.as_str()))
                || index.columns.is_empty()
                || index.columns.iter().any(|name| !self.has_column(name))
                || index.deferrable && (!index.unique || !index.is_constraint)
                || index.initially_deferred && !index.deferrable
            {
                return Err(reject("unsupported_index"));
            }
        }
        for key in &self.foreign_keys {
            if !snapshot_identifier(&key.name)
                || !constraints.insert(key.name.as_str())
                || key.columns.is_empty()
                || key.columns.len() != key.referenced_columns.len()
                || key.columns.iter().any(|name| !self.has_column(name))
                || key.initially_deferred && !key.deferrable
            {
                return Err(reject("unsupported_foreign_key"));
            }
        }
        for check in &self.checks {
            if !snapshot_identifier(&check.name)
                || !constraints.insert(check.name.as_str())
                || check.expression.is_empty()
            {
                return Err(reject("unsupported_check"));
            }
        }
        Ok(())
    }
}

fn numeric_literal(value: &str) -> bool {
    let unsigned = value.strip_prefix(['+', '-']).unwrap_or(value);
    let mut parts = unsigned.split('.');
    let integer = parts.next().unwrap_or_default();
    let fraction = parts.next();
    !integer.is_empty()
        && integer.bytes().all(|byte| byte.is_ascii_digit())
        && fraction.is_none_or(|value| {
            !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
        })
        && parts.next().is_none()
}

impl SnapshotType {
    pub fn native_name(&self, engine: &str) -> String {
        let postgres = engine == "postgresql";
        match self {
            Self::Integer { bits: 16 } => "smallint".into(),
            Self::Integer { bits: 32 } => if postgres { "integer" } else { "int" }.into(),
            Self::Integer { .. } => "bigint".into(),
            Self::Decimal { precision, scale } => format!(
                "{}({precision},{scale})",
                if postgres { "numeric" } else { "decimal" }
            ),
            Self::Text {
                length: Some(length),
            } => format!("varchar({length})"),
            Self::Text { length: None } => "text".into(),
            Self::Binary { .. } if postgres => "bytea".into(),
            Self::Binary {
                length: Some(length),
            } => format!("varbinary({length})"),
            Self::Binary { length: None } => "longblob".into(),
            Self::Boolean => if postgres { "boolean" } else { "tinyint(1)" }.into(),
            Self::Date => "date".into(),
            Self::Timestamp {
                precision,
                timezone,
            } => {
                let name = if postgres || *timezone {
                    "timestamp"
                } else {
                    "datetime"
                };
                let suffix = if postgres && *timezone {
                    " with time zone"
                } else {
                    ""
                };
                format!("{name}({precision}){suffix}")
            }
        }
    }

    pub fn is_valid(&self) -> bool {
        match self {
            Self::Integer { bits } => matches!(bits, 16 | 32 | 64),
            Self::Decimal { precision, scale } => {
                (1..=65).contains(precision) && scale <= precision
            }
            Self::Text { length } | Self::Binary { length } => {
                length.is_none_or(|length| length > 0)
            }
            Self::Timestamp { precision, .. } => *precision <= 6,
            Self::Boolean | Self::Date => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_cannot_name_private_objects_or_inject_ddl() {
        for name in ["fg_g1", "_fg_generated", "bad.name", "x;DROP", "", "1id"] {
            assert!(!snapshot_identifier(name));
        }
        assert!(snapshot_identifier("OrderItem"));
    }

    #[test]
    fn decimal_and_timestamp_shapes_are_bounded() {
        assert!(
            SnapshotType::Decimal {
                precision: 19,
                scale: 4
            }
            .is_valid()
        );
        assert!(
            !SnapshotType::Decimal {
                precision: 12,
                scale: 13
            }
            .is_valid()
        );
        assert!(
            !SnapshotType::Timestamp {
                precision: 7,
                timezone: true
            }
            .is_valid()
        );
    }
}
