//! Complete, line-delimited typed artifacts. A footer is the commit record.

use std::io::{self, BufRead, Write};

use serde::{Deserialize, Serialize};

use crate::{CatalogColumn, ReplayOrigin, SnapshotManifest, SnapshotType};

mod document;
mod plan;
pub use document::{
    DocumentChange, bson_document, bson_key, encode_bson, validate_document_change,
};
pub use plan::{ReplayStatement, replay_order, replay_statement, validate_replay_change};

pub const ARTIFACT_LIMIT: u64 = 1024 * 1024 * 1024;
pub const ARTIFACT_RECORD_LIMIT: usize = 64 * 1024 * 1024;
pub const ARTIFACT_VERSION: u8 = 2;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactHeader {
    pub format_version: u8,
    pub engine: String,
    pub source_branch_id: i64,
    pub origin: ReplayOrigin,
    pub native_write: bool,
    pub manifest: Option<SnapshotManifest>,
    pub tables: Vec<ArtifactTable>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactTable {
    pub id: i64,
    pub schema: String,
    pub table: String,
    pub generated_key: Option<String>,
    pub columns: Vec<CatalogColumn>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeOperation {
    Insert,
    Update,
    Delete,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TypedChange {
    pub table_id: i64,
    pub operation: ChangeOperation,
    pub key: Vec<String>,
    pub before: Option<Vec<Option<String>>>,
    pub after: Option<Vec<Option<String>>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactEnd {
    pub complete: bool,
    pub changes: u64,
    pub replayable: bool,
    pub reasons: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
// Framing owns one bounded record at a time. The few hundred bytes of header
// storage are small next to its independently bounded 64 MiB payload.
#[allow(clippy::large_enum_variant)]
#[serde(
    tag = "record",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ArtifactRecord {
    Header(ArtifactHeader),
    Change(TypedChange),
    DocumentChange(DocumentChange),
    End(ArtifactEnd),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArtifactEntry {
    Sql(TypedChange),
    Document(DocumentChange),
}

impl ArtifactEntry {
    pub fn validate_replay(&self, header: &ArtifactHeader) -> io::Result<()> {
        match self {
            Self::Sql(change) => validate_replay_change(header, change),
            Self::Document(change) => validate_document_change(header, change),
        }
    }
}

/// The plan is uploaded only over authenticated control channels. It never
/// enables a frontend SQL feature or carries arbitrary client SQL.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayPermit {
    pub job_id: i64,
    pub branch_id: i64,
    pub owner: String,
    pub generation_id: i64,
    pub credential_expires_at: i64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayResolve {
    pub principal: String,
    pub expires_at: i64,
    pub job_id: i64,
    pub native_session_id: u32,
    pub verify_only: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaySession {
    pub principal: String,
    pub session_id: String,
    pub native_session_id: u32,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayIds {
    pub session: ReplaySession,
    pub table_id: i64,
    pub highest: i64,
}

pub struct ArtifactWriter<W> {
    inner: W,
    bytes: u64,
    changes: u64,
    ended: bool,
    header: ArtifactHeader,
    reasons: Vec<String>,
}

impl<W: Write> ArtifactWriter<W> {
    pub fn new(inner: W, header: ArtifactHeader) -> io::Result<Self> {
        header.validate()?;
        let reasons = header
            .require_replay_source()
            .err()
            .map(|error| error.to_string())
            .into_iter()
            .collect();
        let mut writer = Self {
            inner,
            bytes: 0,
            changes: 0,
            ended: false,
            header: header.clone(),
            reasons,
        };
        writer.record(&ArtifactRecord::Header(header))?;
        Ok(writer)
    }

    fn record(&mut self, record: &ArtifactRecord) -> io::Result<()> {
        let mut bytes = serde_json::to_vec(record).map_err(invalid)?;
        bytes.push(b'\n');
        if bytes.len() > ARTIFACT_RECORD_LIMIT
            || self.bytes.saturating_add(bytes.len() as u64) > ARTIFACT_LIMIT
        {
            return Err(invalid("artifact_limit_exceeded"));
        }
        self.inner.write_all(&bytes)?;
        self.bytes += bytes.len() as u64;
        Ok(())
    }

    pub fn change(&mut self, change: TypedChange) -> io::Result<()> {
        if self.ended {
            return Err(invalid("artifact_already_complete"));
        }
        if let Err(error) = validate_replay_change(&self.header, &change) {
            let reason = error.to_string();
            if !self.reasons.contains(&reason) {
                self.reasons.push(reason);
            }
        }
        self.record(&ArtifactRecord::Change(change))?;
        self.changes += 1;
        Ok(())
    }

    pub fn document(&mut self, change: DocumentChange) -> io::Result<()> {
        if self.ended {
            return Err(invalid("artifact_already_complete"));
        }
        validate_document_change(&self.header, &change)?;
        self.record(&ArtifactRecord::DocumentChange(change))?;
        self.changes += 1;
        Ok(())
    }

    pub fn finish(mut self, mut reasons: Vec<String>) -> io::Result<W> {
        reasons.append(&mut self.reasons);
        reasons.sort();
        reasons.dedup();
        self.record(&ArtifactRecord::End(ArtifactEnd {
            complete: true,
            changes: self.changes,
            replayable: reasons.is_empty(),
            reasons,
        }))?;
        self.ended = true;
        self.inner.flush()?;
        Ok(self.inner)
    }
}

pub struct ArtifactReader<R> {
    reader: R,
    bytes: u64,
    changes: u64,
    ended: bool,
    header: ArtifactHeader,
    end: Option<ArtifactEnd>,
    last_key: Option<(i64, Vec<i64>)>,
}

impl<R: BufRead> ArtifactReader<R> {
    pub fn new(mut reader: R) -> io::Result<Self> {
        let (record, bytes) = read_record(&mut reader)?;
        let ArtifactRecord::Header(header) = record else {
            return Err(invalid("missing_header"));
        };
        header.validate()?;
        Ok(Self {
            reader,
            bytes: bytes as u64,
            changes: 0,
            ended: false,
            header,
            end: None,
            last_key: None,
        })
    }

    pub fn header(&self) -> &ArtifactHeader {
        &self.header
    }
    pub fn end(&self) -> Option<&ArtifactEnd> {
        self.end.as_ref()
    }

    pub fn next_change(&mut self) -> io::Result<Option<TypedChange>> {
        match self.next_entry()? {
            Some(ArtifactEntry::Sql(change)) => Ok(Some(change)),
            None => Ok(None),
            _ => Err(invalid("sql_row_required")),
        }
    }

    pub fn next_entry(&mut self) -> io::Result<Option<ArtifactEntry>> {
        if self.ended {
            return Ok(None);
        }
        let (record, bytes) = read_record(&mut self.reader)?;
        self.bytes = self.bytes.saturating_add(bytes as u64);
        if self.bytes > ARTIFACT_LIMIT {
            return Err(invalid("artifact_limit_exceeded"));
        }
        match record {
            ArtifactRecord::Change(change) => {
                self.header.validate_change(&change)?;
                if self.header.engine != "mongodb" {
                    let key = (
                        change.table_id,
                        change
                            .key
                            .iter()
                            .map(|key| key.parse::<i64>().map_err(invalid))
                            .collect::<io::Result<Vec<_>>>()?,
                    );
                    if self
                        .last_key
                        .as_ref()
                        .is_some_and(|previous| previous >= &key)
                    {
                        return Err(invalid("artifact_keys_not_strictly_ordered"));
                    }
                    self.last_key = Some(key);
                }
                self.changes += 1;
                Ok(Some(ArtifactEntry::Sql(change)))
            }
            ArtifactRecord::DocumentChange(change) => {
                validate_document_change(&self.header, &change)?;
                self.changes += 1;
                Ok(Some(ArtifactEntry::Document(change)))
            }
            ArtifactRecord::End(end)
                if end.complete
                    && end.changes == self.changes
                    && end.replayable == end.reasons.is_empty() =>
            {
                if !self.reader.fill_buf()?.is_empty() {
                    return Err(invalid("trailing_artifact_data"));
                }
                self.ended = true;
                self.end = Some(end);
                Ok(None)
            }
            _ => Err(invalid("invalid_or_incomplete_artifact")),
        }
    }
}

fn read_record(reader: &mut impl BufRead) -> io::Result<(ArtifactRecord, usize)> {
    let mut bytes = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Err(invalid("incomplete_artifact"));
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |at| at + 1);
        if bytes.len().saturating_add(take) > ARTIFACT_RECORD_LIMIT {
            return Err(invalid("artifact_record_limit_exceeded"));
        }
        let done = available[take - 1] == b'\n';
        bytes.extend_from_slice(&available[..take]);
        reader.consume(take);
        if done {
            break;
        }
    }
    let record = serde_json::from_slice(&bytes).map_err(invalid)?;
    Ok((record, bytes.len()))
}

impl ArtifactHeader {
    pub fn require_replay_source(&self) -> io::Result<()> {
        if matches!(self.origin.snapshot.as_str(), "v2" | "v3")
            || crate::gate_order_count(&self.origin.snapshot).is_some()
            || self.manifest.is_some()
        {
            Ok(())
        } else {
            Err(invalid("source_snapshot_not_writable"))
        }
    }

    pub fn validate(&self) -> io::Result<()> {
        if self.format_version != ARTIFACT_VERSION
            || self.source_branch_id <= 0
            || !self.origin.is_valid()
            || !matches!(
                self.engine.as_str(),
                "mysql" | "postgresql" | "tidb" | "mongodb"
            )
            || self.tables.is_empty()
            || !self.tables.windows(2).all(|pair| pair[0].id < pair[1].id)
        {
            return Err(invalid("invalid_artifact_context"));
        }
        for table in &self.tables {
            if table.id <= 0
                || !crate::snapshot_identifier(&table.schema)
                || !crate::snapshot_identifier(&table.table)
                || (self.engine != "mongodb" && table.columns.is_empty())
                || table
                    .columns
                    .iter()
                    .any(|column| !crate::snapshot_identifier(&column.name))
            {
                return Err(invalid("invalid_artifact_catalog"));
            }
        }
        if let Some(manifest) = &self.manifest {
            manifest.validate().map_err(invalid)?;
            if manifest.engine != self.engine
                || manifest.name != self.origin.snapshot
                || if self.engine == "mongodb" {
                    manifest
                        .document
                        .as_ref()
                        .is_none_or(|document| document.collections.len() != self.tables.len())
                } else {
                    manifest.tables.len() != self.tables.len()
                }
            {
                return Err(invalid("artifact_manifest_mismatch"));
            }
        }
        Ok(())
    }

    pub fn validate_change(&self, change: &TypedChange) -> io::Result<()> {
        if self.engine == "mongodb" {
            return Err(invalid("document_change_required"));
        }
        let table = self
            .tables
            .iter()
            .find(|table| table.id == change.table_id)
            .ok_or_else(|| invalid("unknown_artifact_table"))?;
        let keys = table.key_indexes()?;
        if change.key.len() != keys.len() {
            return Err(invalid("invalid_artifact_key"));
        }
        match (&change.operation, &change.before, &change.after) {
            (ChangeOperation::Insert, None, Some(_)) | (ChangeOperation::Delete, Some(_), None) => {
            }
            (ChangeOperation::Update, Some(before), Some(after)) if before != after => (),
            _ => return Err(invalid("invalid_artifact_row_images")),
        }
        for row in [change.before.as_ref(), change.after.as_ref()]
            .into_iter()
            .flatten()
        {
            if row.len() != table.columns.len()
                || keys
                    .iter()
                    .zip(&change.key)
                    .any(|(index, key)| row[*index].as_ref() != Some(key))
            {
                return Err(invalid("invalid_artifact_row_images"));
            }
        }
        Ok(())
    }

    pub fn column_type(&self, table: &ArtifactTable, index: usize) -> io::Result<SnapshotType> {
        if let Some(manifest) = &self.manifest {
            let column = manifest
                .tables
                .iter()
                .find(|item| item.name == table.table)
                .and_then(|item| {
                    item.columns
                        .iter()
                        .find(|item| item.name == table.columns[index].name)
                })
                .ok_or_else(|| invalid("artifact_column_not_registered"))?;
            return Ok(column.sql_type.clone());
        }
        native_type(&table.columns[index].type_name)
            .ok_or_else(|| invalid("unsupported_artifact_column_type"))
    }
}

impl ArtifactTable {
    pub fn key_indexes(&self) -> io::Result<Vec<usize>> {
        let mut keys: Vec<_> = self
            .columns
            .iter()
            .enumerate()
            .filter_map(|(index, column)| {
                column.primary_key_ordinal.map(|ordinal| (ordinal, index))
            })
            .collect();
        keys.sort_unstable();
        if keys.is_empty()
            || keys.iter().enumerate().any(|(offset, (ordinal, index))| {
                usize::from(*ordinal) != offset + 1 || self.columns[*index].nullable
            })
        {
            return Err(invalid("invalid_artifact_primary_key"));
        }
        Ok(keys.into_iter().map(|(_, index)| index).collect())
    }
}

pub fn native_type(name: &str) -> Option<SnapshotType> {
    let kind = name.to_ascii_lowercase();
    match kind.as_str() {
        "smallint" | "int2" | "tinyint" | "tinyint(1)" => {
            return Some(SnapshotType::Integer { bits: 16 });
        }
        "int" | "integer" | "int4" => return Some(SnapshotType::Integer { bits: 32 }),
        "bigint" | "int8" => return Some(SnapshotType::Integer { bits: 64 }),
        "text" => return Some(SnapshotType::Text { length: None }),
        "bytea" | "blob" | "longblob" => return Some(SnapshotType::Binary { length: None }),
        "boolean" | "bool" => return Some(SnapshotType::Boolean),
        "date" => return Some(SnapshotType::Date),
        _ => (),
    }
    for prefix in ["varchar(", "character varying(", "varbinary("] {
        if let Some(length) = kind
            .strip_prefix(prefix)
            .and_then(|rest| rest.strip_suffix(')'))
            .and_then(|value| value.parse().ok())
        {
            return Some(if prefix == "varbinary(" {
                SnapshotType::Binary {
                    length: Some(length),
                }
            } else {
                SnapshotType::Text {
                    length: Some(length),
                }
            });
        }
    }
    for prefix in ["decimal(", "numeric("] {
        if let Some((precision, scale)) = kind
            .strip_prefix(prefix)
            .and_then(|rest| rest.strip_suffix(')'))
            .and_then(|value| value.split_once(','))
        {
            return Some(SnapshotType::Decimal {
                precision: precision.trim().parse().ok()?,
                scale: scale.trim().parse().ok()?,
            });
        }
    }
    if kind.starts_with("timestamp") || kind.starts_with("datetime") {
        let precision = kind
            .split_once('(')
            .and_then(|(_, rest)| rest.split_once(')'))
            .map_or(Some(6), |(value, _)| value.parse().ok())?;
        return Some(SnapshotType::Timestamp {
            precision,
            timezone: kind.contains("with time zone"),
        });
    }
    None
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn header() -> ArtifactHeader {
        ArtifactHeader {
            format_version: 2,
            engine: "postgresql".into(),
            source_branch_id: 1,
            origin: ReplayOrigin {
                deployment_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
                generation_id: 1,
                snapshot: "v2".into(),
            },
            native_write: true,
            manifest: None,
            tables: vec![ArtifactTable {
                id: 1,
                schema: "app".into(),
                table: "events".into(),
                generated_key: Some("id".into()),
                columns: vec![
                    CatalogColumn {
                        name: "id".into(),
                        type_name: "bigint".into(),
                        nullable: false,
                        primary_key_ordinal: Some(1),
                    },
                    CatalogColumn {
                        name: "enabled".into(),
                        type_name: "boolean".into(),
                        nullable: false,
                        primary_key_ordinal: None,
                    },
                ],
            }],
        }
    }

    fn inserted(id: i64, enabled: &str) -> TypedChange {
        TypedChange {
            table_id: 1,
            operation: ChangeOperation::Insert,
            key: vec![id.to_string()],
            before: None,
            after: Some(vec![Some(id.to_string()), Some(enabled.into())]),
        }
    }

    #[test]
    fn complete_stream_exceeds_legacy_limits_and_refuses_missing_footer() -> io::Result<()> {
        let mut writer = ArtifactWriter::new(Vec::new(), header())?;
        for key in 1..=5000 {
            writer.change(inserted(key, "true"))?;
        }
        let bytes = writer.finish(Vec::new())?;
        let mut reader = ArtifactReader::new(Cursor::new(&bytes))?;
        let mut seen = 0;
        while reader.next_change()?.is_some() {
            seen += 1;
        }
        assert_eq!(seen, 5000);
        assert_eq!(reader.end().map(|end| end.changes), Some(5000));
        let last = bytes[..bytes.len() - 1]
            .iter()
            .rposition(|byte| *byte == b'\n')
            .ok_or_else(|| invalid("footer missing"))?
            + 1;
        let mut truncated = ArtifactReader::new(Cursor::new(&bytes[..last]))?;
        let mut failed = false;
        loop {
            match truncated.next_change() {
                Ok(Some(_)) => (),
                Ok(None) => break,
                Err(_) => {
                    failed = true;
                    break;
                }
            }
        }
        assert!(
            failed,
            "an incomplete transfer must never be published as complete"
        );
        Ok(())
    }

    #[test]
    fn seed_v1_saves_complete_changes_but_refuses_replay_even_when_empty() -> io::Result<()> {
        let mut header = header();
        header.origin.snapshot = "v1".into();
        assert!(header.origin.is_valid());
        for populated in [false, true] {
            let mut writer = ArtifactWriter::new(Vec::new(), header.clone())?;
            if populated {
                writer.change(inserted(1, "true"))?;
            }
            let mut reader = ArtifactReader::new(Cursor::new(writer.finish(Vec::new())?))?;
            assert!(replay_order(reader.header()).is_err());
            let mut count = 0;
            while reader.next_entry()?.is_some() {
                count += 1;
            }
            assert_eq!(count, usize::from(populated));
            let footer = reader.end().ok_or_else(|| invalid("footer"))?;
            assert!(footer.complete && !footer.replayable);
            assert!(
                footer
                    .reasons
                    .iter()
                    .any(|reason| reason == "source_snapshot_not_writable")
            );
        }
        Ok(())
    }

    #[test]
    fn output_retains_unreplayable_values_without_coercing_boolean() -> io::Result<()> {
        let mut writer = ArtifactWriter::new(Vec::new(), header())?;
        writer.change(inserted(1, "2"))?;
        let bytes = writer.finish(Vec::new())?;
        let mut reader = ArtifactReader::new(Cursor::new(bytes))?;
        let row = reader
            .next_change()?
            .ok_or_else(|| invalid("missing change"))?;
        assert_eq!(
            row.after.as_ref().and_then(|row| row[1].as_deref()),
            Some("2")
        );
        assert!(validate_replay_change(reader.header(), &row).is_err());
        assert!(reader.next_change()?.is_none());
        assert!(reader.end().is_some_and(|end| !end.replayable));
        Ok(())
    }

    #[test]
    fn generated_keys_are_preserved_and_rendered_only_for_the_bound_target() -> io::Result<()> {
        let header = header();
        let change = inserted(crate::GENERATED_ID_START, "false");
        let target =
            crate::WriteTarget::new("postgresql", 9, "fg_b9").ok_or_else(|| invalid("target"))?;
        let statement = replay_statement(&header, &change, &target)?;
        assert_eq!(statement.generated_id, Some(crate::GENERATED_ID_START));
        assert!(statement.sql.contains("\"fg_b9\".\"events\""));
        assert!(statement.sql.contains("\"_fg_generated\""));
        let mut writer = ArtifactWriter::new(Vec::new(), header)?;
        writer.change(change.clone())?;
        let bytes = writer.finish(Vec::new())?;
        let mut reader = ArtifactReader::new(Cursor::new(bytes))?;
        assert_eq!(reader.next_change()?, Some(change));
        assert!(reader.next_change()?.is_none());
        assert!(reader.end().is_some_and(|end| end.replayable));
        Ok(())
    }

    #[test]
    fn duplicate_keys_trailing_data_and_false_totals_are_invalid() -> io::Result<()> {
        let mut writer = ArtifactWriter::new(Vec::new(), header())?;
        writer.change(inserted(1, "true"))?;
        writer.change(inserted(1, "false"))?;
        let bytes = writer.finish(Vec::new())?;
        let mut reader = ArtifactReader::new(Cursor::new(bytes))?;
        assert!(reader.next_change()?.is_some());
        assert!(reader.next_change().is_err());
        let mut bytes = ArtifactWriter::new(Vec::new(), header())?.finish(Vec::new())?;
        bytes.extend_from_slice(b"untrusted trailing data");
        assert!(
            ArtifactReader::new(Cursor::new(bytes))?
                .next_change()
                .is_err()
        );
        Ok(())
    }
}
