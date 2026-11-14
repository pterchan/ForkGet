use std::io;

use super::*;

pub struct ReplayStatement {
    pub sql: String,
    pub operation: crate::WriteOperation,
    pub generated_id: Option<i64>,
}

pub fn replay_order(header: &ArtifactHeader) -> io::Result<Vec<i64>> {
    header.require_replay_source()?;
    if header.engine == "mongodb" {
        return Ok(header.tables.iter().map(|table| table.id).collect());
    }
    if let Some(manifest) = &header.manifest {
        return manifest
            .validate()
            .map_err(invalid)?
            .into_iter()
            .map(|index| {
                header
                    .tables
                    .iter()
                    .find(|table| table.table == manifest.tables[index].name)
                    .map(|table| table.id)
                    .ok_or_else(|| invalid("artifact_catalog_mismatch"))
            })
            .collect();
    }
    Ok(header.tables.iter().map(|table| table.id).collect())
}

pub fn validate_replay_change(header: &ArtifactHeader, change: &TypedChange) -> io::Result<()> {
    header.validate_change(change)?;
    let table = header
        .tables
        .iter()
        .find(|table| table.id == change.table_id)
        .ok_or_else(|| invalid("artifact_catalog_mismatch"))?;
    for row in [change.before.as_ref(), change.after.as_ref()]
        .into_iter()
        .flatten()
    {
        for (index, value) in row.iter().enumerate() {
            literal(
                &header.engine,
                &header.column_type(table, index)?,
                table.columns[index].nullable,
                value.as_deref(),
            )?;
        }
    }
    if header.manifest.is_none()
        && table.schema == "app"
        && table.table == "parents"
        && let (Some(before), Some(after)) = (&change.before, &change.after)
    {
        for name in ["tenant_id", "code"] {
            let index = table
                .columns
                .iter()
                .position(|column| column.name == name)
                .ok_or_else(|| invalid("legacy_parent_catalog_mismatch"))?;
            if before[index] != after[index] {
                return Err(invalid("referenced_key_transition_not_admitted"));
            }
        }
    }
    // Updating a referenced locator may need a transient graph outside the
    // admitted scalar replay order. Preserve it in the artifact, refuse early.
    if let (Some(manifest), Some(before), Some(after)) =
        (&header.manifest, &change.before, &change.after)
    {
        for child in &manifest.tables {
            for key in child
                .foreign_keys
                .iter()
                .filter(|key| key.referenced_table == table.table)
            {
                for name in &key.referenced_columns {
                    let index = table
                        .columns
                        .iter()
                        .position(|column| &column.name == name)
                        .ok_or_else(|| invalid("artifact_catalog_mismatch"))?;
                    if before[index] != after[index] {
                        return Err(invalid("referenced_key_transition_not_admitted"));
                    }
                }
            }
        }
    }
    Ok(())
}

pub fn replay_statement(
    header: &ArtifactHeader,
    change: &TypedChange,
    target: &crate::WriteTarget,
) -> io::Result<ReplayStatement> {
    validate_replay_change(header, change)?;
    let table = header
        .tables
        .iter()
        .find(|table| table.id == change.table_id)
        .ok_or_else(|| invalid("artifact_catalog_mismatch"))?;
    let quote = |name: &str| quote(&header.engine, name);
    let relation = format!(
        "{}.{}",
        quote(target.schema()),
        quote(&target.table(&table.table))
    );
    let keys = table.key_indexes()?;
    let predicate = keys
        .iter()
        .zip(&change.key)
        .map(|(index, key)| {
            Ok(format!(
                "{} = {}",
                quote(&table.columns[*index].name),
                literal(
                    &header.engine,
                    &header.column_type(table, *index)?,
                    false,
                    Some(key)
                )?
            ))
        })
        .collect::<io::Result<Vec<_>>>()?
        .join(" AND ");
    let mut generated_id = None;
    let sql = match (&change.operation, &change.before, &change.after) {
        (ChangeOperation::Insert, None, Some(row)) => {
            let mut names = Vec::new();
            let mut values = Vec::new();
            for (index, column) in table.columns.iter().enumerate() {
                names.push(quote(&column.name));
                values.push(literal(
                    &header.engine,
                    &header.column_type(table, index)?,
                    column.nullable,
                    row[index].as_deref(),
                )?);
            }
            if let Some(generated) = &table.generated_key {
                let index = table
                    .columns
                    .iter()
                    .position(|column| &column.name == generated)
                    .ok_or_else(|| invalid("invalid_generated_key"))?;
                let value: i64 = row[index]
                    .as_deref()
                    .ok_or_else(|| invalid("invalid_generated_key"))?
                    .parse()
                    .map_err(invalid)?;
                if value >= crate::GENERATED_ID_START {
                    if value > crate::GENERATED_ID_MAX {
                        return Err(invalid("invalid_generated_key"));
                    }
                    generated_id = Some(value);
                    names.push(quote("_fg_generated"));
                    values.push("TRUE".into());
                }
            }
            format!(
                "INSERT INTO {relation} ({}) VALUES ({})",
                names.join(", "),
                values.join(", ")
            )
        }
        (ChangeOperation::Update, Some(before), Some(after)) => {
            let mut values = Vec::new();
            for (index, (old, new)) in before
                .iter()
                .zip(after)
                .enumerate()
                .filter(|(_, (old, new))| old != new)
            {
                if table.columns[index].primary_key_ordinal.is_some() {
                    return Err(invalid("primary_key_mutation_not_admitted"));
                }
                let _ = old;
                values.push(format!(
                    "{} = {}",
                    quote(&table.columns[index].name),
                    literal(
                        &header.engine,
                        &header.column_type(table, index)?,
                        table.columns[index].nullable,
                        new.as_deref()
                    )?
                ));
            }
            format!(
                "UPDATE {relation} SET {} WHERE {predicate}",
                values.join(", ")
            )
        }
        (ChangeOperation::Delete, Some(_), None) => {
            format!("DELETE FROM {relation} WHERE {predicate}")
        }
        _ => return Err(invalid("invalid_change")),
    };
    Ok(ReplayStatement {
        sql,
        generated_id,
        operation: crate::WriteOperation {
            table_id: table.id,
            kind: match change.operation {
                ChangeOperation::Insert => crate::WriteKind::Insert,
                ChangeOperation::Update => crate::WriteKind::Update,
                ChangeOperation::Delete => crate::WriteKind::Delete,
            },
        },
    })
}

fn literal(
    engine: &str,
    kind: &SnapshotType,
    nullable: bool,
    value: Option<&str>,
) -> io::Result<String> {
    let Some(value) = value else {
        return if nullable {
            Ok("NULL".into())
        } else {
            Err(invalid("nonnullable_artifact_value"))
        };
    };
    match kind {
        SnapshotType::Integer { bits } => {
            let number: i64 = value.parse().map_err(invalid)?;
            if number.to_string() != value
                || (*bits == 16 && i16::try_from(number).is_err())
                || (*bits == 32 && i32::try_from(number).is_err())
            {
                return Err(invalid("integer_out_of_range"));
            }
            Ok(value.into())
        }
        SnapshotType::Decimal { precision, scale } => {
            let number = value.strip_prefix('-').unwrap_or(value);
            let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
            if whole.is_empty()
                || !whole.bytes().all(|byte| byte.is_ascii_digit())
                || !fraction.bytes().all(|byte| byte.is_ascii_digit())
                || fraction.len() > usize::from(*scale)
                || whole.trim_start_matches('0').len() > usize::from(precision - scale)
            {
                return Err(invalid("decimal_out_of_range"));
            }
            Ok(value.into())
        }
        SnapshotType::Binary { length } => {
            if value.len() % 2 != 0
                || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
                || length.is_some_and(|length| value.len() / 2 > length as usize)
            {
                return Err(invalid("invalid_binary_value"));
            }
            Ok(if engine == "postgresql" {
                format!("pg_catalog.decode('{value}', 'hex')")
            } else {
                format!("X'{value}'")
            })
        }
        SnapshotType::Boolean => match value {
            "true" | "t" | "1" => Ok("TRUE".into()),
            "false" | "f" | "0" => Ok("FALSE".into()),
            _ => Err(invalid("invalid_boolean_value")),
        },
        SnapshotType::Text { length } => {
            if length.is_some_and(|length| value.chars().count() > length as usize) {
                return Err(invalid("text_out_of_range"));
            }
            Ok(text_literal(engine, value))
        }
        SnapshotType::Date => {
            value.parse::<jiff::civil::Date>().map_err(invalid)?;
            Ok(format!("CAST('{}' AS DATE)", value))
        }
        SnapshotType::Timestamp {
            timezone,
            precision,
        } => {
            if let Some((_, fraction)) = value.split_once('.') {
                let digits: String = fraction.chars().take_while(char::is_ascii_digit).collect();
                if digits
                    .bytes()
                    .skip(usize::from(*precision))
                    .any(|digit| digit != b'0')
                {
                    return Err(invalid("timestamp_precision_exceeded"));
                }
            }
            if *timezone && engine == "postgresql" {
                if !value.ends_with('Z') {
                    return Err(invalid("timestamp_must_be_canonical_utc"));
                }
                value.parse::<jiff::Timestamp>().map_err(invalid)?;
            } else {
                value
                    .trim_end_matches('Z')
                    .parse::<jiff::civil::DateTime>()
                    .map_err(invalid)?;
            }
            let name = if engine == "postgresql" {
                if *timezone {
                    "timestamptz"
                } else {
                    "timestamp"
                }
            } else {
                "datetime(6)"
            };
            Ok(format!(
                "CAST('{}' AS {name})",
                value.trim_end_matches('Z').replace('T', " ")
            ))
        }
    }
}

fn text_literal(engine: &str, value: &str) -> String {
    // Hex encoding preserves NUL/backslashes independently of SQL modes.
    let hex: String = value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if engine == "postgresql" {
        format!("pg_catalog.convert_from(pg_catalog.decode('{hex}', 'hex'), 'UTF8')")
    } else {
        format!("CONVERT(X'{hex}' USING utf8mb4)")
    }
}

fn quote(engine: &str, name: &str) -> String {
    if engine == "postgresql" {
        format!("\"{}\"", name.replace('"', "\"\""))
    } else {
        format!("`{}`", name.replace('`', "``"))
    }
}
