//! Finite native-dialect introspection over the authorized logical snapshot.

mod mysql;
mod postgres;

use fg_protocol_common::{BranchBinding, ColumnDefault, TableManifest};
use sqlparser::ast::Statement;

use super::{CompileError, CompiledRead, Dialect, OutputColumn, Result};

pub(super) fn compile(
    dialect: Dialect,
    statement: &Statement,
    parameters: usize,
    postgres_parameters: &[u32],
    binding: &BranchBinding,
) -> Result<Option<CompiledRead>> {
    let canonical = statement.to_string();
    let context = match dialect {
        Dialect::MySql if canonical.eq_ignore_ascii_case("SELECT DATABASE()") => {
            Some((&binding.name, "DATABASE()"))
        }
        Dialect::PostgreSql if canonical.eq_ignore_ascii_case("SELECT current_schema()") => {
            Some((&binding.default_schema, "current_schema"))
        }
        Dialect::PostgreSql if canonical.eq_ignore_ascii_case("SELECT current_database()") => {
            Some((&binding.name, "current_database"))
        }
        _ => None,
    };
    if let Some((value, column)) = context {
        let value = if dialect == Dialect::MySql {
            mysql::literal(value)
        } else {
            literal(value)
        };
        return Ok(Some(result(
            dialect,
            vec![(column.into(), "text".into())],
            vec![vec![value]],
            "",
            parameters,
            postgres_parameters,
        )));
    }
    if binding.snapshot_manifest.is_none() {
        return Ok(None);
    }
    match dialect {
        Dialect::MySql => mysql::compile(statement, binding),
        Dialect::PostgreSql => {
            postgres::compile(statement, parameters, postgres_parameters, binding)
        }
    }
}

fn literal(value: &str) -> String {
    format!("E'{}'", value.replace('\\', "\\\\").replace('\'', "''"))
}

fn quote(dialect: Dialect, value: &str) -> String {
    crate::quote_identifier(dialect, value)
}

fn result(
    dialect: Dialect,
    columns: Vec<(String, String)>,
    rows: Vec<Vec<String>>,
    filter: &str,
    parameters: usize,
    postgres_parameters: &[u32],
) -> CompiledRead {
    let typed = |row: &[String]| {
        row.iter()
            .zip(&columns)
            .map(|(value, (name, kind))| {
                let value = if dialect == Dialect::PostgreSql {
                    format!("CAST({value} AS {kind})")
                } else {
                    value.clone()
                };
                format!("{value} AS {}", quote(dialect, name))
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let empty = rows.is_empty();
    let body = if empty {
        format!("SELECT {}", typed(&vec!["NULL".into(); columns.len()]))
    } else {
        rows.iter()
            .map(|row| format!("SELECT {}", typed(row)))
            .collect::<Vec<_>>()
            .join(" UNION ALL ")
    };
    let mut sql = format!("SELECT * FROM ({body}) AS metadata");
    let mut conditions = Vec::new();
    if empty {
        conditions.push("FALSE".into());
    }
    if !filter.is_empty() {
        conditions.push(filter.into());
    }
    for index in 1..=parameters {
        conditions.push(format!(
            "(${index}::text IS NULL OR ${index}::text IS NOT NULL)"
        ));
    }
    if !conditions.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&conditions.join(" AND "));
    }
    CompiledRead {
        sql,
        parameter_count: parameters,
        postgres_parameters: postgres_parameters.to_vec(),
        columns: columns
            .into_iter()
            .map(|(name, _)| OutputColumn {
                name: Some(name),
                origin: None,
            })
            .collect(),
    }
}

fn default_value(value: &ColumnDefault, dialect: Dialect) -> String {
    match value {
        ColumnDefault::Null => "NULL".into(),
        ColumnDefault::Number(value) => value.clone(),
        ColumnDefault::Text(value) => {
            if dialect == Dialect::MySql {
                format!("'{}'", value.replace('\\', "\\\\").replace('\'', "''"))
            } else {
                literal(value)
            }
        }
        ColumnDefault::Boolean(value) => if *value { "TRUE" } else { "FALSE" }.into(),
        ColumnDefault::CurrentTimestamp => "CURRENT_TIMESTAMP".into(),
        ColumnDefault::CurrentTimestampPrecision(value) => format!("CURRENT_TIMESTAMP({value})"),
        ColumnDefault::Generated => if dialect == Dialect::MySql {
            "AUTO_INCREMENT"
        } else {
            ""
        }
        .into(),
    }
}

fn table<'a>(
    binding: &'a BranchBinding,
    schema: Option<&str>,
    name: &str,
) -> Result<&'a TableManifest> {
    if schema.is_some_and(|schema| {
        schema != binding.default_schema
            && !(binding.engine != "postgresql" && schema == binding.name)
    }) {
        return Err(CompileError::Object);
    }
    binding
        .snapshot_manifest
        .as_ref()
        .and_then(|manifest| manifest.tables.iter().find(|table| table.name == name))
        .ok_or(CompileError::Object)
}
