use std::sync::OnceLock;

use fg_protocol_common::{
    BranchBinding, ForeignKeySpec, ReferentialAction, SnapshotType, TableManifest,
};
use serde::Deserialize;
use sqlparser::ast::Statement;
use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};

use super::{CompileError, CompiledRead, Dialect, Result, default_value, literal, quote, result};

const DIALECT: Dialect = Dialect::PostgreSql;

#[derive(Deserialize)]
struct Profile {
    kind: String,
    sql: String,
    parameters: Vec<String>,
    columns: Vec<String>,
    #[serde(skip)]
    canonical: String,
}

fn profiles() -> Result<&'static [Profile]> {
    static PROFILES: OnceLock<Option<Vec<Profile>>> = OnceLock::new();
    PROFILES
        .get_or_init(|| {
            let mut profiles: Vec<Profile> =
                serde_json::from_str(include_str!("sqlalchemy_pg.json")).ok()?;
            for profile in &mut profiles {
                let statements = Parser::parse_sql(&PostgreSqlDialect {}, &profile.sql).ok()?;
                let [statement] = statements.as_slice() else {
                    return None;
                };
                profile.canonical = statement.to_string();
            }
            Some(profiles)
        })
        .as_deref()
        .ok_or(CompileError::Catalog)
}

pub(super) fn compile(
    statement: &Statement,
    parameters: usize,
    postgres_parameters: &[u32],
    binding: &BranchBinding,
) -> Result<Option<CompiledRead>> {
    let canonical = statement.to_string();
    let Some(profile) = profiles()?
        .iter()
        .find(|profile| profile.canonical == canonical)
    else {
        return Ok(None);
    };
    if profile.parameters.len() != parameters {
        return Err(CompileError::Catalog);
    }
    let manifest = binding
        .snapshot_manifest
        .as_ref()
        .ok_or(CompileError::Catalog)?;
    let mut rows = Vec::new();
    if profile.kind == "types" {
        for (name, oid, array_oid, regtype) in [
            ("bool", 16, 1000, "boolean"),
            ("int2", 21, 1005, "smallint"),
            ("int4", 23, 1007, "integer"),
            ("int8", 20, 1016, "bigint"),
            ("numeric", 1700, 1231, "numeric"),
            ("text", 25, 1009, "text"),
            ("varchar", 1043, 1015, "character varying"),
            ("bytea", 17, 1001, "bytea"),
            ("date", 1082, 1182, "date"),
            ("timestamp", 1114, 1115, "timestamp without time zone"),
            ("timestamptz", 1184, 1185, "timestamp with time zone"),
        ] {
            rows.push(vec![
                literal(name),
                oid.to_string(),
                array_oid.to_string(),
                literal(regtype),
                literal(","),
            ]);
        }
    } else {
        for (index, table) in manifest.tables.iter().enumerate() {
            rows.extend(table_rows(
                &profile.kind,
                table,
                index + 1,
                &manifest.logical_schema,
            )?);
        }
    }
    if profile.kind == "access_methods" {
        rows = vec![vec!["1".into(), literal("btree")]];
    }
    let mut names = profile.columns.clone();
    let mut conditions = Vec::new();
    if profile.kind == "keys" {
        names.push("constraint_kind".into());
        if let Some(parameter) = parameter(profile, "contype") {
            conditions.push(format!("constraint_kind={parameter}::text"));
        }
    }
    if let Some(parameter) =
        parameter(profile, "filter_names_1").or_else(|| parameter(profile, "table_names_1"))
    {
        conditions.push(format!(
            "{}={parameter}::text",
            if profile.kind == "columns" {
                "table_name"
            } else {
                "relname"
            }
        ));
    }
    if let Some(parameter) = parameter(profile, "oids_1") {
        conditions.push(format!(
            "{}={parameter}::bigint",
            if profile.kind == "keys" {
                "conrelid"
            } else {
                "indrelid"
            }
        ));
    }
    if profile.kind == "access_methods"
        && let Some(parameter) = parameter(profile, "amname_1")
    {
        conditions.push(format!("amname={parameter}::text"));
    }
    if profile.kind == "types"
        && let Some(parameter) = parameter(profile, "name")
    {
        conditions.push(format!(
            "(name={parameter}::text OR regtype={parameter}::text)"
        ));
    }
    let columns = names
        .iter()
        .map(|name| (name.clone(), column_type(name).into()))
        .collect();
    let mut read = result(
        DIALECT,
        columns,
        rows,
        &conditions.join(" AND "),
        parameters,
        postgres_parameters,
    );
    if profile.kind == "keys" {
        read.sql = format!(
            "SELECT {} FROM ({}) AS visible",
            profile
                .columns
                .iter()
                .map(|name| quote(DIALECT, name))
                .collect::<Vec<_>>()
                .join(", "),
            read.sql
        );
        read.columns.truncate(profile.columns.len());
    }
    Ok(Some(read))
}

fn parameter(profile: &Profile, name: &str) -> Option<String> {
    profile
        .parameters
        .iter()
        .position(|item| item == name)
        .map(|index| format!("${}", index + 1))
}

fn column_type(name: &str) -> &'static str {
    match name {
        "not_null" | "indnullsnotdistinct" | "indisunique" | "indisvalid" | "has_constraint" => {
            "boolean"
        }
        "oid" | "array_oid" | "conrelid" | "indrelid" | "relam" => "bigint",
        "indnkeyatts" => "integer",
        "identity_options" | "collation" => "json",
        "cols" | "reloptions" | "elements" | "parent_table_names" => "text[]",
        "indoption" => "int2vector",
        "elements_is_expr" => "boolean[]",
        "elements_opclass" => "bigint[]",
        _ => "text",
    }
}

fn array(values: impl IntoIterator<Item = String>) -> String {
    format!(
        "ARRAY[{}]",
        values.into_iter().collect::<Vec<_>>().join(", ")
    )
}

fn names(values: &[String]) -> String {
    values
        .iter()
        .map(|name| quote(DIALECT, name))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_type(kind: &SnapshotType) -> String {
    match kind {
        SnapshotType::Text {
            length: Some(length),
        } => format!("character varying({length})"),
        SnapshotType::Timestamp {
            precision,
            timezone,
        } => format!(
            "timestamp({precision}) {} time zone",
            if *timezone { "with" } else { "without" }
        ),
        _ => kind.native_name("postgresql"),
    }
}

fn table_rows(
    kind: &str,
    table: &TableManifest,
    oid: usize,
    schema: &str,
) -> Result<Vec<Vec<String>>> {
    let null = || "NULL".to_owned();
    let oid = oid.to_string();
    let table_name = literal(&table.name);
    Ok(match kind {
        "tables" => vec![vec![table_name]],
        "table_oids" => vec![vec![oid, table_name]],
        "columns" => table
            .columns
            .iter()
            .map(|column| {
                let default = if table.generated_key.as_ref() == Some(&column.name) {
                    literal(&format!(
                        "nextval('{}'::regclass)",
                        format!("{}_{}_seq", table.name, column.name).replace('\'', "''")
                    ))
                } else {
                    column
                        .default
                        .as_ref()
                        .map_or_else(null, |value| literal(&default_value(value, DIALECT)))
                };
                vec![
                    literal(&column.name),
                    literal(&format_type(&column.sql_type)),
                    default,
                    (!column.nullable).to_string().to_uppercase(),
                    table_name.clone(),
                    null(),
                    literal(""),
                    null(),
                    null(),
                ]
            })
            .collect(),
        "keys" => {
            let mut rows = vec![vec![
                oid.clone(),
                array(table.primary_key.iter().map(|name| literal(name))),
                literal(
                    table
                        .primary_key_name
                        .as_deref()
                        .unwrap_or(&format!("{}_pkey", table.name)),
                ),
                null(),
                table.primary_key.len().to_string(),
                "FALSE".into(),
                literal("p"),
            ]];
            for index in table
                .indexes
                .iter()
                .filter(|index| index.unique && index.is_constraint)
            {
                rows.push(vec![
                    oid.clone(),
                    array(index.columns.iter().map(|name| literal(name))),
                    literal(&index.name),
                    null(),
                    index.columns.len().to_string(),
                    "FALSE".into(),
                    literal("u"),
                ]);
            }
            rows
        }
        "foreign_keys" => {
            if table.foreign_keys.is_empty() {
                vec![vec![table_name, null(), null(), null(), null()]]
            } else {
                table
                    .foreign_keys
                    .iter()
                    .map(|key| {
                        vec![
                            table_name.clone(),
                            literal(&key.name),
                            literal(&foreign_key(key)),
                            literal(schema),
                            null(),
                        ]
                    })
                    .collect()
            }
        }
        "indexes" => table
            .indexes
            .iter()
            .map(|index| {
                vec![
                    oid.clone(),
                    literal(&index.name),
                    index.unique.to_string().to_uppercase(),
                    "TRUE".into(),
                    index.is_constraint.to_string().to_uppercase(),
                    literal(&vec!["0"; index.columns.len()].join(" ")),
                    null(),
                    "1".into(),
                    null(),
                    index.columns.len().to_string(),
                    "FALSE".into(),
                    array(index.columns.iter().map(|name| literal(name))),
                    array(index.columns.iter().map(|_| "FALSE".into())),
                    array(index.columns.iter().map(|_| "0".into())),
                ]
            })
            .collect(),
        "checks" => {
            if table.checks.is_empty() {
                vec![vec![table_name, null(), null(), null()]]
            } else {
                table
                    .checks
                    .iter()
                    .map(|check| {
                        vec![
                            table_name.clone(),
                            literal(&check.name),
                            literal(&format!("CHECK ({})", check.expression)),
                            null(),
                        ]
                    })
                    .collect()
            }
        }
        "comments" => vec![vec![table_name, null()]],
        "table_options" => vec![vec![
            oid,
            table_name,
            null(),
            null(),
            null(),
            null(),
            null(),
        ]],
        "access_methods" | "opclasses" => Vec::new(),
        _ => return Err(CompileError::Catalog),
    })
}

fn foreign_key(key: &ForeignKeySpec) -> String {
    let action = |action| match action {
        ReferentialAction::NoAction => "NO ACTION",
        ReferentialAction::Restrict => "RESTRICT",
        ReferentialAction::Cascade => "CASCADE",
        ReferentialAction::SetNull => "SET NULL",
    };
    let mut sql = format!(
        "FOREIGN KEY ({}) REFERENCES {}({}) ON UPDATE {} ON DELETE {}",
        names(&key.columns),
        quote(DIALECT, &key.referenced_table),
        names(&key.referenced_columns),
        action(key.on_update),
        action(key.on_delete)
    );
    if key.deferrable {
        sql.push_str(" DEFERRABLE");
        if key.initially_deferred {
            sql.push_str(" INITIALLY DEFERRED");
        }
    }
    sql
}
