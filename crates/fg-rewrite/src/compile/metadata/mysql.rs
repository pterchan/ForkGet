use fg_protocol_common::{BranchBinding, ColumnDefault, TableManifest};
use sqlparser::ast::{
    BinaryOperator, Expr, ObjectNamePart, SetExpr, ShowCreateObject, Statement, Value,
};

use super::{CompileError, CompiledRead, Dialect, Result, default_value, quote, result, table};

const DIALECT: Dialect = Dialect::MySql;

pub(super) fn literal(value: &str) -> String {
    let hex = value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("CONVERT(X'{hex}' USING utf8mb4)")
}

pub(super) fn compile(
    statement: &Statement,
    binding: &BranchBinding,
) -> Result<Option<CompiledRead>> {
    if let Some(read) = reflection_columns(statement, binding) {
        return Ok(Some(read));
    }
    match statement {
        Statement::ShowTables {
            terse: false,
            history: false,
            extended: false,
            full,
            external: false,
            show_options,
        } if show_options.starts_with.is_none()
            && show_options.limit.is_none()
            && show_options.limit_from.is_none()
            && show_options.filter_position.is_none() =>
        {
            if let Some(scope) = &show_options.show_in {
                let schema = scope.parent_name.as_ref().ok_or(CompileError::Object)?;
                let [ObjectNamePart::Identifier(name)] = schema.0.as_slice() else {
                    return Err(CompileError::Object);
                };
                if name.value != binding.name && name.value != binding.default_schema {
                    return Err(CompileError::Object);
                }
            }
            let mut columns = vec![(format!("Tables_in_{}", binding.name), "text".into())];
            if *full {
                columns.push(("Table_type".into(), "text".into()));
            }
            let rows = binding
                .snapshot_manifest
                .as_ref()
                .ok_or(CompileError::Catalog)?
                .tables
                .iter()
                .map(|table| {
                    let mut row = vec![literal(&table.name)];
                    if *full {
                        row.push(literal("BASE TABLE"));
                    }
                    row
                })
                .collect();
            Ok(Some(result(DIALECT, columns, rows, "", 0, &[])))
        }
        Statement::ShowCreate {
            obj_type: ShowCreateObject::Table,
            obj_name,
        } => {
            let (schema, name) = super::super::scope::object_name(DIALECT, obj_name)?;
            let table = table(binding, schema.as_deref(), &name)?;
            if table
                .columns
                .iter()
                .filter_map(|column| column.collation.as_deref())
                .any(|name| {
                    name.is_empty()
                        || !name
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                })
            {
                return Err(CompileError::Catalog);
            }
            Ok(Some(result(
                DIALECT,
                vec![
                    ("Table".into(), "text".into()),
                    ("Create Table".into(), "text".into()),
                ],
                vec![vec![literal(&table.name), literal(&create_table(table))]],
                "",
                0,
                &[],
            )))
        }
        Statement::ExplainTable {
            hive_format: None,
            table_name,
            ..
        } => {
            let (schema, name) = super::super::scope::object_name(DIALECT, table_name)?;
            let table = table(binding, schema.as_deref(), &name)?;
            let rows = table
                .columns
                .iter()
                .map(|column| {
                    vec![
                        literal(&column.name),
                        literal(&column.sql_type.native_name("mysql")),
                        literal(if column.nullable { "YES" } else { "NO" }),
                        literal(if table.primary_key.contains(&column.name) {
                            "PRI"
                        } else {
                            ""
                        }),
                        column
                            .default
                            .as_ref()
                            .filter(|value| !matches!(value, ColumnDefault::Generated))
                            .map_or("NULL".into(), |value| {
                                literal(&default_value(value, DIALECT))
                            }),
                        literal(if table.generated_key.as_ref() == Some(&column.name) {
                            "auto_increment"
                        } else {
                            ""
                        }),
                    ]
                })
                .collect();
            Ok(Some(result(
                DIALECT,
                ["Field", "Type", "Null", "Key", "Default", "Extra"]
                    .into_iter()
                    .map(|name| (name.into(), "text".into()))
                    .collect(),
                rows,
                "",
                0,
                &[],
            )))
        }
        _ => Ok(None),
    }
}

const MAX_REFLECTION_TABLE_GROUPS: usize = 64;

struct ReflectionGroup {
    table: String,
    columns: Vec<String>,
    sql: String,
}

fn reflection_columns(statement: &Statement, binding: &BranchBinding) -> Option<CompiledRead> {
    let Statement::Query(query) = statement else {
        return None;
    };
    let SetExpr::Select(select) = query.body.as_ref() else {
        return None;
    };
    let Expr::BinaryOp {
        left,
        op: BinaryOperator::And,
        right,
    } = select.selection.as_ref()?
    else {
        return None;
    };
    let (schema, groups, grouped) = match (left.as_ref(), right.as_ref()) {
        (
            Expr::BinaryOp {
                left: schema,
                op: BinaryOperator::And,
                right: table,
            },
            Expr::InList { .. },
        ) => (
            schema.as_ref(),
            vec![reflection_group(table, right)?],
            false,
        ),
        (schema, Expr::Nested(groups)) => (schema, reflection_groups(groups)?, true),
        _ => return None,
    };
    let Expr::BinaryOp {
        op: BinaryOperator::Eq,
        right: schema,
        ..
    } = schema
    else {
        return None;
    };
    let schema_value = reflection_string(schema)?;
    if schema_value != binding.name && schema_value != binding.default_schema {
        return None;
    }
    let predicates = groups
        .iter()
        .map(|group| group.sql.as_str())
        .collect::<Vec<_>>()
        .join(" OR ");
    let predicates = if grouped {
        format!("({predicates})")
    } else {
        predicates
    };
    let expected = format!(
        "SELECT information_schema.columns.table_schema, information_schema.columns.table_name, information_schema.columns.column_name FROM information_schema.columns WHERE information_schema.columns.table_schema = {schema} AND {predicates}"
    );
    // Match the entire ORM query so extra catalog sources, projections or
    // predicates cannot widen this virtual logical-catalog read.
    if statement.to_string() != expected {
        return None;
    }
    let tables = &binding.snapshot_manifest.as_ref()?.tables;
    for group in &groups {
        let table = tables.iter().find(|table| table.name == group.table)?;
        if group.columns.iter().any(|name| {
            !table
                .columns
                .iter()
                .any(|column| name == &column.name.to_ascii_lowercase())
        }) {
            return None;
        }
    }
    let mut rows = Vec::new();
    for table in tables {
        for column in &table.columns {
            if groups.iter().any(|group| {
                group.table == table.name
                    && group
                        .columns
                        .iter()
                        .any(|name| name == &column.name.to_ascii_lowercase())
            }) {
                rows.push(vec![
                    literal(&schema_value),
                    literal(&table.name),
                    literal(&column.name),
                ]);
            }
        }
    }
    Some(result(
        DIALECT,
        ["table_schema", "table_name", "column_name"]
            .into_iter()
            .map(|name| (name.into(), "text".into()))
            .collect(),
        rows,
        "",
        0,
        &[],
    ))
}

fn reflection_string(expression: &Expr) -> Option<String> {
    let Expr::Value(value) = expression else {
        return None;
    };
    let Value::SingleQuotedString(value) = &value.value else {
        return None;
    };
    Some(value.clone())
}

fn reflection_group(table: &Expr, columns: &Expr) -> Option<ReflectionGroup> {
    let Expr::BinaryOp {
        op: BinaryOperator::Eq,
        right: table,
        ..
    } = table
    else {
        return None;
    };
    let Expr::InList {
        list,
        negated: false,
        ..
    } = columns
    else {
        return None;
    };
    if list.is_empty() {
        return None;
    }
    Some(ReflectionGroup {
        table: reflection_string(table)?,
        columns: list
            .iter()
            .map(reflection_string)
            .collect::<Option<Vec<_>>>()?,
        sql: format!(
            "information_schema.columns.table_name = {table} AND lower(information_schema.columns.column_name) IN ({})",
            list.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    })
}

fn reflection_groups(expression: &Expr) -> Option<Vec<ReflectionGroup>> {
    let mut pending = vec![expression];
    let mut groups = Vec::new();
    while let Some(expression) = pending.pop() {
        match expression {
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Or,
                right,
            } => {
                pending.push(right.as_ref());
                pending.push(left.as_ref());
            }
            Expr::BinaryOp {
                left,
                op: BinaryOperator::And,
                right,
            } => {
                groups.push(reflection_group(left, right)?);
            }
            _ => return None,
        }
        if pending.len() + groups.len() > MAX_REFLECTION_TABLE_GROUPS {
            return None;
        }
    }
    Some(groups)
}

fn names(columns: &[String]) -> String {
    columns
        .iter()
        .map(|name| quote(DIALECT, name))
        .collect::<Vec<_>>()
        .join(", ")
}

fn create_table(table: &TableManifest) -> String {
    let mut lines = table
        .columns
        .iter()
        .map(|column| {
            let mut definition = format!(
                "  {} {}",
                quote(DIALECT, &column.name),
                column.sql_type.native_name("mysql")
            );
            if let Some(collation) = &column.collation {
                // Native SHOW CREATE spells collations without identifier
                // quotes; the dialect parser uses that spelling to retain
                // subsequent NOT NULL and DEFAULT column attributes.
                definition.push_str(&format!(" COLLATE {collation}"));
            }
            definition.push_str(if column.nullable {
                " NULL"
            } else {
                " NOT NULL"
            });
            if table.generated_key.as_ref() == Some(&column.name) {
                definition.push_str(" AUTO_INCREMENT");
            } else if let Some(default) = &column.default {
                definition.push_str(&format!(" DEFAULT {}", default_value(default, DIALECT)));
            }
            definition
        })
        .collect::<Vec<_>>();
    lines.push(format!("  PRIMARY KEY ({})", names(&table.primary_key)));
    for index in &table.indexes {
        lines.push(format!(
            "  {}KEY {} ({})",
            if index.unique { "UNIQUE " } else { "" },
            quote(DIALECT, &index.name),
            names(&index.columns)
        ));
    }
    for key in &table.foreign_keys {
        let action = |action: fg_protocol_common::ReferentialAction| match action {
            fg_protocol_common::ReferentialAction::NoAction => "NO ACTION",
            fg_protocol_common::ReferentialAction::Restrict => "RESTRICT",
            fg_protocol_common::ReferentialAction::Cascade => "CASCADE",
            fg_protocol_common::ReferentialAction::SetNull => "SET NULL",
        };
        lines.push(format!(
            "  CONSTRAINT {} FOREIGN KEY ({}) REFERENCES {} ({}) ON DELETE {} ON UPDATE {}",
            quote(DIALECT, &key.name),
            names(&key.columns),
            quote(DIALECT, &key.referenced_table),
            names(&key.referenced_columns),
            action(key.on_delete),
            action(key.on_update)
        ));
    }
    for check in &table.checks {
        lines.push(format!(
            "  CONSTRAINT {} CHECK ({})",
            quote(DIALECT, &check.name),
            check.expression
        ));
    }
    format!(
        "CREATE TABLE {} (\n{}\n) ENGINE=InnoDB",
        quote(DIALECT, &table.name),
        lines.join(",\n")
    )
}
