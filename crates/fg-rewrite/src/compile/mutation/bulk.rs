//! The finite ordered VALUES form emitted by SQLAlchemy's native PG dialect.

use fg_protocol_common::{CatalogEntry, SnapshotManifest, SnapshotType};
use sqlparser::ast::{
    DataType, Expr, GroupByExpr, OrderByKind, Query, SelectItem, SetExpr, TableFactor, Value,
};

use super::{CompileError, Dialect, Result, insert_values};

pub(super) fn input_rows<'a>(
    dialect: Dialect,
    query: &'a Query,
    table: &CatalogEntry,
    columns: &[&str],
    manifest: Option<&SnapshotManifest>,
) -> Result<Vec<&'a [Expr]>> {
    if matches!(query.body.as_ref(), SetExpr::Values(_)) {
        return Ok(insert_values(query)?
            .rows
            .iter()
            .map(|row| row.content.as_slice())
            .collect());
    }
    if dialect != Dialect::PostgreSql
        || query.with.is_some()
        || query.limit_clause.is_some()
        || query.fetch.is_some()
        || !query.locks.is_empty()
        || query.for_clause.is_some()
        || query.settings.is_some()
        || query.format_clause.is_some()
        || !query.pipe_operators.is_empty()
    {
        return Err(CompileError::Unsupported);
    }
    let SetExpr::Select(select) = query.body.as_ref() else {
        return Err(CompileError::Unsupported);
    };
    super::super::scope::check_select(select)?;
    if select.distinct.is_some()
        || select.selection.is_some()
        || select.having.is_some()
        || !matches!(&select.group_by, GroupByExpr::Expressions(group, modifiers) if group.is_empty() && modifiers.is_empty())
    {
        return Err(CompileError::Unsupported);
    }
    let [from] = select.from.as_slice() else {
        return Err(CompileError::Unsupported);
    };
    let TableFactor::Derived {
        lateral: false,
        subquery,
        alias: Some(alias),
        sample: None,
    } = &from.relation
    else {
        return Err(CompileError::Unsupported);
    };
    if !from.joins.is_empty()
        || alias.at.is_some()
        || alias.columns.len() != columns.len() + 1
        || alias
            .columns
            .iter()
            .any(|column| column.data_type.is_some())
        || select.projection.len() != columns.len()
    {
        return Err(CompileError::Unsupported);
    }
    for (index, projection) in select.projection.iter().enumerate() {
        let SelectItem::UnnamedExpr(Expr::Cast {
            kind,
            expr,
            data_type,
            format: None,
        }) = projection
        else {
            return Err(CompileError::Unsupported);
        };
        if !super::super::expression::allows_cast(dialect, kind, data_type)
            || !matches!(expr.as_ref(), Expr::Identifier(name) if *name == alias.columns[index].name)
            || !cast_matches_column(data_type, table, columns[index], manifest)
        {
            return Err(CompileError::Unsupported);
        }
    }
    let sentinel = &alias.columns[columns.len()].name;
    let order = query.order_by.as_ref().ok_or(CompileError::Unsupported)?;
    if order.interpolate.is_some()
        || !matches!(&order.kind, OrderByKind::Expressions(items)
        if items.len()==1 && items[0].with_fill.is_none() && items[0].options==Default::default()
        && matches!(&items[0].expr, Expr::Identifier(name) if name==sentinel))
    {
        return Err(CompileError::Unsupported);
    }
    let values = insert_values(subquery)?;
    let mut rows = Vec::with_capacity(values.rows.len());
    for (index, row) in values.rows.iter().enumerate() {
        if row.len() != columns.len() + 1
            || !matches!(row.content.last(), Some(Expr::Value(value))
            if matches!(&value.value, Value::Number(number,false) if number==&index.to_string()))
        {
            return Err(CompileError::Unsupported);
        }
        rows.push(&row.content[..columns.len()]);
    }
    Ok(rows)
}

fn cast_matches_column(
    data_type: &DataType,
    table: &CatalogEntry,
    column: &str,
    manifest: Option<&SnapshotManifest>,
) -> bool {
    let Some(kind) = manifest
        .and_then(|manifest| {
            manifest
                .tables
                .iter()
                .find(|item| item.name == table.logical_table)
        })
        .and_then(|table| table.columns.iter().find(|item| item.name == column))
        .map(|column| &column.sql_type)
    else {
        return false;
    };
    match (kind, data_type) {
        (SnapshotType::Integer { bits: 64 }, DataType::BigInt(None) | DataType::Int8(None))
        | (
            SnapshotType::Integer { bits: 32 },
            DataType::Int(None) | DataType::Integer(None) | DataType::Int4(None),
        )
        | (SnapshotType::Integer { bits: 16 }, DataType::SmallInt(None) | DataType::Int2(None))
        | (SnapshotType::Text { .. }, DataType::Varchar(None) | DataType::Text)
        | (SnapshotType::Boolean, DataType::Boolean | DataType::Bool)
        | (SnapshotType::Date, DataType::Date) => true,
        (
            SnapshotType::Decimal { precision, scale },
            DataType::Numeric(info) | DataType::Decimal(info) | DataType::Dec(info),
        ) => info.to_string().replace(' ', "") == format!("({precision},{scale})"),
        (
            SnapshotType::Timestamp {
                precision: _,
                timezone,
            },
            DataType::Timestamp(None, zone),
        ) => {
            (*timezone && zone.to_string() == " WITH TIME ZONE")
                || (!*timezone && matches!(zone.to_string().as_str(), "" | " WITHOUT TIME ZONE"))
        }
        _ => false,
    }
}
