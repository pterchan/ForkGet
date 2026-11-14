use std::ops::Range;

mod bulk;

use fg_protocol_common::{
    BranchBinding, CatalogColumn, CatalogEntry, MAX_GENERATED_ROWS, SqlLimit, WriteKind,
    WriteOperation, WriteTarget,
};
use sqlparser::ast::{
    AssignmentTarget, BinaryOperator, Delete, Expr, FromTable, Ident, Insert, ObjectName, Query,
    SelectItem, SelectItemQualifiedWildcardKind, SetExpr, Statement, TableFactor, TableObject,
    TableWithJoins, UnaryOperator, Update, Value,
};

use crate::{Dialect, TableRef, quote_identifier, quote_table, validate_columns};

use super::{
    ColumnOrigin, CompileError, OutputColumn, Result,
    expression::check_value,
    lexical::{Source, postgres_parameter},
    scope::{admitted_ident, column_eq, object_name, plain_wildcard},
};

const GENERATED_COLUMN: &str = "_fg_generated";
pub const MYSQL_GENERATED_START: &str = "@_fg_generated_start";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GeneratedIds {
    pub table_id: i64,
    pub count: u16,
}

#[derive(Debug)]
pub struct CompiledWrite {
    pub operation: WriteOperation,
    pub sql: String,
    pub parameter_count: usize,
    pub columns: Vec<OutputColumn>,
    pub generated: Option<GeneratedIds>,
    /// One-based positions compared to integral PostgreSQL primary keys.
    pub postgres_point_parameters: Vec<u32>,
    start_locations: Vec<Range<usize>>,
}

impl CompiledWrite {
    fn new(table_id: i64, kind: WriteKind, parameter_count: usize) -> Self {
        Self {
            operation: WriteOperation { table_id, kind },
            sql: String::new(),
            parameter_count,
            columns: Vec::new(),
            generated: None,
            postgres_point_parameters: Vec::new(),
            start_locations: Vec::new(),
        }
    }

    /// Substitute a trusted reservation into only the compiler-created slots.
    pub fn text_sql(&self, start: i64) -> String {
        let mut sql = self.sql.clone();
        let start = start.to_string();
        for location in self.start_locations.iter().rev() {
            sql.replace_range(location.clone(), &start);
        }
        sql
    }
}

pub(super) fn compile(
    dialect: Dialect,
    binding: &BranchBinding,
    target: Option<&WriteTarget>,
    source: Source<'_>,
    statement: Statement,
    parameter_count: usize,
) -> Result<CompiledWrite> {
    let compiler = Mutation {
        dialect,
        binding,
        target,
        source,
    };
    match statement {
        Statement::Insert(insert) => compiler.insert(&insert, parameter_count),
        Statement::Update(update) => compiler.update(&update, parameter_count),
        Statement::Delete(delete) => compiler.delete(&delete, parameter_count),
        _ => Err(CompileError::Unsupported),
    }
}

struct Mutation<'a> {
    dialect: Dialect,
    binding: &'a BranchBinding,
    target: Option<&'a WriteTarget>,
    source: Source<'a>,
}

struct PointTerm<'a> {
    name: &'a str,
    sql: String,
    postgres_parameter: Option<u32>,
    primary_key: bool,
}

impl Mutation<'_> {
    fn has_default(&self, table: &CatalogEntry, column: &str) -> bool {
        self.binding
            .snapshot_manifest
            .as_ref()
            .and_then(|manifest| {
                manifest
                    .tables
                    .iter()
                    .find(|entry| entry.name == table.logical_table)
            })
            .and_then(|table| table.columns.iter().find(|entry| entry.name == column))
            .is_some_and(|column| column.default.is_some())
    }

    fn insert(&self, insert: &Insert, parameter_count: usize) -> Result<CompiledWrite> {
        let (name, query) = insert_target(insert)?;
        let table = self.table(name)?;
        let mut columns = Vec::with_capacity(insert.columns.len() + 2);
        for name in &insert.columns {
            let column = self.unqualified_column(table, name)?;
            if columns.contains(&column.name.as_str()) {
                return Err(CompileError::Unsupported);
            }
            columns.push(column.name.as_str());
        }
        let generated = table
            .generated_key
            .as_deref()
            .filter(|key| !columns.contains(key));
        if table.columns.iter().any(|column| {
            !column.nullable
                && Some(column.name.as_str()) != generated
                && !columns.contains(&column.name.as_str())
                && !self.has_default(table, &column.name)
        }) {
            return Err(CompileError::Unsupported);
        }

        let mut output = CompiledWrite::new(table.id, WriteKind::Insert, parameter_count);
        let input_columns = columns.len();
        let rows = bulk::input_rows(
            self.dialect,
            query,
            table,
            &columns,
            self.binding.snapshot_manifest.as_ref(),
        )?;
        if let Some(key) = generated {
            output.generated = Some(GeneratedIds {
                table_id: table.id,
                count: u16::try_from(rows.len()).map_err(|_| CompileError::Unsupported)?,
            });
            columns.extend([key, GENERATED_COLUMN]);
        }
        let columns = columns
            .iter()
            .map(|column| self.quote(column))
            .collect::<Vec<_>>()
            .join(", ");
        output.sql = format!("INSERT INTO {} ({columns}) VALUES ", self.physical(table));
        for (index, row) in rows.iter().enumerate() {
            if row.len() != input_columns {
                return Err(CompileError::Syntax);
            }
            self.insert_row(&mut output, index, row)?;
        }
        self.returning(table, insert.returning.as_deref(), &mut output)?;
        Ok(output)
    }

    fn insert_row(&self, output: &mut CompiledWrite, index: usize, row: &[Expr]) -> Result<()> {
        if index > 0 {
            output.sql.push_str(", ");
        }
        output.sql.push('(');
        let values = row
            .iter()
            .map(|expr| self.scalar(expr))
            .collect::<Result<Vec<_>>>()?;
        output.sql.push_str(&values.join(", "));
        if output.generated.is_some() {
            output.sql.push_str(", ");
            let is_mysql_first = self.dialect == Dialect::MySql && index == 0;
            if is_mysql_first {
                output.sql.push_str("LAST_INSERT_ID(");
            }
            if self.dialect == Dialect::MySql {
                output.sql.push_str("CAST(");
            }
            let start = output.sql.len();
            match self.dialect {
                Dialect::MySql => output.sql.push_str(MYSQL_GENERATED_START),
                Dialect::PostgreSql => output
                    .sql
                    .push_str(&format!("${}", output.parameter_count + 1)),
            }
            output.start_locations.push(start..output.sql.len());
            if self.dialect == Dialect::MySql {
                output.sql.push_str(" AS SIGNED)");
            }
            if index > 0 {
                output.sql.push_str(&format!(" + {index}"));
            }
            if is_mysql_first {
                output.sql.push(')');
            }
            output.sql.push_str(", TRUE");
        }
        output.sql.push(')');
        Ok(())
    }

    fn update(&self, update: &Update, parameter_count: usize) -> Result<CompiledWrite> {
        if !update.optimizer_hints.is_empty()
            || update.from.is_some()
            || update.output.is_some()
            || update.or.is_some()
            || !update.order_by.is_empty()
            || update.limit.is_some()
            || update.assignments.is_empty()
        {
            return Err(CompileError::Unsupported);
        }
        let table = self.table(single_target(&update.table)?)?;
        let mut assigned = Vec::new();
        let mut assignments = Vec::new();
        for assignment in &update.assignments {
            let AssignmentTarget::ColumnName(name) = &assignment.target else {
                return Err(CompileError::Unsupported);
            };
            let column = self.unqualified_column(table, name)?;
            if column.primary_key_ordinal.is_some() || assigned.contains(&column.name.as_str()) {
                return Err(CompileError::Unsupported);
            }
            assigned.push(column.name.as_str());
            let value = self.scalar(&assignment.value)?;
            assignments.push(format!("{} = {value}", self.quote(&column.name)));
        }
        let mut output = CompiledWrite::new(table.id, WriteKind::Update, parameter_count);
        let predicate = self.point_predicate(table, update.selection.as_ref(), &mut output)?;
        output.sql = format!(
            "UPDATE {} SET {} WHERE {predicate}",
            self.physical(table),
            assignments.join(", "),
        );
        self.returning(table, update.returning.as_deref(), &mut output)?;
        Ok(output)
    }

    fn delete(&self, delete: &Delete, parameter_count: usize) -> Result<CompiledWrite> {
        let FromTable::WithFromKeyword(from) = &delete.from else {
            return Err(CompileError::Unsupported);
        };
        let [target] = from.as_slice() else {
            return Err(CompileError::Unsupported);
        };
        if !delete.optimizer_hints.is_empty()
            || !delete.tables.is_empty()
            || delete.using.is_some()
            || delete.output.is_some()
            || !delete.order_by.is_empty()
            || delete.limit.is_some()
        {
            return Err(CompileError::Unsupported);
        }
        let table = self.table(single_target(target)?)?;
        let mut output = CompiledWrite::new(table.id, WriteKind::Delete, parameter_count);
        let predicate = self.point_predicate(table, delete.selection.as_ref(), &mut output)?;
        output.sql = format!("DELETE FROM {} WHERE {predicate}", self.physical(table));
        self.returning(table, delete.returning.as_deref(), &mut output)?;
        Ok(output)
    }

    fn table(&self, name: &ObjectName) -> Result<&CatalogEntry> {
        let (schema, table) = object_name(self.dialect, name)?;
        let schema = schema.as_deref().unwrap_or(&self.binding.default_schema);
        let table = self
            .binding
            .tables
            .iter()
            .find(|entry| entry.logical_schema == schema && entry.logical_table == table)
            .ok_or(CompileError::Object)?;
        let columns = table
            .columns
            .iter()
            .map(|column| column.name.as_str())
            .collect::<Vec<_>>();
        validate_columns(&columns)?;
        Ok(table)
    }

    fn quote(&self, identifier: &str) -> String {
        quote_identifier(self.dialect, identifier)
    }

    fn physical(&self, table: &CatalogEntry) -> String {
        let physical;
        let (schema, name) = match self.target {
            Some(target) => {
                physical = target.table(&table.logical_table);
                (target.schema(), physical.as_str())
            }
            None => (table.logical_schema.as_str(), table.logical_table.as_str()),
        };
        quote_table(
            self.dialect,
            TableRef {
                schema,
                table: name,
            },
        )
    }

    fn unqualified_column<'a>(
        &self,
        table: &'a CatalogEntry,
        name: &ObjectName,
    ) -> Result<&'a CatalogColumn> {
        let (schema, name) = object_name(self.dialect, name)?;
        if schema.is_some() {
            return Err(CompileError::Unsupported);
        }
        self.column(table, &name)
    }

    fn column<'a>(&self, table: &'a CatalogEntry, name: &str) -> Result<&'a CatalogColumn> {
        table
            .columns
            .iter()
            .find(|column| column_eq(self.dialect, &column.name, name))
            .ok_or(CompileError::Object)
    }

    fn column_reference<'a>(
        &self,
        table: &'a CatalogEntry,
        expr: &Expr,
    ) -> Result<&'a CatalogColumn> {
        let ident = match expr {
            Expr::Identifier(ident) => ident,
            Expr::CompoundIdentifier(parts) => {
                let (schema, qualifier, ident) = match parts.as_slice() {
                    [name, ident] => (None, name, ident),
                    [schema, name, ident] => (Some(schema), name, ident),
                    _ => return Err(CompileError::Object),
                };
                let qualifier = admitted_ident(self.dialect, qualifier)?;
                let schema = schema
                    .map(|schema| admitted_ident(self.dialect, schema))
                    .transpose()?;
                check_qualifier(table, schema.as_deref(), &qualifier)?;
                ident
            }
            _ => return Err(CompileError::Unsupported),
        };
        self.column(table, &admitted_ident(self.dialect, ident)?)
    }

    fn scalar(&self, expr: &Expr) -> Result<String> {
        if let Expr::Cast {
            kind,
            expr,
            data_type,
            format: None,
        } = expr
            && super::expression::allows_cast(self.dialect, kind, data_type)
        {
            return Ok(format!("CAST({} AS {data_type})", self.scalar(expr)?));
        }
        let (sign, value) = match expr {
            Expr::Value(value) => ("", value),
            Expr::UnaryOp {
                op: op @ (UnaryOperator::Plus | UnaryOperator::Minus),
                expr,
            } => {
                let Expr::Value(value) = expr.as_ref() else {
                    return Err(CompileError::Unsupported);
                };
                if !matches!(value.value, Value::Number(_, false)) {
                    return Err(CompileError::Unsupported);
                }
                (if *op == UnaryOperator::Plus { "+" } else { "-" }, value)
            }
            _ => return Err(CompileError::Unsupported),
        };
        check_value(self.dialect, &value.value)?;
        if let Value::Placeholder(parameter) = &value.value {
            match self.dialect {
                Dialect::MySql if parameter != "?" => return Err(CompileError::Syntax),
                Dialect::PostgreSql => {
                    postgres_parameter(parameter)?;
                }
                Dialect::MySql => (),
            }
        }
        Ok(format!(
            "{sign}{}",
            &self.source.sql[self.source.range(value.span)?]
        ))
    }

    fn point_predicate(
        &self,
        table: &CatalogEntry,
        selection: Option<&Expr>,
        output: &mut CompiledWrite,
    ) -> Result<String> {
        let mut terms = Vec::new();
        self.key_terms(
            table,
            selection.ok_or(CompileError::Unsupported)?,
            &mut terms,
        )?;
        if table
            .columns
            .iter()
            .filter(|column| column.primary_key_ordinal.is_some())
            .count()
            != terms.iter().filter(|term| term.primary_key).count()
        {
            return Err(CompileError::Unsupported);
        }
        output.postgres_point_parameters.extend(
            terms
                .iter()
                .filter(|term| term.primary_key)
                .filter_map(|term| term.postgres_parameter),
        );
        Ok(terms
            .into_iter()
            .map(|term| term.sql)
            .collect::<Vec<_>>()
            .join(" AND "))
    }

    fn key_terms<'a>(
        &self,
        table: &'a CatalogEntry,
        expr: &Expr,
        terms: &mut Vec<PointTerm<'a>>,
    ) -> Result<()> {
        match expr {
            Expr::Nested(expr) => self.key_terms(table, expr, terms),
            Expr::BinaryOp {
                left,
                op: BinaryOperator::And,
                right,
            } => {
                self.key_terms(table, left, terms)?;
                self.key_terms(table, right, terms)
            }
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right,
            } => {
                let term = self.key_term(table, left, right)?;
                if terms.iter().any(|other| other.name == term.name) {
                    return Err(CompileError::Unsupported);
                }
                terms.push(term);
                Ok(())
            }
            _ => Err(CompileError::Unsupported),
        }
    }

    fn key_term<'a>(
        &self,
        table: &'a CatalogEntry,
        left: &Expr,
        right: &Expr,
    ) -> Result<PointTerm<'a>> {
        let column = self.column_reference(table, left)?;
        let primary_key = column.primary_key_ordinal.is_some();
        if primary_key && !is_integral(&column.type_name) {
            return Err(CompileError::Unsupported);
        }
        let mut value = self.scalar(right)?;
        let mut parameter = None;
        // Approximate coercions can match neighboring integral IDs above 2^53.
        // PostgreSQL admission limits the declared OID of point parameters.
        if self.dialect == Dialect::MySql && primary_key {
            value = format!("CAST({value} AS DECIMAL(65, 30))");
        } else if self.dialect == Dialect::PostgreSql && primary_key {
            parameter = scalar_parameter(right)
                .map(postgres_parameter)
                .transpose()?;
        }
        Ok(PointTerm {
            name: &column.name,
            sql: format!("{} = {value}", self.quote(&column.name)),
            postgres_parameter: parameter,
            primary_key,
        })
    }

    fn returning(
        &self,
        table: &CatalogEntry,
        items: Option<&[SelectItem]>,
        output: &mut CompiledWrite,
    ) -> Result<()> {
        let Some(items) = items else {
            return Ok(());
        };
        if self.dialect != Dialect::PostgreSql {
            return Err(CompileError::Unsupported);
        }
        let mut projection = Vec::new();
        for item in items {
            match item {
                SelectItem::Wildcard(options) if plain_wildcard(options) => {
                    for column in &table.columns {
                        self.return_column(table, column, None, &mut projection, output)?;
                    }
                }
                SelectItem::QualifiedWildcard(
                    SelectItemQualifiedWildcardKind::ObjectName(name),
                    options,
                ) if plain_wildcard(options) => {
                    let (schema, name) = object_name(self.dialect, name)?;
                    check_qualifier(table, schema.as_deref(), &name)?;
                    for column in &table.columns {
                        self.return_column(table, column, None, &mut projection, output)?;
                    }
                }
                SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => {
                    let column = self.column_reference(table, expr)?;
                    let alias = match item {
                        SelectItem::ExprWithAlias { alias, .. } => Some(alias),
                        _ => None,
                    };
                    self.return_column(table, column, alias, &mut projection, output)?;
                }
                _ => return Err(CompileError::Unsupported),
            }
        }
        output.sql.push_str(" RETURNING ");
        output.sql.push_str(&projection.join(", "));
        Ok(())
    }

    fn return_column(
        &self,
        table: &CatalogEntry,
        column: &CatalogColumn,
        alias: Option<&Ident>,
        projection: &mut Vec<String>,
        output: &mut CompiledWrite,
    ) -> Result<()> {
        let alias = alias
            .map(|alias| admitted_ident(self.dialect, alias))
            .transpose()?;
        let mut expr = self.quote(&column.name);
        if let Some(alias) = &alias {
            expr.push_str(" AS ");
            expr.push_str(&self.quote(alias));
        }
        projection.push(expr);
        output.columns.push(OutputColumn {
            name: Some(alias.unwrap_or_else(|| column.name.clone())),
            origin: Some(ColumnOrigin {
                logical_schema: table.logical_schema.clone(),
                logical_table: table.logical_table.clone(),
                logical_column: column.name.clone(),
                table_alias: None,
            }),
        });
        Ok(())
    }
}

fn is_integral(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "smallint" | "int2" | "integer" | "int" | "int4" | "bigint" | "int8"
    )
}

fn check_qualifier(table: &CatalogEntry, schema: Option<&str>, name: &str) -> Result<()> {
    if name != table.logical_table || schema.is_some_and(|schema| schema != table.logical_schema) {
        return Err(CompileError::Object);
    }
    Ok(())
}

fn scalar_parameter(expr: &Expr) -> Option<&str> {
    match expr {
        Expr::Cast { expr, .. } => scalar_parameter(expr),
        Expr::Value(value) => match &value.value {
            Value::Placeholder(name) => Some(name),
            _ => None,
        },
        _ => None,
    }
}

fn insert_target(insert: &Insert) -> Result<(&ObjectName, &Query)> {
    let TableObject::TableName(name) = &insert.table else {
        return Err(CompileError::Unsupported);
    };
    let Some(source) = &insert.source else {
        return Err(CompileError::Unsupported);
    };
    if !insert.optimizer_hints.is_empty()
        || insert.or.is_some()
        || insert.ignore
        || !insert.into
        || insert.table_alias.is_some()
        || insert.columns.is_empty()
        || insert.overwrite
        || !insert.assignments.is_empty()
        || insert.partitioned.is_some()
        || !insert.after_columns.is_empty()
        || insert.has_table_keyword
        || insert.on.is_some()
        || insert.output.is_some()
        || insert.replace_into
        || insert.priority.is_some()
        || insert.insert_alias.is_some()
        || insert.settings.is_some()
        || insert.format_clause.is_some()
        || insert.multi_table_insert_type.is_some()
        || !insert.multi_table_into_clauses.is_empty()
        || !insert.multi_table_when_clauses.is_empty()
        || insert.multi_table_else_clause.is_some()
    {
        return Err(CompileError::Unsupported);
    }
    Ok((name, source))
}

fn insert_values(query: &Query) -> Result<&sqlparser::ast::Values> {
    let SetExpr::Values(values) = query.body.as_ref() else {
        return Err(CompileError::Unsupported);
    };
    if values.rows.len() > usize::from(MAX_GENERATED_ROWS) {
        return Err(CompileError::Limit {
            kind: SqlLimit::BulkRows,
            actual: values.rows.len() as u64,
            limit: u64::from(MAX_GENERATED_ROWS),
        });
    }
    if query.with.is_some()
        || query.order_by.is_some()
        || query.limit_clause.is_some()
        || query.fetch.is_some()
        || !query.locks.is_empty()
        || query.for_clause.is_some()
        || query.settings.is_some()
        || query.format_clause.is_some()
        || !query.pipe_operators.is_empty()
        || values.explicit_row
        || values.value_keyword
        || values.rows.is_empty()
    {
        return Err(CompileError::Unsupported);
    }
    Ok(values)
}

fn single_target(target: &TableWithJoins) -> Result<&ObjectName> {
    match &target.relation {
        TableFactor::Table {
            name,
            alias: None,
            args: None,
            with_hints,
            version: None,
            with_ordinality: false,
            partitions,
            json_path: None,
            sample: None,
            index_hints,
        } if with_hints.is_empty()
            && partitions.is_empty()
            && index_hints.is_empty()
            && target.joins.is_empty() =>
        {
            Ok(name)
        }
        _ => Err(CompileError::Unsupported),
    }
}
