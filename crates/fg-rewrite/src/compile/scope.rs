use fg_protocol_common::MYSQL_WRITE_SCHEMA;
use sqlparser::ast::{
    Distinct, Expr, GroupByExpr, Ident, JoinConstraint, JoinOperator, LimitClause, ObjectName,
    ObjectNamePart, OrderByExpr, OrderByKind, OrderBySort, Query, Select, SelectFlavor, SelectItem,
    SelectItemQualifiedWildcardKind, SetExpr, SetOperator, SetQuantifier, Spanned, TableAlias,
    TableFactor, WildcardAdditionalOptions,
};

use crate::{
    Dialect, TableRef, quote_identifier, quote_table, render_visible_relation, validate_table,
};

use super::{ColumnOrigin, CompileError, Compiler, OutputColumn, ReadCatalog, Result};

pub(super) type Scope = Vec<Relation>;

#[derive(Clone)]
pub(super) struct Relation {
    alias: String,
    implicit_schema: Option<String>,
    columns: Vec<OutputColumn>,
}

impl Relation {
    fn derived(alias: String, mut columns: Vec<OutputColumn>) -> Self {
        for origin in columns
            .iter_mut()
            .filter_map(|column| column.origin.as_mut())
        {
            origin.table_alias = Some(alias.clone());
        }
        Self {
            alias,
            implicit_schema: None,
            columns,
        }
    }
}

#[derive(Clone)]
pub(super) struct Cte {
    name: String,
    columns: Vec<OutputColumn>,
}

pub(super) struct Selection {
    pub(super) columns: Vec<OutputColumn>,
    scope: Scope,
}

#[derive(Clone, Copy)]
pub(super) struct Context<'a> {
    pub(super) ctes: &'a [Cte],
    pub(super) outer: &'a [Scope],
    pub(super) scope: &'a Scope,
    pub(super) output: &'a [OutputColumn],
}

impl<'a> Context<'a> {
    fn new(ctes: &'a [Cte], outer: &'a [Scope], scope: &'a Scope) -> Self {
        Self {
            ctes,
            outer,
            scope,
            output: &[],
        }
    }

    fn with_output(self, output: &'a [OutputColumn]) -> Self {
        Self { output, ..self }
    }
}

pub(super) fn validate_catalog(dialect: Dialect, catalog: &ReadCatalog<'_>) -> Result<()> {
    if !valid_name(dialect, catalog.default_schema) || forbidden(catalog.default_schema) {
        return Err(CompileError::Catalog);
    }
    for (index, entry) in catalog.tables.iter().enumerate() {
        let logical = entry.logical;
        if [logical.schema, logical.table]
            .iter()
            .any(|name| !valid_name(dialect, name) || forbidden(name))
        {
            return Err(CompileError::Catalog);
        }
        let base = entry.shape.base;
        let delta = entry.shape.delta;
        if [base.schema, base.table, delta.schema, delta.table]
            .iter()
            .any(|name| !valid_name(dialect, name))
            || (base.schema == delta.schema && base.table == delta.table)
        {
            return Err(CompileError::Catalog);
        }
        if catalog.tables[..index].iter().any(|other| {
            other.logical.schema == logical.schema && other.logical.table == logical.table
        }) {
            return Err(CompileError::Catalog);
        }
        let columns = entry.shape.columns;
        if columns.iter().enumerate().any(|(index, column)| {
            !valid_name(dialect, column)
                || columns[..index]
                    .iter()
                    .any(|other| column_eq(dialect, column, other))
        }) {
            return Err(CompileError::Catalog);
        }
    }
    Ok(())
}

fn valid_name(dialect: Dialect, name: &str) -> bool {
    !name.is_empty()
        && !name.chars().any(char::is_control)
        && match dialect {
            Dialect::PostgreSql => name.len() <= 63,
            Dialect::MySql => name.chars().count() <= 64,
        }
}

fn forbidden(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "forkget_delta"
            | "pg_catalog"
            | "information_schema"
            | "mysql"
            | "sys"
            | "performance_schema"
            | "pg_toast"
            | "pg_temp"
    ) || lower == MYSQL_WRITE_SCHEMA
        || lower.strip_prefix("fg_b").is_some_and(|suffix| {
            let id = suffix.split_once('_').map_or(suffix, |(id, _)| id);
            !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit())
        })
        || ["fg_g", "_fg_", "_d_g", "pg_toast_", "pg_temp_"]
            .iter()
            .any(|prefix| lower.starts_with(prefix))
}

pub(super) fn column_eq(dialect: Dialect, left: &str, right: &str) -> bool {
    match dialect {
        Dialect::MySql => left.eq_ignore_ascii_case(right),
        Dialect::PostgreSql => left == right,
    }
}

pub(super) fn admitted_ident(dialect: Dialect, ident: &Ident) -> Result<String> {
    let quote = match dialect {
        Dialect::MySql => '`',
        Dialect::PostgreSql => '"',
    };
    if !valid_name(dialect, &ident.value) || forbidden(&ident.value) {
        return Err(CompileError::Object);
    }
    match ident.quote_style {
        Some(style) if style == quote => Ok(ident.value.clone()),
        Some(_) => Err(CompileError::Syntax),
        None if !unquoted_name(&ident.value) => Err(CompileError::Syntax),
        None if dialect == Dialect::PostgreSql => Ok(ident.value.to_ascii_lowercase()),
        None => Ok(ident.value.clone()),
    }
}

pub(super) fn object_name(dialect: Dialect, name: &ObjectName) -> Result<(Option<String>, String)> {
    match name.0.as_slice() {
        [ObjectNamePart::Identifier(table)] => Ok((None, admitted_ident(dialect, table)?)),
        [
            ObjectNamePart::Identifier(schema),
            ObjectNamePart::Identifier(table),
        ] => Ok((
            Some(admitted_ident(dialect, schema)?),
            admitted_ident(dialect, table)?,
        )),
        _ => Err(CompileError::Object),
    }
}

impl Compiler<'_> {
    pub(super) fn ident(&self, ident: &Ident) -> Result<String> {
        admitted_ident(self.dialect, ident)
    }
    pub(super) fn query(
        &mut self,
        query: &Query,
        inherited_ctes: &[Cte],
        outer: &[Scope],
    ) -> Result<Selection> {
        check_query(query)?;
        let ctes = self.ctes(query, inherited_ctes, outer)?;
        let result = self.set_expr(&query.body, &ctes, outer)?;
        let ctx = Context::new(&ctes, outer, &result.scope);
        if let Some(order) = &query.order_by {
            let OrderByKind::Expressions(exprs) = &order.kind else {
                return Err(CompileError::Unsupported);
            };
            if order.interpolate.is_some() {
                return Err(CompileError::Unsupported);
            }
            self.order_by(exprs, ctx.with_output(&result.columns))?;
        }
        if let Some(limit) = &query.limit_clause {
            self.limit(limit, ctx)?;
        }
        if let Some(fetch) = &query.fetch {
            if self.dialect != Dialect::PostgreSql
                || fetch.percent
                || fetch.with_ties
                || query.limit_clause.as_ref().is_some_and(|limit| {
                    !matches!(limit, LimitClause::LimitOffset { limit: None, .. })
                })
            {
                return Err(CompileError::Unsupported);
            }
            let count = fetch.quantity.as_ref().ok_or(CompileError::Unsupported)?;
            self.limit_value(count, ctx)?;
        }
        Ok(result)
    }

    fn ctes(&mut self, query: &Query, inherited: &[Cte], outer: &[Scope]) -> Result<Vec<Cte>> {
        let mut visible = inherited.to_vec();
        let Some(with) = &query.with else {
            return Ok(visible);
        };
        if with.recursive {
            return Err(CompileError::Unsupported);
        }
        for cte in &with.cte_tables {
            if cte.from.is_some() || cte.materialized.is_some() {
                return Err(CompileError::Unsupported);
            }
            let name = self.ident(&cte.alias.name)?;
            if visible[inherited.len()..]
                .iter()
                .any(|prior| prior.name == name)
            {
                return Err(CompileError::Object);
            }
            let mut columns = self.query(&cte.query, &visible, outer)?.columns;
            self.alias_columns(&cte.alias, &mut columns)?;
            visible.push(Cte { name, columns });
        }
        Ok(visible)
    }

    fn set_expr(&mut self, set: &SetExpr, ctes: &[Cte], outer: &[Scope]) -> Result<Selection> {
        match set {
            SetExpr::Select(select) => self.select(select, ctes, outer),
            SetExpr::Query(query) => self.query(query, ctes, outer),
            SetExpr::SetOperation {
                left,
                op: SetOperator::Union,
                set_quantifier: SetQuantifier::None | SetQuantifier::All | SetQuantifier::Distinct,
                right,
            } => {
                let mut left = self.set_expr(left, ctes, outer)?.columns;
                let right = self.set_expr(right, ctes, outer)?.columns;
                if left.len() != right.len() {
                    return Err(CompileError::Unsupported);
                }
                for (left, right) in left.iter_mut().zip(right) {
                    if left.origin != right.origin {
                        left.origin = None;
                    }
                }
                Ok(Selection {
                    columns: left,
                    scope: Vec::new(),
                })
            }
            _ => Err(CompileError::Unsupported),
        }
    }

    fn select(&mut self, select: &Select, ctes: &[Cte], outer: &[Scope]) -> Result<Selection> {
        check_select(select)?;
        let scope = self.from(select, ctes, outer)?;
        let ctx = Context::new(ctes, outer, &scope);
        let mut columns = Vec::new();
        for item in &select.projection {
            self.project(item, ctx, &mut columns)?;
        }
        if let Some(predicate) = &select.selection {
            self.expr(predicate, ctx, 0)?;
        }
        let GroupByExpr::Expressions(group, modifiers) = &select.group_by else {
            return Err(CompileError::Unsupported);
        };
        if !modifiers.is_empty() {
            return Err(CompileError::Unsupported);
        }
        self.exprs(group, ctx.with_output(&columns), 0)?;
        if let Some(having) = &select.having {
            let ctx = if self.dialect == Dialect::MySql {
                ctx.with_output(&columns)
            } else {
                ctx
            };
            self.expr(having, ctx, 0)?;
        }
        Ok(Selection { columns, scope })
    }

    fn from(&mut self, select: &Select, ctes: &[Cte], outer: &[Scope]) -> Result<Scope> {
        let mut scope = Vec::new();
        let Some(first) = select.from.first() else {
            return Ok(scope);
        };
        scope.push(self.relation(&first.relation, ctes, outer)?);
        for join in &first.joins {
            if join.global {
                return Err(CompileError::Unsupported);
            }
            let relation = self.relation(&join.relation, ctes, outer)?;
            if scope.iter().any(|prior| prior.alias == relation.alias) {
                return Err(CompileError::Object);
            }
            scope.push(relation);
            if let Some(on) = join_predicate(self.dialect, &join.join_operator)? {
                self.expr(on, Context::new(ctes, outer, &scope), 0)?;
            }
        }
        Ok(scope)
    }

    fn relation(
        &mut self,
        relation: &TableFactor,
        ctes: &[Cte],
        outer: &[Scope],
    ) -> Result<Relation> {
        match relation {
            TableFactor::Table {
                name,
                alias,
                args: None,
                with_hints,
                version: None,
                with_ordinality: false,
                partitions,
                json_path: None,
                sample: None,
                index_hints,
            } if with_hints.is_empty() && partitions.is_empty() && index_hints.is_empty() => {
                self.named_relation(name, alias.as_ref(), ctes)
            }
            TableFactor::Derived {
                lateral: false,
                subquery,
                alias: Some(alias),
                sample: None,
            } => {
                let mut columns = self.query(subquery, ctes, outer)?.columns;
                self.alias_columns(alias, &mut columns)?;
                Ok(Relation::derived(self.ident(&alias.name)?, columns))
            }
            _ => Err(CompileError::Unsupported),
        }
    }

    fn named_relation(
        &mut self,
        name: &ObjectName,
        alias: Option<&TableAlias>,
        ctes: &[Cte],
    ) -> Result<Relation> {
        let (schema, table) = object_name(self.dialect, name)?;
        let effective = alias.map_or_else(|| Ok(table.clone()), |alias| self.ident(&alias.name))?;
        if let Some(cte) = schema
            .is_none()
            .then(|| ctes.iter().rev().find(|candidate| candidate.name == table))
            .flatten()
        {
            let mut columns = cte.columns.clone();
            if let Some(alias) = alias {
                self.alias_columns(alias, &mut columns)?;
            }
            return Ok(Relation::derived(effective, columns));
        }
        if alias.is_some_and(|alias| alias.at.is_some() || !alias.columns.is_empty()) {
            return Err(CompileError::Unsupported);
        }
        let schema = schema.as_deref().unwrap_or(self.catalog.default_schema());
        let entry = self
            .catalog
            .find_table(schema, &table)
            .ok_or(CompileError::Object)?;
        let columns = entry
            .shape
            .columns
            .iter()
            .map(|column| OutputColumn {
                name: Some((*column).to_owned()),
                origin: Some(ColumnOrigin {
                    logical_schema: schema.to_owned(),
                    logical_table: table.clone(),
                    logical_column: (*column).to_owned(),
                    table_alias: alias.map(|_| effective.clone()),
                }),
            })
            .collect();
        let visible = if let Some(target) = self.write_target {
            validate_table(&entry.shape)?;
            let columns = entry
                .shape
                .columns
                .iter()
                .map(|column| quote_identifier(self.dialect, column))
                .collect::<Vec<_>>()
                .join(", ");
            let table = quote_table(
                self.dialect,
                TableRef {
                    schema: target.schema(),
                    table: &target.table(entry.logical.table),
                },
            );
            format!("SELECT {columns} FROM {table}")
        } else if self.base_only {
            validate_table(&entry.shape)?;
            let columns = entry
                .shape
                .columns
                .iter()
                .map(|column| quote_identifier(self.dialect, column))
                .collect::<Vec<_>>()
                .join(", ");
            let table = quote_table(self.dialect, entry.shape.base);
            format!("SELECT {columns} FROM {table}")
        } else {
            render_visible_relation(self.dialect, self.catalog.branch(), &entry.shape)?
        };
        let mut replacement = format!("({visible})");
        if alias.is_none() {
            replacement.push_str(" AS ");
            replacement.push_str(&quote_identifier(self.dialect, &effective));
        }
        self.edit(name.span(), replacement)?;
        Ok(Relation {
            alias: effective,
            implicit_schema: alias.is_none().then(|| schema.to_owned()),
            columns,
        })
    }

    fn alias_columns(&self, alias: &TableAlias, columns: &mut [OutputColumn]) -> Result<()> {
        if alias.at.is_some() || (!alias.columns.is_empty() && alias.columns.len() != columns.len())
        {
            return Err(CompileError::Unsupported);
        }
        for (column, renamed) in columns.iter_mut().zip(&alias.columns) {
            if renamed.data_type.is_some() {
                return Err(CompileError::Unsupported);
            }
            column.name = Some(self.ident(&renamed.name)?);
        }
        Ok(())
    }

    fn project(
        &mut self,
        item: &SelectItem,
        ctx: Context<'_>,
        output: &mut Vec<OutputColumn>,
    ) -> Result<()> {
        match item {
            SelectItem::Wildcard(options) if plain_wildcard(options) && !ctx.scope.is_empty() => {
                output.extend(
                    ctx.scope
                        .iter()
                        .flat_map(|relation| relation.columns.iter().cloned()),
                );
            }
            SelectItem::QualifiedWildcard(
                SelectItemQualifiedWildcardKind::ObjectName(name),
                options,
            ) if plain_wildcard(options) => {
                let (schema, alias) = object_name(self.dialect, name)?;
                let relation = lookup_relation(ctx, schema.as_deref(), &alias)?;
                if schema.is_some() {
                    self.edit(name.span(), quote_identifier(self.dialect, &relation.alias))?;
                }
                output.extend(relation.columns.iter().cloned());
            }
            SelectItem::UnnamedExpr(expr) => output.push(self.projection(expr, None, ctx)?),
            SelectItem::ExprWithAlias { expr, alias } => {
                output.push(self.projection(expr, Some(alias), ctx)?);
            }
            _ => return Err(CompileError::Unsupported),
        }
        Ok(())
    }

    fn projection(
        &mut self,
        expr: &Expr,
        alias: Option<&Ident>,
        ctx: Context<'_>,
    ) -> Result<OutputColumn> {
        let before = self.edits.len();
        let column = match simple_reference(expr) {
            Some(parts) => Some(self.column(parts, ctx)?),
            None => {
                self.expr(expr, ctx, 0)?;
                None
            }
        };
        if alias.is_none()
            && column.is_none()
            && self.dialect == Dialect::MySql
            && self.edits.len() != before
        {
            // MySQL can expose computed expression text as the column name.
            return Err(CompileError::Unsupported);
        }
        let mut column = column.unwrap_or(OutputColumn {
            name: self.implicit_name(expr),
            origin: None,
        });
        if let Some(alias) = alias {
            column.name = Some(self.ident(alias)?);
        }
        Ok(column)
    }

    pub(super) fn column(&mut self, parts: &[Ident], ctx: Context<'_>) -> Result<OutputColumn> {
        let column = match parts {
            [name] => lookup_unqualified(self.dialect, ctx, &self.ident(name)?)?,
            [relation, name] => {
                let relation = lookup_relation(ctx, None, &self.ident(relation)?)?;
                lookup_column(self.dialect, &relation.columns, &self.ident(name)?)?
            }
            [schema, table, name] => {
                let relation =
                    lookup_relation(ctx, Some(&self.ident(schema)?), &self.ident(table)?)?;
                let column = lookup_column(self.dialect, &relation.columns, &self.ident(name)?)?;
                let qualifier = schema.span.union(&table.span);
                self.edit(qualifier, quote_identifier(self.dialect, &relation.alias))?;
                column
            }
            _ => return Err(CompileError::Object),
        };
        Ok(column.clone())
    }

    fn limit(&mut self, limit: &LimitClause, ctx: Context<'_>) -> Result<()> {
        match limit {
            LimitClause::LimitOffset {
                limit,
                offset,
                limit_by,
            } if limit_by.is_empty() => {
                if let Some(limit) = limit {
                    self.limit_value(limit, ctx)?;
                }
                if let Some(offset) = offset {
                    self.limit_value(&offset.value, ctx)?;
                }
                Ok(())
            }
            LimitClause::OffsetCommaLimit { offset, limit } if self.dialect == Dialect::MySql => {
                self.limit_value(offset, ctx)?;
                self.limit_value(limit, ctx)
            }
            _ => Err(CompileError::Unsupported),
        }
    }

    pub(super) fn order_by(&mut self, order: &[OrderByExpr], ctx: Context<'_>) -> Result<()> {
        for element in order {
            if element.with_fill.is_some()
                || matches!(element.options.sort, Some(OrderBySort::Using(_)))
                || (self.dialect == Dialect::MySql && element.options.nulls_first.is_some())
            {
                return Err(CompileError::Unsupported);
            }
            self.expr(&element.expr, ctx, 0)?;
        }
        Ok(())
    }
}

fn unquoted_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn simple_reference(expr: &Expr) -> Option<&[Ident]> {
    match expr {
        Expr::Identifier(ident) => Some(std::slice::from_ref(ident)),
        Expr::CompoundIdentifier(parts) => Some(parts),
        Expr::Nested(expr) => simple_reference(expr),
        _ => None,
    }
}

pub(super) fn plain_wildcard(options: &WildcardAdditionalOptions) -> bool {
    options.opt_ilike.is_none()
        && options.opt_exclude.is_none()
        && options.opt_except.is_none()
        && options.opt_replace.is_none()
        && options.opt_rename.is_none()
        && options.opt_alias.is_none()
}

fn check_query(query: &Query) -> Result<()> {
    if !query.locks.is_empty()
        || query.for_clause.is_some()
        || query.settings.is_some()
        || query.format_clause.is_some()
        || !query.pipe_operators.is_empty()
    {
        return Err(CompileError::Unsupported);
    }
    Ok(())
}

pub(super) fn check_select(select: &Select) -> Result<()> {
    if !select.optimizer_hints.is_empty()
        || matches!(select.distinct, Some(Distinct::On(_)))
        || select.select_modifiers.is_some()
        || select.top.is_some()
        || select.top_before_distinct
        || select.exclude.is_some()
        || select.into.is_some()
        || select.from.len() > 1
        || !select.lateral_views.is_empty()
        || select.prewhere.is_some()
        || !select.connect_by.is_empty()
        || !select.cluster_by.is_empty()
        || !select.distribute_by.is_empty()
        || !select.sort_by.is_empty()
        || !select.named_window.is_empty()
        || select.qualify.is_some()
        || select.window_before_qualify
        || select.value_table_mode.is_some()
        || select.flavor != SelectFlavor::Standard
    {
        return Err(CompileError::Unsupported);
    }
    Ok(())
}

fn join_predicate(dialect: Dialect, join: &JoinOperator) -> Result<Option<&Expr>> {
    match join {
        JoinOperator::Join(JoinConstraint::On(expr))
        | JoinOperator::Inner(JoinConstraint::On(expr))
        | JoinOperator::Left(JoinConstraint::On(expr))
        | JoinOperator::LeftOuter(JoinConstraint::On(expr))
        | JoinOperator::Right(JoinConstraint::On(expr))
        | JoinOperator::RightOuter(JoinConstraint::On(expr)) => Ok(Some(expr)),
        JoinOperator::FullOuter(JoinConstraint::On(expr)) if dialect == Dialect::PostgreSql => {
            Ok(Some(expr))
        }
        JoinOperator::CrossJoin(JoinConstraint::None) => Ok(None),
        _ => Err(CompileError::Unsupported),
    }
}

fn lookup_relation<'a>(
    ctx: Context<'a>,
    schema: Option<&str>,
    alias: &str,
) -> Result<&'a Relation> {
    for scope in std::iter::once(ctx.scope).chain(ctx.outer.iter().rev()) {
        if let Some(relation) = scope.iter().find(|relation| relation.alias == alias) {
            // A nearer binding of the same alias would capture a qualified
            // reference after its schema is removed during lowering.
            return if schema
                .is_none_or(|schema| relation.implicit_schema.as_deref() == Some(schema))
            {
                Ok(relation)
            } else {
                Err(CompileError::Object)
            };
        }
    }
    Err(CompileError::Object)
}

fn lookup_unqualified<'a>(
    dialect: Dialect,
    ctx: Context<'a>,
    name: &str,
) -> Result<&'a OutputColumn> {
    if let Some(output) = unique_column(dialect, ctx.output.iter(), name)? {
        return Ok(output);
    }
    for scope in std::iter::once(ctx.scope).chain(ctx.outer.iter().rev()) {
        let columns = scope.iter().flat_map(|relation| &relation.columns);
        if let Some(column) = unique_column(dialect, columns, name)? {
            return Ok(column);
        }
        if scope
            .iter()
            .any(|relation| relation.columns.iter().any(|column| column.name.is_none()))
        {
            return Err(CompileError::Object);
        }
    }
    Err(CompileError::Object)
}

fn lookup_column<'a>(
    dialect: Dialect,
    columns: &'a [OutputColumn],
    name: &str,
) -> Result<&'a OutputColumn> {
    unique_column(dialect, columns.iter(), name)?.ok_or(CompileError::Object)
}

fn unique_column<'a>(
    dialect: Dialect,
    columns: impl Iterator<Item = &'a OutputColumn>,
    name: &str,
) -> Result<Option<&'a OutputColumn>> {
    let mut matching = columns.filter(|column| {
        column
            .name
            .as_deref()
            .is_some_and(|current| column_eq(dialect, current, name))
    });
    let first = matching.next();
    if matching.next().is_some() {
        return Err(CompileError::Object);
    }
    Ok(first)
}
