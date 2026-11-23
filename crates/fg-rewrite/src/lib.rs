//! Compile admitted read queries against trusted, generation-pinned catalog
//! metadata after branch authorization.

mod compile;
mod error;

pub use compile::{
    BoundCompiler, CatalogTable, ColumnOrigin, CompileError, CompiledExplain, CompiledRead,
    CompiledStatement, CompiledWrite, GeneratedIds, MYSQL_GENERATED_START, OutputColumn,
    PlanMapping, QueryMode, ReadCatalog, compile_bound_read, compile_bound_statement, compile_read,
    validate_dryrun_statement,
};
pub use error::RewriteError;

const BRANCH_COLUMN: &str = "_fg_branch";
const OPERATION_COLUMN: &str = "_fg_op";
const INTERNAL_COLUMN_PREFIX: &str = "_fg_";
const LIVE_OPERATIONS_SQL: &str = "('I', 'U')";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Dialect {
    MySql,
    PostgreSql,
}

/// Wire-protocol families share a rewrite dialect; engine identity stays
/// separate because compatible wire protocols can use different storage layouts.
pub fn engine_matches_dialect(engine: &str, dialect: Dialect) -> bool {
    match dialect {
        Dialect::MySql => matches!(engine, "mysql" | "tidb"),
        Dialect::PostgreSql => engine == "postgresql",
    }
}

/// An authenticated branch's positive, signed BIGINT metadata identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BranchId(i64);

impl BranchId {
    pub fn new(value: i64) -> Result<Self, RewriteError> {
        if value <= 0 {
            return Err(RewriteError::InvalidBranchId);
        }
        Ok(Self(value))
    }
}

/// Physical catalog names; schema and table are separate identifier components.
#[derive(Clone, Copy, Debug)]
pub struct TableRef<'a> {
    pub schema: &'a str,
    pub table: &'a str,
}

/// Both relations must belong to the same immutable generation.
///
/// The catalog must guarantee matching column types/collations, a non-null base
/// primary key, one delta row per (branch, complete primary key), valid I/U/D
/// operations, and full live row images. Nullable tombstone payload is permitted.
pub struct TableShape<'a> {
    pub base: TableRef<'a>,
    pub delta: TableRef<'a>,
    pub columns: &'a [&'a str],
    pub primary_key: &'a [&'a str],
}

/// Render a SELECT that can be embedded as a derived table by the AST rewriter.
///
/// This preserves catalog column order and exposes no internal delta columns.
/// No client placeholders are added, renumbered, or consumed.
///
/// Uses LEFT JOIN + IS NULL instead of NOT EXISTS for better optimizer support
/// in modern SQL engines (MySQL 8.0+, PostgreSQL 12+, TiDB). The semantic is
/// identical: delta rows with I/U operations UNION ALL base rows that do not
/// have a delta entry in this branch.
pub fn render_visible_relation(
    dialect: Dialect,
    branch: BranchId,
    table: &TableShape<'_>,
) -> Result<String, RewriteError> {
    validate_table(table)?;
    let base = quote_table(dialect, table.base);
    let delta = quote_table(dialect, table.delta);
    let base_columns = project_columns(dialect, "b", table.columns);
    let delta_columns = project_columns(dialect, "d", table.columns);
    let branch_column = quote_identifier(dialect, BRANCH_COLUMN);
    let operation_column = quote_identifier(dialect, OPERATION_COLUMN);
    let key_match = table
        .primary_key
        .iter()
        .map(|column| {
            let column = quote_identifier(dialect, column);
            format!("hidden.{column} = b.{column}")
        })
        .collect::<Vec<_>>()
        .join(" AND ");
    // The validated metadata integer cannot inject SQL or change frontend binds.
    let branch_id = branch.0;

    // For IS NULL check, use the first PK column (guaranteed to be non-null in delta schema).
    let first_pk = quote_identifier(dialect, table.primary_key[0]);

    Ok(format!(
        "SELECT {delta_columns}\n\
         FROM {delta} AS d\n\
         WHERE d.{branch_column} = {branch_id} AND d.{operation_column} IN {LIVE_OPERATIONS_SQL}\n\
         UNION ALL\n\
         SELECT {base_columns}\n\
         FROM {base} AS b\n\
         LEFT JOIN {delta} AS hidden ON hidden.{branch_column} = {branch_id} AND {key_match}\n\
         WHERE hidden.{first_pk} IS NULL"
    ))
}

fn validate_table(table: &TableShape<'_>) -> Result<(), RewriteError> {
    for identifier in [
        table.base.schema,
        table.base.table,
        table.delta.schema,
        table.delta.table,
    ] {
        validate_identifier(identifier)?;
    }
    if table.columns.is_empty() {
        return Err(RewriteError::EmptyProjection);
    }
    validate_columns(table.columns)?;
    if table.primary_key.is_empty() {
        return Err(RewriteError::MissingPrimaryKey);
    }
    for (index, column) in table.primary_key.iter().enumerate() {
        if !table.columns.contains(column) || table.primary_key[..index].contains(column) {
            return Err(RewriteError::InvalidPrimaryKey);
        }
    }
    Ok(())
}

fn validate_columns(columns: &[&str]) -> Result<(), RewriteError> {
    for (index, column) in columns.iter().enumerate() {
        validate_identifier(column)?;
        if column
            .get(..INTERNAL_COLUMN_PREFIX.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(INTERNAL_COLUMN_PREFIX))
        {
            return Err(RewriteError::ReservedColumn);
        }
        if columns[..index].contains(column) {
            return Err(RewriteError::DuplicateColumn);
        }
    }
    Ok(())
}

fn validate_identifier(identifier: &str) -> Result<(), RewriteError> {
    if identifier.is_empty() || identifier.contains('\0') {
        return Err(RewriteError::InvalidIdentifier);
    }
    Ok(())
}

fn quote_identifier(dialect: Dialect, identifier: &str) -> String {
    let quote = match dialect {
        Dialect::MySql => '`',
        Dialect::PostgreSql => '"',
    };
    let escaped = identifier.replace(quote, &format!("{quote}{quote}"));
    format!("{quote}{escaped}{quote}")
}

fn quote_table(dialect: Dialect, table: TableRef<'_>) -> String {
    format!(
        "{}.{}",
        quote_identifier(dialect, table.schema),
        quote_identifier(dialect, table.table)
    )
}

fn project_columns(dialect: Dialect, alias: &str, columns: &[&str]) -> String {
    columns
        .iter()
        .map(|column| format!("{alias}.{}", quote_identifier(dialect, column)))
        .collect::<Vec<_>>()
        .join(", ")
}
