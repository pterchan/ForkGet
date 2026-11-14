mod bound;
mod catalog;
mod explain;
mod expression;
mod lexical;
mod metadata;
mod mutation;
mod scope;

use std::ops::Range;

use fg_protocol_common::{BranchBinding, SqlErrorKind, SqlLimit, WireError, WriteTarget};
use sqlparser::{
    ast::{Query, Statement},
    tokenizer::Span,
};
use thiserror::Error;

use crate::{BranchId, Dialect, RewriteError, TableRef, TableShape};
pub use bound::BoundCompiler;
use catalog::CatalogView;
pub use explain::{CompiledExplain, PlanMapping};
use lexical::Source;
pub use mutation::{CompiledWrite, GeneratedIds, MYSQL_GENERATED_START};

pub enum CompiledStatement {
    Read(CompiledRead),
    Write(CompiledWrite),
    Savepoint(String),
    Explain(CompiledExplain),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryMode {
    Text,
    Prepared,
}

/// A logical table and its immutable generation's physical tables.
pub struct CatalogTable<'a> {
    pub logical: TableRef<'a>,
    pub shape: TableShape<'a>,
}

/// A trusted snapshot of the tables visible to an authorized branch.
pub struct ReadCatalog<'a> {
    pub default_schema: &'a str,
    pub branch: BranchId,
    pub tables: &'a [CatalogTable<'a>],
}

/// Logical origin for a result position proven to refer to a catalog column.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ColumnOrigin {
    pub logical_schema: String,
    pub logical_table: String,
    pub logical_column: String,
    /// The visible query alias, separate from the original logical table.
    pub table_alias: Option<String>,
}

/// Native result names can be retained when the compiler supplies no name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutputColumn {
    pub name: Option<String>,
    pub origin: Option<ColumnOrigin>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledRead {
    pub sql: String,
    /// MySQL positional count or the largest PostgreSQL parameter number.
    pub parameter_count: usize,
    /// PostgreSQL parameter numbers in source order, including repeats.
    pub postgres_parameters: Vec<u32>,
    pub columns: Vec<OutputColumn>,
}

/// Stable errors without source SQL, names, or parameter values.
#[derive(Debug, Error, Eq, PartialEq)]
#[error("{}", self.wire())]
pub enum CompileError {
    Syntax,
    Unsupported,
    Object,
    Function,
    Catalog,
    Policy,
    Limit {
        kind: SqlLimit,
        actual: u64,
        limit: u64,
    },
}

impl CompileError {
    pub const fn code(&self) -> &'static str {
        self.wire().code()
    }

    pub const fn wire(&self) -> WireError {
        match self {
            Self::Syntax => WireError::SqlSyntax,
            Self::Unsupported => WireError::Unsupported,
            Self::Object | Self::Catalog => WireError::SqlObject,
            Self::Function => WireError::SqlFunction,
            Self::Policy => WireError::ReadOnly,
            Self::Limit {
                kind,
                actual,
                limit,
            } => WireError::SqlLimit {
                kind: *kind,
                actual: *actual,
                limit: *limit,
            },
        }
    }

    /// Locate the refused statement without retaining SQL or parameter text.
    pub fn wire_at(&self, dialect: Dialect, sql: &str) -> WireError {
        let kind = match self {
            Self::Syntax => SqlErrorKind::Syntax,
            Self::Unsupported => SqlErrorKind::Unsupported,
            Self::Object => SqlErrorKind::Object,
            Self::Function => SqlErrorKind::Function,
            Self::Catalog | Self::Policy | Self::Limit { .. } => return self.wire(),
        };
        let (line, column) = lexical::statement_start(dialect, sql);
        WireError::SqlAt { kind, line, column }
    }
}

impl From<RewriteError> for CompileError {
    fn from(error: RewriteError) -> Self {
        match error {
            RewriteError::MissingPrimaryKey | RewriteError::ReservedColumn => Self::Unsupported,
            _ => Self::Catalog,
        }
    }
}

type Result<T> = std::result::Result<T, CompileError>;

/// Validate a dry-run manifest item without permitting transaction commands.
pub fn validate_dryrun_statement(dialect: Dialect, sql: &str, is_change: bool) -> Result<()> {
    let source = Source::new(sql)?;
    let (statement, _, _) = lexical::parse(dialect, QueryMode::Text, &source)?;
    match (is_change, statement) {
        (true, Statement::Insert(_) | Statement::Update(_) | Statement::Delete(_))
        | (false, Statement::Query(_)) => Ok(()),
        _ => Err(CompileError::Unsupported),
    }
}

/// Admit a single dialect-specific read and substitute its visible relations.
pub fn compile_read(
    dialect: Dialect,
    mode: QueryMode,
    sql: &str,
    catalog: &ReadCatalog<'_>,
) -> Result<CompiledRead> {
    scope::validate_catalog(dialect, catalog)?;
    let source = Source::new(sql)?;
    let (statement, parameter_count, postgres_parameters) = lexical::parse(dialect, mode, &source)?;
    let Statement::Query(query) = statement else {
        return Err(CompileError::Unsupported);
    };
    compile_query(
        Compiler {
            dialect,
            catalog: CatalogView::Borrowed(catalog),
            source,
            edits: Vec::new(),
            write_target: None,
            base_only: false,
        },
        &query,
        parameter_count,
        postgres_parameters,
    )
}

fn replay_context(sql: &str, binding: &BranchBinding) -> Result<Option<CompiledRead>> {
    let sql = sql.trim_ascii();
    let command = sql.strip_suffix(';').unwrap_or(sql).trim_ascii_end();
    if !command.eq_ignore_ascii_case("SELECT FORKGET_REPLAY_CONTEXT()") {
        return Ok(None);
    }
    let origin = binding
        .replay_origin
        .as_ref()
        .filter(|origin| origin.is_valid() && origin.generation_id == binding.generation_id)
        .ok_or(CompileError::Catalog)?;
    let sql = format!(
        "SELECT '{}' AS forkget_replay_context",
        origin.session_context(binding.id)
    );
    Ok(Some(CompiledRead {
        sql,
        parameter_count: 0,
        postgres_parameters: Vec::new(),
        columns: vec![OutputColumn {
            name: Some("forkget_replay_context".to_owned()),
            origin: None,
        }],
    }))
}

fn compile_query(
    mut compiler: Compiler<'_>,
    query: &Query,
    parameter_count: usize,
    postgres_parameters: Vec<u32>,
) -> Result<CompiledRead> {
    let columns = compiler.query(query, &[], &[])?.columns;
    Ok(CompiledRead {
        sql: compiler.finish()?,
        parameter_count,
        postgres_parameters,
        columns,
    })
}

/// Compile using the session-pinned transport catalog.
pub fn compile_bound_read(
    dialect: Dialect,
    mode: QueryMode,
    sql: &str,
    binding: &BranchBinding,
) -> Result<CompiledRead> {
    BoundCompiler::new(dialect, binding)?.compile_read(mode, sql)
}

/// Admit a read or a bounded mutation against the session-pinned catalog.
pub fn compile_bound_statement(
    dialect: Dialect,
    mode: QueryMode,
    sql: &str,
    binding: &BranchBinding,
) -> Result<CompiledStatement> {
    BoundCompiler::new(dialect, binding)?.compile_statement(mode, sql)
}

fn compile_savepoint(
    dialect: Dialect,
    statement: &Statement,
    source: &Source<'_>,
) -> Result<Option<String>> {
    let (verb, name) = match statement {
        Statement::Savepoint { name } => ("SAVEPOINT", name),
        Statement::ReleaseSavepoint { name } => ("RELEASE SAVEPOINT", name),
        Statement::Rollback {
            chain: false,
            savepoint: Some(name),
        } => ("ROLLBACK TO SAVEPOINT", name),
        _ => return Ok(None),
    };
    let prefix = &source.sql[..source.range(name.span)?.start];
    let abbreviated_rollback = verb == "ROLLBACK TO SAVEPOINT" && same_words(prefix, "ROLLBACK TO");
    let abbreviated_release = verb == "RELEASE SAVEPOINT" && same_words(prefix, "RELEASE");
    if !(same_words(prefix, verb) || abbreviated_rollback || abbreviated_release) {
        return Err(CompileError::Unsupported);
    }
    let name = scope::admitted_ident(dialect, name)?;
    Ok(Some(format!(
        "{verb} {}",
        crate::quote_identifier(dialect, &name)
    )))
}

fn same_words(actual: &str, expected: &str) -> bool {
    let mut actual = actual.split_ascii_whitespace();
    expected.split_ascii_whitespace().all(|word| {
        actual
            .next()
            .is_some_and(|value| value.eq_ignore_ascii_case(word))
    }) && actual.next().is_none()
}

struct Edit {
    range: Range<usize>,
    text: String,
}

struct Compiler<'a> {
    dialect: Dialect,
    catalog: CatalogView<'a>,
    source: Source<'a>,
    edits: Vec<Edit>,
    write_target: Option<&'a WriteTarget>,
    base_only: bool,
}

impl Compiler<'_> {
    fn edit(&mut self, span: Span, text: String) -> Result<()> {
        self.edits.push(Edit {
            range: self.source.range(span)?,
            text,
        });
        Ok(())
    }

    fn finish(mut self) -> Result<String> {
        self.edits.sort_unstable_by_key(|edit| edit.range.start);
        let mut output = String::new();
        let mut offset = 0;
        for edit in self.edits {
            let prefix = self
                .source
                .sql
                .get(offset..edit.range.start)
                .ok_or(CompileError::Syntax)?;
            output.push_str(prefix);
            output.push_str(&edit.text);
            offset = edit.range.end;
        }
        output.push_str(self.source.sql.get(offset..).ok_or(CompileError::Syntax)?);
        Ok(output)
    }
}
