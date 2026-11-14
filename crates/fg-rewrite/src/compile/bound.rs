use fg_protocol_common::{BranchBinding, ReadStrategy, WriteTarget};
use sqlparser::ast::Statement;

use super::{
    CompileError, CompiledRead, CompiledStatement, Compiler, QueryMode, ReadCatalog, Result,
    catalog::{CatalogView, DerivedTable},
    compile_query, compile_savepoint, explain, lexical,
    lexical::Source,
    metadata, mutation, replay_context, scope,
};
use crate::{BranchId, Dialect, engine_matches_dialect};

/// A session's derived catalog borrows its immutable authorized binding. SQL,
/// syntax trees and authorization decisions are never cached here.
pub struct BoundCompiler<'a> {
    pub(super) dialect: Dialect,
    pub(super) binding: &'a BranchBinding,
    branch: BranchId,
    write_target: Option<WriteTarget>,
    tables: Vec<DerivedTable<'a>>,
}

impl<'a> BoundCompiler<'a> {
    pub fn new(dialect: Dialect, binding: &'a BranchBinding) -> Result<Self> {
        if binding.generation_id <= 0
            || !engine_matches_dialect(&binding.engine, dialect)
            || !binding.valid_storage_contract()
        {
            return Err(CompileError::Catalog);
        }
        let branch = BranchId::new(binding.id)?;
        let write_target = binding
            .write_schema
            .as_deref()
            .map(|schema| {
                WriteTarget::new(&binding.engine, binding.id, schema).ok_or(CompileError::Catalog)
            })
            .transpose()?;
        let tables = binding
            .tables
            .iter()
            .map(DerivedTable::new)
            .collect::<Result<Vec<_>>>()?;
        let compiler = Self {
            dialect,
            binding,
            branch,
            write_target,
            tables,
        };
        compiler.validate_catalog()?;
        Ok(compiler)
    }

    pub fn binding(&self) -> &'a BranchBinding {
        self.binding
    }

    fn validate_catalog(&self) -> Result<()> {
        let tables = self
            .tables
            .iter()
            .map(DerivedTable::view)
            .collect::<Vec<_>>();
        scope::validate_catalog(
            self.dialect,
            &ReadCatalog {
                default_schema: &self.binding.default_schema,
                branch: self.branch,
                tables: &tables,
            },
        )
    }

    pub fn compile_read(&self, mode: QueryMode, sql: &str) -> Result<CompiledRead> {
        match self.compile(mode, sql, false)? {
            CompiledStatement::Read(read) => Ok(read),
            _ => Err(CompileError::Unsupported),
        }
    }

    pub fn compile_statement(&self, mode: QueryMode, sql: &str) -> Result<CompiledStatement> {
        self.compile(mode, sql, true)
    }

    fn compile(
        &self,
        mode: QueryMode,
        sql: &str,
        is_write_allowed: bool,
    ) -> Result<CompiledStatement> {
        let source = Source::new(sql)?;
        if is_write_allowed
            && self.binding.can_write()
            && self.write_target.is_some()
            && let Some(read) = replay_context(sql, self.binding)?
        {
            return Ok(CompiledStatement::Read(read));
        }
        let (statement, parameter_count, postgres_parameters) =
            lexical::parse(self.dialect, mode, &source)?;
        if let Some(read) = metadata::compile(
            self.dialect,
            &statement,
            parameter_count,
            &postgres_parameters,
            self.binding,
        )? {
            return Ok(CompiledStatement::Read(read));
        }
        if let Some(plan) = explain::compile(self, mode, &statement)? {
            return Ok(CompiledStatement::Explain(plan));
        }
        let Statement::Query(query) = statement else {
            return self.compile_control_or_write(
                source,
                statement,
                MutationContext {
                    parameter_count,
                    is_write_allowed,
                },
            );
        };
        compile_query(
            Compiler {
                dialect: self.dialect,
                catalog: CatalogView::Bound {
                    default_schema: &self.binding.default_schema,
                    branch: self.branch,
                    tables: &self.tables,
                },
                source,
                edits: Vec::new(),
                write_target: self.write_target.as_ref(),
                base_only: self.binding.read_strategy == ReadStrategy::BaseOnly,
            },
            &query,
            parameter_count,
            postgres_parameters,
        )
        .map(CompiledStatement::Read)
    }

    fn compile_control_or_write(
        &self,
        source: Source<'_>,
        statement: Statement,
        context: MutationContext,
    ) -> Result<CompiledStatement> {
        if context.is_write_allowed
            && !self.binding.can_write()
            && matches!(
                statement,
                Statement::Insert(_) | Statement::Update(_) | Statement::Delete(_)
            )
        {
            mutation::compile(
                self.dialect,
                self.binding,
                None,
                source,
                statement,
                context.parameter_count,
            )?;
            return Err(CompileError::Policy);
        }
        if context.is_write_allowed
            && let Some(sql) = compile_savepoint(self.dialect, &statement, &source)?
        {
            return Ok(CompiledStatement::Savepoint(sql));
        }
        let target = self
            .write_target
            .as_ref()
            .filter(|_| context.is_write_allowed)
            .ok_or(CompileError::Unsupported)?;
        mutation::compile(
            self.dialect,
            self.binding,
            Some(target),
            source,
            statement,
            context.parameter_count,
        )
        .map(CompiledStatement::Write)
    }
}

struct MutationContext {
    parameter_count: usize,
    is_write_allowed: bool,
}
