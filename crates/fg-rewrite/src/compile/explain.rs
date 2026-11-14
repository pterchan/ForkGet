//! Bounded native JSON plans with logical identities and no opaque native text.

use fg_protocol_common::WriteTarget;
use serde_json::{Map, Value as Json};
use sqlparser::ast::{AnalyzeFormat, AnalyzeFormatKind, Expr, Statement};

use super::{BoundCompiler, CompileError, CompiledRead, Dialect, OutputColumn, QueryMode, Result};

const MAX_PLAN_BYTES: usize = 1024 * 1024;

pub struct CompiledExplain {
    pub read: CompiledRead,
    pub mapping: PlanMapping,
}

#[derive(Clone)]
pub struct PlanMapping {
    relations: Vec<(String, String, &'static str)>,
    schema: String,
    indexes: Vec<String>,
    is_tidb: bool,
}

pub(super) fn compile(
    compiler: &BoundCompiler<'_>,
    mode: QueryMode,
    statement: &Statement,
) -> Result<Option<CompiledExplain>> {
    let dialect = compiler.dialect;
    let binding = compiler.binding;
    let Statement::Explain {
        analyze,
        verbose,
        query_plan,
        estimate,
        statement,
        format,
        options,
        ..
    } = statement
    else {
        return Ok(None);
    };
    if *analyze
        || *verbose
        || *query_plan
        || *estimate
        || !matches!(statement.as_ref(), Statement::Query(_))
    {
        return Err(CompileError::Unsupported);
    }
    let json_format = matches!(
        format,
        Some(
            AnalyzeFormatKind::Keyword(AnalyzeFormat::JSON)
                | AnalyzeFormatKind::Assignment(AnalyzeFormat::JSON)
        )
    );
    let json_option=options.as_ref().is_some_and(|options| options.len()==1 && options[0].name.value.eq_ignore_ascii_case("format")
        && matches!(&options[0].arg,Some(Expr::Identifier(name)) if name.value.eq_ignore_ascii_case("json")));
    if !(json_format && options.is_none()
        || dialect == Dialect::PostgreSql && format.is_none() && json_option)
    {
        return Err(CompileError::Unsupported);
    }
    let mut read = compiler.compile_read(mode, &statement.to_string())?;
    read.sql = format!(
        "{} {}",
        if binding.engine == "tidb" {
            "EXPLAIN FORMAT='tidb_json'"
        } else if dialect == Dialect::MySql {
            "EXPLAIN FORMAT=JSON"
        } else {
            "EXPLAIN (FORMAT JSON)"
        },
        read.sql
    );
    read.columns = vec![OutputColumn {
        name: Some(
            if dialect == Dialect::MySql {
                "EXPLAIN"
            } else {
                "QUERY PLAN"
            }
            .into(),
        ),
        origin: None,
    }];
    let target = binding
        .write_schema
        .as_deref()
        .and_then(|schema| WriteTarget::new(&binding.engine, binding.id, schema));
    let mut relations = Vec::new();
    for table in &binding.tables {
        relations.push((
            table.base_table.clone(),
            table.logical_table.clone(),
            "shared_base",
        ));
        relations.push((
            table.delta_table.clone(),
            table.logical_table.clone(),
            "delta",
        ));
        if let Some(target) = &target {
            relations.insert(
                0,
                (
                    target.table(&table.logical_table),
                    table.logical_table.clone(),
                    "materialized_copy",
                ),
            );
        }
    }
    let indexes = binding
        .snapshot_manifest
        .as_ref()
        .map(|manifest| {
            manifest
                .tables
                .iter()
                .flat_map(|table| {
                    table
                        .indexes
                        .iter()
                        .map(|index| index.name.clone())
                        .chain(table.primary_key_name.clone())
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(Some(CompiledExplain {
        read,
        mapping: PlanMapping {
            relations,
            schema: binding.default_schema.clone(),
            indexes,
            is_tidb: binding.engine == "tidb",
        },
    }))
}

impl PlanMapping {
    pub fn sanitize(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        if bytes.len() > MAX_PLAN_BYTES {
            return Err(CompileError::Unsupported);
        }
        let native: Json = serde_json::from_slice(bytes).map_err(|_| CompileError::Catalog)?;
        let recognized = match &native {
            Json::Array(items) if self.is_tidb => {
                !items.is_empty()
                    && items.iter().all(|item| {
                        item.as_object().is_some_and(|item| {
                            item.contains_key("id") && item.contains_key("estRows")
                        })
                    })
            }
            Json::Object(object) => {
                object.contains_key("query_block") || object.contains_key("Plan")
            }
            Json::Array(items) => {
                items.len() == 1
                    && items[0]
                        .as_object()
                        .is_some_and(|object| object.contains_key("Plan"))
            }
            _ => false,
        };
        if !recognized {
            return Err(CompileError::Catalog);
        }
        let mut plan = self.node(&native, 0)?;
        let info = serde_json::json!({"scope":"proxy_execution","identities":"logical"});
        match &mut plan {
            Json::Object(object) => {
                object.insert("Forkget".into(), info);
            }
            Json::Array(items) => {
                if let Some(Json::Object(object)) = items.first_mut() {
                    object.insert("Forkget".into(), info);
                }
            }
            _ => return Err(CompileError::Catalog),
        }
        let encoded = serde_json::to_vec(&plan).map_err(|_| CompileError::Catalog)?;
        if encoded.len() > MAX_PLAN_BYTES {
            return Err(CompileError::Unsupported);
        }
        Ok(encoded)
    }

    fn node(&self, value: &Json, depth: usize) -> Result<Json> {
        if depth > 64 {
            return Err(CompileError::Unsupported);
        }
        match value {
            Json::Array(items) => items
                .iter()
                .map(|item| self.node(item, depth + 1))
                .collect::<Result<Vec<_>>>()
                .map(Json::Array),
            Json::Object(native) => {
                let mut safe = Map::new();
                for (key, value) in native {
                    match key.as_str() {
                        "id" if self.is_tidb => {
                            if let Some(name) = value.as_str().and_then(tidb_operator) {
                                safe.insert("Node Type".into(), Json::String(name.into()));
                            }
                        }
                        "estRows" if self.is_tidb => {
                            if scalar_metric(value) {
                                safe.insert("Plan Rows".into(), value.clone());
                            }
                        }
                        "taskType" if self.is_tidb => {
                            if let Some(task) = value.as_str().filter(|task| {
                                matches!(
                                    *task,
                                    "root" | "cop[tikv]" | "cop[tiflash]" | "mpp[tiflash]"
                                )
                            }) {
                                safe.insert("Task Type".into(), Json::String(task.into()));
                            }
                        }
                        "subOperators" if self.is_tidb => {
                            safe.insert("Plans".into(), self.node(value, depth + 1)?);
                        }
                        "accessObject" if self.is_tidb => {
                            if let Some(name) = value
                                .as_str()
                                .and_then(|value| value.strip_prefix("table:"))
                                .and_then(|value| value.split(',').next())
                            {
                                let name = name.trim().rsplit('.').next().unwrap_or_default();
                                if let Some((_, logical, role)) = self
                                    .relations
                                    .iter()
                                    .find(|(physical, _, _)| physical == name)
                                {
                                    safe.insert(
                                        "Relation Name".into(),
                                        Json::String(logical.clone()),
                                    );
                                    safe.insert(
                                        "Forkget Storage".into(),
                                        Json::String((*role).into()),
                                    );
                                }
                            }
                        }
                        "Relation Name" | "table_name" => {
                            if let Some(name) = value.as_str() {
                                if let Some((_, logical, role)) = self
                                    .relations
                                    .iter()
                                    .find(|(physical, _, _)| physical == name)
                                {
                                    safe.insert(key.clone(), Json::String(logical.clone()));
                                    safe.insert(
                                        "Forkget Storage".into(),
                                        Json::String((*role).into()),
                                    );
                                } else {
                                    safe.insert(key.clone(), Json::String("derived".into()));
                                }
                            }
                        }
                        "Schema" => {
                            safe.insert(key.clone(), Json::String(self.schema.clone()));
                        }
                        "Index Name" | "key" => {
                            if let Some(name) = value.as_str() {
                                safe.insert(
                                    key.clone(),
                                    Json::String(
                                        if self.indexes.iter().any(|index| index == name) {
                                            name
                                        } else {
                                            "index"
                                        }
                                        .into(),
                                    ),
                                );
                            }
                        }
                        "Alias" => {}
                        key if structural_key(key) => {
                            safe.insert(key.into(), self.node(value, depth + 1)?);
                        }
                        key if metric_key(key) => {
                            if scalar_metric(value) {
                                safe.insert(key.into(), value.clone());
                            }
                        }
                        key if operation_key(key) => {
                            if let Some(value) = value.as_str().filter(|value| {
                                value
                                    .chars()
                                    .all(|c| c.is_ascii_alphabetic() || matches!(c, ' ' | '_'))
                            }) {
                                safe.insert(key.into(), Json::String(value.into()));
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Json::Object(safe))
            }
            Json::Null | Json::Bool(_) | Json::Number(_) => Ok(value.clone()),
            _ => Err(CompileError::Catalog),
        }
    }
}

fn tidb_operator(value: &str) -> Option<&str> {
    let (name, ordinal) = value.rsplit_once('_')?;
    (name.starts_with(|c: char| c.is_ascii_uppercase())
        && name.chars().all(|c| c.is_ascii_alphabetic() || c == '_')
        && !ordinal.is_empty()
        && ordinal.bytes().all(|c| c.is_ascii_digit()))
    .then_some(name)
}

fn structural_key(key: &str) -> bool {
    matches!(
        key,
        "Plan"
            | "Plans"
            | "query_block"
            | "nested_loop"
            | "table"
            | "grouping_operation"
            | "ordering_operation"
            | "duplicates_removal"
            | "materialized_from_subquery"
            | "union_result"
            | "query_specifications"
            | "buffer_result"
            | "cost_info"
            | "windowing"
            | "windows"
    )
}

fn metric_key(key: &str) -> bool {
    matches!(
        key,
        "Startup Cost"
            | "Total Cost"
            | "Plan Rows"
            | "Plan Width"
            | "Parallel Aware"
            | "Async Capable"
            | "Inner Unique"
            | "select_id"
            | "rows_examined_per_scan"
            | "rows_produced_per_join"
            | "filtered"
            | "query_cost"
            | "read_cost"
            | "eval_cost"
            | "prefix_cost"
            | "sort_cost"
            | "data_read_per_join"
            | "using_temporary_table"
            | "using_filesort"
            | "using_index"
    )
}

fn scalar_metric(value: &Json) -> bool {
    value.is_number()
        || value.is_boolean()
        || value.as_str().is_some_and(|value| {
            value.chars().all(|c| {
                c.is_ascii_digit() || matches!(c, '.' | '-' | '+' | 'e' | 'E' | 'K' | 'M' | 'G')
            })
        })
}

fn operation_key(key: &str) -> bool {
    matches!(
        key,
        "Node Type"
            | "Parent Relationship"
            | "Strategy"
            | "Partial Mode"
            | "Join Type"
            | "Scan Direction"
            | "access_type"
            | "using_join_buffer"
    )
}
