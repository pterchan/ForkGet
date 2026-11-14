use fg_protocol_common::CatalogEntry;

use super::{CatalogTable, CompileError, ReadCatalog, Result};
use crate::{BranchId, TableRef, TableShape};

pub(super) struct DerivedTable<'a> {
    entry: &'a CatalogEntry,
    columns: Vec<&'a str>,
    primary_key: Vec<&'a str>,
}

impl<'a> DerivedTable<'a> {
    pub(super) fn new(entry: &'a CatalogEntry) -> Result<Self> {
        if entry.columns.iter().any(|column| {
            column.type_name.is_empty() || (column.primary_key_ordinal.is_some() && column.nullable)
        }) {
            return Err(CompileError::Catalog);
        }
        let columns = entry
            .columns
            .iter()
            .map(|column| column.name.as_str())
            .collect();
        let mut keys = entry
            .columns
            .iter()
            .filter_map(|column| Some((column.primary_key_ordinal?, column.name.as_str())))
            .collect::<Vec<_>>();
        keys.sort_unstable_by_key(|(ordinal, _)| *ordinal);
        if keys
            .iter()
            .enumerate()
            .any(|(index, (ordinal, _))| usize::from(*ordinal) != index + 1)
        {
            return Err(CompileError::Catalog);
        }
        Ok(Self {
            entry,
            columns,
            primary_key: keys.into_iter().map(|(_, name)| name).collect(),
        })
    }

    pub(super) fn view(&self) -> CatalogTable<'_> {
        let entry = self.entry;
        CatalogTable {
            logical: TableRef {
                schema: &entry.logical_schema,
                table: &entry.logical_table,
            },
            shape: TableShape {
                base: TableRef {
                    schema: &entry.base_schema,
                    table: &entry.base_table,
                },
                delta: TableRef {
                    schema: &entry.delta_schema,
                    table: &entry.delta_table,
                },
                columns: &self.columns,
                primary_key: &self.primary_key,
            },
        }
    }
}

pub(super) enum CatalogView<'a> {
    Borrowed(&'a ReadCatalog<'a>),
    Bound {
        default_schema: &'a str,
        branch: BranchId,
        tables: &'a [DerivedTable<'a>],
    },
}

impl<'a> CatalogView<'a> {
    pub(super) fn default_schema(&self) -> &'a str {
        match self {
            Self::Borrowed(catalog) => catalog.default_schema,
            Self::Bound { default_schema, .. } => default_schema,
        }
    }

    pub(super) fn branch(&self) -> BranchId {
        match self {
            Self::Borrowed(catalog) => catalog.branch,
            Self::Bound { branch, .. } => *branch,
        }
    }

    pub(super) fn find_table(&self, schema: &str, table: &str) -> Option<CatalogTable<'a>> {
        match self {
            Self::Borrowed(catalog) => {
                let entry = catalog
                    .tables
                    .iter()
                    .find(|entry| entry.logical.schema == schema && entry.logical.table == table)?;
                Some(CatalogTable {
                    logical: entry.logical,
                    shape: TableShape {
                        base: entry.shape.base,
                        delta: entry.shape.delta,
                        columns: entry.shape.columns,
                        primary_key: entry.shape.primary_key,
                    },
                })
            }
            Self::Bound { tables, .. } => {
                let tables: &'a [DerivedTable<'a>] = tables;
                tables
                    .iter()
                    .find(|entry| {
                        entry.entry.logical_schema == schema && entry.entry.logical_table == table
                    })
                    .map(DerivedTable::view)
            }
        }
    }
}
