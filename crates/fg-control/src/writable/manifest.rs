//! Materialized user-data branches are built only from the admitted catalog.

use fg_protocol_common::{CatalogEntry, SnapshotManifest, SnapshotType, WriteTarget};

use crate::{
    ControlError,
    native::{Engine, Native},
    snapshot::ddl,
};

use super::{GENERATED_ID_MAX, GENERATED_ID_START, GENERATED_MARKER};

pub(super) async fn build(
    native: &mut Native,
    target: &WriteTarget,
    tables: &[CatalogEntry],
    source: &SnapshotManifest,
) -> Result<(), ControlError> {
    source
        .validate()
        .map_err(crate::snapshot::SnapshotError::from)?;
    let engine = native.engine();
    if target.prefix().is_none() {
        native
            .execute(&format!("CREATE SCHEMA {}", engine.quote(target.schema())))
            .await?;
    }
    let mut physical = source.clone();
    for (ordinal, table) in physical.tables.iter_mut().enumerate() {
        table.name = target.table(&table.name);
        table.primary_key_name = Some(format!("fg_b{}_p{ordinal}", target.branch_id()));
        for column in &mut table.columns {
            if column.default == Some(fg_protocol_common::ColumnDefault::Generated) {
                column.default = None;
            }
        }
        for (number, index) in table.indexes.iter_mut().enumerate() {
            index.name = format!("fg_b{}_i{ordinal}_{number}", target.branch_id());
        }
        for (number, check) in table.checks.iter_mut().enumerate() {
            check.name = format!("fg_b{}_c{ordinal}_{number}", target.branch_id());
        }
        for (number, key) in table.foreign_keys.iter_mut().enumerate() {
            key.name = format!("fg_b{}_f{ordinal}_{number}", target.branch_id());
            key.referenced_table = target.table(&key.referenced_table);
        }
    }
    for table in tables {
        let definition = physical
            .tables
            .iter()
            .find(|entry| entry.name == target.table(&table.logical_table))
            .ok_or(ControlError::Provision(
                "snapshot table definition is missing",
            ))?;
        let relation = engine.relation(target.schema(), &definition.name);
        native
            .execute(&ddl::table(engine, &relation, definition, false)?)
            .await?;
        native
            .execute(&format!(
                "ALTER TABLE {relation} ADD COLUMN {GENERATED_MARKER}"
            ))
            .await?;
        if let Some(key) = &table.generated_key {
            let key = engine.quote(key);
            native.execute(&format!("ALTER TABLE {relation} ADD CHECK ((_fg_generated=FALSE AND {key} BETWEEN 1 AND {}) OR (_fg_generated=TRUE AND {key} BETWEEN {GENERATED_ID_START} AND {GENERATED_ID_MAX}))",GENERATED_ID_START-1)).await?;
        }
        let columns = table
            .columns
            .iter()
            .map(|column| engine.quote(&column.name))
            .collect::<Vec<_>>()
            .join(",");
        let base = engine.relation(&table.base_schema, &table.base_table);
        native
            .execute(&format!(
                "INSERT INTO {relation} ({columns}) SELECT {columns} FROM {base}"
            ))
            .await?;
    }
    ddl::constraints(native, target.schema(), &physical).await?;
    verify(native, target, tables, source).await
}

pub(super) async fn verify(
    native: &mut Native,
    target: &WriteTarget,
    tables: &[CatalogEntry],
    manifest: &SnapshotManifest,
) -> Result<(), ControlError> {
    let engine = native.engine();
    for table in tables {
        let definition = manifest
            .tables
            .iter()
            .find(|entry| entry.name == table.logical_table)
            .ok_or(ControlError::Provision(
                "snapshot table definition is missing",
            ))?;
        let base = engine.relation(&table.base_schema, &table.base_table);
        let copy = engine.relation(target.schema(), &target.table(&table.logical_table));
        let join = definition
            .primary_key
            .iter()
            .map(|name| {
                let name = engine.quote(name);
                format!("b.{name}=c.{name}")
            })
            .collect::<Vec<_>>()
            .join(" AND ");
        let first = definition
            .primary_key
            .first()
            .ok_or(ControlError::Provision("snapshot primary key is missing"))?;
        let equals=definition.columns.iter().map(|column|{
            let name=engine.quote(&column.name);
            if engine==Engine::Postgres {
                if matches!(column.sql_type,SnapshotType::Text{..}) {
                    format!("convert_to(b.{name},'UTF8') IS NOT DISTINCT FROM convert_to(c.{name},'UTF8')")
                } else {format!("b.{name} IS NOT DISTINCT FROM c.{name}")}
            } else if matches!(column.sql_type,SnapshotType::Text{..}|SnapshotType::Binary{..}) {
                format!("HEX(b.{name}) <=> HEX(c.{name})")
            } else {format!("b.{name} <=> c.{name}")}
        }).collect::<Vec<_>>().join(" AND ");
        let count_sql = format!(
            "SELECT {} FROM {copy}",
            if engine == Engine::Postgres {
                "COUNT(*)"
            } else {
                "CAST(COUNT(*) AS SIGNED)"
            }
        );
        let count = scalar(native, &count_sql).await?;
        if count != definition.rows {
            return Err(ControlError::Provision(
                "materialized snapshot row count differs",
            ));
        }
        let count_expr = if engine == Engine::Postgres {
            "COUNT(*)"
        } else {
            "CAST(COUNT(*) AS SIGNED)"
        };
        let sql = format!(
            "SELECT {count_expr} FROM {base} b LEFT JOIN {copy} c ON {join} WHERE c.{} IS NULL OR NOT ({equals})",
            engine.quote(first)
        );
        if scalar(native, &sql).await? != 0 {
            return Err(ControlError::Provision("materialized snapshot rows differ"));
        }
    }
    Ok(())
}

async fn scalar(native: &mut Native, sql: &str) -> Result<i64, ControlError> {
    match native {
        Native::MySql(connection) | Native::TiDB(connection) => {
            Ok(sqlx::query_scalar(sql).fetch_one(connection).await?)
        }
        Native::Postgres(connection) => Ok(sqlx::query_scalar(sql).fetch_one(connection).await?),
        Native::Mongo(_) => Err(ControlError::Provision(
            "SQL materialization requires a SQL engine",
        )),
    }
}
