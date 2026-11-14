use fg_meta::{BootstrapGeneration, Metadata, NativeCatalog, SeedTable};
use fg_protocol_common::CatalogEntry;

use crate::{
    ControlError, gate_seed,
    grants::{self, NativeRoles},
    mongo,
    native::{Engine, Native, NativeOptions},
    seed::{self, DELTA_SCHEMA, MYSQL_COLLATION, SeedVersion},
    verify,
};

pub(crate) async fn run(
    metadata: &Metadata,
    options: &NativeOptions,
    roles: &NativeRoles,
) -> Result<i64, ControlError> {
    let _guard = metadata.lock_bootstrap().await?;
    let mut native = options.connect().await?;
    recover(metadata, &mut native, roles).await?;
    let version = SeedVersion::V1;
    let seeds = seed::tables(native.engine(), version);
    let generation = metadata
        .allocate_generation(native.engine().name(), &seeds)
        .await?;
    let catalog = NativeCatalog {
        generations: Vec::new(),
        branches: Vec::new(),
    };
    install(
        metadata,
        &mut native,
        roles,
        Import {
            generation: &generation,
            seeds: &seeds,
            version,
            catalog: &catalog,
        },
    )
    .await?;
    // An uncertain commit must not trigger physical removal. Recovery checks
    // the authoritative state before touching any owned objects.
    metadata.activate_generation(generation.id).await?;
    Ok(generation.id)
}

pub(crate) async fn recover(
    metadata: &Metadata,
    native: &mut Native,
    roles: &NativeRoles,
) -> Result<(), ControlError> {
    if let Some(stale) = metadata.importing_generation().await? {
        if stale.engine != native.engine().name() {
            return Err(ControlError::Config(
                "importing generation belongs to another engine",
            ));
        }
        if stale.native_claimed {
            remove_generation(native, &stale, roles).await?;
        }
        metadata.fail_generation(stale.id).await?;
    }
    Ok(())
}

pub(crate) struct Import<'a> {
    pub(crate) generation: &'a BootstrapGeneration,
    pub(crate) seeds: &'a [SeedTable],
    pub(crate) version: SeedVersion,
    pub(crate) catalog: &'a NativeCatalog,
}

pub(crate) async fn install(
    metadata: &Metadata,
    native: &mut Native,
    roles: &NativeRoles,
    import: Import<'_>,
) -> Result<(), ControlError> {
    let id = import.generation.id;
    let preflight = async {
        verify::check_constraint_enforcement(native).await?;
        ensure_fresh(native, import.generation).await?;
        grants::verify(native, roles, import.catalog, None).await
    };
    if let Err(error) = preflight.await {
        metadata.fail_generation(id).await?;
        return Err(error);
    }
    metadata.claim_generation(id).await?;
    if let Err(error) = build(native, &import, roles).await {
        tracing::warn!(
            generation_id = id,
            engine = native.engine().name(),
            reason = "snapshot_build_failed_before_activation",
            "generation failed; collecting only its owned objects"
        );
        if remove_generation(native, import.generation, roles)
            .await
            .is_ok()
        {
            metadata.fail_generation(id).await?;
        }
        return Err(error);
    }
    Ok(())
}

async fn ensure_fresh(
    native: &mut Native,
    generation: &BootstrapGeneration,
) -> Result<(), ControlError> {
    if let Native::Mongo(client) = native {
        return mongo::ensure_fresh(client, generation).await;
    }
    if verify::has_schema(native, &generation.schema).await? {
        return Err(ControlError::Seed(
            "physical generation schema already exists",
        ));
    }
    for table in &generation.tables {
        if verify::has_table(native, &table.delta_schema, &table.delta_table).await? {
            return Err(ControlError::Seed("physical delta table already exists"));
        }
    }
    Ok(())
}

async fn build(
    native: &mut Native,
    import: &Import<'_>,
    roles: &NativeRoles,
) -> Result<(), ControlError> {
    let engine = native.engine();
    let generation = import.generation;
    if let Native::Mongo(client) = native {
        // MongoDB collections live in their own databases; there is no
        // SQL schema DDL and no SQL integrity fixture.
        return mongo::build(client, generation, import.seeds, import.version, roles).await;
    }
    create_schema(native, &generation.schema, false).await?;
    create_schema(native, DELTA_SCHEMA, true).await?;
    for table in &generation.tables {
        let seed = import
            .seeds
            .iter()
            .find(|seed| seed.name == table.logical_table)
            .ok_or(ControlError::Seed("unregistered seed table"))?;
        create_table_pair(native, table, seed, import.version).await?;
        verify::pair(native, table, seed).await?;
    }
    if import.version.has_integrity_fixture() {
        // Validate the loaded rows against the native unique and foreign keys
        // before granting access or allowing the generation to activate.
        seed::add_integrity_constraints(native, &generation.schema, None).await?;
    }
    if engine == Engine::Postgres {
        let base = engine.quote(&generation.schema);
        let delta = engine.quote(DELTA_SCHEMA);
        native
            .execute(&format!(
                "GRANT USAGE ON SCHEMA {base}, {delta} TO {}",
                roles.service.account
            ))
            .await?;
        native
            .execute(&format!(
                "GRANT USAGE ON SCHEMA {delta} TO {}",
                roles.collector.account
            ))
            .await?;
        if let Some(role) = &roles.branch_admin {
            native
                .execute(&format!("GRANT USAGE ON SCHEMA {base} TO {}", role.account))
                .await?;
        }
    }
    for table in &generation.tables {
        grants::grant_table(native, table, roles).await?;
    }
    grants::verify(native, roles, import.catalog, Some(generation)).await
}

async fn create_schema(native: &mut Native, name: &str, shared: bool) -> Result<(), ControlError> {
    let engine = native.engine();
    let name = engine.quote(name);
    let existence = if shared { " IF NOT EXISTS" } else { "" };
    let charset = match engine {
        Engine::MySql | Engine::TiDB => {
            format!(" CHARACTER SET utf8mb4 COLLATE {MYSQL_COLLATION}")
        }
        Engine::Postgres | Engine::MongoDb => String::new(),
    };
    native
        .execute(&format!("CREATE SCHEMA{existence} {name}{charset}"))
        .await
}

async fn create_table_pair(
    native: &mut Native,
    entry: &CatalogEntry,
    seed: &SeedTable,
    version: SeedVersion,
) -> Result<(), ControlError> {
    let engine = native.engine();
    let base = engine.relation(&entry.base_schema, &entry.base_table);
    let delta = engine.relation(&entry.delta_schema, &entry.delta_table);
    native
        .execute(&table_ddl(engine, &base, seed, false))
        .await?;
    let rows = seed::rows(version, seed.name).ok_or(ControlError::Seed("missing seed rows"))?;
    let values = rows
        .iter()
        .map(|row| {
            let value = row
                .iter()
                .map(|value| value.native(engine))
                .collect::<Vec<_>>()
                .join(", ");
            format!("({value})")
        })
        .collect::<Vec<_>>()
        .join(", ");
    native
        .execute(&format!("INSERT INTO {base} VALUES {values}"))
        .await?;
    verify::snapshot(native, &base, seed, &rows).await?;
    if let Some(count) = version.gate_orders(seed.name) {
        gate_seed::load(native, &base, count).await?;
        if let Err(error) = gate_seed::verify(native, &base, count).await {
            tracing::warn!(logical_table=%entry.logical_table,
                "gate seed content validation failed before compensation");
            return Err(error);
        }
    }
    native
        .execute(&table_ddl(engine, &delta, seed, true))
        .await?;
    Ok(())
}

pub(crate) fn table_ddl(
    engine: Engine,
    relation: &str,
    seed: &SeedTable,
    is_delta: bool,
) -> String {
    let mut fields = seed
        .columns
        .iter()
        .map(|column| {
            let name = engine.quote(column.name);
            let nonnull = column.primary_key_ordinal.is_some() || (!is_delta && !column.nullable);
            let constraint = if nonnull { " NOT NULL" } else { "" };
            let collation =
                if matches!(engine, Engine::MySql | Engine::TiDB) && column.collation.is_some() {
                    format!(" CHARACTER SET utf8mb4 COLLATE {MYSQL_COLLATION}")
                } else {
                    String::new()
                };
            format!("{name} {}{collation}{constraint}", column.type_name)
        })
        .collect::<Vec<_>>();
    let mut key = ordered_key(seed)
        .iter()
        .map(|name| engine.quote(name))
        .collect::<Vec<_>>();
    if is_delta {
        fields.extend([
            "_fg_branch BIGINT NOT NULL CHECK (_fg_branch > 0)".to_owned(),
            "_fg_op CHAR(1) NOT NULL CHECK (_fg_op IN ('I', 'U', 'D'))".to_owned(),
        ]);
        key.insert(0, "_fg_branch".to_owned());
    }
    fields.push(format!("PRIMARY KEY ({})", key.join(", ")));
    let storage = if matches!(engine, Engine::MySql | Engine::TiDB) {
        " ENGINE=InnoDB"
    } else {
        ""
    };
    format!("CREATE TABLE {relation} ({}){storage}", fields.join(", "))
}

pub(crate) fn ordered_key(seed: &SeedTable) -> Vec<&'static str> {
    let mut columns = seed
        .columns
        .iter()
        .filter_map(|column| {
            column
                .primary_key_ordinal
                .map(|ordinal| (ordinal, column.name))
        })
        .collect::<Vec<_>>();
    columns.sort_unstable_by_key(|(ordinal, _)| *ordinal);
    columns.into_iter().map(|(_, name)| name).collect()
}

pub(crate) async fn remove_generation(
    native: &mut Native,
    generation: &BootstrapGeneration,
    roles: &NativeRoles,
) -> Result<(), ControlError> {
    if let Native::Mongo(client) = native {
        return mongo::remove_generation(client, generation, roles).await;
    }
    grants::revoke_partial(native, roles, &generation.tables).await?;
    let engine = native.engine();
    // The catalog registers referenced parents before their dependent children.
    for table in generation.tables.iter().rev() {
        let delta = engine.relation(&table.delta_schema, &table.delta_table);
        let base = engine.relation(&table.base_schema, &table.base_table);
        native
            .execute(&format!("DROP TABLE IF EXISTS {delta}"))
            .await?;
        native
            .execute(&format!("DROP TABLE IF EXISTS {base}"))
            .await?;
    }
    if let Native::MySql(connection) = native
        && !verify::mysql_namespace_is_empty(connection, &generation.schema, None).await?
    {
        return Err(ControlError::Seed(
            "owned schema contains unregistered objects",
        ));
    }
    let schema = engine.quote(&generation.schema);
    native
        .execute(&format!("DROP SCHEMA IF EXISTS {schema}"))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branch_delta_precedes_all_source_key_columns() {
        let orders = &seed::tables(Engine::Postgres, SeedVersion::V1)[0];
        assert_eq!(ordered_key(orders), ["tenant_id", "id"]);
        let ddl = table_ddl(Engine::Postgres, "forkget_delta.example", orders, true);
        assert!(ddl.contains("PRIMARY KEY (_fg_branch, \"tenant_id\", \"id\")"));
        assert!(!ddl.contains("\"customer_id\" integer NOT NULL"));
    }
}
