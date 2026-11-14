use std::{future::Future, time::Duration};

pub(crate) mod audit;
mod manifest;
pub(crate) use audit::WitnessError;

use fg_meta::{LifecycleBranch, Metadata, SeedTable};
use fg_protocol_common::{
    BranchGrantCheck, CatalogEntry, GENERATED_ID_MAX, GENERATED_ID_START, WriteTarget,
};
use sqlx::Executor;
use tokio::time::timeout;

use crate::{
    ControlError, bootstrap, gate_seed,
    grants::{self, BRANCH_ACCESS, BranchAdminCheck, NativeRoles},
    mongo,
    native::{Engine, Native, NativeOptions},
    seed::{self, MYSQL_COLLATION, SeedVersion},
    verify,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const GENERATED_MARKER: &str = "_fg_generated BOOLEAN NOT NULL DEFAULT FALSE";

pub(crate) struct Admin {
    pub(crate) options: NativeOptions,
    pub(crate) roles: NativeRoles,
}

impl Admin {
    pub(crate) async fn verify_startup(&self, metadata: &Metadata) -> Result<(), ControlError> {
        let _guard = metadata.lock_bootstrap().await?;
        let engine = self.options.engine().name();
        let catalog = metadata.native_catalog(engine).await?;
        let active_generation = metadata.active_generation_id(engine).await?;
        let importing = metadata
            .importing_generation()
            .await?
            .filter(|generation| generation.engine == engine && generation.native_claimed);
        let mut native = self.connect().await?;
        if let Native::Mongo(client) = &native {
            return mongo::verify(client, &self.roles, !catalog.generations.is_empty()).await;
        }
        verify::check_constraint_enforcement(&mut native).await?;
        let check = BranchAdminCheck::Startup { active_generation };
        grants::verify_branch_admin(
            &mut native,
            &self.roles,
            &catalog,
            importing.as_ref(),
            check,
        )
        .await
    }

    pub(crate) async fn provision<F, Fut>(
        &self,
        metadata: &Metadata,
        id: i64,
        verify_grants: F,
    ) -> Result<(), ControlError>
    where
        F: FnOnce(BranchGrantCheck) -> Fut,
        Fut: Future<Output = Result<(), ControlError>>,
    {
        let _guard = metadata.lock_bootstrap().await?;
        let engine = self.options.engine().name();
        let Some(branch) = metadata.provisioning_branch(id, engine).await? else {
            return Ok(());
        };
        let tables = metadata
            .generation_tables(branch.generation_id, engine)
            .await?;
        let target = WriteTarget::for_branch(id, branch.uses_mysql_shared_schema);
        metadata.lifecycle_progress(id, "preflight", None).await?;
        let result = async {
            if !self
                .provision_native(metadata, &branch, &target, &tables)
                .await?
            {
                return Ok(());
            }
            let mut native = self.connect().await?;
            self.prepare_witness(metadata, &mut native, &target).await?;
            if let Native::Postgres(connection) = &mut native {
                grants::verify_postgres_branch(connection, &self.roles, &target, &tables).await?;
            }
            // The shared fgwrite layout serves MySQL and TiDB alike.
            if matches!(self.options.engine(), Engine::MySql | Engine::TiDB) {
                metadata.lifecycle_progress(id, "granting", None).await?;
                verify_grants(BranchGrantCheck {
                    write_schema: target.schema().to_owned(),
                    tables: tables
                        .iter()
                        .map(|table| table.logical_table.clone())
                        .collect(),
                })
                .await?;
            }
            // A concurrent drop or expiry prevents activation.
            metadata.activate_branch(id).await?;
            Ok(())
        }
        .await;
        if let Err(error) = &result
            && verification_failed(error)
        {
            metadata.reject_branch(id).await?;
        }
        result
    }

    async fn provision_native(
        &self,
        metadata: &Metadata,
        branch: &LifecycleBranch,
        target: &WriteTarget,
        tables: &[CatalogEntry],
    ) -> Result<bool, ControlError> {
        if branch.native_claimed
            && !metadata
                .reset_provisioning_audit_witness(self.options.engine().name(), branch.id)
                .await?
        {
            return Err(WitnessError::Pending.into());
        }
        let mut capacity_native = self.connect().await?;
        let relations = tables
            .iter()
            .map(|table| (table.base_schema.clone(), table.base_table.clone()))
            .collect::<Vec<_>>();
        let estimated = crate::capacity::estimate(&mut capacity_native, &relations).await?;
        drop(capacity_native);
        let storage_preflight = crate::capacity::assess(
            estimated,
            "native_allocation_statistics_with_64KiB_minimum_per_relation",
            1,
            0,
            &std::env::temp_dir(),
        )?;
        metadata
            .record_branch_storage_preflight(
                branch.id,
                &serde_json::to_value(&storage_preflight)
                    .map_err(|_| ControlError::Provision("storage preflight encoding"))?,
            )
            .await?;
        storage_preflight.ensure_capacity()?;
        if let Some(snapshot) = metadata.snapshot_manifest(branch.generation_id).await? {
            let mut native = self.connect().await?;
            if branch.native_claimed {
                remove(&mut native, target, tables, &self.roles).await?;
            } else {
                ensure_empty(&mut native, target).await?;
                if !metadata.claim_branch(branch.id).await? {
                    return Ok(false);
                }
            }
            metadata
                .lifecycle_progress(branch.id, "copying", None)
                .await?;
            if let Native::Mongo(client) = &mut native {
                mongo::build_manifest_branch(client, target, tables, &snapshot).await?;
            } else {
                manifest::build(&mut native, target, tables, &snapshot).await?;
            }
            metadata
                .lifecycle_progress(branch.id, "granting", None)
                .await?;
            grant_access(&mut native, target, tables, &self.roles).await?;
            return Ok(true);
        }
        let version = SeedVersion::parse(&branch.snapshot).ok_or(ControlError::Provision(
            "generation snapshot does not support writes",
        ))?;
        let seeds = seed::tables(self.options.engine(), version);
        verify_registration(tables, &seeds)?;
        let mut native = self.connect().await?;
        if branch.native_claimed {
            remove(&mut native, target, tables, &self.roles).await?;
        } else {
            ensure_empty(&mut native, target).await?;
            if !metadata.claim_branch(branch.id).await? {
                return Ok(false);
            }
        }
        if let Native::Mongo(client) = &mut native {
            metadata
                .lifecycle_progress(branch.id, "copying", None)
                .await?;
            mongo::build_branch(client, target, tables).await?;
        } else {
            metadata
                .lifecycle_progress(branch.id, "copying", None)
                .await?;
            build(&mut native, target, tables, &seeds).await?;
        }
        metadata
            .lifecycle_progress(branch.id, "validating", None)
            .await?;
        verify_copy(&mut native, target, version, &seeds).await?;
        grant_access(&mut native, target, tables, &self.roles).await?;
        Ok(true)
    }

    pub(crate) async fn collect(
        &self,
        metadata: &Metadata,
        branch: &LifecycleBranch,
    ) -> Result<(), ControlError> {
        let _guard = metadata.lock_bootstrap().await?;
        let engine = self.options.engine().name();
        let tables = metadata
            .generation_tables(branch.generation_id, engine)
            .await?;
        let mut native = self.connect().await?;
        let target = WriteTarget::for_branch(branch.id, branch.uses_mysql_shared_schema);
        if !metadata.audit_cleanup_ready(engine, branch.id).await? {
            metadata
                .lifecycle_progress(branch.id, "audit_recovery_pending", None)
                .await?;
            return Err(WitnessError::Pending.into());
        }
        metadata
            .begin_audit_storage_reclaim(engine, branch.id)
            .await?;
        metadata
            .lifecycle_progress(branch.id, "removing", None)
            .await?;
        remove(&mut native, &target, &tables, &self.roles).await?;
        metadata.complete_drop(branch.id).await?;
        Ok(())
    }

    async fn connect(&self) -> Result<Native, ControlError> {
        let mut native = timeout(CONNECT_TIMEOUT, self.options.connect())
            .await
            .map_err(|_| ControlError::NativeTimeout)??;
        match native.engine() {
            Engine::MySql | Engine::TiDB => {
                native.execute("SET time_zone = '+00:00'").await?;
                native.execute("SET SESSION lock_wait_timeout = 10").await?;
                native
                    .execute("SET SESSION innodb_lock_wait_timeout = 10")
                    .await?;
                native.execute("SET SESSION foreign_key_checks = 1").await?;
            }
            Engine::Postgres => {
                native.execute("SET TIME ZONE 'UTC'").await?;
                native.execute("SET lock_timeout = '10s'").await?;
                native.execute("SET statement_timeout = '15s'").await?;
            }
            // MongoDB provisioning runs command-based (crate::mongo); no
            // session variables to pin.
            Engine::MongoDb => {}
        }
        Ok(native)
    }
}

fn verification_failed(error: &ControlError) -> bool {
    match error {
        ControlError::Provision(_) | ControlError::Seed(_) | ControlError::Grants(_) => true,
        ControlError::Native(error) => error.as_database_error().is_some_and(|error| {
            if let Some(mysql) = error.try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>() {
                return matches!(mysql.number(), 1062 | 1451 | 1452 | 3819);
            }
            error.code().is_some_and(|code| code.starts_with("23"))
        }),
        _ => false,
    }
}

fn verify_registration(tables: &[CatalogEntry], seeds: &[SeedTable]) -> Result<(), ControlError> {
    if tables.len() != seeds.len()
        || !tables.iter().zip(seeds).all(|(table, seed)| {
            table.logical_table == seed.name
                && table.generated_key.as_deref() == seed.generated_key
                && supports_generated_key(seed)
                && table.columns.len() == seed.columns.len()
                && table
                    .columns
                    .iter()
                    .zip(seed.columns)
                    .all(|(column, source)| {
                        column.name == source.name
                            && column.type_name == source.type_name
                            && column.nullable == source.nullable
                            && column.primary_key_ordinal == source.primary_key_ordinal
                    })
        })
    {
        return Err(ControlError::Provision(
            "branch registration differs from the seed manifest",
        ));
    }
    Ok(())
}

fn supports_generated_key(seed: &SeedTable) -> bool {
    let Some(key) = seed.generated_key else {
        return true;
    };
    let mut primary_key = seed
        .columns
        .iter()
        .filter(|column| column.primary_key_ordinal.is_some());
    primary_key.next().is_some_and(|column| {
        column.name == key
            && column.type_name == "bigint"
            && !column.nullable
            && column.primary_key_ordinal == Some(1)
    }) && primary_key.next().is_none()
}

async fn verify_copy(
    native: &mut Native,
    target: &WriteTarget,
    version: SeedVersion,
    seeds: &[SeedTable],
) -> Result<(), ControlError> {
    if let Native::Mongo(client) = native {
        return mongo::verify_branch_copy(client, target, seeds, version).await;
    }
    let engine = native.engine();
    for seed in seeds {
        let name = target.table(seed.name);
        let relation = engine.relation(target.schema(), &name);
        let expected = seed::rows(version, seed.name)
            .ok_or(ControlError::Provision("missing branch seed manifest"))?;
        verify::branch_table(native, target.schema(), &name, seed).await?;
        if let Some(count) = version.gate_orders(seed.name) {
            let small_rows = gate_seed::small_orders(&relation);
            verify::snapshot(native, &small_rows, seed, &expected).await?;
            gate_seed::verify(native, &relation, count).await?;
        } else {
            verify::snapshot(native, &relation, seed, &expected).await?;
        }
    }
    Ok(())
}

async fn ensure_empty(native: &mut Native, target: &WriteTarget) -> Result<(), ControlError> {
    if let Native::Mongo(client) = native {
        if !mongo::branch_namespace_is_empty(client, target).await? {
            return Err(ControlError::Provision(
                "branch database already contains collections",
            ));
        }
        return Ok(());
    }
    let is_occupied = match (&mut *native, target.prefix()) {
        (Native::MySql(connection) | Native::TiDB(connection), Some(prefix)) => {
            !verify::mysql_namespace_is_empty(connection, target.schema(), Some(prefix)).await?
        }
        (native, _) => verify::has_schema(native, target.schema()).await?,
    };
    if is_occupied {
        if let (Native::MySql(connection) | Native::TiDB(connection), Some(prefix)) =
            (&mut *native, target.prefix())
        {
            let objects = verify::namespace_objects(connection, target.schema(), Some(prefix))
                .await
                .unwrap_or_default();
            tracing::error!(
                component = "provision",
                schema = target.schema(),
                prefix,
                ?objects,
                "physical branch namespace already exists"
            );
        }
        return Err(ControlError::Provision(
            "physical branch namespace already exists",
        ));
    }
    Ok(())
}

async fn build(
    native: &mut Native,
    target: &WriteTarget,
    tables: &[CatalogEntry],
    seeds: &[SeedTable],
) -> Result<(), ControlError> {
    let engine = native.engine();
    if target.prefix().is_none() {
        let quoted = engine.quote(target.schema());
        let charset = match engine {
            Engine::MySql | Engine::TiDB => {
                format!(" CHARACTER SET utf8mb4 COLLATE {MYSQL_COLLATION}")
            }
            Engine::Postgres => String::new(),
            Engine::MongoDb => String::new(),
        };
        native
            .execute(&format!("CREATE SCHEMA {quoted}{charset}"))
            .await?;
    }
    for (table, seed) in tables.iter().zip(seeds) {
        clone_table(native, target, table, seed).await?;
    }
    seed::add_integrity_constraints(native, target.schema(), target.prefix()).await
}

async fn grant_access(
    native: &mut Native,
    target: &WriteTarget,
    tables: &[CatalogEntry],
    roles: &NativeRoles,
) -> Result<(), ControlError> {
    if let Native::Mongo(client) = native {
        return mongo::grant_branch(client, roles, target).await;
    }
    let engine = native.engine();
    if engine == Engine::Postgres {
        let quoted = engine.quote(target.schema());
        native
            .execute(&format!(
                "GRANT USAGE ON SCHEMA {quoted} TO {}",
                roles.service.account
            ))
            .await?;
    }
    for table in tables {
        let relation = engine.relation(target.schema(), &target.table(&table.logical_table));
        native
            .execute(&format!(
                "GRANT {BRANCH_ACCESS} ON {relation} TO {}",
                roles.service.account
            ))
            .await?;
    }
    Ok(())
}

async fn clone_table(
    native: &mut Native,
    target: &WriteTarget,
    table: &CatalogEntry,
    seed: &SeedTable,
) -> Result<(), ControlError> {
    let engine = native.engine();
    let base = engine.relation(&table.base_schema, &table.base_table);
    let name = target.table(&table.logical_table);
    let relation = engine.relation(target.schema(), &name);
    let columns = table
        .columns
        .iter()
        .map(|column| engine.quote(&column.name))
        .collect::<Vec<_>>()
        .join(", ");
    native
        .execute(&bootstrap::table_ddl(engine, &relation, seed, false))
        .await?;
    native
        .execute(&format!(
            "ALTER TABLE {relation} ADD COLUMN {GENERATED_MARKER}"
        ))
        .await?;
    if let Some(key) = &table.generated_key {
        let key = engine.quote(key);
        let constraint = engine.quote(&format!("{name}_generated_range"));
        let max_explicit = GENERATED_ID_START - 1;
        native
            .execute(&format!(
                "ALTER TABLE {relation} ADD CONSTRAINT {constraint} CHECK (
                    (_fg_generated = FALSE AND {key} BETWEEN 1 AND {max_explicit})
                    OR (_fg_generated = TRUE AND {key} BETWEEN {GENERATED_ID_START} AND {GENERATED_ID_MAX})
                )"
            ))
            .await?;
    }
    native
        .execute(&format!(
            "INSERT INTO {relation} ({columns}) SELECT {columns} FROM {base}"
        ))
        .await?;
    Ok(())
}

async fn remove(
    native: &mut Native,
    target: &WriteTarget,
    tables: &[CatalogEntry],
    roles: &NativeRoles,
) -> Result<(), ControlError> {
    if let Native::Mongo(client) = native {
        return mongo::remove_branch(client, roles, target).await;
    }
    audit::remove(native, target, roles).await?;
    let engine = native.engine();
    let schema = target.schema();
    let quoted = engine.quote(schema);
    let relations = tables
        .iter()
        .map(|table| engine.relation(schema, &target.table(&table.logical_table)))
        .collect::<Vec<_>>();
    match engine {
        Engine::MySql | Engine::TiDB => {
            // MySQL-family engines retain table grants even after a database
            // is dropped. The snapshot registers children after parents for
            // dependency-ordered cleanup.
            for relation in &relations {
                if engine == Engine::TiDB {
                    revoke_existing(native, relation, &roles.service.account).await?;
                } else {
                    native
                        .execute(&format!(
                            "REVOKE IF EXISTS {BRANCH_ACCESS} ON {relation} FROM {}",
                            roles.service.account
                        ))
                        .await?;
                }
            }
            for relation in relations.into_iter().rev() {
                native
                    .execute(&format!("DROP TABLE IF EXISTS {relation}"))
                    .await?;
            }
            if let Native::MySql(connection) | Native::TiDB(connection) = native
                && !verify::mysql_namespace_is_empty(connection, schema, target.prefix()).await?
            {
                return Err(ControlError::Provision(
                    "branch namespace contains unregistered objects",
                ));
            }
        }
        Engine::Postgres if verify::has_schema(native, schema).await? => {
            native
                .execute(&format!(
                    "REVOKE USAGE ON SCHEMA {quoted} FROM {}",
                    roles.service.account
                ))
                .await?;
            for (table, relation) in tables.iter().zip(&relations) {
                if verify::has_table(native, schema, &table.logical_table).await? {
                    native
                        .execute(&format!(
                            "REVOKE {BRANCH_ACCESS} ON {relation} FROM {}",
                            roles.service.account
                        ))
                        .await?;
                }
            }
            // RESTRICT keeps dependencies owned by operators outside this schema intact.
            let relations = relations.join(", ");
            native
                .execute(&format!("DROP TABLE IF EXISTS {relations}"))
                .await?;
        }
        Engine::Postgres => {}
        Engine::MongoDb => {}
    }
    if target.prefix().is_some() {
        return Ok(());
    }
    native
        .execute(&format!("DROP SCHEMA IF EXISTS {quoted}"))
        .await
}

/// TiDB rejects `REVOKE IF EXISTS` and branch administrators
/// cannot read other accounts' grants, so revoke the full branch privilege
/// set and tolerate "no such grant" (1147) when a privilege is absent.
async fn revoke_existing(
    native: &mut Native,
    relation: &str,
    account: &str,
) -> Result<(), ControlError> {
    let Native::TiDB(connection) = native else {
        return Ok(());
    };
    for rights in ["SELECT", "INSERT", "UPDATE", "DELETE"] {
        let statement = format!("REVOKE {rights} ON {relation} FROM {account}");
        let result = connection.execute(statement.as_str()).await;
        if let Err(sqlx::Error::Database(database)) = result {
            // TiDB reports an absent grant as 1105 with the no-such-grant
            // message; MySQL 8.0 uses 1147.
            let mysql = database
                .try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>()
                .map(|mysql| (mysql.number(), mysql.message().to_owned()));
            let absent = mysql.is_some_and(|(number, message)| {
                number == 1147 || (number == 1105 && message.contains("no such grant"))
            });
            if !absent {
                return Err(ControlError::Native(sqlx::Error::Database(database)));
            }
        } else if let Err(error) = result {
            return Err(ControlError::Native(error));
        }
    }
    Ok(())
}
