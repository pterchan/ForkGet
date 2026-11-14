//! MongoDB administrative operations for the control plane:
//! generation build, grants, verification, and cleanup run
//! through the official driver. The proxy data path stays hand-rolled.

use bson::Document;
use fg_meta::{BootstrapGeneration, SeedTable};
use fg_protocol_common::{CatalogEntry, WriteTarget};
use mongodb::{
    Client, IndexModel,
    bson::{Bson, Document as BsonDocument, doc},
    options::{ValidationAction, ValidationLevel},
};

use crate::{
    ControlError,
    grants::NativeRoles,
    seed::{SeedVersion, mongo_documents},
};

/// The admin database holds the deployment roles; the role name matches the
/// account name it authorizes, so one lookup answers both questions.
const ADMIN_DB: &str = "admin";

/// Cluster-wide privilege the proxy observer needs for $currentOp (drain).
fn inprog_privilege() -> BsonDocument {
    doc! {
        "resource": { "cluster": true },
        "actions": ["inprog"],
    }
}

pub(crate) async fn ensure_fresh(
    client: &Client,
    generation: &BootstrapGeneration,
) -> Result<(), ControlError> {
    if has_collection(client, &generation.schema, None).await? {
        return Err(ControlError::Seed(
            "physical generation schema already exists",
        ));
    }
    for table in &generation.tables {
        if has_collection(client, &table.delta_schema, Some(&table.delta_table)).await? {
            return Err(ControlError::Seed("physical delta table already exists"));
        }
    }
    Ok(())
}

/// Build one generation: base collections with reviewed seed documents and
/// delta collections carrying the branch/operation validator plus the
/// per-branch document uniqueness index.
pub(crate) async fn build(
    client: &Client,
    generation: &BootstrapGeneration,
    seeds: &[SeedTable],
    version: SeedVersion,
    roles: &NativeRoles,
) -> Result<(), ControlError> {
    for table in &generation.tables {
        let seed = seeds
            .iter()
            .find(|seed| seed.name == table.logical_table)
            .ok_or(ControlError::Seed("unregistered seed table"))?;
        let documents = mongo_documents(version, seed.name)
            .ok_or(ControlError::Seed("missing seed documents"))?;
        let base_db = client.database(&table.base_schema);
        base_db.create_collection(&table.base_table).await?;
        let base = base_db.collection::<BsonDocument>(&table.base_table);
        if !documents.is_empty() {
            base.insert_many(documents.clone()).await?;
        }
        verify_seed(&base, &documents).await?;
        initialize_delta(client, table).await?;
    }
    grant_generation(client, roles, generation).await
}

pub(crate) async fn initialize_manifest_delta(
    client: &Client,
    generation: &BootstrapGeneration,
    roles: &NativeRoles,
) -> Result<(), ControlError> {
    for table in &generation.tables {
        initialize_delta(client, table).await?;
    }
    grant_generation(client, roles, generation).await
}

async fn initialize_delta(client: &Client, table: &CatalogEntry) -> Result<(), ControlError> {
    let database = client.database(&table.delta_schema);
    database
        .create_collection(&table.delta_table)
        .validator(delta_validator())
        .validation_level(ValidationLevel::Strict)
        .validation_action(ValidationAction::Error)
        .await?;
    database
        .collection::<BsonDocument>(&table.delta_table)
        .create_index(
            IndexModel::builder()
                .keys(doc! {"_fg_branch":1i32,"_doc._id":1i32})
                .options(
                    mongodb::options::IndexOptions::builder()
                        .unique(true)
                        .name("_fg_branch_document".to_owned())
                        .build(),
                )
                .build(),
        )
        .await?;
    Ok(())
}

fn delta_validator() -> BsonDocument {
    doc! {
        "$jsonSchema": {
            "bsonType": "object",
            "required": ["_fg_branch", "_fg_op", "_doc"],
            "properties": {
                "_fg_branch": { "bsonType": ["int", "long"] },
                "_fg_op": { "enum": ["I", "U", "D"] },
                "_doc": { "bsonType": "object" }
            }
        }
    }
}

/// Seed verification is row-for-row: every fixture document must come back
/// byte-for-byte (field order included) when read back sorted by _id.
async fn verify_seed(
    collection: &mongodb::Collection<BsonDocument>,
    expected: &[BsonDocument],
) -> Result<(), ControlError> {
    let mut cursor = collection.find(doc! {}).sort(doc! { "_id": 1i32 }).await?;
    let mut observed = Vec::with_capacity(expected.len());
    while cursor.advance().await? {
        observed.push(cursor.deserialize_current()?);
    }
    if observed != expected {
        return Err(ControlError::Seed(
            "native rows differ from the repository snapshot",
        ));
    }
    Ok(())
}

/// Roles are named after the accounts they authorize. Each generation adds
/// its base-database read privilege to the service role; delta privileges
/// and the observer's inprog action are merged idempotently.
/// Membership is granted to both accounts.
async fn grant_generation(
    client: &Client,
    roles: &NativeRoles,
    generation: &BootstrapGeneration,
) -> Result<(), ControlError> {
    let admin = client.database(ADMIN_DB);
    let (service, collector) = generation_privileges(generation);
    ensure_role(&admin, &roles.service.account, service).await?;
    ensure_role(&admin, &roles.collector.account, collector).await?;
    for role in [&roles.service, &roles.collector] {
        admin
            .run_command(doc! {
                "grantRolesToUser": role.account.as_str(),
                "roles": [{ "role": role.account.as_str(), "db": ADMIN_DB }],
            })
            .await?;
    }
    Ok(())
}

fn generation_privileges(
    generation: &BootstrapGeneration,
) -> (Vec<BsonDocument>, Vec<BsonDocument>) {
    let mut service = vec![inprog_privilege()];
    let mut collector = Vec::new();
    for table in &generation.tables {
        service.push(doc! {
            "resource": { "db": &table.base_schema, "collection": &table.base_table },
            "actions": ["find"],
        });
        let delta = doc! { "db": &table.delta_schema, "collection": &table.delta_table };
        service.push(doc! {
            "resource": delta.clone(), "actions": ["find", "insert", "update", "remove"],
        });
        collector.push(doc! { "resource": delta, "actions": ["find", "remove"] });
    }
    (service, collector)
}

/// Merge `added` into the role's current privileges, creating the role when
/// missing. Retirement removes the generation privileges explicitly.
async fn ensure_role(
    admin: &mongodb::Database,
    role: &str,
    added: Vec<BsonDocument>,
) -> Result<(), ControlError> {
    let existing = role_privileges(admin, role).await?;
    match existing {
        Some(mut current) => {
            let before = current.len();
            for privilege in added {
                if !current.contains(&privilege) {
                    current.push(privilege);
                }
            }
            if current.len() != before {
                admin
                    .run_command(doc! {
                        "updateRole": role,
                        "privileges": current,
                    })
                    .await?;
            }
        }
        None => {
            admin
                .run_command(doc! {
                    "createRole": role,
                    "privileges": added,
                    "roles": [],
                })
                .await?;
        }
    }
    Ok(())
}

async fn role_privileges(
    admin: &mongodb::Database,
    role: &str,
) -> Result<Option<Vec<BsonDocument>>, ControlError> {
    let reply = admin
        .run_command(doc! {
            "rolesInfo": [role],
            "showPrivileges": true,
        })
        .await?;
    let roles = reply
        .get_array("roles")
        .map_err(|_| ControlError::Seed("rolesInfo reply shape"))?;
    let Some(first) = roles.first() else {
        return Ok(None);
    };
    let document = first
        .as_document()
        .ok_or(ControlError::Seed("rolesInfo reply shape"))?;
    let privileges = document
        .get_array("privileges")
        .map_err(|_| ControlError::Seed("rolesInfo reply shape"))?
        .iter()
        .filter_map(Bson::as_document)
        .cloned()
        .collect::<Vec<_>>();
    Ok(Some(privileges))
}

/// Canary verification: both accounts must
/// exist and, once anything is registered, hold the role named after them.
/// This is weaker than the SQL engines' exact-grant checks and the matrix
/// entry records that limitation.
pub(crate) async fn verify(
    client: &Client,
    roles: &NativeRoles,
    registered: bool,
) -> Result<(), ControlError> {
    let admin = client.database(ADMIN_DB);
    for role in [&roles.service, &roles.collector] {
        let reply = admin
            .run_command(doc! { "usersInfo": [{ "user": role.account.as_str(), "db": ADMIN_DB }] })
            .await?;
        let users = reply
            .get_array("users")
            .map_err(|_| ControlError::Seed("usersInfo reply shape"))?;
        if users.is_empty() {
            tracing::error!(component = "grants", role = %role.account,
                detail = "user is missing on the mongod deployment",
                "native role verification failed");
            return Err(ControlError::Seed(
                "native role privileges differ from the registered catalog",
            ));
        }
        if registered {
            let privileges = role_privileges(&admin, &role.account)
                .await?
                .unwrap_or_default();
            if privileges.iter().any(has_generation_wide_writes) {
                return Err(ControlError::Seed(
                    "unsafe MongoDB generation-wide writes; replace legacy grants with collection-scoped base read and delta write grants",
                ));
            }
            let user = users[0]
                .as_document()
                .ok_or(ControlError::Seed("usersInfo reply shape"))?;
            let holds = user
                .get_array("roles")
                .map_err(|_| ControlError::Seed("usersInfo reply shape"))?
                .iter()
                .filter_map(Bson::as_document)
                .any(|entry| {
                    entry.get_str("role") == Ok(role.account.as_str())
                        && entry.get_str("db") == Ok(ADMIN_DB)
                });
            if !holds {
                tracing::error!(component = "grants", role = %role.account,
                    detail = "deployment role membership is missing",
                    "native role verification failed");
                return Err(ControlError::Seed(
                    "native role privileges differ from the registered catalog",
                ));
            }
        }
    }
    Ok(())
}

fn has_generation_wide_writes(privilege: &BsonDocument) -> bool {
    let Ok(resource) = privilege.get_document("resource") else {
        return false;
    };
    resource
        .get_str("db")
        .is_ok_and(|name| name.starts_with("fg_g"))
        && resource.get_str("collection") == Ok("")
        && privilege.get_array("actions").is_ok_and(|actions| {
            actions.iter().any(|action| {
                matches!(
                    action.as_str(),
                    Some("insert" | "update" | "remove" | "anyAction")
                )
            })
        })
}

/// Retirement: drop the generation privileges from the roles, then remove
/// the delta collections before the base ones, mirroring the SQL recipe.
pub(crate) async fn remove_generation(
    client: &Client,
    generation: &BootstrapGeneration,
    roles: &NativeRoles,
) -> Result<(), ControlError> {
    let admin = client.database(ADMIN_DB);
    for role in [&roles.service, &roles.collector] {
        if let Some(mut privileges) = role_privileges(&admin, &role.account).await? {
            let before = privileges.len();
            privileges.retain(|privilege| {
                privilege
                    .get_document("resource")
                    .and_then(|resource| resource.get_str("db"))
                    != Ok(generation.schema.as_str())
            });
            if privileges.len() != before {
                admin
                    .run_command(doc! {
                        "updateRole": role.account.as_str(),
                        "privileges": privileges,
                    })
                    .await?;
            }
        }
    }
    for table in generation.tables.iter().rev() {
        for (schema, name) in [
            (&table.delta_schema, &table.delta_table),
            (&table.base_schema, &table.base_table),
        ] {
            if let Err(error) = client
                .database(schema)
                .collection::<Document>(name)
                .drop()
                .await
                && !matches!(error.kind.as_ref(), mongodb::error::ErrorKind::Command(command) if command.code == 26)
            {
                return Err(error.into());
            }
        }
    }
    Ok(())
}

/// Branch drop purges the branch's delta documents; the base collections
/// stay shared with the whole generation.
pub(crate) async fn delete_branch(
    client: &Client,
    branch: i64,
    tables: &[CatalogEntry],
) -> Result<(), ControlError> {
    for table in tables {
        client
            .database(&table.delta_schema)
            .collection::<Document>(&table.delta_table)
            .delete_many(doc! { "_fg_branch": branch })
            .await?;
    }
    Ok(())
}

/// A database "exists" once it holds at least one collection; mongod does
/// not materialize empty databases.
pub(crate) async fn has_collection(
    client: &Client,
    database: &str,
    collection: Option<&str>,
) -> Result<bool, ControlError> {
    let names = client.database(database).list_collection_names().await?;
    match collection {
        Some(name) => Ok(names.iter().any(|known| known == name)),
        None => Ok(!names.is_empty()),
    }
}

// Branch-owned document copies.

/// Branch provisioning creates the branch-owned
/// collections in `fg_b<id>` and copy the pinned generation documents into
/// them. Collections keep their logical names; `_id` uniqueness is mongod's.
pub(crate) async fn build_branch(
    client: &Client,
    target: &WriteTarget,
    tables: &[CatalogEntry],
) -> Result<(), ControlError> {
    for table in tables {
        let source = client
            .database(&table.base_schema)
            .collection::<BsonDocument>(&table.base_table);
        let mut cursor = source.find(doc! {}).sort(doc! { "_id": 1i32 }).await?;
        let mut documents = Vec::new();
        let mut bytes = 0usize;
        while cursor.advance().await? {
            let image: BsonDocument = cursor.deserialize_current()?;
            bytes += bson::to_vec(&image)
                .map_err(|_| ControlError::Provision("invalid BSON document"))?
                .len();
            documents.push(image);
            if documents.len() >= 500 || bytes >= 8 * 1024 * 1024 {
                client
                    .database(target.schema())
                    .collection::<BsonDocument>(&target.table(&table.logical_table))
                    .insert_many(std::mem::take(&mut documents))
                    .ordered(true)
                    .await?;
                bytes = 0;
            }
        }
        let branch = client
            .database(target.schema())
            .collection::<BsonDocument>(&target.table(&table.logical_table));
        if !documents.is_empty() {
            branch.insert_many(documents).ordered(true).await?;
        }
    }
    Ok(())
}

/// Imported document collections preserve native validators, options and indexes.
/// Copy cursors stay bounded, including when the collection exceeds process RAM.
pub(crate) async fn build_manifest_branch(
    client: &Client,
    target: &WriteTarget,
    tables: &[CatalogEntry],
    manifest: &fg_protocol_common::SnapshotManifest,
) -> Result<(), ControlError> {
    let document = manifest
        .document
        .as_ref()
        .ok_or(ControlError::Provision("document manifest missing"))?;
    for collection in &document.collections {
        let name = target.table(&collection.name);
        let mut command = doc! {"create":&name};
        let options = decode_metadata(&collection.options_bson)?;
        for (key, value) in options {
            if !matches!(
                key.as_str(),
                "capped"
                    | "size"
                    | "max"
                    | "validator"
                    | "validationLevel"
                    | "validationAction"
                    | "collation"
                    | "storageEngine"
            ) {
                return Err(ControlError::Provision(
                    "unsupported document collection option",
                ));
            }
            command.insert(key, value);
        }
        client
            .database(target.schema())
            .run_command(command)
            .await?;
    }
    build_branch(client, target, tables).await?;
    for collection in &document.collections {
        let name = target.table(&collection.name);
        let mut indexes = Vec::new();
        for encoded in &collection.indexes_bson {
            let mut index = decode_metadata(encoded)?;
            // ns is old server metadata; createIndexes derives the target namespace.
            index.remove("ns");
            if index.contains_key("expireAfterSeconds") {
                return Err(ControlError::Provision(
                    "expiring indexes cannot pin an immutable snapshot",
                ));
            }
            indexes.push(index);
        }
        if !indexes.is_empty() {
            client
                .database(target.schema())
                .run_command(doc! {"createIndexes":&name,"indexes":indexes})
                .await?;
        }
    }
    for table in tables {
        let mut base = client
            .database(&table.base_schema)
            .collection::<BsonDocument>(&table.base_table)
            .find(doc! {})
            .sort(doc! {"_id":1})
            .await?;
        let mut copy = client
            .database(target.schema())
            .collection::<BsonDocument>(&target.table(&table.logical_table))
            .find(doc! {})
            .sort(doc! {"_id":1})
            .await?;
        let mut rows = 0i64;
        loop {
            let source = base.advance().await?;
            let destination = copy.advance().await?;
            if source != destination {
                return Err(ControlError::Provision(
                    "materialized document count differs",
                ));
            }
            if !source {
                break;
            }
            if base.current().as_bytes() != copy.current().as_bytes() {
                return Err(ControlError::Provision("materialized BSON image differs"));
            }
            rows += 1;
        }
        if rows != table.baseline_rows {
            return Err(ControlError::Provision(
                "materialized document count differs from catalog",
            ));
        }
    }
    Ok(())
}

fn decode_metadata(encoded: &str) -> Result<BsonDocument, ControlError> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| ControlError::Provision("invalid BSON collection metadata"))?;
    bson::from_slice(&bytes)
        .map_err(|_| ControlError::Provision("invalid BSON collection metadata"))
}

/// Provision verification: every branch collection matches the repository
/// snapshot document-for-document (the same bar the generation build sets).
pub(crate) async fn verify_branch_copy(
    client: &Client,
    target: &WriteTarget,
    seeds: &[SeedTable],
    version: SeedVersion,
) -> Result<(), ControlError> {
    for seed in seeds {
        let expected = mongo_documents(version, seed.name)
            .ok_or(ControlError::Seed("missing seed documents"))?;
        let branch = client
            .database(target.schema())
            .collection::<BsonDocument>(&target.table(seed.name));
        let mut cursor = branch.find(doc! {}).sort(doc! { "_id": 1i32 }).await?;
        let mut observed = Vec::with_capacity(expected.len());
        while cursor.advance().await? {
            observed.push(cursor.deserialize_current()?);
        }
        if observed != expected {
            return Err(ControlError::Provision(
                "native branch documents differ from the seed catalog",
            ));
        }
    }
    Ok(())
}

/// Branch grants merge into the service role: whole-database read/write on
/// `fg_b<id>` (the collector stays delta-only).
pub(crate) async fn grant_branch(
    client: &Client,
    roles: &NativeRoles,
    target: &WriteTarget,
) -> Result<(), ControlError> {
    let admin = client.database(ADMIN_DB);
    ensure_role(
        &admin,
        &roles.service.account,
        vec![doc! {
            "resource": { "db": target.schema(), "collection": "" },
            "actions": ["find", "insert", "update", "remove"],
        }],
    )
    .await?;
    admin
        .run_command(doc! {
            "grantRolesToUser": roles.service.account.as_str(),
            "roles": [{ "role": roles.service.account.as_str(), "db": ADMIN_DB }],
        })
        .await?;
    Ok(())
}

/// Branch cleanup: strip the branch-database privileges from the service
/// role, then drop the whole `fg_b<id>` database. Idempotent on the way down.
pub(crate) async fn remove_branch(
    client: &Client,
    roles: &NativeRoles,
    target: &WriteTarget,
) -> Result<(), ControlError> {
    let admin = client.database(ADMIN_DB);
    if let Some(mut privileges) = role_privileges(&admin, &roles.service.account).await? {
        let before = privileges.len();
        privileges.retain(|privilege| {
            privilege
                .get_document("resource")
                .and_then(|resource| resource.get_str("db"))
                != Ok(target.schema())
        });
        if privileges.len() != before {
            admin
                .run_command(doc! {
                    "updateRole": roles.service.account.as_str(),
                    "privileges": privileges,
                })
                .await?;
        }
    }
    client.database(target.schema()).drop().await?;
    Ok(())
}

/// The branch namespace is empty when the database holds no collections
/// (mongod does not materialize empty databases).
pub(crate) async fn branch_namespace_is_empty(
    client: &Client,
    target: &WriteTarget,
) -> Result<bool, ControlError> {
    Ok(client
        .database(target.schema())
        .list_collection_names()
        .await?
        .is_empty())
}
