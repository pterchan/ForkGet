//! Native catalog admission; unsupported source objects fail before capture.

use fg_protocol_common::{
    CheckSpec, ColumnDefault, ColumnSpec, ForeignKeySpec, IndexSpec, ReferentialAction,
    SNAPSHOT_FORMAT_VERSION, SnapshotManifest, SnapshotType, TableManifest, snapshot_identifier,
};
use serde_json::Value;
use sqlx::Executor;

use super::SnapshotError;
use crate::native::{Engine, Native};

fn unsupported(object: impl Into<String>, reason: &'static str) -> SnapshotError {
    SnapshotError::Unsupported {
        object: object.into(),
        reason,
    }
}

pub(super) async fn execute(native: &mut Native, sql: &str) -> Result<(), SnapshotError> {
    match native {
        Native::MySql(connection) | Native::TiDB(connection) => {
            connection.execute(sql).await?;
        }
        Native::Postgres(connection) => {
            connection.execute(sql).await?;
        }
        Native::Mongo(_) => return Err(unsupported("schema", "unsupported_snapshot_engine")),
    }
    Ok(())
}

pub(super) async fn text(native: &mut Native, sql: &str) -> Result<String, SnapshotError> {
    Ok(match native {
        Native::MySql(connection) | Native::TiDB(connection) => {
            sqlx::query_scalar(sql).fetch_one(connection).await?
        }
        Native::Postgres(connection) => sqlx::query_scalar(sql).fetch_one(connection).await?,
        Native::Mongo(_) => return Err(unsupported("schema", "unsupported_snapshot_engine")),
    })
}

async fn rows(
    native: &mut Native,
    mysql: &str,
    postgres: &str,
    args: &[&str],
) -> Result<Vec<Value>, SnapshotError> {
    let strings: Vec<String> = match native {
        Native::MySql(connection) | Native::TiDB(connection) => {
            let mut query = sqlx::query_scalar(mysql);
            for value in args {
                query = query.bind(*value);
            }
            query.fetch_all(connection).await?
        }
        Native::Postgres(connection) => {
            let mut query = sqlx::query_scalar(postgres);
            for value in args {
                query = query.bind(*value);
            }
            query.fetch_all(connection).await?
        }
        Native::Mongo(_) => return Err(unsupported("schema", "unsupported_snapshot_engine")),
    };
    strings
        .into_iter()
        .map(|value| serde_json::from_str(&value).map_err(SnapshotError::Json))
        .collect()
}

fn required<'a>(row: &'a Value, key: &str) -> Result<&'a str, SnapshotError> {
    row[key]
        .as_str()
        .ok_or_else(|| unsupported("catalog", "incomplete_native_catalog"))
}

fn identifier(value: &str) -> Result<String, SnapshotError> {
    if !snapshot_identifier(value) {
        return Err(unsupported("identifier", "unsupported_source_identifier"));
    }
    Ok(value.to_owned())
}

pub(super) async fn source_visibility(
    native: &mut Native,
    schema: &str,
) -> Result<(), SnapshotError> {
    let Native::MySql(connection) = native else {
        return Ok(());
    };
    let grants: Vec<String> = sqlx::query_scalar("SHOW GRANTS FOR CURRENT_USER")
        .fetch_all(connection)
        .await?;
    for (privilege, reason) in [
        ("SELECT", "mysql_source_schema_select_coverage_unproven"),
        ("TRIGGER", "mysql_source_trigger_visibility_unproven"),
        ("EVENT", "mysql_source_event_visibility_unproven"),
    ] {
        if !direct_privilege(&grants, schema, privilege, false) {
            return Err(unsupported("source", reason));
        }
    }
    if !direct_privilege(&grants, schema, "SHOW_ROUTINE", true)
        && !direct_privilege(&grants, schema, "SELECT", true)
        && !["CREATE ROUTINE", "ALTER ROUTINE", "EXECUTE"]
            .iter()
            .any(|privilege| direct_privilege(&grants, schema, privilege, false))
    {
        return Err(unsupported(
            "source",
            "mysql_source_routine_visibility_unproven",
        ));
    }
    Ok(())
}

fn direct_privilege(grants: &[String], schema: &str, privilege: &str, global_only: bool) -> bool {
    // SHOW GRANTS returns canonical server-generated statements. Deliberately
    // prove direct global/exact-schema coverage, not a partial list of visible
    // tables or an unexpanded role assignment. Insufficient visibility would
    // otherwise turn hidden tables/triggers/routines into a false admission.
    let scope_matches = |scope: &str, global_only: bool| {
        scope == "*.*"
            || (!global_only
                && (scope.replace("\\_", "_") == format!("`{schema}`.*")
                    || scope == format!("{schema}.*")))
    };
    let has = |statement: &str, prefix: &str, separator: &str, global_only: bool| {
        statement
            .strip_prefix(prefix)
            .and_then(|rest| rest.split_once(" ON "))
            .and_then(|(privileges, rest)| {
                rest.split_once(separator)
                    .map(|(scope, _)| (privileges, scope))
            })
            .is_some_and(|(privileges, scope)| {
                scope_matches(scope, global_only)
                    && privileges.split(',').any(|value| {
                        matches!(value.trim(), "ALL" | "ALL PRIVILEGES")
                            || value.trim() == privilege
                    })
            })
    };
    grants
        .iter()
        .any(|grant| has(grant, "GRANT ", " TO ", global_only))
        && !grants
            .iter()
            .any(|grant| has(grant, "REVOKE ", " FROM ", false))
}

pub(super) async fn read(
    native: &mut Native,
    physical_schema: &str,
    logical_schema: &str,
    name: &str,
) -> Result<SnapshotManifest, SnapshotError> {
    identifier(logical_schema)?;
    let source_version = text(native, "SELECT VERSION()").await?;
    if native.engine() == Engine::MySql && !source_version.starts_with("8.0.") {
        return Err(unsupported("server", "mysql_8_0_required"));
    }
    if native.engine() == Engine::TiDB && !source_version.contains("TiDB-v8.5.") {
        return Err(unsupported("server", "tidb_8_5_required"));
    }
    if native.engine() == Engine::Postgres && !source_version.starts_with("PostgreSQL 16.") {
        return Err(unsupported("server", "postgresql_16_required"));
    }
    reject_objects(native, physical_schema).await?;
    let tables = rows(native,
        "SELECT CAST(JSON_OBJECT('name',TABLE_NAME,'kind',TABLE_TYPE,'storage',COALESCE(ENGINE,''),'options',COALESCE(CREATE_OPTIONS,'')) AS CHAR) FROM information_schema.tables WHERE table_schema=? ORDER BY table_name",
        "SELECT json_build_object('name',c.relname,'kind',c.relkind::text,'persistence',c.relpersistence::text,'rls',c.relrowsecurity,'inherited',EXISTS(SELECT 1 FROM pg_inherits i WHERE i.inhrelid=c.oid))::text FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relkind IN ('r','p','v','m','f') ORDER BY c.relname", &[physical_schema]).await?;
    let mut admitted = Vec::new();
    for table in tables {
        let table_name = identifier(required(&table, "name")?)?;
        if native.engine() != Engine::Postgres && table_name.len() > 39 {
            return Err(unsupported(
                table_name,
                "table_name_too_long_for_native_copy",
            ));
        }
        if native.engine() == Engine::Postgres {
            if required(&table, "kind")? != "r"
                || required(&table, "persistence")? != "p"
                || table["rls"] == true
                || table["inherited"] == true
            {
                return Err(unsupported(
                    table_name,
                    "views_partitions_inheritance_and_rls_not_supported",
                ));
            }
        } else if required(&table, "kind")? != "BASE TABLE"
            || !required(&table, "storage")?.eq_ignore_ascii_case("InnoDB")
            || !required(&table, "options")?.is_empty()
        {
            return Err(unsupported(
                table_name,
                "unsupported_table_storage_or_options",
            ));
        }
        admitted.push(read_table(native, physical_schema, &table_name).await?);
    }
    let manifest = SnapshotManifest {
        format_version: SNAPSHOT_FORMAT_VERSION,
        engine: native.engine().name().to_owned(),
        name: name.to_owned(),
        logical_schema: logical_schema.to_owned(),
        source_version,
        tables: admitted,
        document: None,
    };
    manifest.validate()?;
    Ok(manifest)
}

async fn reject_objects(native: &mut Native, schema: &str) -> Result<(), SnapshotError> {
    let objects = rows(native,
        "SELECT CAST(JSON_OBJECT('kind',kind) AS CHAR) FROM (SELECT 'trigger' kind FROM information_schema.triggers WHERE trigger_schema=? UNION ALL SELECT 'routine' FROM information_schema.routines WHERE routine_schema=? UNION ALL SELECT 'event' FROM information_schema.events WHERE event_schema=?) objects LIMIT 1",
        "SELECT json_build_object('kind',kind)::text FROM (SELECT 'function' kind FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=$1 UNION ALL SELECT 'trigger' FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$2 AND NOT t.tgisinternal UNION ALL SELECT 'custom_type' FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname=$3 AND t.typtype IN ('d','e','r') UNION ALL SELECT 'unowned_sequence' FROM pg_class seq JOIN pg_namespace n ON n.oid=seq.relnamespace WHERE n.nspname=$1 AND seq.relkind='S' AND NOT EXISTS(SELECT 1 FROM pg_depend d JOIN pg_class owner_table ON owner_table.oid=d.refobjid WHERE d.classid='pg_class'::regclass AND d.objid=seq.oid AND d.deptype IN ('a','i') AND owner_table.relnamespace=n.oid) UNION ALL SELECT 'rule' FROM pg_rewrite r JOIN pg_class t ON t.oid=r.ev_class JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname=$1 AND r.rulename<>'_RETURN' UNION ALL SELECT 'unvalidated_or_nonstandard_constraint' FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname=$1 AND (NOT c.convalidated OR (c.contype='c' AND c.connoinherit) OR (c.contype='f' AND c.confmatchtype<>'s'))) objects LIMIT 1", &[schema,schema,schema]).await?;
    if !objects.is_empty() {
        return Err(unsupported(
            "schema",
            "routines_triggers_events_and_custom_types_not_supported",
        ));
    }
    Ok(())
}

async fn read_table(
    native: &mut Native,
    schema: &str,
    table: &str,
) -> Result<TableManifest, SnapshotError> {
    let columns = rows(native,
        "SELECT CAST(JSON_OBJECT('name',COLUMN_NAME,'type',LOWER(COLUMN_TYPE),'nullable',IS_NULLABLE='YES','default',COLUMN_DEFAULT,'collation',COLLATION_NAME,'extra',EXTRA,'expression',GENERATION_EXPRESSION) AS CHAR) FROM information_schema.columns WHERE table_schema=? AND table_name=? ORDER BY ordinal_position",
        "SELECT json_build_object('name',a.attname,'type',format_type(a.atttypid,a.atttypmod),'nullable',NOT a.attnotnull,'default',pg_get_expr(d.adbin,d.adrelid),'collation',CASE WHEN a.attcollation=0 THEN NULL ELSE col.collname END,'extra',a.attidentity::text,'expression',a.attgenerated::text,'sequence_owned',EXISTS(SELECT 1 FROM pg_depend owner_dep JOIN pg_class seq ON seq.oid=owner_dep.objid WHERE owner_dep.classid='pg_class'::regclass AND owner_dep.refobjid=c.oid AND owner_dep.refobjsubid=a.attnum AND owner_dep.deptype IN ('a','i') AND seq.relkind='S' AND seq.relnamespace=n.oid))::text FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum LEFT JOIN pg_collation col ON col.oid=a.attcollation WHERE n.nspname=$1 AND c.relname=$2 AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum", &[schema,table]).await?;
    let mut specs = Vec::new();
    let mut generated_key = None;
    for column in columns {
        let spec = column_spec(native.engine(), &column)?;
        if spec.default == Some(ColumnDefault::Generated)
            && generated_key.replace(spec.name.clone()).is_some()
        {
            return Err(unsupported(
                table,
                "multiple_generated_columns_not_supported",
            ));
        }
        specs.push(spec);
    }
    let (primary_key_name, primary_key, indexes) = indexes(native, schema, table).await?;
    let foreign_keys = foreign_keys(native, schema, table).await?;
    let checks = checks(native, schema, table, &specs).await?;
    let relation = native.engine().relation(schema, table);
    let mut invalid_values = Vec::new();
    if let Some(key) = &generated_key {
        invalid_values.push(format!(
            "{} NOT BETWEEN 1 AND 4611686018427387903",
            native.engine().quote(key)
        ));
    }
    if native.engine() != Engine::Postgres {
        for column in &specs {
            if column.sql_type == SnapshotType::Boolean {
                invalid_values.push(format!(
                    "{} IS NOT NULL AND {} NOT IN (0,1)",
                    native.engine().quote(&column.name),
                    native.engine().quote(&column.name)
                ));
            }
        }
    }
    if !invalid_values.is_empty() {
        let sql = if native.engine() == Engine::Postgres {
            format!(
                "SELECT COUNT(*) FROM {relation} WHERE {}",
                invalid_values.join(" OR ")
            )
        } else {
            format!(
                "SELECT CAST(COUNT(*) AS SIGNED) FROM {relation} WHERE {}",
                invalid_values.join(" OR ")
            )
        };
        let invalid: i64 = match native {
            Native::MySql(connection) | Native::TiDB(connection) => {
                sqlx::query_scalar(&sql).fetch_one(connection).await?
            }
            Native::Postgres(connection) => sqlx::query_scalar(&sql).fetch_one(connection).await?,
            Native::Mongo(_) => return Err(unsupported(table, "unsupported_snapshot_engine")),
        };
        if invalid != 0 {
            return Err(unsupported(
                table,
                "generated_key_or_boolean_value_outside_admitted_domain",
            ));
        }
    }
    let sql = if native.engine() == Engine::Postgres {
        format!("SELECT COUNT(*) FROM {relation}")
    } else {
        format!("SELECT CAST(COUNT(*) AS SIGNED) FROM {relation}")
    };
    let count: i64 = match native {
        Native::MySql(connection) | Native::TiDB(connection) => {
            sqlx::query_scalar(&sql).fetch_one(connection).await?
        }
        Native::Postgres(connection) => sqlx::query_scalar(&sql).fetch_one(connection).await?,
        Native::Mongo(_) => return Err(unsupported(table, "unsupported_snapshot_engine")),
    };
    Ok(TableManifest {
        name: table.to_owned(),
        columns: specs,
        primary_key,
        primary_key_name,
        generated_key,
        rows: count,
        indexes,
        foreign_keys,
        checks,
    })
}

fn column_spec(engine: Engine, row: &Value) -> Result<ColumnSpec, SnapshotError> {
    let name = identifier(required(row, "name")?)?;
    let extra = required(row, "extra")?;
    if !required(row, "expression")?.is_empty() {
        return Err(unsupported(name, "computed_columns_not_supported"));
    }
    let kind = required(row, "type")?;
    let sql_type = parse_type(engine, kind)?;
    let default = parse_default(engine, &sql_type, row["default"].as_str(), extra)?;
    if engine == Engine::Postgres
        && default == Some(ColumnDefault::Generated)
        && !truth(row, "sequence_owned")
    {
        return Err(unsupported(
            &name,
            "generated_sequence_must_be_owned_in_source_schema",
        ));
    }
    let collation = match row["collation"].as_str() {
        Some("default") | None => None,
        Some(value)
            if engine == Engine::Postgres
                && matches!(value, "C" | "POSIX" | "ucs_basic" | "C.utf8") =>
        {
            Some(value.to_owned())
        }
        Some(value)
            if engine != Engine::Postgres
                && value.starts_with("utf8mb4_")
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_') =>
        {
            Some(value.to_owned())
        }
        _ => return Err(unsupported(name, "unsupported_column_collation")),
    };
    let nullable = row["nullable"]
        .as_bool()
        .or_else(|| row["nullable"].as_u64().map(|value| value != 0))
        .ok_or_else(|| unsupported(&name, "missing_nullability"))?;
    Ok(ColumnSpec {
        name,
        sql_type,
        nullable,
        collation,
        default,
    })
}

fn parse_type(engine: Engine, value: &str) -> Result<SnapshotType, SnapshotError> {
    let value = value.to_ascii_lowercase();
    let number = |prefix: &str| {
        value
            .strip_prefix(prefix)
            .and_then(|value| value.strip_suffix(')'))
            .and_then(|value| value.parse::<u32>().ok())
    };
    let result = match value.as_str() {
        "smallint" => SnapshotType::Integer { bits: 16 },
        "int" | "integer" => SnapshotType::Integer { bits: 32 },
        "bigint" => SnapshotType::Integer { bits: 64 },
        "tinyint(1)" | "boolean" => SnapshotType::Boolean,
        "date" => SnapshotType::Date,
        "text" => SnapshotType::Text { length: None },
        "bytea" | "longblob" => SnapshotType::Binary { length: None },
        _ if number("varchar(")
            .or_else(|| number("character varying("))
            .is_some() =>
        {
            SnapshotType::Text {
                length: number("varchar(").or_else(|| number("character varying(")),
            }
        }
        _ if number("varbinary(").is_some() => SnapshotType::Binary {
            length: number("varbinary("),
        },
        _ if value.starts_with("decimal(") || value.starts_with("numeric(") => {
            let body = value
                .split_once('(')
                .and_then(|(_, body)| body.strip_suffix(')'))
                .ok_or_else(|| unsupported("column", "unsupported_decimal_type"))?;
            let (precision, scale) = body
                .split_once(',')
                .ok_or_else(|| unsupported("column", "unsupported_decimal_type"))?;
            SnapshotType::Decimal {
                precision: precision
                    .parse()
                    .map_err(|_| unsupported("column", "unsupported_decimal_type"))?,
                scale: scale
                    .parse()
                    .map_err(|_| unsupported("column", "unsupported_decimal_type"))?,
            }
        }
        _ if value.starts_with("timestamp") || value.starts_with("datetime") => {
            let timezone = value.contains("with time zone")
                || (engine != Engine::Postgres && value.starts_with("timestamp"));
            let digits = value
                .split_once('(')
                .and_then(|(_, tail)| tail.split_once(')'))
                .map(|(digits, _)| digits);
            SnapshotType::Timestamp {
                precision: digits
                    .map(|digits| digits.parse())
                    .transpose()
                    .map_err(|_| unsupported("column", "unsupported_timestamp_precision"))?
                    .unwrap_or(if engine == Engine::Postgres { 6 } else { 0 }),
                timezone,
            }
        }
        _ => return Err(unsupported("column", "unsupported_column_type")),
    };
    if !result.is_valid() {
        return Err(unsupported("column", "unsupported_column_type"));
    }
    Ok(result)
}

fn parse_default(
    engine: Engine,
    kind: &SnapshotType,
    value: Option<&str>,
    extra: &str,
) -> Result<Option<ColumnDefault>, SnapshotError> {
    if extra == "a" {
        return Err(unsupported(
            "column",
            "generated_always_identity_not_supported",
        ));
    }
    if extra.contains("auto_increment")
        || extra == "d"
        || value.is_some_and(|value| value.starts_with("nextval("))
    {
        return Ok(Some(ColumnDefault::Generated));
    }
    if !extra.is_empty() && extra != "DEFAULT_GENERATED" {
        return Err(unsupported("column", "unsupported_column_attributes"));
    }
    let Some(value) = value else { return Ok(None) };
    let lower = value.to_ascii_lowercase();
    if engine == Engine::Postgres && (lower == "null" || lower.starts_with("null::")) {
        return Ok(Some(ColumnDefault::Null));
    }
    if matches!(kind, SnapshotType::Timestamp { .. }) {
        if lower == "current_timestamp" || lower == "now()" {
            return Ok(Some(ColumnDefault::CurrentTimestamp));
        }
        if let Some(precision) = lower
            .strip_prefix("current_timestamp(")
            .and_then(|value| value.strip_suffix(')'))
        {
            let precision = precision
                .parse::<u8>()
                .ok()
                .filter(|value| *value <= 6)
                .ok_or_else(|| unsupported("column", "unsupported_default_precision"))?;
            return Ok(Some(ColumnDefault::CurrentTimestampPrecision(precision)));
        }
    }
    let scalar = value.split("::").next().unwrap_or(value);
    Ok(Some(match kind {
        SnapshotType::Integer { .. } | SnapshotType::Decimal { .. } => {
            ColumnDefault::Number(scalar.trim_matches('(').trim_matches(')').to_owned())
        }
        SnapshotType::Boolean => ColumnDefault::Boolean(match scalar {
            "true" | "1" => true,
            "false" | "0" => false,
            _ => return Err(unsupported("column", "unsupported_boolean_default")),
        }),
        SnapshotType::Text { .. } if engine != Engine::Postgres => {
            ColumnDefault::Text(value.to_owned())
        }
        SnapshotType::Text { .. } if scalar.starts_with('\'') && scalar.ends_with('\'') => {
            ColumnDefault::Text(scalar[1..scalar.len() - 1].replace("''", "'"))
        }
        SnapshotType::Date | SnapshotType::Timestamp { .. } if engine != Engine::Postgres => {
            ColumnDefault::Text(value.to_owned())
        }
        SnapshotType::Date | SnapshotType::Timestamp { .. }
            if scalar.starts_with('\'') && scalar.ends_with('\'') =>
        {
            ColumnDefault::Text(scalar[1..scalar.len() - 1].replace("''", "'"))
        }
        _ => return Err(unsupported("column", "unsupported_column_default")),
    }))
}

async fn indexes(
    native: &mut Native,
    schema: &str,
    table: &str,
) -> Result<(Option<String>, Vec<String>, Vec<IndexSpec>), SnapshotError> {
    let rows=rows(native,
        "SELECT CAST(JSON_OBJECT('name',INDEX_NAME,'column',COLUMN_NAME,'position',SEQ_IN_INDEX,'unique',NON_UNIQUE=0,'constraint',NON_UNIQUE=0,'deferrable',false,'deferred',false,'primary',INDEX_NAME='PRIMARY','supported',INDEX_TYPE='BTREE' AND SUB_PART IS NULL AND EXPRESSION IS NULL) AS CHAR) FROM information_schema.statistics WHERE table_schema=? AND table_name=? ORDER BY index_name,seq_in_index",
        "SELECT json_build_object('name',idx.relname,'column',a.attname,'position',k.ordinality,'unique',i.indisunique,'constraint',con.oid IS NOT NULL,'deferrable',COALESCE(con.condeferrable,false),'deferred',COALESCE(con.condeferred,false),'primary',i.indisprimary,'supported',i.indexprs IS NULL AND i.indpred IS NULL AND i.indnkeyatts=i.indnatts AND am.amname='btree' AND i.indisvalid AND NOT i.indnullsnotdistinct AND NOT EXISTS(SELECT 1 FROM unnest(i.indoption) opt WHERE opt<>0) AND NOT EXISTS(SELECT 1 FROM unnest(i.indclass) op JOIN pg_opclass opc ON opc.oid=op WHERE NOT opc.opcdefault))::text FROM pg_index i JOIN pg_class t ON t.oid=i.indrelid JOIN pg_namespace n ON n.oid=t.relnamespace JOIN pg_class idx ON idx.oid=i.indexrelid JOIN pg_am am ON am.oid=idx.relam LEFT JOIN pg_constraint con ON con.conindid=i.indexrelid AND con.contype IN ('p','u') CROSS JOIN LATERAL unnest(i.indkey) WITH ORDINALITY k(attnum,ordinality) LEFT JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum=k.attnum WHERE n.nspname=$1 AND t.relname=$2 ORDER BY idx.relname,k.ordinality",&[schema,table]).await?;
    let mut primary = Vec::new();
    let mut primary_name = None;
    let mut indexes: Vec<IndexSpec> = Vec::new();
    for row in rows {
        if !truth(&row, "supported") {
            return Err(unsupported(
                table,
                "expression_partial_prefix_or_covering_index_not_supported",
            ));
        }
        let column = identifier(required(&row, "column")?)?;
        if truth(&row, "primary") {
            if truth(&row, "deferrable") {
                return Err(unsupported(table, "deferrable_primary_key_not_supported"));
            }
            primary_name = Some(identifier(required(&row, "name")?)?);
            primary.push(column);
            continue;
        }
        let name = identifier(required(&row, "name")?)?;
        if let Some(index) = indexes.last_mut().filter(|index| index.name == name) {
            index.columns.push(column);
        } else {
            indexes.push(IndexSpec {
                name,
                columns: vec![column],
                unique: truth(&row, "unique"),
                is_constraint: truth(&row, "constraint"),
                deferrable: truth(&row, "deferrable"),
                initially_deferred: truth(&row, "deferred"),
            });
        }
    }
    Ok((primary_name, primary, indexes))
}

fn truth(row: &Value, key: &str) -> bool {
    row[key]
        .as_bool()
        .unwrap_or_else(|| row[key].as_i64().is_some_and(|value| value != 0))
}

fn action(value: &str) -> Result<ReferentialAction, SnapshotError> {
    Ok(match value.to_ascii_uppercase().as_str() {
        "NO ACTION" | "A" => ReferentialAction::NoAction,
        "RESTRICT" | "R" => ReferentialAction::Restrict,
        "CASCADE" | "C" => ReferentialAction::Cascade,
        "SET NULL" | "N" => ReferentialAction::SetNull,
        _ => return Err(unsupported("foreign_key", "unsupported_referential_action")),
    })
}

async fn foreign_keys(
    native: &mut Native,
    schema: &str,
    table: &str,
) -> Result<Vec<ForeignKeySpec>, SnapshotError> {
    let rows=rows(native,
        "SELECT CAST(JSON_OBJECT('name',k.CONSTRAINT_NAME,'column',k.COLUMN_NAME,'reference_schema',k.REFERENCED_TABLE_SCHEMA,'reference_table',k.REFERENCED_TABLE_NAME,'reference_column',k.REFERENCED_COLUMN_NAME,'on_update',r.UPDATE_RULE,'on_delete',r.DELETE_RULE,'deferrable',false,'deferred',false) AS CHAR) FROM information_schema.key_column_usage k JOIN information_schema.referential_constraints r ON r.CONSTRAINT_SCHEMA=k.CONSTRAINT_SCHEMA AND r.CONSTRAINT_NAME=k.CONSTRAINT_NAME AND r.TABLE_NAME=k.TABLE_NAME WHERE k.TABLE_SCHEMA=? AND k.TABLE_NAME=? AND k.REFERENCED_TABLE_NAME IS NOT NULL ORDER BY k.CONSTRAINT_NAME,k.ORDINAL_POSITION",
        "SELECT json_build_object('name',c.conname,'column',a.attname,'reference_schema',rn.nspname,'reference_table',rt.relname,'reference_column',ra.attname,'on_update',c.confupdtype::text,'on_delete',c.confdeltype::text,'deferrable',c.condeferrable,'deferred',c.condeferred)::text FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace JOIN pg_class rt ON rt.oid=c.confrelid JOIN pg_namespace rn ON rn.oid=rt.relnamespace CROSS JOIN LATERAL unnest(c.conkey,c.confkey) WITH ORDINALITY k(attnum,refattnum,ordinality) JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum=k.attnum JOIN pg_attribute ra ON ra.attrelid=rt.oid AND ra.attnum=k.refattnum WHERE n.nspname=$1 AND t.relname=$2 AND c.contype='f' ORDER BY c.conname,k.ordinality",&[schema,table]).await?;
    let mut keys: Vec<ForeignKeySpec> = Vec::new();
    for row in rows {
        if required(&row, "reference_schema")? != schema {
            return Err(unsupported(table, "cross_schema_foreign_key_not_supported"));
        }
        let name = identifier(required(&row, "name")?)?;
        let column = identifier(required(&row, "column")?)?;
        let reference = identifier(required(&row, "reference_column")?)?;
        if let Some(key) = keys.last_mut().filter(|key| key.name == name) {
            key.columns.push(column);
            key.referenced_columns.push(reference);
        } else {
            keys.push(ForeignKeySpec {
                name,
                columns: vec![column],
                referenced_table: identifier(required(&row, "reference_table")?)?,
                referenced_columns: vec![reference],
                on_update: action(required(&row, "on_update")?)?,
                on_delete: action(required(&row, "on_delete")?)?,
                deferrable: truth(&row, "deferrable"),
                initially_deferred: truth(&row, "deferred"),
            });
        }
    }
    Ok(keys)
}

async fn checks(
    native: &mut Native,
    schema: &str,
    table: &str,
    columns: &[ColumnSpec],
) -> Result<Vec<CheckSpec>, SnapshotError> {
    if let Native::TiDB(connection) = native {
        let native_checks =
            crate::native::mysql_table_checks(connection, Engine::TiDB, schema, table).await?;
        let mut checks = Vec::with_capacity(native_checks.len());
        for check in native_checks {
            let name = identifier(&check.name)?;
            validate_check(&check.expression, columns)?;
            checks.push(CheckSpec {
                name,
                expression: check.expression,
            });
        }
        checks.sort_by(|left, right| left.name.cmp(&right.name));
        return Ok(checks);
    }
    let rows=rows(native,
        "SELECT CAST(JSON_OBJECT('name',t.CONSTRAINT_NAME,'expression',c.CHECK_CLAUSE) AS CHAR) FROM information_schema.table_constraints t JOIN information_schema.check_constraints c ON c.CONSTRAINT_SCHEMA=t.CONSTRAINT_SCHEMA AND c.CONSTRAINT_NAME=t.CONSTRAINT_NAME WHERE t.TABLE_SCHEMA=? AND t.TABLE_NAME=? AND t.CONSTRAINT_TYPE='CHECK' ORDER BY t.CONSTRAINT_NAME",
        "SELECT json_build_object('name',c.conname,'expression',pg_get_expr(c.conbin,c.conrelid))::text FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname=$1 AND t.relname=$2 AND c.contype='c' ORDER BY c.conname",&[schema,table]).await?;
    rows.into_iter()
        .map(|row| {
            let name = identifier(required(&row, "name")?)?;
            let expression = required(&row, "expression")?.to_owned();
            validate_check(&expression, columns)?;
            Ok(CheckSpec { name, expression })
        })
        .collect()
}

pub(super) fn validate_check(
    expression: &str,
    columns: &[ColumnSpec],
) -> Result<(), SnapshotError> {
    // Admit only local scalar arithmetic/comparison checks. No subqueries,
    // qualified names, arbitrary functions, comments or statement separators.
    let bytes = expression.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let current = bytes[index];
        if bytes
            .get(index..index + 2)
            .is_some_and(|value| value == b"/*" || value == b"*/")
        {
            return Err(unsupported("check", "comments_not_supported"));
        }
        if current.is_ascii_whitespace() || b"()+*/%=<>!,".contains(&current) {
            index += 1;
            continue;
        }
        if matches!(current, b'-' | b'+') {
            if bytes.get(index + 1) == Some(&current) {
                return Err(unsupported("check", "comments_not_supported"));
            }
            index += 1;
            continue;
        }
        if current == b':' && bytes.get(index + 1) == Some(&b':') {
            index += 2;
            continue;
        }
        if matches!(current, b'\'' | b'"' | b'`') {
            let delimiter = current;
            let start = index + 1;
            index += 1;
            let mut closed = false;
            while index < bytes.len() {
                if bytes[index] == delimiter {
                    if bytes.get(index + 1) == Some(&delimiter) {
                        index += 2;
                        continue;
                    }
                    closed = true;
                    break;
                }
                if bytes[index] == b'\\' {
                    return Err(unsupported("check", "backslash_literals_not_supported"));
                }
                index += 1;
            }
            if !closed {
                return Err(unsupported("check", "invalid_check_expression"));
            }
            if delimiter != b'\''
                && !columns
                    .iter()
                    .any(|column| column.name == expression[start..index])
            {
                return Err(unsupported("check", "unknown_check_column"));
            }
            if delimiter != b'\'' && expression[index + 1..].trim_start().starts_with('(') {
                return Err(unsupported("check", "unsupported_check_function"));
            }
            index += 1;
            continue;
        }
        if current.is_ascii_alphanumeric() || current == b'_' {
            let start = index;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            let word = &expression[start..index];
            let upper = word.to_ascii_uppercase();
            if word.bytes().all(|byte| byte.is_ascii_digit()) {
                continue;
            }
            let tail = expression[index..].trim_start();
            let function = tail.starts_with('(');
            let allowed_function = matches!(
                upper.as_str(),
                "ABS" | "LENGTH" | "CHAR_LENGTH" | "OCTET_LENGTH" | "COALESCE" | "CAST"
            );
            let keyword = matches!(
                upper.as_str(),
                "AND"
                    | "OR"
                    | "NOT"
                    | "IS"
                    | "NULL"
                    | "TRUE"
                    | "FALSE"
                    | "IN"
                    | "BETWEEN"
                    | "AS"
                    | "NUMERIC"
                    | "DECIMAL"
                    | "INTEGER"
                    | "SMALLINT"
                    | "BIGINT"
                    | "TEXT"
                    | "VARCHAR"
                    | "DATE"
                    | "BOOLEAN"
            );
            if function
                && !allowed_function
                && !matches!(upper.as_str(), "IN" | "NUMERIC" | "DECIMAL" | "VARCHAR")
            {
                return Err(unsupported("check", "unsupported_check_function"));
            }
            if !keyword
                && !allowed_function
                && !columns
                    .iter()
                    .any(|column| column.name.eq_ignore_ascii_case(word))
            {
                return Err(unsupported("check", "unsupported_check_expression"));
            }
            continue;
        }
        // A decimal point is admitted only between decimal digits.
        if current == b'.'
            && index > 0
            && bytes[index - 1].is_ascii_digit()
            && bytes.get(index + 1).is_some_and(u8::is_ascii_digit)
        {
            index += 1;
            continue;
        }
        return Err(unsupported("check", "unsupported_check_expression"));
    }
    Ok(())
}

#[cfg(test)]
mod visibility_tests {
    use super::direct_privilege;

    #[test]
    fn canonical_direct_grants_prove_coverage_but_table_grants_and_role_names_do_not() {
        let grants = vec![
            "GRANT SELECT, SHOW VIEW, TRIGGER, EVENT ON `shop`.* TO `backup`@`%`".into(),
            "GRANT BACKUP_ADMIN,SHOW_ROUTINE ON *.* TO `backup`@`%`".into(),
        ];
        assert!(direct_privilege(&grants, "shop", "SELECT", false));
        assert!(direct_privilege(&grants, "shop", "TRIGGER", false));
        assert!(direct_privilege(&grants, "shop", "EVENT", false));
        assert!(direct_privilege(&grants, "shop", "SHOW_ROUTINE", true));
        assert!(!direct_privilege(&grants, "other", "SELECT", false));
        let partial = vec![
            "GRANT SELECT ON `shop`.`visible_table` TO `backup`@`%`".into(),
            "GRANT `backup_role`@`%` TO `backup`@`%`".into(),
        ];
        assert!(!direct_privilege(&partial, "shop", "SELECT", false));
    }

    #[test]
    fn global_administrator_grants_remain_valid_without_ignoring_partial_revocations() {
        let mut grants =
            vec!["GRANT ALL PRIVILEGES ON *.* TO `admin`@`%` WITH GRANT OPTION".into()];
        assert!(direct_privilege(&grants, "shop", "SELECT", false));
        assert!(direct_privilege(&grants, "shop", "TRIGGER", false));
        grants.push("REVOKE SELECT ON `other`.* FROM `admin`@`%`".into());
        assert!(direct_privilege(&grants, "shop", "SELECT", false));
        grants.push("REVOKE SELECT ON `shop`.* FROM `admin`@`%`".into());
        assert!(!direct_privilege(&grants, "shop", "SELECT", false));
    }
}
