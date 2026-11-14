use fg_meta::SeedTable;
use fg_protocol_common::CatalogEntry;
use sqlx::{MySqlConnection, Row};

use crate::{
    ControlError,
    bootstrap::ordered_key,
    mongo,
    native::{Engine, Native},
    seed::{MYSQL_COLLATION, POSTGRES_COLLATION, Value},
};

pub(crate) async fn check_constraint_enforcement(native: &mut Native) -> Result<(), ControlError> {
    // TiDB enforces CHECK constraints only with the flag on; the
    // delta-table and generated-key range checks depend on enforcement.
    let Native::TiDB(connection) = native else {
        return Ok(());
    };
    let enforced: i64 = sqlx::query_scalar("SELECT @@GLOBAL.tidb_enable_check_constraint")
        .fetch_one(&mut *connection)
        .await?;
    if enforced != 1 {
        return Err(ControlError::Config(
            "TiDB requires tidb_enable_check_constraint=ON before bootstrap, refresh or writable provisioning",
        ));
    }
    Ok(())
}

pub(crate) async fn has_schema(native: &mut Native, schema: &str) -> Result<bool, ControlError> {
    let name: Option<String> = match native {
        Native::Mongo(client) => {
            return mongo::has_collection(client, schema, None).await;
        }
        Native::MySql(connection) | Native::TiDB(connection) => {
            sqlx::query_scalar(
                "SELECT CONVERT(schema_name USING utf8mb4)
                 FROM information_schema.schemata WHERE schema_name = ?",
            )
            .bind(schema)
            .fetch_optional(connection)
            .await?
        }
        Native::Postgres(connection) => {
            sqlx::query_scalar(
                "SELECT nspname::text FROM pg_catalog.pg_namespace WHERE nspname::text = $1",
            )
            .bind(schema)
            .fetch_optional(connection)
            .await?
        }
    };
    Ok(name.is_some())
}

pub(crate) async fn mysql_namespace_is_empty(
    connection: &mut MySqlConnection,
    schema: &str,
    prefix: Option<&str>,
) -> Result<bool, ControlError> {
    let prefix = prefix.unwrap_or_default();
    let remaining: i64 = sqlx::query_scalar(
        "WITH target AS (SELECT ? AS namespace, ? AS prefix)
         SELECT CAST(EXISTS (SELECT 1 FROM information_schema.tables, target
                       WHERE table_schema = namespace
                       AND CAST(LEFT(table_name, CHAR_LENGTH(prefix)) AS BINARY) = CAST(prefix AS BINARY))
           OR EXISTS (SELECT 1 FROM information_schema.routines, target
                       WHERE routine_schema = namespace
                       AND CAST(LEFT(routine_name, CHAR_LENGTH(prefix)) AS BINARY) = CAST(prefix AS BINARY))
           OR EXISTS (SELECT 1 FROM information_schema.events, target
                       WHERE event_schema = namespace
                       AND CAST(LEFT(event_name, CHAR_LENGTH(prefix)) AS BINARY) = CAST(prefix AS BINARY)) AS SIGNED)",
    )
    .bind(schema)
    .bind(prefix)
    .fetch_one(connection)
    .await?;
    Ok(remaining == 0)
}

/// The unregistered objects that keep a branch namespace occupied; the
/// first names make the refusal actionable in the control log.
pub(crate) async fn namespace_objects(
    connection: &mut MySqlConnection,
    schema: &str,
    prefix: Option<&str>,
) -> Result<Vec<String>, ControlError> {
    let prefix = prefix.unwrap_or_default();
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT CONVERT(object_name USING utf8mb4) FROM (
             SELECT table_name AS object_name FROM information_schema.tables
             WHERE table_schema = ?
             UNION ALL
             SELECT routine_name FROM information_schema.routines WHERE routine_schema = ?
             UNION ALL
             SELECT event_name FROM information_schema.events WHERE event_schema = ?
         ) AS objects
         WHERE object_name LIKE CONCAT(?, '%') LIMIT 8",
    )
    .bind(schema)
    .bind(schema)
    .bind(schema)
    .bind(prefix)
    .fetch_all(connection)
    .await?;
    Ok(names)
}

pub(crate) async fn has_table(
    native: &mut Native,
    schema: &str,
    table: &str,
) -> Result<bool, ControlError> {
    let name: Option<String> = match native {
        Native::Mongo(client) => {
            return mongo::has_collection(client, schema, Some(table)).await;
        }
        Native::MySql(connection) | Native::TiDB(connection) => {
            sqlx::query_scalar(
                "SELECT CONVERT(table_name USING utf8mb4)
                 FROM information_schema.tables WHERE table_schema = ? AND table_name = ?",
            )
            .bind(schema)
            .bind(table)
            .fetch_optional(connection)
            .await?
        }
        Native::Postgres(connection) => {
            sqlx::query_scalar(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = $1 AND table_name = $2",
            )
            .bind(schema)
            .bind(table)
            .fetch_optional(connection)
            .await?
        }
    };
    Ok(name.is_some())
}

pub(crate) async fn pair(
    native: &mut Native,
    entry: &CatalogEntry,
    seed: &SeedTable,
) -> Result<(), ControlError> {
    let pairs = [
        (entry.base_schema.as_str(), entry.base_table.as_str(), false),
        (
            entry.delta_schema.as_str(),
            entry.delta_table.as_str(),
            true,
        ),
    ];
    for (schema, table, is_delta) in pairs {
        let observed_columns = columns(native, schema, table).await?;
        let expected = expected_columns(native.engine(), seed, is_delta);
        if observed_columns != expected {
            // Name the first divergence so bootstrap failures are actionable.
            let detail = expected
                .iter()
                .enumerate()
                .find_map(|(index, expected)| match observed_columns.get(index) {
                    Some(observed) if observed != expected => {
                        Some(format!("{observed:?} != {expected:?}"))
                    }
                    None => Some(format!("missing {expected:?}")),
                    _ => None,
                })
                .or_else(|| {
                    observed_columns
                        .get(expected.len())
                        .map(|observed| format!("unexpected {observed:?}"))
                })
                .unwrap_or_else(|| "column list mismatch".to_owned());
            tracing::error!(component = "bootstrap", table = %entry.base_table, is_delta,
                detail = %detail, "native column shape differs from the seed catalog");
            return Err(ControlError::Seed(
                "native column shape differs from the seed catalog",
            ));
        }
        let mut expected_key = ordered_key(seed);
        if is_delta {
            expected_key.insert(0, "_fg_branch");
        }
        if primary_key(native, schema, table).await? != expected_key {
            return Err(ControlError::Seed(
                "native primary key differs from the seed catalog",
            ));
        }
    }
    Ok(())
}

pub(crate) async fn snapshot(
    native: &mut Native,
    relation: &str,
    seed: &SeedTable,
    expected: &[Vec<Value>],
) -> Result<(), ControlError> {
    let engine = native.engine();
    let projections = seed
        .columns
        .iter()
        .map(|column| {
            let name = engine.quote(column.name);
            match engine {
                Engine::MySql | Engine::TiDB if column.type_name.starts_with("varbinary(") => {
                    format!("LOWER(HEX({name}))")
                }
                Engine::MySql | Engine::TiDB => format!("CAST({name} AS CHAR)"),
                Engine::Postgres if column.type_name == "bytea" => {
                    format!("pg_catalog.encode({name}, 'hex')")
                }
                Engine::Postgres => format!("CAST({name} AS text)"),
                // Snapshot comparison for MongoDB lives in crate::mongo.
                Engine::MongoDb => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    let order = ordered_key(seed)
        .into_iter()
        .map(|name| engine.quote(name))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!("SELECT {projections} FROM {relation} ORDER BY {order}");
    let observed: Vec<Vec<Option<String>>> = match native {
        Native::MySql(connection) | Native::TiDB(connection) => sqlx::query(&sql)
            .fetch_all(connection)
            .await?
            .iter()
            .map(|row| {
                (0..row.len())
                    .map(|position| row.try_get_unchecked(position))
                    .collect()
            })
            .collect::<Result<_, _>>()?,
        Native::Postgres(connection) => sqlx::query(&sql)
            .fetch_all(connection)
            .await?
            .iter()
            .map(|row| {
                (0..row.len())
                    .map(|position| row.try_get(position))
                    .collect()
            })
            .collect::<Result<_, _>>()?,
        // Snapshot comparison for MongoDB runs in crate::mongo::build.
        Native::Mongo(_) => {
            return Err(ControlError::Seed(
                "native rows differ from the repository snapshot",
            ));
        }
    };
    if observed.len() != expected.len()
        || !observed.iter().zip(expected).all(|(row, values)| {
            row.len() == values.len()
                && row
                    .iter()
                    .zip(values)
                    .all(|(value, expected)| value == &expected.canonical())
        })
    {
        return Err(ControlError::Seed(
            "native rows differ from the repository snapshot",
        ));
    }
    Ok(())
}

pub(crate) async fn branch_table(
    native: &mut Native,
    schema: &str,
    table: &str,
    seed: &SeedTable,
) -> Result<(), ControlError> {
    let engine = native.engine();
    let marker_type = match engine {
        Engine::MySql | Engine::TiDB => "tinyint(1)",
        Engine::Postgres => "boolean",
        // MongoDB copies use command-based verification instead of SQL columns.
        Engine::MongoDb => {
            return Err(ControlError::Provision(
                "MongoDB branch verification does not use SQL table metadata",
            ));
        }
    };
    let mut expected = expected_columns(engine, seed, false);
    expected.push((
        "_fg_generated".to_owned(),
        marker_type.to_owned(),
        false,
        None,
    ));
    if columns(native, schema, table).await? != expected
        || primary_key(native, schema, table).await? != ordered_key(seed)
    {
        return Err(ControlError::Provision(
            "native branch table differs from the seed catalog",
        ));
    }
    Ok(())
}

type Column = (String, String, bool, Option<String>);

fn expected_columns(engine: Engine, seed: &SeedTable, is_delta: bool) -> Vec<Column> {
    let mut columns: Vec<Column> = seed
        .columns
        .iter()
        .map(|column| {
            (
                column.name.to_owned(),
                column.type_name.to_owned(),
                column.primary_key_ordinal.is_none() && (is_delta || column.nullable),
                column.collation.map(str::to_owned),
            )
        })
        .collect();
    if is_delta {
        let (operation_type, collation) = match engine {
            Engine::MySql | Engine::TiDB => ("char(1)", MYSQL_COLLATION),
            Engine::Postgres => ("character(1)", POSTGRES_COLLATION),
            Engine::MongoDb => ("char(1)", ""),
        };
        columns.extend([
            ("_fg_branch".to_owned(), "bigint".to_owned(), false, None),
            (
                "_fg_op".to_owned(),
                operation_type.to_owned(),
                false,
                Some(collation.to_owned()),
            ),
        ]);
    }
    columns
}

async fn columns(
    native: &mut Native,
    schema: &str,
    table: &str,
) -> Result<Vec<Column>, ControlError> {
    match native {
        // MongoDB collections carry no registered SQL columns; these
        // SQL introspection helpers only serve the SQL build path.
        Native::Mongo(_) => Err(ControlError::Seed(
            "MongoDB collections carry no registered columns",
        )),
        Native::MySql(connection) | Native::TiDB(connection) => {
            let rows: Vec<(String, String, String, Option<String>)> = sqlx::query_as(
                "SELECT CONVERT(column_name USING utf8mb4), CONVERT(column_type USING utf8mb4),
                        CONVERT(is_nullable USING utf8mb4), CONVERT(collation_name USING utf8mb4)
                 FROM information_schema.columns
                 WHERE table_schema = ? AND table_name = ? ORDER BY ordinal_position",
            )
            .bind(schema)
            .bind(table)
            .fetch_all(connection)
            .await?;
            Ok(rows
                .into_iter()
                .map(|(name, data_type, nullable, collation)| {
                    (name, data_type, nullable == "YES", collation)
                })
                .collect())
        }
        Native::Postgres(connection) => {
            let rows = sqlx::query_as(
                "SELECT a.attname::text, pg_catalog.format_type(a.atttypid, a.atttypmod),
                        NOT a.attnotnull, coll.collname::text
                 FROM pg_catalog.pg_attribute a
                 JOIN pg_catalog.pg_class t ON t.oid = a.attrelid
                 JOIN pg_catalog.pg_namespace n ON n.oid = t.relnamespace
                 LEFT JOIN pg_catalog.pg_collation coll ON coll.oid = a.attcollation
                 WHERE n.nspname = $1 AND t.relname = $2 AND a.attnum > 0 AND NOT a.attisdropped
                 ORDER BY a.attnum",
            )
            .bind(schema)
            .bind(table)
            .fetch_all(connection)
            .await?;
            Ok(rows)
        }
    }
}

async fn primary_key(
    native: &mut Native,
    schema: &str,
    table: &str,
) -> Result<Vec<String>, ControlError> {
    let rows =
        match native {
            Native::Mongo(_) => {
                return Err(ControlError::Seed(
                    "MongoDB collections carry no registered columns",
                ));
            }
            Native::MySql(connection) | Native::TiDB(connection) => sqlx::query_scalar(
                "SELECT CONVERT(column_name USING utf8mb4) FROM information_schema.key_column_usage
                 WHERE table_schema = ? AND table_name = ? AND constraint_name = 'PRIMARY'
                 ORDER BY ordinal_position",
            )
            .bind(schema)
            .bind(table)
            .fetch_all(connection)
            .await?,
            Native::Postgres(connection) => {
                sqlx::query_scalar(
                    "SELECT a.attname::text FROM pg_catalog.pg_constraint c
                 JOIN pg_catalog.pg_class t ON t.oid = c.conrelid
                 JOIN pg_catalog.pg_namespace n ON n.oid = t.relnamespace
                 CROSS JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, position)
                 JOIN pg_catalog.pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum
                 WHERE c.contype = 'p' AND n.nspname = $1 AND t.relname = $2
                 ORDER BY k.position",
                )
                .bind(schema)
                .bind(table)
                .fetch_all(connection)
                .await?
            }
        };
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use std::{env, net::IpAddr, str::FromStr, time::SystemTime};

    use sqlx::{ConnectOptions, Connection, mysql::MySqlConnectOptions, mysql::MySqlSslMode};

    use super::*;

    #[tokio::test]
    #[ignore = "requires a disposable loopback MySQL/TiDB server and FG_GATE_SEED_NATIVE_DSN"]
    async fn namespace_emptiness_uses_exact_schema_and_literal_prefix() -> Result<(), ControlError>
    {
        let engine = env::var("FG_GATE_SEED_NATIVE_ENGINE")
            .map_err(|_| ControlError::Config("FG_GATE_SEED_NATIVE_ENGINE"))?;
        if !matches!(engine.as_str(), "mysql" | "tidb") {
            return Err(ControlError::Config(
                "namespace test requires MySQL or TiDB",
            ));
        }
        let dsn = env::var("FG_GATE_SEED_NATIVE_DSN")
            .map_err(|_| ControlError::Config("FG_GATE_SEED_NATIVE_DSN"))?;
        let options = MySqlConnectOptions::from_str(&dsn)?;
        if !options.get_host().eq_ignore_ascii_case("localhost")
            && !options
                .get_host()
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
        {
            return Err(ControlError::Config(
                "namespace test requires a loopback fixture",
            ));
        }
        // These credentials reach only the explicitly disposable loopback fixture.
        let options = options
            .ssl_mode(MySqlSslMode::Disabled)
            .disable_statement_logging();
        let mut connection = MySqlConnection::connect_with(&options).await?;
        let suffix = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| ControlError::Config("namespace test clock"))?
            .as_nanos();
        let schema = format!("fg_ns_{}_{suffix:x}", std::process::id());
        let unrelated = format!("{schema}_other");
        let result = async {
            execute(&mut connection, &format!("CREATE DATABASE `{schema}`")).await?;
            execute(&mut connection, &format!("CREATE DATABASE `{unrelated}`")).await?;
            execute(&mut connection, &format!("CREATE TABLE `{unrelated}`.`b_7_orders` (id INT)")).await?;
            expect(&mut connection, &schema, None, Expectation { empty: true, case: "empty_exact_namespace" }).await?;
            expect(&mut connection, &schema, Some("b_7_"), Expectation { empty: true, case: "unrelated_namespace_ignored" }).await?;

            execute(&mut connection, &format!("CREATE TABLE `{schema}`.`bX7_orders` (id INT)")).await?;
            expect(&mut connection, &schema, None, Expectation { empty: false, case: "whole_namespace_table" }).await?;
            expect(&mut connection, &schema, Some("b_7_"), Expectation { empty: true, case: "underscore_is_literal" }).await?;

            execute(&mut connection, &format!("CREATE TABLE `{schema}`.`b_7_orders` (id INT)")).await?;
            expect(&mut connection, &schema, Some("b_7_"), Expectation { empty: false, case: "matching_table" }).await?;
            expect(&mut connection, &schema, Some("b_8_"), Expectation { empty: true, case: "other_prefix_ignored" }).await?;
            execute(&mut connection, &format!("DROP TABLE `{schema}`.`b_7_orders`")).await?;
            expect(&mut connection, &schema, Some("b_7_"), Expectation { empty: true, case: "matching_table_removed" }).await?;

            execute(&mut connection, &format!("CREATE VIEW `{schema}`.`b_7_view` AS SELECT 1 AS id")).await?;
            expect(&mut connection, &schema, Some("b_7_"), Expectation { empty: false, case: "matching_view" }).await?;
            execute(&mut connection, &format!("DROP VIEW `{schema}`.`b_7_view`")).await?;

            if engine == "mysql" {
                execute(&mut connection, &format!("CREATE PROCEDURE `{schema}`.`b_7_routine`() SELECT 1")).await?;
                expect(&mut connection, &schema, Some("b_7_"), Expectation { empty: false, case: "matching_routine" }).await?;
                execute(&mut connection, &format!("DROP PROCEDURE `{schema}`.`b_7_routine`")).await?;
                execute(&mut connection, &format!("CREATE EVENT `{schema}`.`b_7_event` ON SCHEDULE EVERY 1 DAY DISABLE DO SELECT 1")).await?;
                expect(&mut connection, &schema, Some("b_7_"), Expectation { empty: false, case: "matching_disabled_event" }).await?;
                execute(&mut connection, &format!("DROP EVENT `{schema}`.`b_7_event`")).await?;
            }
            expect(&mut connection, &schema, Some("b_7_"), Expectation { empty: true, case: "only_nonmatching_object_remains" }).await?;
            execute(&mut connection, &format!("DROP TABLE `{schema}`.`bX7_orders`")).await?;
            expect(&mut connection, &schema, None, Expectation { empty: true, case: "all_local_objects_removed" }).await
        }.await;
        let mut cleanup_error = None;
        for owned in [&schema, &unrelated] {
            if let Err(error) = execute(
                &mut connection,
                &format!("DROP DATABASE IF EXISTS `{owned}`"),
            )
            .await
            {
                cleanup_error.get_or_insert(error);
            }
        }
        println!("namespace_test_cleanup_success={}", cleanup_error.is_none());
        result?;
        match cleanup_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    async fn execute(
        connection: &mut MySqlConnection,
        statement: &str,
    ) -> Result<(), ControlError> {
        sqlx::raw_sql(statement).execute(connection).await?;
        Ok(())
    }

    struct Expectation {
        empty: bool,
        case: &'static str,
    }

    async fn expect(
        connection: &mut MySqlConnection,
        schema: &str,
        prefix: Option<&str>,
        expectation: Expectation,
    ) -> Result<(), ControlError> {
        let Expectation {
            empty: expected,
            case,
        } = expectation;
        let observed = mysql_namespace_is_empty(connection, schema, prefix).await?;
        println!("namespace_case={case} expected_empty={expected} observed_empty={observed}");
        if observed != expected {
            return Err(ControlError::Seed(
                "native namespace emptiness regression failed",
            ));
        }
        Ok(())
    }
}
