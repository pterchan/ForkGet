//! Deterministic benchmark data in a registered, inactive generation.

use crate::{
    ControlError,
    native::{Engine, Native},
};

const TENANT: i32 = 7;
const BATCH: u32 = 100_000;
const NOTE_HEX: &str = "F09F9BA0";
const NOTE_CHARACTERS: usize = 64;
const MYSQL_NOTE: &str = "REPEAT(CONVERT(X'F09F9BA0' USING utf8mb4), 64)";
const POSTGRES_NOTE: &str = "repeat(chr(128736), 64)";
const PAYLOAD: &str = "00017F80FF00017F80FF00017F80FF00";

pub(crate) async fn load(
    native: &mut Native,
    relation: &str,
    count: u32,
) -> Result<(), ControlError> {
    let engine = native.engine();
    let (note, payload) = values(engine);
    for first in (1..=count).step_by(BATCH as usize) {
        let last = (first + BATCH - 1).min(count);
        let numbers = numbers(engine, first, last);
        let sql = format!(
            "INSERT INTO {relation} (tenant_id, id, customer_id, amount, note, payload)
             SELECT {TENANT}, ids.id, 10, 50.00, {note}, {payload}
             FROM ({numbers}) AS ids ORDER BY ids.id"
        );
        let affected = match native {
            Native::MySql(connection) | Native::TiDB(connection) => {
                sqlx::query(&sql).execute(connection).await?.rows_affected()
            }
            Native::Postgres(connection) => {
                sqlx::query(&sql).execute(connection).await?.rows_affected()
            }
            Native::Mongo(_) => return Err(unsupported_engine()),
        };
        tracing::info!(
            component = "gate_seed",
            engine = engine.name(),
            first,
            last,
            expected_rows = last - first + 1,
            actual_rows = affected,
            "gate seed batch loaded"
        );
    }
    Ok(())
}

fn values(engine: Engine) -> (&'static str, String) {
    match engine {
        Engine::MySql | Engine::TiDB => (MYSQL_NOTE, format!("X'{PAYLOAD}'")),
        Engine::Postgres => (POSTGRES_NOTE, format!("decode('{PAYLOAD}', 'hex')")),
        // Gate snapshots never reach MongoDB (CLI-boundary rejection).
        Engine::MongoDb => (MYSQL_NOTE, String::new()),
    }
}

fn numbers(engine: Engine, first: u32, last: u32) -> String {
    if engine == Engine::Postgres {
        return format!("SELECT generate_series({first}, {last}) AS id");
    }
    const DIGITS: &str = "(SELECT 0 AS n UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3
          UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6
          UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9)";
    format!(
        "SELECT {first} + a.n + 10*b.n + 100*c.n + 1000*d.n + 10000*e.n AS id
         FROM {DIGITS} a CROSS JOIN {DIGITS} b CROSS JOIN {DIGITS} c
         CROSS JOIN {DIGITS} d CROSS JOIN {DIGITS} e
         WHERE a.n + 10*b.n + 100*c.n + 1000*d.n + 10000*e.n <= {}",
        last - first
    )
}

pub(crate) fn small_orders(relation: &str) -> String {
    format!("(SELECT * FROM {relation} WHERE tenant_id <> {TENANT}) AS small_orders")
}

pub(crate) async fn verify(
    native: &mut Native,
    relation: &str,
    count: u32,
) -> Result<(), ControlError> {
    let engine = native.engine();
    let sql = verification_sql(engine, relation, count)?;
    let observed: Verification = match native {
        Native::MySql(connection) | Native::TiDB(connection) => {
            sqlx::query_as(&sql).fetch_one(connection).await?
        }
        Native::Postgres(connection) => sqlx::query_as(&sql).fetch_one(connection).await?,
        Native::Mongo(_) => return Err(unsupported_engine()),
    };
    if !observed.matches(count) {
        // Capture counts while the failed target still exists, before bootstrap
        // compensation removes it. Never log relation names or row contents.
        tracing::error!(component = "gate_seed", engine = engine.name(), expected_rows = count,
            actual = ?observed, "gate seed validation failed before compensation");
        return Err(ControlError::Seed("native rows differ from the gate seed"));
    }
    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
struct Verification {
    #[sqlx(rename = "row_count")]
    rows: i64,
    invalid_ids: i64,
    invalid_customers: i64,
    invalid_amounts: i64,
    invalid_notes: i64,
    invalid_payloads: i64,
    min_id: Option<i64>,
    max_id: Option<i64>,
    min_note_characters: Option<i64>,
    max_note_characters: Option<i64>,
    min_note_bytes: Option<i64>,
    max_note_bytes: Option<i64>,
}

impl Verification {
    fn matches(&self, count: u32) -> bool {
        self.rows == i64::from(count)
            && self.invalid_ids == 0
            && self.invalid_customers == 0
            && self.invalid_amounts == 0
            && self.invalid_notes == 0
            && self.invalid_payloads == 0
            && self.min_id == Some(1)
            && self.max_id == Some(i64::from(count))
            && self.min_note_characters == Some(NOTE_CHARACTERS as i64)
            && self.max_note_characters == Some(NOTE_CHARACTERS as i64)
            && self.min_note_bytes == Some((NOTE_CHARACTERS * 4) as i64)
            && self.max_note_bytes == Some((NOTE_CHARACTERS * 4) as i64)
    }
}

fn unsupported_engine() -> ControlError {
    ControlError::Seed("gate-order snapshots are not available for MongoDB")
}

fn verification_sql(engine: Engine, relation: &str, count: u32) -> Result<String, ControlError> {
    let note_hex = NOTE_HEX.repeat(NOTE_CHARACTERS);
    let predicates = match engine {
        Engine::MySql | Engine::TiDB => [
            "NOT (customer_id <=> 10)".to_owned(),
            "NOT (amount <=> 50.00)".to_owned(),
            // TiDB 8.5.8 casts VARCHAR(64) to only 64 binary bytes without an
            // explicit length, truncating this valid 256-byte Unicode fixture.
            // HEX is lossless and avoids that inferred CAST length.
            format!("NOT (HEX(note) <=> '{note_hex}')"),
            format!("NOT (payload <=> X'{PAYLOAD}')"),
        ],
        Engine::Postgres => [
            "customer_id IS DISTINCT FROM 10".to_owned(),
            "amount IS DISTINCT FROM 50.00".to_owned(),
            format!(
                "encode(convert_to(note, 'UTF8'), 'hex') IS DISTINCT FROM '{}'",
                note_hex.to_ascii_lowercase()
            ),
            format!("payload IS DISTINCT FROM decode('{PAYLOAD}', 'hex')"),
        ],
        Engine::MongoDb => return Err(unsupported_engine()),
    };
    let mut fields = vec![match engine {
        Engine::MySql | Engine::TiDB => "CAST(COUNT(*) AS SIGNED) AS row_count".to_owned(),
        Engine::Postgres => "COUNT(*) AS row_count".to_owned(),
        Engine::MongoDb => return Err(unsupported_engine()),
    }];
    for (name, predicate) in [
        ("invalid_ids", format!("id NOT BETWEEN 1 AND {count}")),
        ("invalid_customers", predicates[0].clone()),
        ("invalid_amounts", predicates[1].clone()),
        ("invalid_notes", predicates[2].clone()),
        ("invalid_payloads", predicates[3].clone()),
    ] {
        fields.push(match engine {
            Engine::MySql | Engine::TiDB => {
                format!("CAST(COUNT(CASE WHEN {predicate} THEN 1 END) AS SIGNED) AS {name}")
            }
            Engine::Postgres => format!("COUNT(*) FILTER (WHERE {predicate}) AS {name}"),
            Engine::MongoDb => return Err(unsupported_engine()),
        });
    }
    fields.extend(["MIN(id) AS min_id", "MAX(id) AS max_id"].map(str::to_owned));
    let integer = if engine == Engine::Postgres {
        "BIGINT"
    } else {
        "SIGNED"
    };
    for (function, column) in [
        ("CHAR_LENGTH", "note_characters"),
        ("OCTET_LENGTH", "note_bytes"),
    ] {
        fields.push(format!(
            "CAST(MIN({function}(note)) AS {integer}) AS min_{column}"
        ));
        fields.push(format!(
            "CAST(MAX({function}(note)) AS {integer}) AS max_{column}"
        ));
    }
    Ok(format!(
        "SELECT {} FROM {relation} WHERE tenant_id = {TENANT}",
        fields.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use std::{env, str::FromStr};

    use sqlx::{
        Connection,
        mysql::{MySqlConnectOptions, MySqlSslMode},
        postgres::{PgConnectOptions, PgSslMode},
    };

    use super::*;

    async fn execute(native: &mut Native, sql: &str) -> Result<(), ControlError> {
        match native {
            Native::MySql(connection) | Native::TiDB(connection) => {
                sqlx::query(sql).execute(connection).await?;
            }
            Native::Postgres(connection) => {
                sqlx::query(sql).execute(connection).await?;
            }
            Native::Mongo(_) => return Err(unsupported_engine()),
        }
        Ok(())
    }

    async fn connect() -> Result<Native, Box<dyn std::error::Error>> {
        let dsn = env::var("FG_GATE_SEED_NATIVE_DSN")?;
        let native = match env::var("FG_GATE_SEED_NATIVE_ENGINE")?.as_str() {
            "mysql" | "tidb" => {
                let options = MySqlConnectOptions::from_str(&dsn)?.ssl_mode(MySqlSslMode::Disabled);
                let connection = sqlx::MySqlConnection::connect_with(&options).await?;
                if env::var("FG_GATE_SEED_NATIVE_ENGINE")? == "tidb" {
                    Native::TiDB(connection)
                } else {
                    Native::MySql(connection)
                }
            }
            "postgresql" => Native::Postgres(
                sqlx::PgConnection::connect_with(
                    &PgConnectOptions::from_str(&dsn)?.ssl_mode(PgSslMode::Disable),
                )
                .await?,
            ),
            _ => return Err("Unsupported gate seed test engine".into()),
        };
        Ok(native)
    }

    #[tokio::test]
    #[ignore = "Requires a disposable native database; run test/p7/gate_seed_native.py"]
    async fn native_boundaries_and_corruption() -> Result<(), Box<dyn std::error::Error>> {
        let _ = tracing_subscriber::fmt().json().try_init();
        let mut native = connect().await?;
        let engine = native.engine();
        let version: String = match &mut native {
            Native::MySql(connection) | Native::TiDB(connection) => {
                sqlx::query_scalar("SELECT VERSION()")
                    .fetch_one(connection)
                    .await?
            }
            Native::Postgres(connection) => {
                sqlx::query_scalar("SELECT VERSION()")
                    .fetch_one(connection)
                    .await?
            }
            Native::Mongo(_) => return Err("Unsupported gate seed test engine".into()),
        };
        println!(
            "gate_seed_native_version engine={} version={version}",
            engine.name()
        );
        let binary = if engine == Engine::Postgres {
            "BYTEA"
        } else {
            "VARBINARY(16)"
        };
        execute(
            &mut native,
            &format!(
                "CREATE TABLE orders (
            tenant_id INT NOT NULL, id BIGINT NOT NULL, customer_id INT NOT NULL,
            amount DECIMAL(12,2), note VARCHAR(64), payload {binary}, PRIMARY KEY(tenant_id,id))"
            ),
        )
        .await?;
        for count in [1, 25_001, 99_999, 100_000, 100_001] {
            execute(&mut native, "DELETE FROM orders").await?;
            load(&mut native, "orders", count).await?;
            if count == 1 {
                byte_witness(&mut native).await?;
            }
            verify(&mut native, "orders", count).await?;
            println!(
                "gate_seed_boundary engine={} rows={count} passed",
                engine.name()
            );
        }
        corruption_trials(&mut native).await?;
        execute(&mut native, "DROP TABLE orders").await?;
        Ok(())
    }

    async fn byte_witness(native: &mut Native) -> Result<(), Box<dyn std::error::Error>> {
        let (note, payload): (String, Vec<u8>) = match native {
            Native::MySql(connection) | Native::TiDB(connection) => {
                sqlx::query_as("SELECT note,payload FROM orders WHERE tenant_id=7 AND id=1")
                    .fetch_one(&mut *connection)
                    .await?
            }
            Native::Postgres(connection) => {
                sqlx::query_as("SELECT note,payload FROM orders WHERE tenant_id=7 AND id=1")
                    .fetch_one(connection)
                    .await?
            }
            Native::Mongo(_) => return Err("Unsupported gate seed test engine".into()),
        };
        assert_eq!(note, "\u{1f6e0}".repeat(64));
        assert_eq!(
            payload,
            [
                0, 1, 127, 128, 255, 0, 1, 127, 128, 255, 0, 1, 127, 128, 255, 0
            ]
        );
        if let Native::MySql(connection) | Native::TiDB(connection) = native {
            let observation: (i64, i64, i64, i64) = sqlx::query_as(
                "SELECT CAST(OCTET_LENGTH(note) AS SIGNED), CAST(OCTET_LENGTH(CAST(note AS BINARY)) AS SIGNED),
                 CAST(OCTET_LENGTH(CAST(REPEAT(CONVERT(X'F09F9BA0' USING utf8mb4),64) AS BINARY)) AS SIGNED),
                 CAST(CAST(note AS BINARY)<=>CAST(REPEAT(CONVERT(X'F09F9BA0' USING utf8mb4),64) AS BINARY) AS SIGNED)
                 FROM orders WHERE tenant_id=7 AND id=1"
            ).fetch_one(connection).await?;
            println!(
                "gate_seed_legacy_cast actual_bytes={} column_cast_bytes={} constant_cast_bytes={} equality={}",
                observation.0, observation.1, observation.2, observation.3
            );
        }
        Ok(())
    }

    async fn corruption_trials(native: &mut Native) -> Result<(), Box<dyn std::error::Error>> {
        let engine = native.engine();
        let payload = if engine == Engine::Postgres {
            "decode('00017F80FF00017F80FF00017F80FF01','hex')"
        } else {
            "X'00017F80FF00017F80FF00017F80FF01'"
        };
        let other_note = if engine == Engine::Postgres {
            "repeat(chr(128512),64)"
        } else {
            "REPEAT(CONVERT(X'F09F9880' USING utf8mb4),64)"
        };
        let cases = [
            ("missing_row", "DELETE FROM orders".to_owned()),
            ("out_of_range_id", "UPDATE orders SET id=2".to_owned()),
            (
                "wrong_customer",
                "UPDATE orders SET customer_id=11".to_owned(),
            ),
            ("wrong_amount", "UPDATE orders SET amount=50.01".to_owned()),
            ("null_amount", "UPDATE orders SET amount=NULL".to_owned()),
            ("null_note", "UPDATE orders SET note=NULL".to_owned()),
            (
                "wrong_unicode",
                format!("UPDATE orders SET note={other_note}"),
            ),
            ("short_note", "UPDATE orders SET note='short'".to_owned()),
            ("null_payload", "UPDATE orders SET payload=NULL".to_owned()),
            (
                "wrong_payload",
                format!("UPDATE orders SET payload={payload}"),
            ),
            (
                "extra_row",
                "INSERT INTO orders SELECT tenant_id,2,customer_id,amount,note,payload FROM orders"
                    .to_owned(),
            ),
        ];
        for (case, sql) in cases {
            execute(native, "DELETE FROM orders").await?;
            load(native, "orders", 1).await?;
            execute(native, &sql).await?;
            assert!(
                matches!(
                    verify(native, "orders", 1).await,
                    Err(ControlError::Seed(_))
                ),
                "corrupted fixture was accepted: {case}"
            );
            println!(
                "gate_seed_corruption engine={} case={case} refused",
                engine.name()
            );
        }
        Ok(())
    }
}
