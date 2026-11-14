//! Reviewed, immutable seed snapshots.

use std::borrow::Cow;

use fg_meta::{SeedColumn, SeedTable};
use fg_protocol_common::gate_order_count;

use crate::{
    ControlError,
    native::{Engine, Native},
};

pub(crate) const DELTA_SCHEMA: &str = "forkget_delta";
pub(crate) const MYSQL_COLLATION: &str = "utf8mb4_0900_ai_ci";
pub(crate) const POSTGRES_COLLATION: &str = "default";

#[derive(Clone, Copy)]
pub(crate) enum SeedVersion {
    V1,
    V2,
    V3,
    Gate(u32),
}

impl SeedVersion {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "v2" => Some(Self::V2),
            "v3" => Some(Self::V3),
            _ => gate_order_count(value).map(Self::Gate),
        }
    }

    pub(crate) fn name(self) -> Cow<'static, str> {
        match self {
            Self::V1 => Cow::Borrowed("v1"),
            Self::V2 => Cow::Borrowed("v2"),
            Self::V3 => Cow::Borrowed("v3"),
            Self::Gate(rows) => Cow::Owned(format!("gate-v2-{rows}")),
        }
    }

    pub(crate) fn gate_orders(self, table: &str) -> Option<u32> {
        match self {
            Self::Gate(rows) if table == "orders" => Some(rows),
            _ => None,
        }
    }

    pub(crate) const fn has_integrity_fixture(self) -> bool {
        !matches!(self, Self::V1)
    }
}

pub(crate) async fn add_integrity_constraints(
    native: &mut Native,
    schema: &str,
    prefix: Option<&str>,
) -> Result<(), ControlError> {
    let engine = native.engine();
    let physical_name = |name: &str| format!("{}{name}", prefix.unwrap_or_default());
    let parents = engine.relation(schema, &physical_name("parents"));
    let children = engine.relation(schema, &physical_name("children"));
    let code_key = engine.quote(&physical_name("parents_code_key"));
    let parent_key = engine.quote(&physical_name("parents_parent_fkey"));
    let child_key = engine.quote(&physical_name("children_parent_fkey"));
    let timing = match engine {
        Engine::MySql | Engine::TiDB => {
            native.execute("SET SESSION foreign_key_checks = 1").await?;
            ""
        }
        Engine::Postgres => " DEFERRABLE INITIALLY IMMEDIATE",
        // MongoDB has no SQL integrity fixture; this helper
        // is only called on the SQL build path.
        Engine::MongoDb => {
            return Err(ControlError::Seed("MongoDB carries no integrity fixture"));
        }
    };
    native
        .execute(&format!(
            "ALTER TABLE {parents} ADD CONSTRAINT {code_key} UNIQUE (tenant_id, code)"
        ))
        .await?;
    native
        .execute(&format!(
            "ALTER TABLE {parents} ADD CONSTRAINT {parent_key}
             FOREIGN KEY (tenant_id, parent_code) REFERENCES {parents} (tenant_id, code)
             ON UPDATE CASCADE{timing}"
        ))
        .await?;
    native
        .execute(&format!(
            "ALTER TABLE {children} ADD CONSTRAINT {child_key}
             FOREIGN KEY (tenant_id, parent_code) REFERENCES {parents} (tenant_id, code)
             ON DELETE CASCADE ON UPDATE CASCADE{timing}"
        ))
        .await?;
    if engine == Engine::Postgres {
        native
            .execute(&format!(
                "ALTER TABLE {parents} ADD CONSTRAINT parents_label_key UNIQUE (label){timing}"
            ))
            .await?;
    }
    Ok(())
}

const MYSQL_ORDERS: &[SeedColumn] = &[
    key("tenant_id", "int", 1),
    key("id", "bigint", 2),
    column("customer_id", "int", false, None),
    column("amount", "decimal(12,2)", true, None),
    column("note", "varchar(64)", true, Some(MYSQL_COLLATION)),
    column("payload", "varbinary(16)", true, None),
];
const POSTGRES_ORDERS: &[SeedColumn] = &[
    key("tenant_id", "integer", 1),
    key("id", "bigint", 2),
    column("customer_id", "integer", false, None),
    column("amount", "numeric(12,2)", true, None),
    column(
        "note",
        "character varying(64)",
        true,
        Some(POSTGRES_COLLATION),
    ),
    column("payload", "bytea", true, None),
];
const MYSQL_CUSTOMERS: &[SeedColumn] = &[
    key("id", "int", 1),
    column("name", "varchar(64)", false, Some(MYSQL_COLLATION)),
];
const POSTGRES_CUSTOMERS: &[SeedColumn] = &[
    key("id", "integer", 1),
    column(
        "name",
        "character varying(64)",
        false,
        Some(POSTGRES_COLLATION),
    ),
];

const MYSQL_PARENTS: &[SeedColumn] = &[
    key("id", "bigint", 1),
    column("tenant_id", "int", false, None),
    column("code", "varchar(64)", false, Some(MYSQL_COLLATION)),
    column("parent_code", "varchar(64)", true, Some(MYSQL_COLLATION)),
    column("label", "varchar(64)", true, Some(MYSQL_COLLATION)),
];
const POSTGRES_PARENTS: &[SeedColumn] = &[
    key("id", "bigint", 1),
    column("tenant_id", "integer", false, None),
    column(
        "code",
        "character varying(64)",
        false,
        Some(POSTGRES_COLLATION),
    ),
    column(
        "parent_code",
        "character varying(64)",
        true,
        Some(POSTGRES_COLLATION),
    ),
    column(
        "label",
        "character varying(64)",
        true,
        Some(POSTGRES_COLLATION),
    ),
];
const MYSQL_CHILDREN: &[SeedColumn] = &[
    key("id", "bigint", 1),
    column("tenant_id", "int", false, None),
    column("parent_code", "varchar(64)", false, Some(MYSQL_COLLATION)),
    column("label", "varchar(64)", true, Some(MYSQL_COLLATION)),
];
const POSTGRES_CHILDREN: &[SeedColumn] = &[
    key("id", "bigint", 1),
    column("tenant_id", "integer", false, None),
    column(
        "parent_code",
        "character varying(64)",
        false,
        Some(POSTGRES_COLLATION),
    ),
    column(
        "label",
        "character varying(64)",
        true,
        Some(POSTGRES_COLLATION),
    ),
];

const fn key(name: &'static str, type_name: &'static str, ordinal: u16) -> SeedColumn {
    SeedColumn {
        name,
        type_name,
        collation: None,
        nullable: false,
        primary_key_ordinal: Some(ordinal),
    }
}

const fn column(
    name: &'static str,
    type_name: &'static str,
    nullable: bool,
    collation: Option<&'static str>,
) -> SeedColumn {
    SeedColumn {
        name,
        type_name,
        collation,
        nullable,
        primary_key_ordinal: None,
    }
}

pub(crate) fn tables(engine: Engine, version: SeedVersion) -> Vec<SeedTable> {
    let (orders, customers, parents, children) = match engine {
        Engine::MySql | Engine::TiDB => {
            (MYSQL_ORDERS, MYSQL_CUSTOMERS, MYSQL_PARENTS, MYSQL_CHILDREN)
        }
        // MongoDB registers no column manifests; its documents are the
        // fixture source (crate::mongo_documents).
        Engine::MongoDb => (
            &[] as &[SeedColumn],
            &[] as &[SeedColumn],
            &[] as &[SeedColumn],
            &[] as &[SeedColumn],
        ),
        Engine::Postgres => (
            POSTGRES_ORDERS,
            POSTGRES_CUSTOMERS,
            POSTGRES_PARENTS,
            POSTGRES_CHILDREN,
        ),
    };
    let mut tables = vec![
        SeedTable {
            name: "orders",
            columns: orders,
            generated_key: None,
            baseline_rows: baseline_rows(version, "orders"),
        },
        SeedTable {
            name: "customers",
            columns: customers,
            generated_key: None,
            baseline_rows: baseline_rows(version, "customers"),
        },
    ];
    if version.has_integrity_fixture() {
        tables.extend([
            SeedTable {
                name: "parents",
                columns: parents,
                generated_key: Some("id"),
                baseline_rows: baseline_rows(version, "parents"),
            },
            SeedTable {
                name: "children",
                columns: children,
                generated_key: None,
                baseline_rows: baseline_rows(version, "children"),
            },
        ]);
    }
    if engine == Engine::MongoDb {
        // MongoDB has no column registry to validate a generated key
        // against, and branch writes never allocate generated ids (the
        // document `_id` is the natural key).
        for table in &mut tables {
            table.generated_key = None;
        }
    }
    tables
}

fn baseline_rows(version: SeedVersion, table: &str) -> i64 {
    rows(version, table).map_or(0, |rows| rows.len() as i64)
        + i64::from(version.gate_orders(table).unwrap_or_default())
}

#[derive(Clone, Copy)]
pub(crate) enum Value {
    Integer(i64),
    Decimal(&'static str),
    Text(&'static str),
    Hex(&'static str),
    Null,
}

impl Value {
    pub(crate) fn native(self, engine: Engine) -> String {
        match self {
            Self::Integer(value) => value.to_string(),
            Self::Decimal(value) => value.to_owned(),
            Self::Text(value) => format!("'{}'", value.replace('\'', "''")),
            Self::Hex(value) => match engine {
                Engine::MySql | Engine::TiDB => format!("X'{value}'"),
                Engine::Postgres => format!("decode('{value}', 'hex')"),
                // Mongo rendering is unused: documents are BSON fixtures.
                Engine::MongoDb => format!("X'{value}'"),
            },
            Self::Null => "NULL".to_owned(),
        }
    }

    pub(crate) fn canonical(self) -> Option<String> {
        match self {
            Self::Integer(value) => Some(value.to_string()),
            Self::Decimal(value) | Self::Text(value) => Some(value.to_owned()),
            Self::Hex(value) => Some(value.to_ascii_lowercase()),
            Self::Null => None,
        }
    }
}

pub(crate) fn rows(version: SeedVersion, name: &str) -> Option<Vec<Vec<Value>>> {
    use Value::{Decimal, Hex, Integer, Null, Text};
    let (amount, note, root, leaf) = match version {
        SeedVersion::V1 => ("10.00", "base-one", "", ""),
        SeedVersion::V2 | SeedVersion::Gate(_) => ("110.00", "base-v2-one", "v2-root", "v2-leaf"),
        SeedVersion::V3 => ("210.00", "base-v3-one", "v3-root", "v3-leaf"),
    };
    Some(match name {
        "orders" => vec![
            vec![
                Integer(1),
                Integer(1),
                Integer(10),
                Decimal(amount),
                Text(note),
                Null,
            ],
            vec![
                Integer(1),
                Integer(2),
                Integer(20),
                Decimal("20.00"),
                Text("base-two"),
                Hex(""),
            ],
            vec![
                Integer(2),
                Integer(1),
                Integer(10),
                Decimal("30.00"),
                Null,
                Hex("00FF41"),
            ],
            vec![
                Integer(2),
                Integer(2),
                Integer(30),
                Decimal("40.00"),
                Text("base-four"),
                Hex("6F6B"),
            ],
        ],
        "customers" => vec![
            vec![Integer(10), Text("Ada")],
            vec![Integer(20), Text("Bea")],
            vec![Integer(30), Text("Cal")],
        ],
        "parents" if !matches!(version, SeedVersion::V1) => vec![
            vec![Integer(100), Integer(1), Text("root"), Null, Text(root)],
            vec![
                Integer(101),
                Integer(1),
                Text("leaf"),
                Text("root"),
                Text(leaf),
            ],
            vec![Integer(102), Integer(2), Text("root"), Null, Null],
        ],
        "children" if !matches!(version, SeedVersion::V1) => vec![
            vec![Integer(1000), Integer(1), Text("leaf"), Text("seed-child")],
            vec![Integer(1001), Integer(1), Text("root"), Null],
            vec![Integer(1002), Integer(2), Text("root"), Text("other-child")],
        ],
        _ => return None,
    })
}

/// MongoDB seed documents mirroring `rows` field for field.
/// The `_id` scalar is the document natural key: `orders.id` for
/// the order rows and `customers.id` for the customer rows; `tenant_id`
/// stays an ordinary field because MongoDB has no composite natural keys.
pub(crate) fn mongo_documents(version: SeedVersion, name: &str) -> Option<Vec<bson::Document>> {
    let (order_amount, note, root, leaf) = match version {
        SeedVersion::V1 => (10.0, "base-one", "", ""),
        SeedVersion::V2 | SeedVersion::Gate(_) => (110.0, "base-v2-one", "v2-root", "v2-leaf"),
        SeedVersion::V3 => (210.0, "base-v3-one", "v3-root", "v3-leaf"),
    };
    let binary = |bytes: &[u8]| -> bson::Bson {
        bson::Bson::Binary(bson::Binary {
            subtype: bson::spec::BinarySubtype::Generic,
            bytes: bytes.to_vec(),
        })
    };
    let order = |id: i32,
                 tenant_id: i32,
                 customer_id: i32,
                 amount: f64,
                 note: &str,
                 payload: bson::Bson| {
        bson::doc! {
            "_id": id,
            "tenant_id": tenant_id,
            "customer_id": customer_id,
            "amount": amount,
            "note": note,
            "payload": payload,
        }
    };
    Some(match name {
        "orders" => vec![
            order(1, 1, 10, order_amount, note, bson::Bson::Null),
            order(2, 1, 20, 20.0, "base-two", binary(b"")),
            order(3, 2, 10, 30.0, "", binary(&[0x00, 0xFF, 0x41])),
            order(4, 2, 30, 40.0, "base-four", binary(b"ok")),
        ],
        "customers" => vec![
            bson::doc! { "_id": 10, "name": "Ada" },
            bson::doc! { "_id": 20, "name": "Bea" },
            bson::doc! { "_id": 30, "name": "Cal" },
        ],
        "parents" if !matches!(version, SeedVersion::V1) => vec![
            bson::doc! { "_id": 100, "tenant_id": 1, "code": "root", "parent_code": bson::Bson::Null, "label": root },
            bson::doc! { "_id": 101, "tenant_id": 1, "code": "leaf", "parent_code": "root", "label": leaf },
            bson::doc! { "_id": 102, "tenant_id": 2, "code": "root", "parent_code": bson::Bson::Null, "label": bson::Bson::Null },
        ],
        "children" if !matches!(version, SeedVersion::V1) => vec![
            bson::doc! { "_id": 1000, "tenant_id": 1, "parent_code": "leaf", "label": "seed-child" },
            bson::doc! { "_id": 1001, "tenant_id": 1, "parent_code": "root", "label": bson::Bson::Null },
            bson::doc! { "_id": 1002, "tenant_id": 2, "parent_code": "root", "label": "other-child" },
        ],
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mongo_documents_mirror_the_sql_seed_values() -> Result<(), &'static str> {
        let orders = mongo_documents(SeedVersion::V1, "orders").ok_or("orders")?;
        assert_eq!(orders.len(), 4);
        assert_eq!(orders[0].get_str("note"), Ok("base-one"));
        assert!(orders[0].get_str("payload").is_err());
        assert_eq!(orders[3].get_str("note"), Ok("base-four"));
        let v2 = mongo_documents(SeedVersion::V2, "orders").ok_or("v2")?;
        assert_eq!(v2[0].get_f64("amount"), Ok(110.0));
        assert_eq!(v2[0].get_str("note"), Ok("base-v2-one"));
        let customers = mongo_documents(SeedVersion::V1, "customers").ok_or("customers")?;
        assert_eq!(customers.len(), 3);
        // MongoDB registers no column manifests, so every table loses its
        // generated key because branch writes never allocate ids.
        for table in tables(Engine::MongoDb, SeedVersion::V2) {
            assert!(table.generated_key.is_none());
            assert!(table.columns.is_empty());
        }
        assert!(mongo_documents(SeedVersion::V1, "parents").is_none());
        Ok(())
    }
}
