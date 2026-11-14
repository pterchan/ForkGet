#![allow(clippy::unwrap_used, clippy::panic)]

use fg_protocol_common::{
    BranchAccess, BranchBinding, BranchClass, BranchLayout, CatalogColumn, CatalogEntry,
    ReadStrategy, SnapshotManifest,
};
use fg_rewrite::{CompiledStatement, Dialect, QueryMode, compile_bound_statement};

fn binding(dialect: Dialect) -> BranchBinding {
    let mut manifest: SnapshotManifest =
        serde_json::from_str(include_str!("../../../test/application/manifest.json")).unwrap();
    manifest.engine = if dialect == Dialect::MySql {
        "mysql"
    } else {
        "postgresql"
    }
    .into();
    let tables = manifest
        .tables
        .iter()
        .enumerate()
        .map(|(index, table)| CatalogEntry {
            id: index as i64 + 1,
            baseline_rows: table.rows,
            logical_schema: manifest.logical_schema.clone(),
            logical_table: table.name.clone(),
            base_schema: "fg_g90".into(),
            base_table: table.name.clone(),
            delta_schema: "forkget_delta".into(),
            delta_table: format!("_d_g90_t{}", index + 1),
            generated_key: table.generated_key.clone(),
            columns: table
                .columns
                .iter()
                .map(|column| CatalogColumn {
                    name: column.name.clone(),
                    type_name: column.sql_type.native_name(&manifest.engine),
                    nullable: column.nullable,
                    primary_key_ordinal: table
                        .primary_key
                        .iter()
                        .position(|name| name == &column.name)
                        .map(|index| index as u16 + 1),
                })
                .collect(),
        })
        .collect();
    BranchBinding {
        audit_witness_ready: true,
        id: 901,
        generation_id: 90,
        engine: manifest.engine.clone(),
        name: "business-branch".into(),
        default_schema: manifest.logical_schema.clone(),
        class: BranchClass::Dev,
        access: BranchAccess::ReadWrite,
        layout: BranchLayout::NativeCopy,
        read_strategy: ReadStrategy::Merge,
        expires_at: i64::MAX,
        write_schema: Some("fg_b901".into()),
        replay_origin: None,
        tables,
        snapshot_manifest: Some(manifest),
    }
}

#[test]
fn executed_postgres_reflection_profiles_only_return_logical_catalog_data() {
    let binding = binding(Dialect::PostgreSql);
    let profiles: serde_json::Value =
        serde_json::from_str(include_str!("../src/compile/metadata/sqlalchemy_pg.json")).unwrap();
    for profile in profiles.as_array().unwrap() {
        let sql = profile["sql"].as_str().unwrap();
        let CompiledStatement::Read(read) =
            compile_bound_statement(Dialect::PostgreSql, QueryMode::Prepared, sql, &binding)
                .unwrap()
        else {
            panic!("not a catalog read");
        };
        assert!(!read.sql.contains("pg_catalog."));
        assert!(!read.sql.contains("fg_g90"));
        assert!(!read.sql.contains("fg_b901"));
        assert_eq!(
            read.columns.len(),
            profile["columns"].as_array().unwrap().len()
        );
    }
    assert!(
        compile_bound_statement(
            Dialect::PostgreSql,
            QueryMode::Text,
            "SELECT pg_catalog.pg_read_file('/etc/passwd')",
            &binding
        )
        .is_err()
    );
}

#[test]
fn psycopg_initialization_nested_transaction_works_on_readonly_snapshot() {
    let mut binding = binding(Dialect::PostgreSql);
    binding.access = BranchAccess::ReadOnly;
    binding.layout = BranchLayout::SparseDelta;
    binding.read_strategy = ReadStrategy::BaseOnly;
    binding.write_schema = None;
    for sql in [
        "SAVEPOINT \"_pg3_1\"",
        "RELEASE \"_pg3_1\"",
        "ROLLBACK TO \"_pg3_1\"",
    ] {
        assert!(
            matches!(
                compile_bound_statement(Dialect::PostgreSql, QueryMode::Text, sql, &binding),
                Ok(CompiledStatement::Savepoint(_))
            ),
            "{sql}"
        );
    }
}

#[test]
fn refusal_diagnostics_report_only_safe_locations_and_numeric_caps() {
    use fg_protocol_common::{SqlErrorKind, SqlLimit, WireError};
    for dialect in [Dialect::MySql, Dialect::PostgreSql] {
        let binding = binding(dialect);
        let sql = "/* private-value */\n  CREATE TABLE private_name(id bigint)";
        let error = compile_bound_statement(dialect, QueryMode::Text, sql, &binding)
            .err()
            .unwrap();
        let wire = error.wire_at(dialect, sql);
        assert_eq!(
            wire,
            WireError::SqlAt {
                kind: SqlErrorKind::Unsupported,
                line: 2,
                column: 3
            }
        );
        let message = wire.to_string();
        assert!(message.contains("position_scope=statement_start"));
        assert!(!message.contains("private"));
        let rows = std::iter::repeat_n("('private-value', TRUE)", 1025)
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!("INSERT INTO customers(code,active) VALUES {rows}");
        let error = compile_bound_statement(dialect, QueryMode::Text, &sql, &binding)
            .err()
            .unwrap();
        assert_eq!(
            error.wire(),
            WireError::SqlLimit {
                kind: SqlLimit::BulkRows,
                actual: 1025,
                limit: 1024
            }
        );
        assert!(!error.to_string().contains("private-value"));
    }
}

#[test]
fn five_table_business_catalog_preserves_all_generated_keys_and_relationships() {
    let binding = binding(Dialect::PostgreSql);
    let manifest = binding.snapshot_manifest.unwrap();
    let names = manifest
        .tables
        .iter()
        .map(|table| table.name.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        names,
        std::collections::BTreeSet::from(["customers", "products", "orders", "lines", "payments"])
    );
    assert!(
        manifest
            .tables
            .iter()
            .all(|table| table.generated_key.as_deref() == Some("id"))
    );
    assert_eq!(
        manifest
            .tables
            .iter()
            .map(|table| table.foreign_keys.len())
            .sum::<usize>(),
        5
    );
    assert!(
        manifest
            .tables
            .iter()
            .all(|table| table.indexes.iter().any(|index| index.unique))
    );
}

#[test]
fn native_ordered_bulk_and_optimistic_version_predicate_are_admitted() {
    let binding = binding(Dialect::PostgreSql);
    let rows=(0..1000).map(|index| {
        let first=index*7+1;
        format!("(${first}::BIGINT, ${}::BIGINT, ${}::VARCHAR, ${}::INTEGER, ${}, ${}, ${}::TIMESTAMP WITHOUT TIME ZONE, {index})",first+1,first+2,first+3,first+4,first+5,first+6)
    }).collect::<Vec<_>>().join(", ");
    let sql = format!(
        "INSERT INTO lines (order_id, product_id, reference, quantity, amount, active, occurred_at) SELECT p0::BIGINT, p1::BIGINT, p2::VARCHAR, p3::INTEGER, p4::NUMERIC(12,2), p5::BOOLEAN, p6::TIMESTAMP WITHOUT TIME ZONE FROM (VALUES {rows}) AS imp_sen(p0,p1,p2,p3,p4,p5,p6,sen_counter) ORDER BY sen_counter RETURNING lines.id, lines.id AS id__1"
    );
    let CompiledStatement::Write(write) =
        compile_bound_statement(Dialect::PostgreSql, QueryMode::Prepared, &sql, &binding).unwrap()
    else {
        panic!("not a write");
    };
    assert_eq!(write.generated.unwrap().count, 1000);
    assert_eq!(write.parameter_count, 7000);
    assert_eq!(write.columns[1].name.as_deref(), Some("id__1"));
    assert!(write.sql.contains("VALUES"));
    assert!(!write.sql.contains("sen_counter"));
    for sql in [
        "UPDATE orders SET title=$1::VARCHAR, version=$2::INTEGER WHERE orders.id=$3::BIGINT AND orders.version=$4::INTEGER",
        "INSERT INTO orders (customer_id,reference,title,version,booked_on) VALUES ($1::BIGINT,$2::VARCHAR,$3::VARCHAR,$4::INTEGER,$5::DATE) RETURNING orders.id,orders.created_at",
        "UPDATE orders SET version=$1::INTEGER, created_at=$2::TIMESTAMP WITHOUT TIME ZONE WHERE orders.id=$3::BIGINT AND orders.version=$4::INTEGER",
        "INSERT INTO products (sku, unit_price, active) SELECT p0::VARCHAR, p1::NUMERIC(12,2), p2::BOOLEAN FROM (VALUES ($1::VARCHAR,$2,$3,0),($4::VARCHAR,$5,$6,1)) AS imp_sen(p0,p1,p2,sen_counter) ORDER BY sen_counter RETURNING products.id,products.id AS id__1",
        "INSERT INTO payments (order_id,customer_id,reference,amount,settled,paid_on,recorded_at) VALUES ($1::BIGINT,$2::BIGINT,$3::VARCHAR,$4,$5,$6::DATE,$7::TIMESTAMP WITHOUT TIME ZONE) RETURNING payments.id",
    ] {
        assert!(matches!(
            compile_bound_statement(Dialect::PostgreSql, QueryMode::Prepared, sql, &binding),
            Ok(CompiledStatement::Write(_))
        ));
    }
    assert!(
        compile_bound_statement(
            Dialect::PostgreSql,
            QueryMode::Prepared,
            &sql.replace("ORDER BY sen_counter", "ORDER BY p0"),
            &binding
        )
        .is_err()
    );
    assert!(
        compile_bound_statement(
            Dialect::PostgreSql,
            QueryMode::Text,
            "UPDATE orders SET title='all' WHERE version=1",
            &binding
        )
        .is_err()
    );
}

#[test]
fn mysql_reflection_uses_registered_names_and_native_show_shapes() {
    let binding = binding(Dialect::MySql);
    for sql in [
        "SELECT DATABASE()",
        "SHOW FULL TABLES FROM `business-branch`",
        "DESCRIBE `business-branch`.`orders`",
        "SHOW CREATE TABLE `lines`",
    ] {
        assert!(
            matches!(
                compile_bound_statement(Dialect::MySql, QueryMode::Text, sql, &binding),
                Ok(CompiledStatement::Read(_))
            ),
            "{sql}"
        );
    }
    assert!(
        compile_bound_statement(
            Dialect::MySql,
            QueryMode::Text,
            "SHOW CREATE TABLE `fg_b901`.`lines`",
            &binding
        )
        .is_err()
    );
    let correction = "SELECT information_schema.columns.table_schema, information_schema.columns.table_name, information_schema.columns.column_name FROM information_schema.columns WHERE information_schema.columns.table_schema = 'business-branch' AND information_schema.columns.table_name = 'orders' AND lower(information_schema.columns.column_name) IN ('id')";
    assert!(matches!(
        compile_bound_statement(Dialect::MySql, QueryMode::Text, correction, &binding),
        Ok(CompiledStatement::Read(_))
    ));
    let correction = "SELECT information_schema.columns.table_schema, information_schema.columns.table_name, information_schema.columns.column_name FROM information_schema.columns WHERE information_schema.columns.table_schema = 'business-branch' AND (information_schema.columns.table_name = 'orders' AND lower(information_schema.columns.column_name) IN ('id') OR information_schema.columns.table_name = 'products' AND lower(information_schema.columns.column_name) IN ('id'))";
    for engine in ["mysql", "tidb"] {
        let mut binding = self::binding(Dialect::MySql);
        binding.engine = engine.into();
        binding.snapshot_manifest.as_mut().unwrap().engine = engine.into();
        let CompiledStatement::Read(read) =
            compile_bound_statement(Dialect::MySql, QueryMode::Text, correction, &binding).unwrap()
        else {
            panic!("not a finite ORM reflection read");
        };
        assert_eq!(read.columns.len(), 3);
        assert!(!read.sql.contains("information_schema"));
        assert!(!read.sql.contains("fg_g90"));
        assert!(!read.sql.contains("fg_b901"));
        let group = "information_schema.columns.table_name = 'orders' AND lower(information_schema.columns.column_name) IN ('id')";
        let grouped = |count| {
            format!(
                "SELECT information_schema.columns.table_schema, information_schema.columns.table_name, information_schema.columns.column_name FROM information_schema.columns WHERE information_schema.columns.table_schema = 'business-branch' AND ({})",
                std::iter::repeat_n(group, count)
                    .collect::<Vec<_>>()
                    .join(" OR ")
            )
        };
        let compile_grouped = |count| {
            let CompiledStatement::Read(read) =
                compile_bound_statement(Dialect::MySql, QueryMode::Text, &grouped(count), &binding)
                    .unwrap()
            else {
                panic!("not a finite grouped ORM reflection read");
            };
            read
        };
        assert_eq!(
            compile_grouped(64).sql,
            compile_grouped(1).sql,
            "duplicate OR groups must return each logical column once"
        );
        assert!(
            compile_bound_statement(Dialect::MySql, QueryMode::Text, &grouped(65), &binding)
                .is_err()
        );
        for invalid in [
            correction.replace("'products'", "'not_registered'"),
            correction.replace("'business-branch'", "'fg_b901'"),
            correction.replace(
                "lower(information_schema.columns.column_name) IN ('id')",
                "lower(information_schema.columns.column_name) IN ('_fg_generated')",
            ),
            correction.replacen("SELECT ", "SELECT DISTINCT ", 1),
            format!("{correction} ORDER BY information_schema.columns.table_name"),
            correction.replace(" AND (", " OR ("),
        ] {
            assert!(
                compile_bound_statement(Dialect::MySql, QueryMode::Text, &invalid, &binding)
                    .is_err(),
                "{engine}: {invalid}"
            );
        }
    }
    for sql in [
        "SELECT * FROM information_schema.columns",
        "SELECT table_name FROM information_schema.tables",
    ] {
        assert!(compile_bound_statement(Dialect::MySql, QueryMode::Text, sql, &binding).is_err());
    }
}

#[test]
fn json_explain_admits_only_read_plans_and_removes_private_native_identity() {
    for dialect in [Dialect::MySql, Dialect::PostgreSql] {
        let binding = binding(dialect);
        let prefix = if dialect == Dialect::MySql {
            "EXPLAIN FORMAT=JSON"
        } else {
            "EXPLAIN (FORMAT JSON)"
        };
        let sql = format!("{prefix} SELECT id FROM orders WHERE id=1");
        let CompiledStatement::Explain(plan) =
            compile_bound_statement(dialect, QueryMode::Text, &sql, &binding).unwrap()
        else {
            panic!("not an explain");
        };
        let raw = if dialect == Dialect::PostgreSql {
            r#"[{"Plan":{"Node Type":"Seq Scan","Relation Name":"orders","Schema":"fg_b901","Alias":"b901_orders","Plan Rows":10,"Total Cost":42.5,"Filter":"_fg_generated AND title='private-value'","Output":["fg_b901.orders.id"]}}]"#
        } else {
            r#"{"query_block":{"select_id":1,"table":{"table_name":"orders","access_type":"ALL","rows_examined_per_scan":10,"attached_condition":"fg_b901.private-value","cost_info":{"read_cost":"1.00"}}}}"#
        };
        let sanitized = String::from_utf8(plan.mapping.sanitize(raw.as_bytes()).unwrap()).unwrap();
        assert!(sanitized.contains("orders"));
        assert!(sanitized.contains("proxy_execution"));
        assert!(sanitized.contains("materialized_copy"));
        assert!(!sanitized.contains("fg_b901"));
        assert!(!sanitized.contains("_fg_generated"));
        assert!(!sanitized.contains("private-value"));
        assert!(
            plan.mapping
                .sanitize(br#"{"message":"unexpected native error"}"#)
                .is_err()
        );
        for sql in [
            format!("{prefix} DELETE FROM orders WHERE id=1"),
            format!("{prefix} SELECT id FROM fg_g90.orders"),
            "EXPLAIN ANALYZE SELECT id FROM orders".into(),
            "EXPLAIN (FORMAT JSON, ANALYZE FALSE) SELECT id FROM orders".into(),
        ] {
            assert!(
                compile_bound_statement(dialect, QueryMode::Text, &sql, &binding).is_err(),
                "{sql}"
            );
        }
    }
}

#[test]
fn tidb_json_plan_uses_native_format_and_logical_safe_fields() {
    let mut binding = binding(Dialect::MySql);
    binding.engine = "tidb".into();
    binding.snapshot_manifest.as_mut().unwrap().engine = "tidb".into();
    binding.write_schema = Some("fgwrite".into());
    let CompiledStatement::Explain(plan) = compile_bound_statement(
        Dialect::MySql,
        QueryMode::Text,
        "EXPLAIN FORMAT=JSON SELECT id FROM orders WHERE id=1",
        &binding,
    )
    .unwrap() else {
        panic!("not explain");
    };
    assert!(plan.read.sql.starts_with("EXPLAIN FORMAT='tidb_json'"));
    let native=br#"[{"id":"Projection_4","estRows":"10.00","taskType":"root","operatorInfo":"fgwrite.fg_b901_orders.id","subOperators":[{"id":"Point_Get_6","estRows":"1.00","taskType":"root","accessObject":"table:fg_b901_orders, index:physical_index(id)","operatorInfo":"handle:private-value"}]}]"#;
    let safe = String::from_utf8(plan.mapping.sanitize(native).unwrap()).unwrap();
    for retained in [
        "Projection",
        "Point_Get",
        "orders",
        "materialized_copy",
        "Plan Rows",
        "Plans",
        "proxy_execution",
    ] {
        assert!(safe.contains(retained));
    }
    for removed in [
        "fgwrite",
        "fg_b901",
        "physical_index",
        "private-value",
        "operatorInfo",
    ] {
        assert!(!safe.contains(removed));
    }
}
