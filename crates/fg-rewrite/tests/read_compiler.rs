use fg_protocol_common::{BranchBinding, BranchClass, CatalogColumn, CatalogEntry};
use fg_rewrite::{
    BranchId, CatalogTable, CompileError, Dialect, QueryMode, ReadCatalog, TableRef, TableShape,
    compile_bound_read, compile_read,
};
use sqlparser::{
    dialect::{Dialect as ParserDialect, MySqlDialect, PostgreSqlDialect},
    parser::Parser,
    tokenizer::{Token, Tokenizer},
};

const DIALECTS: [Dialect; 2] = [Dialect::MySql, Dialect::PostgreSql];
const KEY: &[&str] = &["tenant_id", "id"];
const TABLES: &[CatalogTable<'_>] = &[
    CatalogTable {
        logical: TableRef {
            schema: "app",
            table: "orders",
        },
        shape: TableShape {
            base: TableRef {
                schema: "fg_g1",
                table: "base_orders",
            },
            delta: TableRef {
                schema: "forkget_delta",
                table: "_d_g1_t1",
            },
            columns: &["tenant_id", "id", "customer_id", "amount", "memo"],
            primary_key: KEY,
        },
    },
    CatalogTable {
        logical: TableRef {
            schema: "app",
            table: "customers",
        },
        shape: TableShape {
            base: TableRef {
                schema: "fg_g1",
                table: "base_customers",
            },
            delta: TableRef {
                schema: "forkget_delta",
                table: "_d_g1_t2",
            },
            columns: &["tenant_id", "id", "label"],
            primary_key: KEY,
        },
    },
    CatalogTable {
        logical: TableRef {
            schema: "archive",
            table: "orders",
        },
        shape: TableShape {
            base: TableRef {
                schema: "fg_g1",
                table: "base_archive_orders",
            },
            delta: TableRef {
                schema: "forkget_delta",
                table: "_d_g1_t3",
            },
            columns: &["tenant_id", "id", "memo"],
            primary_key: KEY,
        },
    },
    CatalogTable {
        logical: TableRef {
            schema: "app",
            table: "Mixed \"Label",
        },
        shape: TableShape {
            base: TableRef {
                schema: "fg_g1",
                table: "base_quoted",
            },
            delta: TableRef {
                schema: "forkget_delta",
                table: "_d_g1_t4",
            },
            columns: &["tenant_id", "id", "Mémo"],
            primary_key: KEY,
        },
    },
];

fn catalog() -> Result<ReadCatalog<'static>, CompileError> {
    Ok(ReadCatalog {
        default_schema: "app",
        branch: BranchId::new(7)?,
        tables: TABLES,
    })
}

#[test]
fn bound_catalog_validates_key_order_and_engine() -> Result<(), CompileError> {
    let mut binding = BranchBinding {
        audit_witness_ready: true,
        class: BranchClass::Dev,
        access: fg_protocol_common::BranchAccess::ReadOnly,
        layout: fg_protocol_common::BranchLayout::SparseDelta,
        read_strategy: fg_protocol_common::ReadStrategy::Merge,
        snapshot_manifest: None,
        id: 7,
        generation_id: 1,
        engine: "postgresql".to_owned(),
        name: "demo".to_owned(),
        default_schema: "app".to_owned(),
        expires_at: i64::MAX,
        write_schema: None,
        replay_origin: None,
        tables: vec![CatalogEntry {
            baseline_rows: 10,
            id: 1,
            generated_key: None,
            logical_schema: "app".to_owned(),
            logical_table: "orders".to_owned(),
            base_schema: "fg_g1".to_owned(),
            base_table: "base_orders".to_owned(),
            delta_schema: "forkget_delta".to_owned(),
            delta_table: "_d_g1_t1".to_owned(),
            columns: vec![
                CatalogColumn {
                    name: "id".to_owned(),
                    type_name: "bigint".to_owned(),
                    nullable: false,
                    primary_key_ordinal: Some(2),
                },
                CatalogColumn {
                    name: "tenant_id".to_owned(),
                    type_name: "bigint".to_owned(),
                    nullable: false,
                    primary_key_ordinal: Some(1),
                },
            ],
        }],
    };
    let sql = "SELECT * FROM orders";
    let compiled = compile_bound_read(Dialect::PostgreSql, QueryMode::Text, sql, &binding)?;
    assert_eq!(compiled.columns[0].name.as_deref(), Some("id"));
    assert_eq!(compiled.columns[1].name.as_deref(), Some("tenant_id"));
    assert!(
        compiled
            .sql
            .contains("hidden.\"tenant_id\" = b.\"tenant_id\" AND hidden.\"id\" = b.\"id\"")
    );
    assert_eq!(
        compile_bound_read(Dialect::MySql, QueryMode::Text, sql, &binding),
        Err(CompileError::Catalog)
    );
    binding.tables[0].columns[0].nullable = true;
    assert_eq!(
        compile_bound_read(Dialect::PostgreSql, QueryMode::Text, sql, &binding),
        Err(CompileError::Catalog)
    );
    binding.tables[0].columns[0].nullable = false;
    binding.tables[0].columns[0].primary_key_ordinal = Some(1);
    assert_eq!(
        compile_bound_read(Dialect::PostgreSql, QueryMode::Text, sql, &binding),
        Err(CompileError::Catalog)
    );
    Ok(())
}

fn parser_dialect(dialect: Dialect) -> &'static dyn ParserDialect {
    match dialect {
        Dialect::MySql => &MySqlDialect {},
        Dialect::PostgreSql => &PostgreSqlDialect {},
    }
}

#[test]
fn source_literals_and_prepared_parameter_order_survive_lowering() -> Result<(), CompileError> {
    let catalog = catalog()?;
    let mysql = r"SELECT ?, memo FROM app.orders WHERE memo = 'a\\b\'c' AND id = ? LIMIT ?";
    let compiled = compile_read(Dialect::MySql, QueryMode::Prepared, mysql, &catalog)?;
    assert_eq!(compiled.parameter_count, 3);
    assert!(compiled.postgres_parameters.is_empty());
    assert!(
        compiled
            .sql
            .ends_with(r"WHERE memo = 'a\\b\'c' AND id = ? LIMIT ?")
    );
    assert!(compiled.sql.contains("`_fg_branch` = 7"));
    assert!(
        compiled
            .sql
            .contains("hidden.`tenant_id` = b.`tenant_id` AND hidden.`id` = b.`id`")
    );
    let postgres =
        "SELECT $2 AS n, memo FROM app.orders WHERE memo = $tag$α;$1$tag$ AND id = $1 OR id = $2";
    let compiled = compile_read(Dialect::PostgreSql, QueryMode::Prepared, postgres, &catalog)?;
    assert_eq!(compiled.parameter_count, 2);
    assert_eq!(compiled.postgres_parameters, [2, 1, 2]);
    assert!(
        compiled
            .sql
            .ends_with("WHERE memo = $tag$α;$1$tag$ AND id = $1 OR id = $2")
    );
    assert_eq!(compiled.columns[0].name.as_deref(), Some("n"));
    assert_eq!(
        compiled.columns[1]
            .origin
            .as_ref()
            .map(|column| column.logical_column.as_str()),
        Some("memo")
    );
    Ok(())
}

#[test]
fn prepared_count_matches_the_bind_limit() -> Result<(), CompileError> {
    let catalog = catalog()?;
    let mysql = |parameters: &[&str]| format!("SELECT {}", parameters.join(", "));
    for (dialect, accepted, refused) in [
        (Dialect::MySql, mysql(&["?"; 16_384]), mysql(&["?"; 16_385])),
        (
            Dialect::PostgreSql,
            "SELECT $16384".to_owned(),
            "SELECT $16385".to_owned(),
        ),
    ] {
        assert_eq!(
            compile_read(dialect, QueryMode::Prepared, &accepted, &catalog)?.parameter_count,
            16_384
        );
        assert_eq!(
            compile_read(dialect, QueryMode::Prepared, &refused, &catalog),
            Err(CompileError::Limit {
                kind: fg_protocol_common::SqlLimit::BindParameters,
                actual: 16_385,
                limit: 16_384
            })
        );
    }
    Ok(())
}

#[test]
fn postgres_fetch_admits_native_integer_and_bind_counts() -> Result<(), CompileError> {
    let catalog = catalog()?;
    let first = "SELECT id FROM orders ORDER BY id FETCH FIRST 2 ROWS ONLY";
    let dialect = Dialect::PostgreSql;
    let compiled = compile_read(dialect, QueryMode::Text, first, &catalog)?;
    assert!(compiled.sql.ends_with("FETCH FIRST 2 ROWS ONLY"));
    let next = "SELECT id FROM orders ORDER BY id OFFSET $1 ROWS FETCH NEXT $2 ROWS ONLY";
    let compiled = compile_read(dialect, QueryMode::Prepared, next, &catalog)?;
    assert_eq!(compiled.postgres_parameters, [1, 2]);
    assert!(
        compiled
            .sql
            .ends_with("OFFSET $1 ROWS FETCH NEXT $2 ROWS ONLY")
    );
    assert!(compile_read(Dialect::MySql, QueryMode::Text, first, &catalog).is_err());
    for sql in [
        "SELECT id FROM orders ORDER BY id FETCH FIRST 2 PERCENT ROWS ONLY",
        "SELECT id FROM orders ORDER BY id FETCH FIRST 2 ROWS WITH TIES",
        "SELECT id FROM orders ORDER BY id FETCH FIRST (1 + 1) ROWS ONLY",
        "SELECT id FROM orders ORDER BY id FETCH FIRST 2 ROWS",
        "SELECT id FROM orders ORDER BY id FETCH 2 ROWS ONLY",
    ] {
        assert_eq!(
            compile_read(dialect, QueryMode::Text, sql, &catalog),
            Err(CompileError::Unsupported)
        );
    }
    Ok(())
}

#[test]
fn scope_cases_preserve_logical_binding_and_relation_multiplicity() -> Result<(), CompileError> {
    let catalog = catalog()?;
    let cases = [
        ("SELECT id FROM orders", 1),
        ("SELECT orders.id FROM orders", 1),
        ("SELECT app.orders.id FROM app.orders", 1),
        ("SELECT app.orders.* FROM app.orders", 1),
        ("SELECT o.* FROM app.orders AS o", 1),
        ("SELECT o.id AS order_id FROM orders o", 1),
        ("SELECT * FROM orders WHERE customer_id IS NOT NULL", 1),
        (
            "SELECT o.id, c.label FROM orders o JOIN customers c ON c.id = o.customer_id",
            2,
        ),
        (
            "SELECT o.id, c.label FROM orders o LEFT JOIN customers c ON c.tenant_id = o.tenant_id AND c.id = o.customer_id",
            2,
        ),
        (
            "SELECT o.id, c.id AS customer_id FROM orders o CROSS JOIN customers c",
            2,
        ),
        (
            "SELECT a.id, b.memo FROM orders a JOIN orders b ON a.id = b.id",
            2,
        ),
        (
            "SELECT a.id, b.memo FROM app.orders a JOIN archive.orders b ON a.id = b.id",
            2,
        ),
        (
            "SELECT a.id FROM archive.orders a WHERE EXISTS (SELECT 1 FROM app.orders b WHERE a.id = b.id)",
            2,
        ),
        (
            "SELECT orders.id FROM orders WHERE EXISTS (SELECT 1 FROM customers WHERE customers.id = orders.customer_id)",
            2,
        ),
        (
            "SELECT app.orders.id FROM app.orders WHERE EXISTS (SELECT 1 FROM customers c WHERE c.id = app.orders.customer_id)",
            2,
        ),
        (
            "SELECT id FROM orders o WHERE o.customer_id IN (SELECT c.id FROM customers c)",
            2,
        ),
        (
            "SELECT id FROM orders o WHERE o.customer_id NOT IN (SELECT c.id FROM customers c WHERE c.label IS NOT NULL)",
            2,
        ),
        (
            "SELECT id FROM orders WHERE NOT EXISTS (SELECT 1 FROM customers WHERE label = 'new')",
            2,
        ),
        (
            "SELECT id FROM orders WHERE EXISTS (SELECT 1 FROM customers WHERE EXISTS (SELECT 1 FROM archive.orders a WHERE a.id = customers.id))",
            3,
        ),
        ("SELECT (SELECT MAX(id) FROM orders) AS maximum", 1),
        ("SELECT q.id FROM (SELECT id FROM orders) q", 1),
        (
            "SELECT q.* FROM (SELECT id, amount FROM orders) q WHERE q.amount > 0",
            1,
        ),
        (
            "SELECT q.order_id FROM (SELECT id AS order_id FROM orders) q",
            1,
        ),
        (
            "SELECT q.id FROM (SELECT o.id FROM orders o UNION ALL SELECT c.id FROM customers c) q",
            2,
        ),
        (
            "SELECT id FROM orders UNION SELECT id FROM customers ORDER BY id",
            2,
        ),
        (
            "SELECT id AS k FROM orders UNION ALL SELECT id FROM customers ORDER BY k",
            2,
        ),
        ("WITH q AS (SELECT id FROM orders) SELECT id FROM q", 1),
        (
            "WITH q AS (SELECT id FROM orders) SELECT q.id AS k FROM q",
            1,
        ),
        (
            "WITH q AS (SELECT id FROM orders), r AS (SELECT id FROM q) SELECT id FROM r",
            1,
        ),
        (
            "WITH q AS (SELECT id FROM orders) SELECT q.id FROM q JOIN q AS r ON q.id = r.id",
            1,
        ),
        ("WITH q(k) AS (SELECT id FROM orders) SELECT k FROM q", 1),
        (
            "WITH orders AS (SELECT id FROM customers) SELECT id FROM orders",
            1,
        ),
        (
            "WITH orders AS (SELECT id FROM customers) SELECT app.orders.id FROM app.orders",
            2,
        ),
        (
            "WITH orders AS (SELECT id FROM customers) SELECT orders.id FROM orders",
            1,
        ),
        (
            "WITH q AS (SELECT id FROM orders) SELECT d.id FROM (WITH q AS (SELECT id FROM customers) SELECT id FROM q) d",
            2,
        ),
        (
            "WITH q AS (SELECT id FROM customers) SELECT id FROM orders WHERE id IN (SELECT id FROM q)",
            2,
        ),
        (
            "WITH old_orders AS (SELECT id FROM orders), orders AS (SELECT id FROM customers) SELECT id FROM old_orders",
            2,
        ),
        (
            "WITH q AS (SELECT id FROM orders) SELECT q.id FROM q WHERE EXISTS (SELECT 1 FROM customers c WHERE c.id = q.id)",
            2,
        ),
        (
            "WITH q AS (SELECT id FROM customers) SELECT q.id FROM q AS x JOIN orders AS q ON x.id = q.id",
            2,
        ),
        (
            "SELECT customer_id, COUNT(*) AS n FROM orders GROUP BY customer_id HAVING COUNT(*) > 1 ORDER BY n",
            1,
        ),
        (
            "SELECT id, ROW_NUMBER() OVER (PARTITION BY tenant_id ORDER BY id) AS position FROM orders ORDER BY position",
            1,
        ),
        (
            "SELECT DISTINCT id FROM orders ORDER BY id LIMIT 2 OFFSET 1",
            1,
        ),
    ];
    for dialect in DIALECTS {
        for (sql, expected) in cases {
            let compiled =
                compile_read(dialect, QueryMode::Text, sql, &catalog).map_err(|error| {
                    eprintln!("{dialect:?} scope case {sql}: {error:?}");
                    error
                })?;
            assert_eq!(
                compiled.sql.matches("forkget_delta").count(),
                expected * 2,
                "{dialect:?}: {sql}"
            );
        }
    }
    Ok(())
}

#[test]
fn quoted_and_shadowed_column_identity() -> Result<(), CompileError> {
    let catalog = catalog()?;
    for (dialect, sql) in [
        (
            Dialect::MySql,
            "SELECT `Mémo` AS `café` FROM `Mixed \"Label` WHERE id = 2",
        ),
        (
            Dialect::PostgreSql,
            "SELECT \"Mémo\" AS \"café\" FROM \"Mixed \"\"Label\" WHERE id = 2",
        ),
    ] {
        let compiled = compile_read(dialect, QueryMode::Text, sql, &catalog)?;
        assert!(compiled.sql.contains("base_quoted"));
        let column = &compiled.columns[0];
        assert_eq!(column.name.as_deref(), Some("café"));
        assert_eq!(
            column
                .origin
                .as_ref()
                .map(|origin| origin.logical_column.as_str()),
            Some("Mémo")
        );
    }
    assert_eq!(
        compile_read(
            Dialect::MySql,
            QueryMode::Text,
            "SELECT ID FROM ORDERS",
            &catalog
        ),
        Err(CompileError::Object)
    );
    assert!(
        compile_read(
            Dialect::PostgreSql,
            QueryMode::Text,
            "SELECT ID FROM ORDERS",
            &catalog
        )
        .is_ok()
    );
    for dialect in DIALECTS {
        let compiled = compile_read(
            dialect,
            QueryMode::Text,
            "SELECT app.orders.* FROM app.orders",
            &catalog,
        )?;
        assert_eq!(compiled.columns.len(), 5);
        assert_eq!(compiled.columns[0].name.as_deref(), Some("tenant_id"));
        assert_eq!(
            compiled.columns[4]
                .origin
                .as_ref()
                .map(|origin| origin.logical_table.as_str()),
            Some("orders")
        );
        let collision = "SELECT id FROM app.orders WHERE EXISTS (SELECT 1 FROM customers AS orders WHERE app.orders.id = orders.id)";
        assert_eq!(
            compile_read(dialect, QueryMode::Text, collision, &catalog),
            Err(CompileError::Object)
        );
    }
    Ok(())
}

#[test]
fn mysql_metadata_preserves_visible_self_join_and_derived_aliases() -> Result<(), CompileError> {
    let catalog = catalog()?;
    let dialect = Dialect::MySql;
    let sql = "SELECT l.id AS left_id, r.id AS right_id FROM orders l JOIN orders r ON l.id = r.id";
    let compiled = compile_read(dialect, QueryMode::Text, sql, &catalog)?;
    for (column, (label, alias)) in compiled
        .columns
        .iter()
        .zip([("left_id", "l"), ("right_id", "r")])
    {
        let origin = column.origin.as_ref().ok_or(CompileError::Object)?;
        assert_eq!(column.name.as_deref(), Some(label));
        assert_eq!(origin.table_alias.as_deref(), Some(alias));
        assert_eq!(origin.logical_table, "orders");
        assert_eq!(origin.logical_column, "id");
    }
    let sql = "WITH q AS (SELECT o.id, COUNT(*) AS n FROM orders o GROUP BY o.id) SELECT d.* FROM (SELECT q.* FROM q) d";
    let compiled = compile_read(dialect, QueryMode::Text, sql, &catalog)?;
    let origin = compiled.columns[0]
        .origin
        .as_ref()
        .ok_or(CompileError::Object)?;
    assert_eq!(origin.table_alias.as_deref(), Some("d"));
    assert_eq!(origin.logical_table, "orders");
    assert_eq!(origin.logical_column, "id");
    assert!(compiled.columns[1].origin.is_none());
    Ok(())
}

#[test]
fn mysql_line_comment_boundaries_match_admitted_line_endings() -> Result<(), CompileError> {
    let catalog = catalog()?;
    let safe = "SELECT id FROM orders -- ordinary comment\r\n WHERE id = 7";
    assert!(compile_read(Dialect::MySql, QueryMode::Text, safe, &catalog).is_ok());
    for sql in [
        "SELECT id FROM orders -- ordinary comment\rUNION SELECT id FROM fg_g1.orders",
        "SELECT id FROM orders # ordinary comment\rUNION SELECT id FROM fg_g1.orders",
        "SELECT id FROM orders --\u{a0}ambiguous comment",
    ] {
        assert_eq!(
            compile_read(Dialect::MySql, QueryMode::Text, sql, &catalog),
            Err(CompileError::Syntax)
        );
    }
    Ok(())
}

#[test]
fn refusal_cases_use_exact_registry_categories() -> Result<(), CompileError> {
    let catalog = catalog()?;
    let cases = [
        ("", "FG-2001"),
        ("SELECT", "FG-2001"),
        ("SELECT 1; SELECT 2", "FG-2001"),
        ("SELECT 1;;", "FG-2001"),
        ("; SELECT 1", "FG-2001"),
        ("SELECT 'incomplete", "FG-2001"),
        ("SELECT /* never closed", "FG-2001"),
        ("SELECT /*!80000 1 */ 2", "FG-2001"),
        ("SELECT /*+ SET_VAR(sort_buffer_size=1) */ 1", "FG-2001"),
        ("SELECT 1\u{a0}FROM orders", "FG-2001"),
        ("SELECT 1\0", "FG-2001"),
        ("SELECT * FROM fg_g1.base_orders", "FG-2003"),
        ("SELECT * FROM forkget_delta._d_g1_t1", "FG-2003"),
        ("SELECT * FROM information_schema.tables", "FG-2003"),
        ("SELECT * FROM app.absent", "FG-2003"),
        ("SELECT missing FROM orders", "FG-2003"),
        ("SELECT _fg_branch FROM orders", "FG-2003"),
        ("SELECT ctid FROM orders", "FG-2003"),
        ("SELECT orders FROM orders", "FG-2003"),
        ("SELECT orders.id FROM orders AS o", "FG-2003"),
        (
            "SELECT id FROM orders o JOIN customers c ON o.id = c.id",
            "FG-2003",
        ),
        (
            "SELECT a.id FROM orders a JOIN customers a ON a.id = a.id",
            "FG-2003",
        ),
        (
            "WITH q AS (SELECT id FROM r), r AS (SELECT id FROM orders) SELECT id FROM q",
            "FG-2003",
        ),
        (
            "WITH q AS (SELECT id FROM orders), q AS (SELECT id FROM customers) SELECT id FROM q",
            "FG-2003",
        ),
        ("SELECT pg_sleep(1)", "FG-2004"),
        ("SELECT GET_LOCK('demo', 1)", "FG-2004"),
        ("SELECT LOAD_FILE('demo')", "FG-2004"),
        ("SELECT app.count(id) FROM orders", "FG-2004"),
        ("SELECT ROW_NUMBER() FROM orders", "FG-2004"),
        ("SELECT COUNT(*) OVER () FROM orders", "FG-2004"),
        ("SELECT LOWER(memo, memo) FROM orders", "FG-2004"),
        ("SELECT SUM(*) FROM orders", "FG-2004"),
        ("INSERT INTO orders (id) VALUES (1)", "FG-2002"),
        ("UPDATE orders SET amount = 0", "FG-2002"),
        ("DELETE FROM orders", "FG-2002"),
        ("DROP TABLE orders", "FG-2002"),
        ("CREATE TABLE n (id INT)", "FG-2002"),
        ("ALTER TABLE orders ADD COLUMN new_field INT", "FG-2002"),
        ("TRUNCATE TABLE orders", "FG-2002"),
        ("SELECT id FROM orders FOR UPDATE", "FG-2002"),
        ("SELECT id INTO new_table FROM orders", "FG-2002"),
        (
            "WITH RECURSIVE q AS (SELECT id FROM orders) SELECT id FROM q",
            "FG-2002",
        ),
        (
            "SELECT id FROM orders INTERSECT SELECT id FROM customers",
            "FG-2002",
        ),
        ("SELECT id FROM orders, customers", "FG-2002"),
        ("SELECT * FROM orders NATURAL JOIN customers", "FG-2002"),
        ("SELECT * FROM orders JOIN customers USING (id)", "FG-2002"),
    ];
    for dialect in DIALECTS {
        for (sql, expected) in cases {
            assert_eq!(
                compile_read(dialect, QueryMode::Text, sql, &catalog)
                    .err()
                    .map(|error| error.code()),
                Some(expected),
                "{dialect:?}: {sql}"
            );
        }
    }
    Ok(())
}

fn seed_queries(dialect: Dialect, number: u32) -> [String; 10] {
    let (bind1, bind2, quoted, cast) = match dialect {
        Dialect::MySql => ("?", "?", "`orders`", "SIGNED"),
        Dialect::PostgreSql => ("$1", "$2", "\"orders\"", "INTEGER"),
    };
    [
        format!("SELECT tenant_id, id FROM {quoted} WHERE id = {number}"),
        format!(
            "SELECT o.id AS order_id FROM app.orders AS o WHERE o.tenant_id = {number} ORDER BY o.id"
        ),
        format!(
            "SELECT id FROM orders WHERE id BETWEEN {number} AND {} LIMIT 5 OFFSET 1",
            number + 5
        ),
        format!("SELECT DISTINCT customer_id FROM orders WHERE tenant_id = {number}"),
        format!("SELECT id, COALESCE(memo, 'x{number}') AS label FROM orders"),
        format!("SELECT id, CAST(amount AS {cast}) AS n FROM orders WHERE id = {number}"),
        format!("SELECT SUM(amount) AS total FROM orders WHERE tenant_id = {number}"),
        format!("WITH q AS (SELECT id FROM orders WHERE id >= {number}) SELECT id FROM q"),
        format!(
            "SELECT id FROM orders WHERE tenant_id = {bind1} AND id = {bind2} OR id = {number}"
        ),
        format!("SELECT id, ROW_NUMBER() OVER (ORDER BY id) AS rn FROM orders WHERE id < {number}"),
    ]
}

#[test]
fn one_thousand_structural_round_trips_preserve_bind_tokens()
-> Result<(), Box<dyn std::error::Error>> {
    let catalog = catalog()?;
    let mut cases = 0;
    for dialect in DIALECTS {
        let parser_dialect = parser_dialect(dialect);
        for index in 0..50 {
            for sql in seed_queries(dialect, index) {
                let compiled = compile_read(dialect, QueryMode::Prepared, &sql, &catalog)?;
                let before = Parser::parse_sql(parser_dialect, &sql)?;
                let lowered = Parser::parse_sql(parser_dialect, &compiled.sql)?;
                let rendered = lowered
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ");
                let round_trip = Parser::parse_sql(parser_dialect, &rendered)?;
                assert_eq!(lowered, round_trip, "{dialect:?}: {sql}");
                assert_eq!(before.len(), lowered.len());
                assert_eq!(
                    binds(parser_dialect, &sql)?,
                    binds(parser_dialect, &compiled.sql)?
                );
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 1000);
    Ok(())
}

fn binds(
    dialect: &dyn ParserDialect,
    sql: &str,
) -> Result<Vec<String>, sqlparser::tokenizer::TokenizerError> {
    Ok(Tokenizer::new(dialect, sql)
        .tokenize()?
        .into_iter()
        .filter_map(|token| match token {
            Token::Placeholder(value) => Some(value),
            _ => None,
        })
        .collect())
}

#[test]
fn deterministic_parser_mutations_are_bounded() -> Result<(), Box<dyn std::error::Error>> {
    let catalog = catalog()?;
    let inserts = [
        "'", "\"", "(", ")", "/*!", "*/", ";", "$1", "?", "\0", " + ", "UNION",
    ];
    let mut state = 0x7506_2026_u32;
    let mut cases = 0;
    for dialect in DIALECTS {
        for seed in seed_queries(dialect, 7) {
            for _ in 0..20 {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let index = state as usize % (seed.len() + 1);
                let mut input = seed.clone();
                input.insert_str(index, inserts[(state >> 16) as usize % inserts.len()]);
                if let Ok(compiled) = compile_read(dialect, QueryMode::Prepared, &input, &catalog) {
                    assert_eq!(
                        Parser::parse_sql(parser_dialect(dialect), &compiled.sql)?.len(),
                        1
                    );
                    assert_eq!(
                        binds(parser_dialect(dialect), &input)?,
                        binds(parser_dialect(dialect), &compiled.sql)?
                    );
                }
                cases += 1;
            }
        }
        let oversized = format!("SELECT '{}'", "x".repeat(1024 * 1024));
        assert_eq!(
            compile_read(dialect, QueryMode::Text, &oversized, &catalog),
            Err(CompileError::Limit {
                kind: fg_protocol_common::SqlLimit::Bytes,
                actual: oversized.len() as u64,
                limit: 1024 * 1024
            })
        );
        let deep = format!("SELECT {}1{}", "(".repeat(100), ")".repeat(100));
        assert_eq!(
            compile_read(dialect, QueryMode::Text, &deep, &catalog),
            Err(CompileError::Syntax)
        );
        let flat = format!("SELECT {}1", "1 + ".repeat(170));
        assert_eq!(
            compile_read(dialect, QueryMode::Text, &flat, &catalog),
            Err(CompileError::Syntax)
        );
    }
    assert_eq!(cases, 400);
    Ok(())
}
