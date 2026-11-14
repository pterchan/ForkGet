use fg_protocol_common::{
    BranchAccess, BranchBinding, BranchClass, BranchLayout, CatalogColumn, CatalogEntry,
    ReadStrategy,
};
use fg_rewrite::{BoundCompiler, CompileError, Dialect, QueryMode, compile_bound_read};

fn binding(engine: &str, id: i64, generation: i64) -> BranchBinding {
    BranchBinding {
        id,
        generation_id: generation,
        engine: engine.into(),
        name: format!("branch-{id}"),
        default_schema: "app".into(),
        class: BranchClass::Dev,
        access: BranchAccess::ReadOnly,
        layout: BranchLayout::SparseDelta,
        read_strategy: ReadStrategy::Merge,
        audit_witness_ready: false,
        snapshot_manifest: None,
        expires_at: i64::MAX,
        write_schema: None,
        replay_origin: None,
        tables: vec![CatalogEntry {
            id: 1,
            baseline_rows: 10,
            generated_key: None,
            logical_schema: "app".into(),
            logical_table: "orders".into(),
            base_schema: format!("fg_g{generation}"),
            base_table: "orders".into(),
            delta_schema: "forkget_delta".into(),
            delta_table: format!("_d_g{generation}_t1"),
            columns: vec![
                CatalogColumn {
                    name: "id".into(),
                    type_name: "bigint".into(),
                    nullable: false,
                    primary_key_ordinal: Some(2),
                },
                CatalogColumn {
                    name: "tenant_id".into(),
                    type_name: "bigint".into(),
                    nullable: false,
                    primary_key_ordinal: Some(1),
                },
            ],
        }],
    }
}

#[test]
fn reused_compilers_keep_generation_branch_and_key_order_isolated() -> Result<(), CompileError> {
    for (engine, dialect) in [
        ("mysql", Dialect::MySql),
        ("postgresql", Dialect::PostgreSql),
    ] {
        let first = binding(engine, 7, 1);
        let second = binding(engine, 8, 2);
        let same_generation = binding(engine, 9, 1);
        let first_compiler = BoundCompiler::new(dialect, &first)?;
        let second_compiler = BoundCompiler::new(dialect, &second)?;
        let same_generation_compiler = BoundCompiler::new(dialect, &same_generation)?;
        for sql in [
            "SELECT id,tenant_id FROM orders WHERE id=1",
            "SELECT tenant_id FROM orders ORDER BY id",
        ] {
            let before = first_compiler.compile_read(QueryMode::Text, sql)?;
            let other = second_compiler.compile_read(QueryMode::Text, sql)?;
            let after = first_compiler.compile_read(QueryMode::Text, sql)?;
            assert_eq!(before, after);
            assert_eq!(
                before,
                compile_bound_read(dialect, QueryMode::Text, sql, &first)?
            );
            assert!(before.sql.contains("fg_g1") && !before.sql.contains("fg_g2"));
            assert!(other.sql.contains("fg_g2") && !other.sql.contains("fg_g1"));
            assert_ne!(
                before.sql,
                same_generation_compiler
                    .compile_read(QueryMode::Text, sql)?
                    .sql
            );
            let quote = if dialect == Dialect::MySql { "`" } else { "\"" };
            assert!(before.sql.contains(&format!("hidden.{quote}tenant_id{quote} = b.{quote}tenant_id{quote} AND hidden.{quote}id{quote} = b.{quote}id{quote}")));
        }
    }
    Ok(())
}

#[test]
fn every_statement_still_checks_syntax_scope_parameters_and_size() -> Result<(), CompileError> {
    let binding = binding("postgresql", 7, 1);
    let compiler = BoundCompiler::new(Dialect::PostgreSql, &binding)?;
    let prepared = compiler.compile_read(
        QueryMode::Prepared,
        "SELECT id FROM orders WHERE tenant_id=$1 AND id=$2",
    )?;
    assert_eq!(prepared.parameter_count, 2);
    for sql in [
        "SELECT id FROM orders; SELECT 1",
        "SELECT secret FROM orders",
        "SELECT id FROM unregistered",
        "SELECT pg_sleep(1) FROM orders",
        "SELECT )",
    ] {
        assert!(
            compiler.compile_read(QueryMode::Text, sql).is_err(),
            "{sql}"
        );
    }
    assert!(
        compiler
            .compile_read(QueryMode::Prepared, "SELECT id FROM orders WHERE id=$16385")
            .is_err()
    );
    let oversized = " ".repeat(1024 * 1024 + 1);
    assert!(matches!(
        compiler.compile_read(QueryMode::Text, &oversized),
        Err(CompileError::Limit { .. })
    ));
    assert_eq!(
        compiler
            .compile_read(QueryMode::Text, "SELECT id FROM orders")?
            .columns
            .len(),
        1
    );
    Ok(())
}

#[test]
fn malformed_immutable_catalog_is_refused_before_session_use() {
    let mut binding = binding("postgresql", 7, 1);
    binding.tables[0].columns[0].primary_key_ordinal = Some(1);
    assert!(matches!(
        BoundCompiler::new(Dialect::PostgreSql, &binding),
        Err(CompileError::Catalog)
    ));
    binding.tables[0].columns[0].primary_key_ordinal = Some(2);
    binding.tables[0].columns[0].nullable = true;
    assert!(matches!(
        BoundCompiler::new(Dialect::PostgreSql, &binding),
        Err(CompileError::Catalog)
    ));
    binding.tables[0].columns[0].nullable = false;
    binding.tables[0].columns[0].type_name.clear();
    assert!(matches!(
        BoundCompiler::new(Dialect::PostgreSql, &binding),
        Err(CompileError::Catalog)
    ));
}

#[test]
fn fixed_base_only_strategy_avoids_delta_and_keeps_column_identity() -> Result<(), CompileError> {
    let mut binding = binding("postgresql", 7, 1);
    binding.read_strategy = ReadStrategy::BaseOnly;
    let compiler = BoundCompiler::new(Dialect::PostgreSql, &binding)?;
    let read = compiler.compile_read(QueryMode::Text, "SELECT tenant_id,id FROM orders")?;
    assert!(!read.sql.contains("forkget_delta"));
    assert_eq!(
        read.columns[0]
            .origin
            .as_ref()
            .map(|origin| origin.logical_column.as_str()),
        Some("tenant_id")
    );
    assert_eq!(
        read.columns[1]
            .origin
            .as_ref()
            .map(|origin| origin.logical_column.as_str()),
        Some("id")
    );
    Ok(())
}
