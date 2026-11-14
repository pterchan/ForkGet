use fg_protocol_common::{
    BranchBinding, BranchClass, CatalogColumn, CatalogEntry, GENERATED_ID_START, ReplayOrigin,
    WriteKind, WriteOperation,
};
use fg_rewrite::{
    CompileError, CompiledStatement, CompiledWrite, Dialect, QueryMode, compile_bound_statement,
};

fn catalog(dialect: Dialect) -> BranchBinding {
    let engine = match dialect {
        Dialect::MySql => "mysql",
        Dialect::PostgreSql => "postgresql",
    };
    let table = |id, name: &str, generated_key: Option<&str>, columns| CatalogEntry {
        id,
        logical_schema: "app".to_owned(),
        logical_table: name.to_owned(),
        base_schema: "fg_g1".to_owned(),
        base_table: name.to_owned(),
        delta_schema: "forkget_delta".to_owned(),
        delta_table: format!("_d_g1_t{id}"),
        columns,
        baseline_rows: 10,
        generated_key: generated_key.map(str::to_owned),
    };
    let column = |name: &str, type_name: &str, nullable, primary_key_ordinal| CatalogColumn {
        name: name.to_owned(),
        type_name: type_name.to_owned(),
        nullable,
        primary_key_ordinal,
    };
    BranchBinding {
        audit_witness_ready: true,
        class: BranchClass::Dev,
        access: fg_protocol_common::BranchAccess::ReadWrite,
        layout: fg_protocol_common::BranchLayout::NativeCopy,
        read_strategy: fg_protocol_common::ReadStrategy::Merge,
        snapshot_manifest: None,
        id: 17,
        generation_id: 1,
        engine: engine.to_owned(),
        name: "test-branch".to_owned(),
        default_schema: "app".to_owned(),
        expires_at: i64::MAX,
        write_schema: Some("fg_b17".to_owned()),
        replay_origin: None,
        tables: vec![
            table(
                1,
                "orders",
                None,
                vec![
                    column("tenant_id", "int", false, Some(1)),
                    column("id", "bigint", false, Some(2)),
                    column("payload", "varchar", true, None),
                ],
            ),
            table(
                2,
                "parents",
                Some("id"),
                vec![
                    column("id", "bigint", false, Some(1)),
                    column("code", "varchar", false, None),
                ],
            ),
        ],
    }
}

fn write(dialect: Dialect, mode: QueryMode, sql: &str) -> Result<CompiledWrite, CompileError> {
    match compile_bound_statement(dialect, mode, sql, &catalog(dialect))? {
        CompiledStatement::Write(write) => Ok(write),
        _ => Err(CompileError::Unsupported),
    }
}

#[test]
fn mysql_insert_retains_scalar_spelling_and_ordered_binds() -> Result<(), CompileError> {
    let statement = write(
        Dialect::MySql,
        QueryMode::Prepared,
        "INSERT INTO app.orders (tenant_id, id, payload) VALUES (001, ?, X'01FF'), (- 2, ?, NULL)",
    )?;
    assert_eq!(
        statement.operation,
        WriteOperation {
            table_id: 1,
            kind: WriteKind::Insert
        }
    );
    assert_eq!(statement.parameter_count, 2);
    assert!(statement.generated.is_none());
    assert_eq!(
        statement.sql,
        "INSERT INTO `fg_b17`.`orders` (`tenant_id`, `id`, `payload`) VALUES (001, ?, X'01FF'), (-2, ?, NULL)",
    );
    Ok(())
}

#[test]
fn mysql_generated_text_replaces_only_internal_positions() -> Result<(), CompileError> {
    let statement = write(
        Dialect::MySql,
        QueryMode::Text,
        "INSERT INTO app.parents (code) VALUES ('@_fg_generated_start'), ('literal')",
    )?;
    assert_eq!(
        statement.generated.map(|ids| (ids.table_id, ids.count)),
        Some((2, 2))
    );
    assert_eq!(statement.parameter_count, 0);
    let lowered = statement.text_sql(GENERATED_ID_START);
    assert!(lowered.contains("'@_fg_generated_start'"));
    assert!(lowered.contains("LAST_INSERT_ID(CAST(4611686018427387904 AS SIGNED))"));
    assert!(lowered.contains("CAST(4611686018427387904 AS SIGNED) + 1"));
    Ok(())
}

#[test]
fn postgres_generated_prepare_appends_only_one_bind_and_projects_returning()
-> Result<(), CompileError> {
    let statement = write(
        Dialect::PostgreSql,
        QueryMode::Prepared,
        "INSERT INTO app.parents (code) VALUES ($2), ($1), ($2) RETURNING parents.*, parents.id AS new_id",
    )?;
    assert_eq!(statement.parameter_count, 2);
    assert_eq!(statement.generated.map(|ids| ids.count), Some(3));
    assert!(
        statement
            .sql
            .contains("($2, $3, TRUE), ($1, $3 + 1, TRUE), ($2, $3 + 2, TRUE)")
    );
    let columns = statement
        .columns
        .iter()
        .filter_map(|column| column.name.as_deref())
        .collect::<Vec<_>>();
    assert_eq!(columns, ["id", "code", "new_id"]);
    Ok(())
}

#[test]
fn point_mutations_require_all_key_parts_and_keep_native_parameter_positions()
-> Result<(), CompileError> {
    let statement = write(
        Dialect::PostgreSql,
        QueryMode::Prepared,
        "UPDATE app.orders SET payload=$3 WHERE (orders.id=$2 AND app.orders.tenant_id=$1) RETURNING payload",
    )?;
    assert_eq!(statement.parameter_count, 3);
    assert_eq!(statement.postgres_point_parameters, [2, 1]);
    assert_eq!(
        statement.sql,
        "UPDATE \"fg_b17\".\"orders\" SET \"payload\" = $3 WHERE \"id\" = $2 AND \"tenant_id\" = $1 RETURNING \"payload\"",
    );
    let mysql = write(
        Dialect::MySql,
        QueryMode::Prepared,
        "DELETE FROM parents WHERE id=?",
    )?;
    assert!(mysql.sql.contains("`id` = CAST(? AS DECIMAL(65, 30))"));
    Ok(())
}

#[test]
fn writes_reject_expression_bypasses_and_unregistered_targets() {
    for dialect in [Dialect::MySql, Dialect::PostgreSql] {
        for sql in [
            "INSERT INTO parents VALUES (1, 'x')",
            "INSERT INTO parents (code) SELECT 'x'",
            "INSERT INTO parents (code) VALUES (LOWER('X'))",
            "INSERT INTO parents (code) VALUES (DEFAULT)",
            "INSERT INTO parents (code) VALUES ('one'\n'two')",
            "INSERT INTO parents (code) VALUES (@_fg_generated_start)",
            "INSERT INTO parents (code) VALUES (:1)",
            "INSERT INTO fg_b17.parents (code) VALUES ('x')",
            "INSERT INTO parents (code, _fg_generated) VALUES ('x', TRUE)",
            "INSERT INTO parents (code) VALUES ('x'); DELETE FROM parents WHERE id = 1",
            "UPDATE orders SET payload='x' WHERE id=1",
            "UPDATE orders SET payload='x' WHERE tenant_id=1 AND id=1 AND id=2",
            "UPDATE orders SET id=2 WHERE tenant_id=1 AND id=1",
            "UPDATE orders SET payload='x' WHERE tenant_id=1 AND id=1 OR id=2",
            "UPDATE orders SET payload=payload WHERE tenant_id=1 AND id=1",
            "DELETE FROM parents WHERE id IN (1, 2)",
            "DELETE FROM parents WHERE id = 1 RETURNING _fg_generated",
            "DELETE FROM parents WHERE id = 1 RETURNING orders.id",
            "DELETE FROM parents",
        ] {
            assert!(
                write(dialect, QueryMode::Text, sql).is_err(),
                "{dialect:?} {sql}"
            );
        }
    }
}

#[test]
fn reads_project_only_catalog_columns_and_read_only_branches_refuse_writes()
-> Result<(), CompileError> {
    let dialect = Dialect::PostgreSql;
    let mut binding = catalog(dialect);
    let CompiledStatement::Read(read) = compile_bound_statement(
        dialect,
        QueryMode::Text,
        "SELECT p.* FROM app.parents AS p",
        &binding,
    )?
    else {
        return Err(CompileError::Unsupported);
    };
    assert_eq!(read.columns.len(), 2);
    assert!(
        read.sql
            .contains("SELECT \"id\", \"code\" FROM \"fg_b17\".\"parents\"")
    );
    assert!(!read.sql.contains("_fg_generated"));
    for (sql, lowered) in [
        ("SAVEPOINT Before_Insert", "SAVEPOINT \"before_insert\""),
        (
            "ROLLBACK TO SAVEPOINT Before_Insert",
            "ROLLBACK TO SAVEPOINT \"before_insert\"",
        ),
        (
            "RELEASE SAVEPOINT Before_Insert",
            "RELEASE SAVEPOINT \"before_insert\"",
        ),
    ] {
        assert!(matches!(
            compile_bound_statement(dialect, QueryMode::Text, sql, &binding),
            Ok(CompiledStatement::Savepoint(sql)) if sql == lowered
        ));
    }
    assert!(matches!(
        compile_bound_statement(
            dialect,
            QueryMode::Text,
            "ROLLBACK AND NO CHAIN TO SAVEPOINT Before_Insert",
            &binding,
        ),
        Err(CompileError::Unsupported),
    ));
    binding.write_schema = None;
    binding.access = fg_protocol_common::BranchAccess::ReadOnly;
    binding.layout = fg_protocol_common::BranchLayout::SparseDelta;
    assert!(matches!(
        compile_bound_statement(
            dialect,
            QueryMode::Text,
            "DELETE FROM parents WHERE id = 1",
            &binding
        ),
        Err(CompileError::Policy),
    ));
    Ok(())
}

#[test]
fn staging_rejects_a_valid_mutation_after_logical_validation() {
    for dialect in [Dialect::MySql, Dialect::PostgreSql] {
        let mut binding = catalog(dialect);
        binding.class = BranchClass::Staging;
        binding.write_schema = None;
        binding.access = fg_protocol_common::BranchAccess::ReadOnly;
        binding.layout = fg_protocol_common::BranchLayout::SparseDelta;
        for (sql, expected) in [
            ("DELETE FROM parents WHERE id=1", CompileError::Policy),
            ("DELETE FROM parents", CompileError::Unsupported),
            (
                "DELETE FROM fg_b17.parents WHERE id=1",
                CompileError::Object,
            ),
            ("DELETE FROM unregistered WHERE id=1", CompileError::Object),
        ] {
            assert!(matches!(
                compile_bound_statement(dialect, QueryMode::Text, sql, &binding),
                Err(error) if error == expected
            ));
        }
    }
}

#[test]
fn replay_context_is_a_writable_session_probe_with_no_user_arguments() -> Result<(), CompileError> {
    for dialect in [Dialect::MySql, Dialect::PostgreSql] {
        let mut binding = catalog(dialect);
        binding.replay_origin = Some(ReplayOrigin {
            deployment_id: "00000000-0000-0000-0000-000000000001".to_owned(),
            generation_id: binding.generation_id,
            snapshot: "v2".to_owned(),
        });
        let sql = "SELECT FORKGET_REPLAY_CONTEXT()";
        let CompiledStatement::Read(read) =
            compile_bound_statement(dialect, QueryMode::Text, sql, &binding)?
        else {
            return Err(CompileError::Unsupported);
        };
        assert_eq!(
            read.sql,
            "SELECT '00000000-0000-0000-0000-000000000001:1:17' AS forkget_replay_context"
        );
        assert_eq!(
            read.columns[0].name.as_deref(),
            Some("forkget_replay_context")
        );
        assert!(matches!(
            compile_bound_statement(
                dialect,
                QueryMode::Text,
                "SELECT FORKGET_REPLAY_CONTEXT(17)",
                &binding,
            ),
            Err(CompileError::Function)
        ));
        binding.write_schema = None;
        binding.access = fg_protocol_common::BranchAccess::ReadOnly;
        binding.layout = fg_protocol_common::BranchLayout::SparseDelta;
        assert!(matches!(
            compile_bound_statement(dialect, QueryMode::Text, sql, &binding),
            Err(CompileError::Function)
        ));
    }
    Ok(())
}

#[test]
fn immutable_sql_reads_bypass_delta_without_changing_parameter_or_column_identity()
-> Result<(), CompileError> {
    for dialect in [Dialect::MySql, Dialect::PostgreSql] {
        let mut binding = catalog(dialect);
        binding.write_schema = None;
        binding.access = fg_protocol_common::BranchAccess::ReadOnly;
        binding.layout = fg_protocol_common::BranchLayout::SparseDelta;
        let sql = match dialect {
            Dialect::MySql => {
                "SELECT o.id, o.payload FROM orders o WHERE o.tenant_id = ? AND o.id > ? ORDER BY o.id"
            }
            Dialect::PostgreSql => {
                "SELECT o.id, o.payload FROM orders o WHERE o.tenant_id = $1 AND o.id > $2 ORDER BY o.id"
            }
        };
        let fg_rewrite::CompiledStatement::Read(merged) =
            compile_bound_statement(dialect, QueryMode::Prepared, sql, &binding)?
        else {
            return Err(CompileError::Unsupported);
        };
        assert!(merged.sql.contains("UNION ALL"));
        binding.read_strategy = fg_protocol_common::ReadStrategy::BaseOnly;
        let fg_rewrite::CompiledStatement::Read(base) =
            compile_bound_statement(dialect, QueryMode::Prepared, sql, &binding)?
        else {
            return Err(CompileError::Unsupported);
        };
        assert!(!base.sql.contains("UNION ALL"));
        assert!(!base.sql.contains("forkget_delta"));
        assert!(base.sql.contains("fg_g1"));
        assert_eq!(base.parameter_count, merged.parameter_count);
        assert_eq!(base.postgres_parameters, merged.postgres_parameters);
        assert_eq!(base.columns, merged.columns);
        assert!(matches!(
            compile_bound_statement(
                dialect,
                QueryMode::Text,
                "DELETE FROM parents WHERE id = 1",
                &binding
            ),
            Err(CompileError::Policy)
        ));
    }
    Ok(())
}
