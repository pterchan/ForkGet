use fg_rewrite::{BranchId, Dialect, RewriteError, TableRef, TableShape, render_visible_relation};

fn orders() -> TableShape<'static> {
    TableShape {
        base: TableRef {
            schema: "fg_g1",
            table: "orders",
        },
        delta: TableRef {
            schema: "forkget_delta",
            table: "_d_g1_t1",
        },
        columns: &["tenant_id", "id", "amount", "note"],
        primary_key: &["tenant_id", "id"],
    }
}

#[test]
fn mysql_overlay_matches_golden_sql() -> Result<(), RewriteError> {
    let sql = render_visible_relation(Dialect::MySql, BranchId::new(7)?, &orders())?;
    assert_eq!(
        sql,
        include_str!("fixtures/mysql.sql")
            .replace("\r\n", "\n")
            .trim()
    );
    Ok(())
}

#[test]
fn postgres_overlay_matches_golden_sql() -> Result<(), RewriteError> {
    let sql = render_visible_relation(Dialect::PostgreSql, BranchId::new(7)?, &orders())?;
    assert_eq!(
        sql,
        include_str!("fixtures/postgres.sql")
            .replace("\r\n", "\n")
            .trim()
    );
    Ok(())
}

#[test]
fn quotes_each_identifier_component_without_splitting_dots() -> Result<(), RewriteError> {
    let mut table = orders();
    table.base.schema = "generation.name";
    table.base.table = "table\"`; DROP TABLE sentinel; --";
    table.columns = &["key\"`", "value.with.dot"];
    table.primary_key = &["key\"`"];
    let branch = BranchId::new(7)?;
    let postgres = render_visible_relation(Dialect::PostgreSql, branch, &table)?;
    let mysql = render_visible_relation(Dialect::MySql, branch, &table)?;
    assert!(postgres.contains("\"generation.name\".\"table\"\"`; DROP TABLE sentinel; --\""));
    assert!(mysql.contains("`generation.name`.`table\"``; DROP TABLE sentinel; --`"));
    assert!(postgres.contains("hidden.\"key\"\"`\" = b.\"key\"\"`\""));
    assert!(mysql.contains("hidden.`key\"``` = b.`key\"```"));
    assert!(postgres.contains("d.\"value.with.dot\""));
    Ok(())
}

#[test]
fn preserves_projection_order_and_uses_the_entire_key() -> Result<(), RewriteError> {
    let mut table = orders();
    table.columns = &["note", "id", "tenant_id", "amount"];
    table.primary_key = &["id", "tenant_id"];
    let sql = render_visible_relation(Dialect::PostgreSql, BranchId::new(7)?, &table)?;
    assert!(sql.starts_with("SELECT d.\"note\", d.\"id\", d.\"tenant_id\", d.\"amount\""));
    assert!(sql.contains("hidden.\"id\" = b.\"id\" AND hidden.\"tenant_id\" = b.\"tenant_id\""));
    Ok(())
}

#[test]
fn scopes_both_arms_to_the_requested_branch_without_client_parameters() -> Result<(), RewriteError>
{
    for dialect in [Dialect::MySql, Dialect::PostgreSql] {
        let sql = render_visible_relation(dialect, BranchId::new(i64::MAX)?, &orders())?;
        assert_eq!(sql.matches(&i64::MAX.to_string()).count(), 2);
        assert!(!sql.contains('?'));
        assert!(!sql.contains('$'));
        assert!(!sql.contains('*'));
    }
    Ok(())
}

#[test]
fn uses_generation_specific_physical_names_from_the_catalog() -> Result<(), RewriteError> {
    let mut table = orders();
    table.base.schema = "fg_g2";
    table.delta.table = "_d_g2_t81";
    let sql = render_visible_relation(Dialect::MySql, BranchId::new(7)?, &table)?;
    assert!(sql.contains("`fg_g2`.`orders`"));
    assert_eq!(sql.matches("`forkget_delta`.`_d_g2_t81`").count(), 2);
    assert!(!sql.contains("_d_g1_t1"));
    Ok(())
}

#[test]
fn rejects_nonpositive_branch_ids() {
    for value in [i64::MIN, -1, 0] {
        assert_eq!(BranchId::new(value), Err(RewriteError::InvalidBranchId));
    }
}

#[test]
fn rejects_missing_primary_keys() -> Result<(), RewriteError> {
    let mut table = orders();
    table.primary_key = &[];
    assert_eq!(
        render_visible_relation(Dialect::MySql, BranchId::new(7)?, &table),
        Err(RewriteError::MissingPrimaryKey)
    );
    Ok(())
}

#[test]
fn rejects_missing_or_duplicate_key_columns() -> Result<(), RewriteError> {
    for primary_key in [&["absent"][..], &["id", "id"][..]] {
        let mut table = orders();
        table.primary_key = primary_key;
        assert_eq!(
            render_visible_relation(Dialect::PostgreSql, BranchId::new(7)?, &table),
            Err(RewriteError::InvalidPrimaryKey)
        );
    }
    Ok(())
}

#[test]
fn rejects_empty_or_duplicate_projections() -> Result<(), RewriteError> {
    for (columns, error) in [
        (&[][..], RewriteError::EmptyProjection),
        (&["id", "id"][..], RewriteError::DuplicateColumn),
    ] {
        let mut table = orders();
        table.columns = columns;
        assert_eq!(
            render_visible_relation(Dialect::MySql, BranchId::new(7)?, &table),
            Err(error)
        );
    }
    Ok(())
}

#[test]
fn rejects_internal_column_collisions() -> Result<(), RewriteError> {
    for column in ["_fg_branch", "_fg_op", "_FG_custom"] {
        let columns = ["tenant_id", "id", column];
        let mut table = orders();
        table.columns = &columns;
        assert_eq!(
            render_visible_relation(Dialect::PostgreSql, BranchId::new(7)?, &table),
            Err(RewriteError::ReservedColumn)
        );
    }
    Ok(())
}

#[test]
fn rejects_empty_or_nul_identifiers() -> Result<(), RewriteError> {
    for identifier in ["", "bad\0name"] {
        let mut table = orders();
        table.delta.schema = identifier;
        assert_eq!(
            render_visible_relation(Dialect::MySql, BranchId::new(7)?, &table),
            Err(RewriteError::InvalidIdentifier)
        );
    }
    Ok(())
}

#[test]
fn exposes_stable_actionable_errors() {
    for (error, expected_code) in [
        (RewriteError::InvalidBranchId, "FG-2003"),
        (RewriteError::MissingPrimaryKey, "FG-2002"),
    ] {
        assert_eq!(error.code(), expected_code);
        assert!(
            error
                .to_string()
                .starts_with(&format!("[FORKGET {expected_code}] "))
        );
    }
}
