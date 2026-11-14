use super::*;
use sqlx::PgPool;

#[test]
fn catalog_order_rejects_gaps_and_duplicate_positions() {
    assert!(contiguous([1, 2, 3].into_iter()));
    assert!(!contiguous([0, 1].into_iter()));
    assert!(!contiguous([1, 1].into_iter()));
    assert!(!contiguous([1, 3].into_iter()));
}

fn column(table_id: i64, ordinal: i32, name: &str, key_ordinal: Option<i32>) -> RegisteredColumn {
    RegisteredColumn {
        table_id,
        ordinal,
        name: name.into(),
        data_type: "bigint".into(),
        is_nullable: false,
        key_ordinal,
    }
}

#[test]
fn batched_columns_keep_table_order_and_empty_document_catalogs() -> Result<(), MetaError> {
    let mut grouped = group_columns(vec![
        column(1, 1, "id", Some(2)),
        column(2, 1, "other_id", Some(1)),
        column(1, 2, "tenant", Some(1)),
    ]);
    let first = validate_columns(grouped.remove(&1).unwrap_or_default())?;
    assert_eq!(
        first
            .iter()
            .map(|column| column.name.as_str())
            .collect::<Vec<_>>(),
        ["id", "tenant"]
    );
    assert_eq!(
        first
            .iter()
            .map(|column| column.primary_key_ordinal)
            .collect::<Vec<_>>(),
        [Some(2), Some(1)]
    );
    let second = validate_columns(grouped.remove(&2).unwrap_or_default())?;
    assert_eq!(second[0].name, "other_id");
    assert!(grouped.is_empty());
    assert!(validate_columns(Vec::new())?.is_empty());
    Ok(())
}

#[test]
fn batched_columns_refuse_malformed_column_and_key_ordinals() {
    for rows in [
        vec![column(1, 2, "id", Some(1))],
        vec![column(1, 1, "id", Some(1)), column(1, 1, "tenant", Some(2))],
        vec![column(1, 1, "id", Some(2))],
        vec![column(1, 1, "id", Some(1)), column(1, 2, "tenant", Some(1))],
    ] {
        assert!(matches!(
            validate_columns(rows),
            Err(MetaError::InvalidCatalog)
        ));
    }
}

#[sqlx::test]
#[ignore = "requires an isolated metadata PostgreSQL test database"]
async fn batched_catalog_stays_in_generation_and_refuses_native_gaps(
    pool: PgPool,
) -> Result<(), MetaError> {
    let mut generations = Vec::new();
    for (engine, status, snapshot) in [
        ("postgresql", "active", "v2"),
        ("postgresql", "retiring", "v1"),
        ("mongodb", "retiring", "v2"),
    ] {
        let id: i64 = sqlx::query_scalar("INSERT INTO generation(engine,status,native_claimed,activated_at,snapshot) VALUES($1,$2,TRUE,clock_timestamp(),$3) RETURNING id")
            .bind(engine).bind(status).bind(snapshot).fetch_one(&pool).await?;
        generations.push(id);
    }
    let mut tables = Vec::new();
    for generation in &generations {
        let id: i64 = sqlx::query_scalar("INSERT INTO catalog_table(generation_id,logical_schema,logical_table,base_table,baseline_rows) VALUES($1,'app','orders','orders',10) RETURNING id")
            .bind(generation).fetch_one(&pool).await?;
        tables.push(id);
    }
    for (table, ordinal, name, key) in [
        (tables[0], 1, "id", 2),
        (tables[0], 2, "tenant", 1),
        (tables[1], 1, "foreign_generation_id", 1),
    ] {
        sqlx::query("INSERT INTO catalog_column(table_id,ordinal,name,data_type,is_nullable,key_ordinal) VALUES($1,$2,$3,'bigint',FALSE,$4)")
            .bind(table).bind(ordinal).bind(name).bind(key).execute(&pool).await?;
    }
    let mut connection = pool.acquire().await?;
    let current = load_tables(&mut connection, generations[0]).await?;
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].id, tables[0]);
    assert_eq!(
        current[0]
            .columns
            .iter()
            .map(|column| column.name.as_str())
            .collect::<Vec<_>>(),
        ["id", "tenant"]
    );
    let old = load_tables(&mut connection, generations[1]).await?;
    assert_eq!(old[0].columns[0].name, "foreign_generation_id");
    assert!(
        load_tables(&mut connection, generations[2]).await?[0]
            .columns
            .is_empty()
    );
    sqlx::query("DELETE FROM catalog_column WHERE table_id=$1 AND ordinal=1")
        .bind(tables[0])
        .execute(&mut *connection)
        .await?;
    assert!(matches!(
        load_tables(&mut connection, generations[0]).await,
        Err(MetaError::InvalidCatalog)
    ));
    Ok(())
}
