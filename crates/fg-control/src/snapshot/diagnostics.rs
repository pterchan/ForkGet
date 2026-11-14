//! Safe restore-shape diagnostics without native names or source expressions.

use fg_protocol_common::{SnapshotManifest, TableManifest};
use serde::Serialize;

#[derive(Serialize)]
struct RestoreDifference {
    format_version: u8,
    codes: Vec<&'static str>,
    expected_table_count: usize,
    observed_table_count: usize,
    tables: Vec<TableDifference>,
}

#[derive(Serialize)]
struct TableDifference {
    expected_ordinal: Option<usize>,
    observed_ordinal: Option<usize>,
    codes: Vec<&'static str>,
    expected_counts: Option<TableCounts>,
    observed_counts: Option<TableCounts>,
    different_entries: Option<ChangedCounts>,
}

#[derive(Serialize)]
struct TableCounts {
    rows: i64,
    columns: usize,
    primary_key_columns: usize,
    indexes: usize,
    unique_indexes: usize,
    foreign_keys: usize,
    checks: usize,
}

#[derive(Serialize)]
struct ChangedCounts {
    columns: usize,
    primary_key_columns: usize,
    indexes: usize,
    unique_indexes: usize,
    foreign_keys: usize,
    checks: usize,
}

pub(super) fn record(expected: &SnapshotManifest, observed: &SnapshotManifest) {
    // The log survives fixture compensation. No caller-owned bundle is changed,
    // and no identifier, default literal or expression enters this typed record.
    match serde_json::to_value(summary(expected, observed)) {
        Ok(diagnostic) => tracing::warn!(
            component = "snapshot",
            diagnostic = %diagnostic,
            "Snapshot restore catalog mismatch"
        ),
        Err(_) => tracing::warn!(
            component = "snapshot",
            "Snapshot restore diagnostic serialization failed"
        ),
    }
}

fn summary(expected: &SnapshotManifest, observed: &SnapshotManifest) -> RestoreDifference {
    let codes = [
        ("engine", expected.engine != observed.engine),
        (
            "logical_schema",
            expected.logical_schema != observed.logical_schema,
        ),
        (
            "table_count",
            expected.tables.len() != observed.tables.len(),
        ),
    ]
    .into_iter()
    .filter_map(|(code, changed)| changed.then_some(code))
    .collect();
    RestoreDifference {
        format_version: 1,
        codes,
        expected_table_count: expected.tables.len(),
        observed_table_count: observed.tables.len(),
        tables: table_differences(expected, observed),
    }
}

fn table_differences(
    expected: &SnapshotManifest,
    observed: &SnapshotManifest,
) -> Vec<TableDifference> {
    let mut tables = Vec::new();
    for (ordinal, table) in expected.tables.iter().enumerate() {
        if let Some((other_ordinal, other)) = observed
            .tables
            .iter()
            .enumerate()
            .find(|(_, other)| other.name == table.name)
        {
            if table != other || ordinal != other_ordinal {
                tables.push(table_difference(ordinal, table, other_ordinal, other));
            }
        } else {
            tables.push(TableDifference {
                expected_ordinal: Some(ordinal),
                observed_ordinal: None,
                codes: vec!["table_missing"],
                expected_counts: Some(counts(table)),
                observed_counts: None,
                different_entries: None,
            });
        }
    }
    for (ordinal, table) in observed.tables.iter().enumerate() {
        if !expected.tables.iter().any(|other| other.name == table.name) {
            tables.push(TableDifference {
                expected_ordinal: None,
                observed_ordinal: Some(ordinal),
                codes: vec!["unexpected_table"],
                expected_counts: None,
                observed_counts: Some(counts(table)),
                different_entries: None,
            });
        }
    }
    tables
}

fn counts(table: &TableManifest) -> TableCounts {
    TableCounts {
        rows: table.rows,
        columns: table.columns.len(),
        primary_key_columns: table.primary_key.len(),
        indexes: table.indexes.len(),
        unique_indexes: table.indexes.iter().filter(|index| index.unique).count(),
        foreign_keys: table.foreign_keys.len(),
        checks: table.checks.len(),
    }
}

fn different_count<T: PartialEq>(expected: &[T], observed: &[T]) -> usize {
    expected
        .iter()
        .zip(observed)
        .filter(|(left, right)| left != right)
        .count()
        + expected.len().abs_diff(observed.len())
}

fn table_difference(
    ordinal: usize,
    expected: &TableManifest,
    other_ordinal: usize,
    observed: &TableManifest,
) -> TableDifference {
    let expected_unique: Vec<_> = expected
        .indexes
        .iter()
        .filter(|index| index.unique)
        .collect();
    let observed_unique: Vec<_> = observed
        .indexes
        .iter()
        .filter(|index| index.unique)
        .collect();
    TableDifference {
        expected_ordinal: Some(ordinal),
        observed_ordinal: Some(other_ordinal),
        codes: table_codes(expected, observed, ordinal != other_ordinal),
        expected_counts: Some(counts(expected)),
        observed_counts: Some(counts(observed)),
        different_entries: Some(ChangedCounts {
            columns: different_count(&expected.columns, &observed.columns),
            primary_key_columns: different_count(&expected.primary_key, &observed.primary_key),
            indexes: different_count(&expected.indexes, &observed.indexes),
            unique_indexes: different_count(&expected_unique, &observed_unique),
            foreign_keys: different_count(&expected.foreign_keys, &observed.foreign_keys),
            checks: different_count(&expected.checks, &observed.checks),
        }),
    }
}

fn table_codes(
    expected: &TableManifest,
    observed: &TableManifest,
    reordered: bool,
) -> Vec<&'static str> {
    [
        ("table_order", reordered),
        ("rows", expected.rows != observed.rows),
        ("columns", expected.columns != observed.columns),
        (
            "column_names",
            expected
                .columns
                .iter()
                .map(|column| &column.name)
                .ne(observed.columns.iter().map(|column| &column.name)),
        ),
        (
            "column_types",
            expected
                .columns
                .iter()
                .map(|column| &column.sql_type)
                .ne(observed.columns.iter().map(|column| &column.sql_type)),
        ),
        (
            "column_nullability",
            expected
                .columns
                .iter()
                .map(|column| column.nullable)
                .ne(observed.columns.iter().map(|column| column.nullable)),
        ),
        (
            "column_collations",
            expected
                .columns
                .iter()
                .map(|column| &column.collation)
                .ne(observed.columns.iter().map(|column| &column.collation)),
        ),
        (
            "column_defaults",
            expected
                .columns
                .iter()
                .map(|column| &column.default)
                .ne(observed.columns.iter().map(|column| &column.default)),
        ),
        ("primary_key", expected.primary_key != observed.primary_key),
        (
            "primary_key_name",
            expected.primary_key_name != observed.primary_key_name,
        ),
        (
            "generated_key",
            expected.generated_key != observed.generated_key,
        ),
        ("indexes", expected.indexes != observed.indexes),
        (
            "foreign_keys",
            expected.foreign_keys != observed.foreign_keys,
        ),
        ("checks", expected.checks != observed.checks),
        (
            "check_names",
            expected
                .checks
                .iter()
                .map(|check| &check.name)
                .ne(observed.checks.iter().map(|check| &check.name)),
        ),
        (
            "check_expressions",
            expected
                .checks
                .iter()
                .map(|check| &check.expression)
                .ne(observed.checks.iter().map(|check| &check.expression)),
        ),
    ]
    .into_iter()
    .filter_map(|(code, changed)| changed.then_some(code))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn fixture() -> Result<SnapshotManifest, serde_json::Error> {
        serde_json::from_value(json!({"format_version":1,"engine":"tidb",
            "name":"private_snapshot_name","logical_schema":"private_schema_name",
            "source_version":"private_source_version","tables":[{
                "name":"private_table_name","columns":[{"name":"private_column_name",
                    "sql_type":{"kind":"text","length":96},"nullable":false,
                    "collation":"private_collation_name","default":{"kind":"text","value":"private_default_literal"}}],
                "primary_key":["private_column_name"],"primary_key_name":"private_primary_key_name",
                "generated_key":null,"rows":1,
                "indexes":[{"name":"private_index_name","columns":["private_column_name"],"unique":true}],
                "foreign_keys":[{"name":"private_foreign_key_name","columns":["private_column_name"],
                    "referenced_table":"private_parent_name","referenced_columns":["private_parent_column"],
                    "on_update":"restrict","on_delete":"restrict","deferrable":false,"initially_deferred":false}],
                "checks":[{"name":"private_check_name","expression":"private_check_expression"}]}]}))
    }

    #[test]
    fn equal_shapes_do_not_invent_mismatches() -> Result<(), serde_json::Error> {
        let expected = fixture()?;
        let diagnostic = serde_json::to_value(summary(&expected, &expected))?;
        assert_eq!(diagnostic["codes"], json!([]));
        assert_eq!(diagnostic["tables"], json!([]));
        Ok(())
    }

    #[test]
    fn same_cardinality_differences_are_classified_without_literals()
    -> Result<(), serde_json::Error> {
        let expected = fixture()?;
        let mut observed = expected.clone();
        observed.tables[0].columns[0].default = Some(fg_protocol_common::ColumnDefault::Text(
            "other_private_literal".into(),
        ));
        observed.tables[0].checks[0].expression = "other_private_expression".into();
        observed.tables[0].indexes[0].unique = false;
        let diagnostic = serde_json::to_value(summary(&expected, &observed))?;
        let table = &diagnostic["tables"][0];
        for code in ["column_defaults", "checks", "check_expressions", "indexes"] {
            assert!(
                table["codes"]
                    .as_array()
                    .is_some_and(|codes| codes.contains(&json!(code)))
            );
        }
        for field in ["columns", "indexes", "unique_indexes", "checks"] {
            assert_eq!(table["different_entries"][field], 1);
        }
        assert_eq!(
            table["expected_counts"]["columns"],
            table["observed_counts"]["columns"]
        );
        let encoded = serde_json::to_string(&diagnostic)?;
        assert!(!encoded.contains("private_"));
        assert!(!encoded.contains("other_private"));
        Ok(())
    }

    #[test]
    fn rows_order_and_missing_tables_keep_safe_ordinals() -> Result<(), serde_json::Error> {
        let mut expected = fixture()?;
        let mut second = expected.tables[0].clone();
        second.name = "private_second_table".into();
        expected.tables.push(second);
        let mut observed = expected.clone();
        observed.tables.reverse();
        observed.tables[1].rows = 7;
        let reordered = serde_json::to_value(summary(&expected, &observed))?;
        assert_eq!(reordered["tables"][0]["expected_ordinal"], 0);
        assert_eq!(reordered["tables"][0]["observed_ordinal"], 1);
        assert_eq!(reordered["tables"][0]["observed_counts"]["rows"], 7);
        observed.tables[0].name = "private_unexpected_table".into();
        let missing = serde_json::to_value(summary(&expected, &observed))?;
        assert_eq!(missing["tables"][1]["codes"], json!(["table_missing"]));
        assert_eq!(missing["tables"][2]["codes"], json!(["unexpected_table"]));
        assert_eq!(missing["tables"][1]["observed_ordinal"], Value::Null);
        assert!(!serde_json::to_string(&missing)?.contains("private_"));
        Ok(())
    }
}
