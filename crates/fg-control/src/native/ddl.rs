use sqlparser::{
    ast::{ColumnOption, ObjectNamePart, Statement, TableConstraint},
    dialect::MySqlDialect,
    parser::Parser,
};
use sqlx::{MySqlConnection, Row};
use thiserror::Error;

use super::Engine;

#[derive(Debug, Error)]
pub(crate) enum DdlError {
    #[error("Native table definition could not be read ({})", crate::native_failure(.0))]
    Native(#[from] sqlx::Error),
    #[error(
        "Native table CHECK metadata cannot be verified; unsupported definition, identity or enforcement"
    )]
    Unsupported,
}

pub(crate) struct TableCheck {
    pub(crate) name: String,
    pub(crate) expression: String,
}

/// TiDB omits CHECK entries from TABLE_CONSTRAINTS; MySQL's CHECK_CLAUSE
/// escapes string literals. Parse the exact native definition for both engines.
pub(crate) async fn mysql_table_checks(
    connection: &mut MySqlConnection,
    engine: Engine,
    schema: &str,
    table: &str,
) -> Result<Vec<TableCheck>, DdlError> {
    let relation = Engine::MySql.relation(schema, table);
    let row = sqlx::query(&format!("SHOW CREATE TABLE {relation}"))
        .fetch_one(&mut *connection)
        .await?;
    let definition: String = row.try_get_unchecked(1)?;
    let checks = parse_checks(&definition, schema, table)?;
    if engine == Engine::MySql {
        // MySQL can render NOT ENFORCED inside a version comment. Its native
        // enforcement flag must agree with every parsed CHECK, including extras.
        let enforcement: Vec<i64> = sqlx::query_scalar("SELECT CAST(ENFORCED='YES' AS SIGNED) FROM information_schema.table_constraints WHERE table_schema=? AND table_name=? AND constraint_type='CHECK'")
            .bind(schema).bind(table).fetch_all(connection).await?;
        if enforcement.len() != checks.len() || enforcement.iter().any(|flag| *flag != 1) {
            return Err(DdlError::Unsupported);
        }
    }
    Ok(checks)
}

fn parse_checks(definition: &str, schema: &str, table: &str) -> Result<Vec<TableCheck>, DdlError> {
    let statements =
        Parser::parse_sql(&MySqlDialect {}, definition).map_err(|_| DdlError::Unsupported)?;
    let [Statement::CreateTable(created)] = statements.as_slice() else {
        return Err(DdlError::Unsupported);
    };
    let matches = match created.name.0.as_slice() {
        [ObjectNamePart::Identifier(name)] => name.value == table,
        [
            ObjectNamePart::Identifier(namespace),
            ObjectNamePart::Identifier(name),
        ] => namespace.value == schema && name.value == table,
        _ => false,
    };
    if !matches || created.temporary || created.unlogged || created.query.is_some() {
        return Err(DdlError::Unsupported);
    }
    let mut checks = Vec::new();
    for constraint in &created.constraints {
        if let TableConstraint::Check(check) = constraint {
            let name = check.name.as_ref().ok_or(DdlError::Unsupported)?;
            if check.enforced == Some(false)
                || checks
                    .iter()
                    .any(|item: &TableCheck| item.name == name.value)
            {
                return Err(DdlError::Unsupported);
            }
            checks.push(TableCheck {
                name: name.value.clone(),
                expression: check.expr.to_string(),
            });
        }
    }
    // Native SHOW CREATE normally renders named table constraints. A different
    // representation must be refused rather than silently omitting a CHECK.
    if created.columns.iter().any(|column| {
        column
            .options
            .iter()
            .any(|option| matches!(option.option, ColumnOption::Check(_)))
    }) {
        return Err(DdlError::Unsupported);
    }
    Ok(checks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_are_bound_to_the_actual_table_and_never_read_from_comments() -> Result<(), DdlError> {
        let ddl = "CREATE TABLE `witness` (`id` bigint NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `identity` CHECK (`id` > 0)) ENGINE=InnoDB";
        let checks = parse_checks(ddl, "fgwrite", "witness")?;
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].name, "identity");
        assert!(parse_checks(ddl, "fgwrite", "other").is_err());
        let comment =
            "CREATE TABLE `witness` (`id` bigint COMMENT 'CONSTRAINT identity CHECK(id>0)')";
        assert!(parse_checks(comment, "fgwrite", "witness")?.is_empty());
        assert!(parse_checks(&format!("{ddl}; SELECT 1"), "fgwrite", "witness").is_err());
        let identity = "CREATE TABLE `witness` (`deployment_id` varchar(64) COLLATE ascii_bin NOT NULL, CONSTRAINT `identity` CHECK ((`deployment_id` = _utf8mb4'00000000-0000-0000-0000-000000000001'))) ENGINE=InnoDB DEFAULT CHARSET=ascii COLLATE=ascii_bin";
        let identity = parse_checks(identity, "fgwrite", "witness")?;
        assert_eq!(identity.len(), 1);
        assert!(
            identity[0]
                .expression
                .contains("00000000-0000-0000-0000-000000000001")
        );
        assert!(
            parse_checks(
                "CREATE TABLE witness (id BIGINT, CONSTRAINT identity CHECK(id>0) NOT ENFORCED)",
                "fgwrite",
                "witness"
            )
            .is_err()
        );
        Ok(())
    }
}
