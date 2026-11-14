use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
};
use fg_protocol_common::{BranchGrantCheck, TXN_WITNESS_TABLE, WriteTarget};
use sqlx::{Connection, Executor, MySqlConnection, Row};
use tokio::time::timeout;

use crate::{Drain, internal_authorized, settings::NativeOptions};

const GRANT_CHECK_TIMEOUT: Duration = Duration::from_secs(5);
const BRANCH_RIGHTS: [&str; 4] = ["SELECT", "INSERT", "UPDATE", "DELETE"];

pub(super) async fn route(
    State(state): State<Drain>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    request: Result<Json<BranchGrantCheck>, JsonRejection>,
) -> StatusCode {
    if !internal_authorized(&headers, &state.token) {
        return StatusCode::UNAUTHORIZED;
    }
    let (NativeOptions::MySql(options), Ok(Json(request))) = (state.observer.as_ref(), request)
    else {
        return StatusCode::BAD_REQUEST;
    };
    let Some(target) = WriteTarget::new(state.engine, id, &request.write_schema) else {
        return StatusCode::BAD_REQUEST;
    };
    let Some(required) = requested_relations(&target, &request.tables) else {
        return StatusCode::BAD_REQUEST;
    };
    let checked = timeout(GRANT_CHECK_TIMEOUT, async {
        let mut connection = MySqlConnection::connect_with(options).await?;
        let rows = (&mut connection)
            .fetch_all("SHOW GRANTS FOR CURRENT_USER")
            .await?;
        connection.close().await?;
        let grants = rows
            .iter()
            .map(|row| row.try_get_unchecked::<String, _>(0))
            .collect::<Result<Vec<_>, _>>()?;
        Ok::<_, sqlx::Error>(verify_grants(&grants, &required))
    })
    .await;
    match checked {
        Ok(Ok(true)) => StatusCode::NO_CONTENT,
        Ok(Ok(false)) => StatusCode::CONFLICT,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}

fn requested_relations(
    target: &WriteTarget,
    tables: &[String],
) -> Option<HashMap<String, HashSet<&'static str>>> {
    let mut required = HashMap::new();
    for logical in tables {
        let physical = target.table(logical);
        if physical.len() > 64
            || !logical
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_lowercase)
            || !logical
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            || required
                .insert(
                    format!("`{}`.`{physical}`", target.schema()),
                    BRANCH_RIGHTS.into_iter().collect(),
                )
                .is_some()
        {
            return None;
        }
    }
    if required.is_empty() {
        return None;
    }
    required.insert(
        format!(
            "`{}`.`{}`",
            target.schema(),
            target.table(TXN_WITNESS_TABLE)
        ),
        HashSet::from(["INSERT"]),
    );
    Some(required)
}

fn verify_grants(grants: &[String], required: &HashMap<String, HashSet<&'static str>>) -> bool {
    let mut seen = HashSet::new();
    for grant in grants {
        let Some((rights, relation)) = grant_parts(grant) else {
            return false;
        };
        if relation == "*.*" && rights == "USAGE" {
            continue;
        }
        if !relation.split_once('.').is_some_and(|(schema, table)| {
            [schema, table]
                .iter()
                .all(|name| name.starts_with('`') && name.ends_with('`') && !name.contains('*'))
        }) {
            return false;
        }
        if let Some(expected) = required.get(relation) {
            // MySQL renders "SELECT, DELETE"; TiDB renders "SELECT,DELETE".
            let observed = rights.split(',').map(str::trim).collect::<HashSet<_>>();
            if &observed != expected || !seen.insert(relation) {
                return false;
            }
        }
    }
    seen.len() == required.len()
}

fn grant_parts(line: &str) -> Option<(&str, &str)> {
    // SHOW GRANTS renders these keywords in English. Privilege order can vary.
    let (specification, grantee) = line.strip_prefix("GRANT ")?.split_once(" TO ")?;
    if grantee.contains(" WITH ") {
        return None;
    }
    specification.split_once(" ON ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attests_exact_non_delegable_table_privileges() -> Result<(), &'static str> {
        let target = WriteTarget::for_branch(17, true);
        let required = requested_relations(&target, &["orders".into()]).ok_or("target")?;
        let usage = "GRANT USAGE ON *.* TO `proxy`@`%`".to_owned();
        let exact =
            "GRANT UPDATE, DELETE, INSERT, SELECT ON `fgwrite`.`fg_b17_orders` TO `proxy`@`%`";
        let witness =
            "GRANT INSERT ON `fgwrite`.`fg_b17__fg_txn_witness` TO `proxy`@`%`".to_owned();
        assert!(verify_grants(
            &[usage.clone(), exact.into(), witness.clone()],
            &required
        ));
        assert!(!verify_grants(
            &[
                usage.clone(),
                exact.into(),
                witness.replace("INSERT", "SELECT, INSERT")
            ],
            &required
        ));
        for untrusted in [
            exact.replace(", DELETE", ""),
            exact.replace("fg_b17_orders", "fg_b18_orders"),
            format!("{exact} WITH GRANT OPTION"),
            "GRANT SELECT ON `fgwrite`.* TO `proxy`@`%`".into(),
        ] {
            assert!(!verify_grants(
                &[usage.clone(), untrusted, witness.clone()],
                &required
            ));
        }
        Ok(())
    }
}
