//! Exact local fixture SQL admission. Branch SQL uses the bound compiler.

const TEXT: &[&[u8]] = &[
    b"SELECT 1",
    b"SELECT id, payload FROM fixture_items ORDER BY id",
    b"SELECT id, payload FROM fixture_items WHERE id = -1",
    b"SELECT COUNT(*) FROM fixture_events",
    b"INSERT INTO fixture_events (id) VALUES (1)",
    b"SELECT CAST(18446744073709551615 AS UNSIGNED)",
];
const SESSION: &[&[u8]] = &[
    b"BEGIN",
    b"START TRANSACTION",
    b"COMMIT",
    b"ROLLBACK",
    b"SAVEPOINT fixture_savepoint",
    b"ROLLBACK TO SAVEPOINT fixture_savepoint",
    b"RELEASE SAVEPOINT fixture_savepoint",
    b"SET NAMES utf8mb4",
    b"SET NAMES utf8mb4 COLLATE utf8mb4_general_ci",
    b"SET NAMES utf8mb4 COLLATE utf8mb4_0900_ai_ci",
    b"SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci",
    b"SET NAMES 'utf8mb4' COLLATE 'utf8mb4_general_ci'",
    b"SET NAMES 'utf8mb4' COLLATE 'utf8mb4_0900_ai_ci'",
    b"SET NAMES 'utf8mb4' COLLATE 'utf8mb4_unicode_ci'",
    b"SET AUTOCOMMIT=0",
    b"SET AUTOCOMMIT=1",
    b"SET AUTOCOMMIT = 0",
    b"SET AUTOCOMMIT = 1",
    b"SET @@session.autocommit = ON",
    b"SET @@session.autocommit = OFF",
    b"SET character_set_results = NULL",
    b"SELECT @@version_comment LIMIT 1",
    b"SELECT VERSION()",
    b"SELECT @@session.transaction_isolation",
    b"SELECT @@session.transaction_read_only",
    b"SELECT @@session.autocommit",
    b"SELECT @@sql_mode",
    b"SELECT @@lower_case_table_names",
    b"SELECT @@transaction_isolation",
];
const PREPARED: &[&[u8]] = &[
    b"SELECT id, payload FROM fixture_items WHERE id = ?",
    b"SELECT CAST(? AS UNSIGNED), CAST(? AS BINARY)",
];
const JDBC_VARIABLES: &str = concat!(
    "SELECT @@session.auto_increment_increment AS auto_increment_increment, ",
    "@@character_set_client AS character_set_client, ",
    "@@character_set_connection AS character_set_connection, ",
    "@@character_set_results AS character_set_results, ",
    "@@character_set_server AS character_set_server, ",
    "@@collation_server AS collation_server, ",
    "@@collation_connection AS collation_connection, ",
    "@@init_connect AS init_connect, ",
    "@@interactive_timeout AS interactive_timeout, ",
    "@@license AS license, ",
    "@@lower_case_table_names AS lower_case_table_names, ",
    "@@max_allowed_packet AS max_allowed_packet, ",
    "@@net_write_timeout AS net_write_timeout, ",
    "@@performance_schema AS performance_schema, ",
    "@@sql_mode AS sql_mode, ",
    "@@system_time_zone AS system_time_zone, ",
    "@@time_zone AS time_zone, ",
    "@@transaction_isolation AS transaction_isolation, ",
    "@@wait_timeout AS wait_timeout"
);
const JDBC_COMMENT: &str = "/* mysql-connector-j-9.3.0";
const MAX_PROBE_SIZE: usize = 8192;

pub(crate) fn text(query: &[u8]) -> Option<&'static [u8]> {
    let query = trim(query);
    TEXT.iter()
        .copied()
        .find(|allowed| query.eq_ignore_ascii_case(allowed))
        .or_else(|| session(query))
}

pub(crate) fn session(query: &[u8]) -> Option<&'static [u8]> {
    let query = trim(query);
    SESSION
        .iter()
        .copied()
        .find(|allowed| query.eq_ignore_ascii_case(allowed))
        .or_else(|| jdbc_probe(query))
}

pub(crate) fn prepared(query: &[u8]) -> Option<&'static [u8]> {
    let query = trim(query);
    PREPARED
        .iter()
        .copied()
        .find(|allowed| query.eq_ignore_ascii_case(allowed))
}

pub(crate) fn write_session(query: &[u8], text: bool) -> Option<&'static [u8]> {
    let query = trim(query);
    const LAST_INSERT_ID: &[u8] = b"SELECT LAST_INSERT_ID()";
    if query.eq_ignore_ascii_case(LAST_INSERT_ID) {
        return Some(LAST_INSERT_ID);
    }
    if !text {
        return None;
    }
    [
        b"SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED".as_slice(),
        b"SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ",
        b"SET TRANSACTION ISOLATION LEVEL READ COMMITTED",
        b"SET TRANSACTION ISOLATION LEVEL REPEATABLE READ",
    ]
    .into_iter()
    .find(|allowed| query.eq_ignore_ascii_case(allowed))
}

pub(crate) fn use_branch(query: &[u8]) -> Option<&[u8]> {
    let mut words = trim(query)
        .split(u8::is_ascii_whitespace)
        .filter(|word| !word.is_empty());
    let verb = words.next()?;
    let name = words.next()?;
    if !verb.eq_ignore_ascii_case(b"USE") || words.next().is_some() {
        return None;
    }
    let quoted = name
        .strip_prefix(b"`")
        .and_then(|name| name.strip_suffix(b"`"));
    quoted.or_else(|| name.iter().all(u8::is_ascii_alphanumeric).then_some(name))
}

fn trim(query: &[u8]) -> &[u8] {
    let query = query.trim_ascii();
    query
        .strip_suffix(b";")
        .map_or(query, <[u8]>::trim_ascii_end)
}

fn jdbc_probe(query: &[u8]) -> Option<&'static [u8]> {
    if query.len() > MAX_PROBE_SIZE {
        return None;
    }
    let query = str::from_utf8(query).ok()?;
    let (build, query) = query.strip_prefix(JDBC_COMMENT)?.split_once("*/")?;
    if !build.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b':' | b'(' | b')' | b'-')
    }) {
        return None;
    }
    let mut actual = query.split_ascii_whitespace();
    for expected in JDBC_VARIABLES.split_ascii_whitespace() {
        if !actual.next()?.eq_ignore_ascii_case(expected) {
            return None;
        }
    }
    actual.next().is_none().then_some(JDBC_VARIABLES.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admits_only_known_statements_and_driver_variables() {
        assert_eq!(text(b"\nselect 1; "), Some(b"SELECT 1".as_slice()));
        assert_eq!(session(b"begin"), Some(b"BEGIN".as_slice()));
        assert!(session(b"INSERT INTO fixture_events (id) VALUES (1)").is_none());
        assert!(session(b"SELECT id, payload FROM fixture_items ORDER BY id").is_none());
        assert_eq!(
            use_branch(b"uSe `p1-fixture`;"),
            Some(b"p1-fixture".as_slice())
        );
        assert_eq!(
            use_branch(b"USE `P1-FIXTURE`"),
            Some(b"P1-FIXTURE".as_slice())
        );
        assert_eq!(use_branch(b"USE branch123"), Some(b"branch123".as_slice()));
        assert!(use_branch(b"USE p1-fixture").is_none());
        let probe = format!("{JDBC_COMMENT} (Revision: abc123) */{JDBC_VARIABLES}");
        assert_eq!(text(probe.as_bytes()), Some(JDBC_VARIABLES.as_bytes()));
        for sql in [
            b"SELECT 1; DROP TABLE fixture_items".as_slice(),
            b"SELECT @@time_zone INTO OUTFILE '/tmp/fixture'",
            b"SELECT @@time_zone, @@global.time_zone",
            b"/*! SELECT @@time_zone */",
            b"SELECT * FROM mysql.user",
            b"SELECT 1;;",
        ] {
            assert!(text(sql).is_none());
            assert!(prepared(sql).is_none());
        }
    }
}
