//! Author-controlled SQL splitting for fixtures and case statements.

/// Split SQL text into individual statements on semicolons that sit outside
/// single/double-quoted strings and `--` line comments. Fixture and corpus SQL
/// is authored in this repository and contains no procedural-language bodies,
/// so no DELIMITER handling is needed.
pub fn split_statements(sql: &str) -> Vec<String> {
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut chars = sql.chars().peekable();
    let mut quote: Option<char> = None;

    while let Some(character) = chars.next() {
        match quote {
            Some(quote_character) => {
                current.push(character);
                if character == quote_character && chars.peek() == Some(&quote_character) {
                    current.push(chars.next().unwrap_or(quote_character));
                } else if character == quote_character {
                    quote = None;
                }
            }
            None => {
                if character == '\'' || character == '"' {
                    quote = Some(character);
                    current.push(character);
                } else if character == '-' && chars.peek() == Some(&'-') {
                    for comment in chars.by_ref() {
                        if comment == '\n' {
                            current.push('\n');
                            break;
                        }
                    }
                } else if character == ';' {
                    let trimmed = current.trim();
                    if !trimmed.is_empty() {
                        statements.push(trimmed.to_string());
                    }
                    current.clear();
                } else {
                    current.push(character);
                }
            }
        }
    }
    let trimmed = current.trim();
    if !trimmed.is_empty() {
        statements.push(trimmed.to_string());
    }
    statements
}

#[cfg(test)]
mod tests {
    use super::split_statements;

    fn first(sql: &str) -> String {
        let statements = split_statements(sql);
        assert_eq!(statements.len(), 1, "expected one statement in {sql:?}");
        statements.into_iter().next().unwrap_or_default()
    }

    #[test]
    fn splits_on_semicolons_and_ignores_empty_tail() {
        let statements = split_statements("SELECT 1;\nSELECT 2;   \n");
        assert_eq!(statements, ["SELECT 1", "SELECT 2"]);
    }

    #[test]
    fn keeps_semicolons_inside_strings() {
        let statement = first("INSERT INTO t VALUES ('a;b', 'c'';d')");
        assert_eq!(statement, "INSERT INTO t VALUES ('a;b', 'c'';d')");
    }

    #[test]
    fn keeps_semicolons_inside_double_quotes() {
        let statement = first("SELECT \"col;name\" FROM t");
        assert_eq!(statement, "SELECT \"col;name\" FROM t");
    }

    #[test]
    fn skips_line_comments() {
        let statements = split_statements("-- drop ; me\nSELECT 1;");
        assert_eq!(statements, ["SELECT 1"]);
    }

    #[test]
    fn preserves_case_statement_body() {
        let statement = first("SELECT CASE WHEN a = 1 THEN 'x' ELSE 'y' END FROM t");
        assert!(statement.ends_with("END FROM t"));
    }
}
