use std::ops::Range;

use sqlparser::{
    ast::Statement,
    derive_dialect,
    dialect::{Dialect as ParserDialect, MySqlDialect, PostgreSqlDialect},
    keywords::Keyword,
    parser::Parser,
    tokenizer::{Location, Span, Token, TokenWithSpan, Tokenizer, Whitespace},
};

use crate::Dialect;
use fg_protocol_common::SqlLimit;

use super::{CompileError, QueryMode, Result as CompileResult};

const MAX_SQL_BYTES: usize = 1024 * 1024;
const MAX_SQL_TOKENS: usize = 65_536;
const MAX_PARSE_RECURSION: usize = 40;
const MAX_PREPARED_PARAMETERS: usize = 16_384;

// Preserve executable comments as lexer tokens so admission can reject them
// before the upstream MySQL dialect retokenizes their contents as SQL.
derive_dialect!(
    MySqlReadDialect,
    MySqlDialect,
    overrides = { supports_multiline_comment_hints = false, }
);

pub(super) struct Source<'a> {
    pub(super) sql: &'a str,
    line_starts: Vec<usize>,
    line_char_offsets: Vec<Option<Vec<usize>>>,
}

impl<'a> Source<'a> {
    pub(super) fn new(sql: &'a str) -> CompileResult<Self> {
        if sql.len() > MAX_SQL_BYTES {
            return Err(CompileError::Limit {
                kind: SqlLimit::Bytes,
                actual: sql.len() as u64,
                limit: MAX_SQL_BYTES as u64,
            });
        }
        if sql.contains('\0') {
            return Err(CompileError::Syntax);
        }
        let mut line_starts = vec![0];
        line_starts.extend(sql.match_indices('\n').map(|(index, _)| index + 1));
        let line_char_offsets = line_starts
            .iter()
            .enumerate()
            .map(|(index, start)| {
                let end = line_starts.get(index + 1).copied().unwrap_or(sql.len());
                let text = &sql[*start..end];
                (!text.is_ascii()).then(|| {
                    text.char_indices()
                        .map(|(offset, _)| offset)
                        .chain(std::iter::once(text.len()))
                        .collect()
                })
            })
            .collect();
        Ok(Self {
            sql,
            line_starts,
            line_char_offsets,
        })
    }

    fn offset(&self, location: Location) -> Option<usize> {
        let line = usize::try_from(location.line.checked_sub(1)?).ok()?;
        let column = usize::try_from(location.column.checked_sub(1)?).ok()?;
        let start = *self.line_starts.get(line)?;
        let end = self
            .line_starts
            .get(line + 1)
            .copied()
            .unwrap_or(self.sql.len());
        if let Some(offsets) = self.line_char_offsets.get(line)?.as_ref() {
            return offsets.get(column).map(|offset| start + offset);
        }
        (column <= end - start).then_some(start + column)
    }

    pub(super) fn range(&self, span: Span) -> CompileResult<Range<usize>> {
        let start = self.offset(span.start).ok_or(CompileError::Syntax)?;
        let end = self.offset(span.end).ok_or(CompileError::Syntax)?;
        if start >= end {
            return Err(CompileError::Syntax);
        }
        Ok(start..end)
    }
}

pub(super) fn statement_start(dialect: Dialect, sql: &str) -> (u32, u32) {
    let parser_dialect: &dyn ParserDialect = match dialect {
        Dialect::MySql => &MySqlReadDialect::new(),
        Dialect::PostgreSql => &PostgreSqlDialect {},
    };
    Tokenizer::new(parser_dialect, sql)
        .tokenize_with_location()
        .ok()
        .and_then(|tokens| {
            tokens
                .into_iter()
                .find(|token| !matches!(token.token, Token::Whitespace(_)))
        })
        .and_then(|token| {
            Some((
                u32::try_from(token.span.start.line).ok()?,
                u32::try_from(token.span.start.column).ok()?,
            ))
        })
        .unwrap_or((1, 1))
}

pub(super) fn parse(
    dialect: Dialect,
    mode: QueryMode,
    source: &Source<'_>,
) -> CompileResult<(Statement, usize, Vec<u32>)> {
    let parser_dialect: &dyn ParserDialect = match dialect {
        Dialect::MySql => &MySqlReadDialect::new(),
        Dialect::PostgreSql => &PostgreSqlDialect {},
    };
    let tokens = Tokenizer::new(parser_dialect, source.sql)
        .tokenize_with_location()
        .map_err(|_| CompileError::Syntax)?;
    let (parameter_count, parameters, concatenated_literals) =
        inspect(dialect, mode, source, &tokens)?;
    let mut statements = Parser::new(parser_dialect)
        .with_recursion_limit(MAX_PARSE_RECURSION)
        .with_tokens_with_locations(tokens)
        .parse_statements()
        .map_err(|_| CompileError::Syntax)?;
    match statements.pop() {
        Some(Statement::Insert(_) | Statement::Update(_) | Statement::Delete(_))
            if statements.is_empty() && concatenated_literals =>
        {
            // sqlparser combines adjacent string tokens but retains only the
            // first token's source span. DML reconstruction requires one token.
            Err(CompileError::Unsupported)
        }
        Some(statement) if statements.is_empty() => Ok((statement, parameter_count, parameters)),
        _ => Err(CompileError::Syntax),
    }
}

fn inspect(
    dialect: Dialect,
    mode: QueryMode,
    source: &Source<'_>,
    tokens: &[TokenWithSpan],
) -> CompileResult<(usize, Vec<u32>, bool)> {
    let token_count = tokens
        .iter()
        .filter(|token| !matches!(token.token, Token::Whitespace(_)))
        .count();
    if token_count > MAX_SQL_TOKENS {
        return Err(CompileError::Limit {
            kind: SqlLimit::Tokens,
            actual: token_count as u64,
            limit: MAX_SQL_TOKENS as u64,
        });
    }
    let mut parameter_count = 0;
    let mut parameters = Vec::new();
    let mut semicolon = false;
    let mut significant = 0;
    let mut previous_string = false;
    let mut concatenated_literals = false;
    for (index, token) in tokens.iter().enumerate() {
        if let Token::Whitespace(whitespace) = &token.token {
            check_whitespace(dialect, source, token.span, whitespace)?;
            continue;
        }
        if semicolon {
            return Err(CompileError::Syntax);
        }
        significant += 1;
        let is_string = matches!(
            &token.token,
            Token::SingleQuotedString(_) | Token::DoubleQuotedString(_)
        );
        concatenated_literals |= previous_string && is_string;
        previous_string = is_string;
        match &token.token {
            Token::SemiColon if significant > 1 => semicolon = true,
            Token::SemiColon => return Err(CompileError::Syntax),
            Token::Word(word)
                if dialect == Dialect::PostgreSql && word.keyword == Keyword::FETCH =>
            {
                check_fetch_tokens(&tokens[index + 1..])?;
            }
            Token::Placeholder(parameter) => {
                if mode == QueryMode::Text {
                    return Err(CompileError::Syntax);
                }
                match dialect {
                    Dialect::MySql if parameter == "?" => parameter_count += 1,
                    Dialect::MySql => return Err(CompileError::Syntax),
                    Dialect::PostgreSql => {
                        let index = postgres_parameter(parameter)?;
                        parameter_count = parameter_count.max(index as usize);
                        parameters.push(index);
                    }
                }
            }
            _ => (),
        }
    }
    if parameter_count > MAX_PREPARED_PARAMETERS {
        return Err(CompileError::Limit {
            kind: SqlLimit::BindParameters,
            actual: parameter_count as u64,
            limit: MAX_PREPARED_PARAMETERS as u64,
        });
    }
    Ok((parameter_count, parameters, concatenated_literals))
}

fn check_fetch_tokens(tokens: &[TokenWithSpan]) -> CompileResult<()> {
    // sqlparser records the count and modifiers but discards the presence of
    // FIRST/NEXT, ROW/ROWS and ONLY. Require the supported native shape here.
    let mut tokens = tokens
        .iter()
        .map(|token| &token.token)
        .filter(|token| !matches!(token, Token::Whitespace(_)));
    let direction = tokens.next();
    let count = tokens.next();
    let rows = tokens.next();
    let only = tokens.next();
    if matches!(direction, Some(Token::Word(word)) if matches!(word.keyword, Keyword::FIRST | Keyword::NEXT))
        && matches!(count, Some(Token::Number(_, false) | Token::Placeholder(_)))
        && matches!(rows, Some(Token::Word(word)) if matches!(word.keyword, Keyword::ROW | Keyword::ROWS))
        && matches!(only, Some(Token::Word(word)) if word.keyword == Keyword::ONLY)
    {
        Ok(())
    } else {
        Err(CompileError::Unsupported)
    }
}

pub(super) fn postgres_parameter(parameter: &str) -> CompileResult<u32> {
    let number = parameter.strip_prefix('$').ok_or(CompileError::Syntax)?;
    if number.starts_with('0') || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CompileError::Syntax);
    }
    number
        .parse::<u16>()
        .ok()
        .filter(|number| *number > 0)
        .map(u32::from)
        .ok_or(CompileError::Syntax)
}

fn check_whitespace(
    dialect: Dialect,
    source: &Source<'_>,
    span: Span,
    whitespace: &Whitespace,
) -> CompileResult<()> {
    match whitespace {
        Whitespace::MultiLineComment(comment) => {
            if comment.starts_with(['!', '+']) || comment.starts_with("M!") {
                return Err(CompileError::Syntax);
            }
        }
        Whitespace::SingleLineComment { comment, prefix } => {
            if dialect == Dialect::MySql && !safe_mysql_line_comment(source, span, prefix, comment)?
            {
                return Err(CompileError::Syntax);
            }
        }
        _ => {
            if !source.sql[source.range(span)?]
                .bytes()
                .all(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
            {
                return Err(CompileError::Syntax);
            }
        }
    }
    Ok(())
}

fn safe_mysql_line_comment(
    source: &Source<'_>,
    span: Span,
    prefix: &str,
    comment: &str,
) -> CompileResult<bool> {
    if prefix == "--"
        && comment
            .as_bytes()
            .first()
            .is_some_and(|byte| !byte.is_ascii())
    {
        return Ok(false);
    }
    if !comment.contains('\r') {
        return Ok(true);
    }
    // Keep CRLF while refusing a standalone CR that might end a line at the
    // backend before the lexer has stopped treating the input as a comment.
    let end = source.range(span)?.end;
    Ok(source.sql.as_bytes().get(end) == Some(&b'\n')
        && comment
            .strip_suffix('\r')
            .is_some_and(|body| !body.contains('\r')))
}
