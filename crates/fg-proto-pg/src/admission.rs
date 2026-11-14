//! SQL admission for exact fixtures and catalog-backed reads.

use std::borrow::Cow;
use std::io;

use fg_protocol_common::{WireError, WriteOperation};
use fg_rewrite::{
    BoundCompiler, CompiledExplain, CompiledStatement, CompiledWrite, Dialect, GeneratedIds,
    PlanMapping, QueryMode,
};

use crate::wire::{Frame, cstring, end, protocol_error, take, take_string, take_u16, take_u32};

const READ_ITEMS: &str = "SELECT id, payload FROM public.fixture_items ORDER BY id";
const READ_ITEM: &str = "SELECT id, payload FROM public.fixture_items WHERE id = $1::int4";
const READ_ITEM_2: &str = "SELECT id, payload FROM public.fixture_items WHERE id = 2";
const COPY_ITEMS: &str =
    "COPY (SELECT id, payload FROM public.fixture_items ORDER BY id) TO STDOUT";
const INSERT_EVENT: &str = "INSERT INTO public.fixture_events (id) VALUES (1)";
const COUNT_EVENTS: &str = "SELECT COUNT(*) FROM public.fixture_events";
const MAX_BIND_PARAMETERS: usize = 16_384;
const MAX_RESULT_FORMATS: usize = 256;
const MAX_HANDLE_NAME_BYTES: usize = 63;
const BIGINT_OID: u32 = 20;

#[derive(Clone, Copy)]
pub(crate) struct GeneratedBind {
    pub(crate) ids: GeneratedIds,
    pub(crate) client_count: u16,
}

pub(crate) enum Admission {
    Ready,
    WriteText(CompiledWrite),
    WriteParse(WriteOperation, Option<GeneratedBind>),
    Explain(PlanMapping),
}

pub(crate) fn admit(
    frame: &mut Frame,
    compiler: Option<&BoundCompiler<'_>>,
) -> Result<Admission, WireError> {
    let check = match frame.tag {
        b'Q' | b'P' => {
            return sql_frame(frame, compiler).map_err(|error| match error {
                SqlError::Protocol => WireError::Protocol,
                SqlError::Refused(error) => error,
            });
        }
        b'B' => validate_bind,
        b'D' | b'C' => validate_target,
        b'E' => validate_execute,
        b'H' | b'S' | b'X' => end,
        _ => return Err(WireError::Unsupported),
    };
    check(&frame.body).map_err(|_| WireError::Protocol)?;
    Ok(Admission::Ready)
}

enum SqlError {
    Protocol,
    Refused(WireError),
}

impl From<io::Error> for SqlError {
    fn from(_: io::Error) -> Self {
        Self::Protocol
    }
}

impl From<WireError> for SqlError {
    fn from(error: WireError) -> Self {
        Self::Refused(error)
    }
}

fn sql_frame(
    frame: &mut Frame,
    compiler: Option<&BoundCompiler<'_>>,
) -> Result<Admission, SqlError> {
    let mut rest = frame.body.as_slice();
    let statement = if frame.tag == b'P' {
        Some(name(&mut rest)?)
    } else {
        None
    };
    let sql = take_string(&mut rest)?;
    if statement.is_none() {
        end(rest)?;
    }
    let prepared = statement.is_some();
    let (admitted, operation, generated, explain) = match compiler {
        Some(compiler) => match compile_sql(sql, prepared, rest, compiler)? {
            AdmittedSql::Sql(sql) => (sql, None, None, None),
            AdmittedSql::Explain(plan) => {
                (Cow::Owned(plan.read.sql), None, None, Some(plan.mapping))
            }
            AdmittedSql::Write(write) if !prepared => {
                return Ok(Admission::WriteText(write));
            }
            AdmittedSql::Write(write) => (
                Cow::Owned(write.sql),
                Some(write.operation),
                write.generated.map(|ids| GeneratedBind {
                    ids,
                    client_count: write.parameter_count as u16,
                }),
                None,
            ),
        },
        None => {
            let admitted = fixture_sql(sql, statement.is_none()).ok_or(WireError::Unsupported)?;
            if statement.is_some() {
                validate_fixture_types(rest, admitted == READ_ITEM)?;
            }
            (Cow::Borrowed(admitted), None, None, None)
        }
    };
    let mut body = Vec::new();
    if let Some(statement) = statement {
        cstring(&mut body, statement);
    }
    cstring(&mut body, &admitted);
    if let Some(generated) = generated {
        append_generated_type(&mut body, rest, generated.client_count);
    } else {
        body.extend_from_slice(rest);
    }
    frame.body = body;
    Ok(if let Some(mapping) = explain {
        Admission::Explain(mapping)
    } else {
        operation.map_or(Admission::Ready, |op| Admission::WriteParse(op, generated))
    })
}

enum AdmittedSql {
    Sql(Cow<'static, str>),
    Write(CompiledWrite),
    Explain(CompiledExplain),
}

fn compile_sql(
    sql: &str,
    prepared: bool,
    types: &[u8],
    compiler: &BoundCompiler<'_>,
) -> Result<AdmittedSql, SqlError> {
    let branch = compiler.binding();
    let normalized = normalize(sql);
    if let Some(control) = session_sql(normalized, !prepared).or_else(|| {
        branch.write_schema.as_ref()?;
        write_session(normalized)
    }) {
        if prepared {
            validate_bound_types(types, 0)?;
        }
        return Ok(AdmittedSql::Sql(Cow::Borrowed(control)));
    }
    let mode = if prepared {
        QueryMode::Prepared
    } else {
        QueryMode::Text
    };
    let compiled = compiler
        .compile_statement(mode, sql)
        .map_err(|error| error.wire_at(Dialect::PostgreSql, sql))?;
    match compiled {
        CompiledStatement::Explain(plan) => {
            if prepared {
                validate_bound_types(types, plan.read.parameter_count)?;
            }
            Ok(AdmittedSql::Explain(plan))
        }
        CompiledStatement::Read(read) => {
            if prepared {
                validate_bound_types(types, read.parameter_count)?;
            }
            Ok(AdmittedSql::Sql(Cow::Owned(read.sql)))
        }
        CompiledStatement::Write(write) => {
            if prepared {
                validate_bound_types(types, write.parameter_count)?;
                validate_point_types(types, &write.postgres_point_parameters)?;
            }
            Ok(AdmittedSql::Write(write))
        }
        CompiledStatement::Savepoint(sql) => {
            if prepared {
                validate_bound_types(types, 0)?;
            }
            Ok(AdmittedSql::Sql(Cow::Owned(sql)))
        }
    }
}

fn append_generated_type(output: &mut Vec<u8>, types: &[u8], client_count: u16) {
    let supplied = &types[2..];
    output.extend((client_count + 1).to_be_bytes());
    output.extend(supplied);
    output.resize(
        output.len() + usize::from(client_count) * 4 - supplied.len(),
        0,
    );
    output.extend(BIGINT_OID.to_be_bytes());
}

fn validate_point_types(types: &[u8], point_parameters: &[u32]) -> Result<(), SqlError> {
    for (index, mut oid) in types[2..].chunks_exact(4).enumerate() {
        if point_parameters.contains(&((index + 1) as u32))
            && !matches!(take_u32(&mut oid)?, 0 | 20 | 21 | 23 | 1700)
        {
            return Err(WireError::Unsupported.into());
        }
    }
    Ok(())
}

fn validate_bound_types(mut body: &[u8], parameter_count: usize) -> Result<(), SqlError> {
    let declared = usize::from(take_u16(&mut body)?);
    if body.len() != declared * 4 {
        return Err(SqlError::Protocol);
    }
    if parameter_count > MAX_BIND_PARAMETERS || declared > parameter_count {
        return Err(WireError::Unsupported.into());
    }
    for _ in 0..declared {
        // Do not invoke backend user-defined type input routines at Bind.
        // Zero leaves inference to PostgreSQL; all other OIDs are built-ins.
        if !matches!(
            take_u32(&mut body)?,
            0 | 16 | 17 | 20 | 21 | 23 | 25 | 700 | 701 | 1042 | 1043 | 1082 | 1114 | 1184 | 1700
        ) {
            return Err(WireError::Unsupported.into());
        }
    }
    Ok(())
}

fn validate_fixture_types(mut body: &[u8], has_integer_parameter: bool) -> Result<(), SqlError> {
    let count = take_u16(&mut body)?;
    if body.len() != usize::from(count) * 4 {
        return Err(SqlError::Protocol);
    }
    if count == 0 {
        return Ok(());
    }
    if !has_integer_parameter || count != 1 {
        return Err(WireError::Unsupported.into());
    }
    // PostgreSQL's integer type OIDs and unspecified (infer from the query).
    if matches!(take_u32(&mut body)?, 0 | 20 | 21 | 23) {
        return Ok(());
    }
    Err(WireError::Unsupported.into())
}

fn normalize(sql: &str) -> &str {
    let sql = sql.trim_ascii();
    sql.strip_suffix(';').unwrap_or(sql).trim_ascii_end()
}

fn session_sql(sql: &str, simple: bool) -> Option<&'static str> {
    // Psycopg invalidates its named statement cache after rolling back.
    if simple && sql.eq_ignore_ascii_case("DEALLOCATE ALL") {
        return Some("DEALLOCATE ALL");
    }
    if simple && sql.eq_ignore_ascii_case("SELECT VERSION()") {
        return Some("SELECT pg_catalog.version()");
    }
    if sql.eq_ignore_ascii_case("SELECT pg_catalog.version()") {
        return Some("SELECT pg_catalog.version()");
    }
    [
        "",
        "BEGIN",
        "COMMIT",
        "ROLLBACK",
        "SAVEPOINT fixture_savepoint",
        "ROLLBACK TO SAVEPOINT fixture_savepoint",
        "SET extra_float_digits = 3",
        "SHOW TRANSACTION ISOLATION LEVEL",
        "SHOW standard_conforming_strings",
    ]
    .into_iter()
    .find(|control| sql.eq_ignore_ascii_case(control))
}

fn write_session(sql: &str) -> Option<&'static str> {
    [
        "BEGIN ISOLATION LEVEL READ COMMITTED",
        "BEGIN ISOLATION LEVEL REPEATABLE READ",
        "START TRANSACTION ISOLATION LEVEL READ COMMITTED",
        "START TRANSACTION ISOLATION LEVEL REPEATABLE READ",
        "SET TRANSACTION ISOLATION LEVEL READ COMMITTED",
        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ",
        "SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL READ COMMITTED",
        "SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL REPEATABLE READ",
        "SET CONSTRAINTS ALL DEFERRED",
        "SET CONSTRAINTS ALL IMMEDIATE",
        "RELEASE SAVEPOINT fixture_savepoint",
    ]
    .into_iter()
    .find(|control| sql.eq_ignore_ascii_case(control))
}

fn fixture_sql(sql: &str, simple: bool) -> Option<&'static str> {
    let sql = normalize(sql);
    if let Some(control) = session_sql(sql, simple) {
        return Some(control);
    }
    let statements = [
        ("SELECT 1", "SELECT 1"),
        (
            "SELECT id, payload FROM fixture_items ORDER BY id",
            READ_ITEMS,
        ),
        (
            "SELECT id, payload FROM fixture_items WHERE id = $1",
            READ_ITEM,
        ),
        (
            "SELECT id, payload FROM fixture_items WHERE id = $1::int4",
            READ_ITEM,
        ),
        (
            "SELECT id, payload FROM fixture_items WHERE id = 2",
            READ_ITEM_2,
        ),
        ("SELECT 1 / 0", "SELECT 1 / 0"),
        ("SELECT pg_sleep(30)", "SELECT pg_catalog.pg_sleep(30)"),
        ("INSERT INTO fixture_events (id) VALUES (1)", INSERT_EVENT),
        ("SELECT COUNT(*) FROM fixture_events", COUNT_EVENTS),
    ];
    if simple
        && sql.eq_ignore_ascii_case(
            "COPY (SELECT id, payload FROM fixture_items ORDER BY id) TO STDOUT",
        )
    {
        return Some(COPY_ITEMS);
    }
    statements
        .iter()
        .find(|(frontend, _)| sql.eq_ignore_ascii_case(frontend))
        .map(|(_, backend)| *backend)
}

fn validate_bind(mut body: &[u8]) -> io::Result<()> {
    name(&mut body)?;
    name(&mut body)?;
    take_formats(&mut body, MAX_BIND_PARAMETERS)?;
    let count = take_u16(&mut body)?;
    if usize::from(count) > MAX_BIND_PARAMETERS {
        return Err(protocol_error());
    }
    for _ in 0..count {
        let length = i32::from_be_bytes(take(&mut body)?);
        if length == -1 {
            continue;
        }
        let length = usize::try_from(length).map_err(|_| protocol_error())?;
        body = body.get(length..).ok_or_else(protocol_error)?;
    }
    take_formats(&mut body, MAX_RESULT_FORMATS)?;
    end(body)
}

pub(crate) fn bind_statement(mut body: &[u8]) -> io::Result<&str> {
    name(&mut body)?;
    name(&mut body)
}

pub(crate) struct BindWithGenerated<'a> {
    prefix: &'a [u8],
    formats: &'a [u8],
    count: u16,
    values: &'a [u8],
    result: &'a [u8],
}

impl<'a> BindWithGenerated<'a> {
    pub(crate) fn parse(body: &'a [u8], expected_count: u16) -> io::Result<Self> {
        let mut rest = body;
        name(&mut rest)?;
        name(&mut rest)?;
        let prefix = &body[..body.len() - rest.len()];
        let format_count = take_u16(&mut rest)?;
        let format_len = usize::from(format_count) * 2;
        let formats = rest.get(..format_len).ok_or_else(protocol_error)?;
        rest = &rest[format_len..];
        let count = take_u16(&mut rest)?;
        if count != expected_count || (format_count > 1 && format_count != count) {
            return Err(protocol_error());
        }
        let values_start = rest;
        for _ in 0..count {
            let length = i32::from_be_bytes(take(&mut rest)?);
            if length != -1 {
                let length = usize::try_from(length).map_err(|_| protocol_error())?;
                rest = rest.get(length..).ok_or_else(protocol_error)?;
            }
        }
        let values = &values_start[..values_start.len() - rest.len()];
        Ok(Self {
            prefix,
            formats,
            count,
            values,
            result: rest,
        })
    }

    pub(crate) fn with_start(&self, start: i64) -> Vec<u8> {
        let count = self.count + 1;
        let mut body = self.prefix.to_vec();
        body.extend(count.to_be_bytes());
        for index in 0..usize::from(self.count) {
            let offset = if self.formats.len() > 2 { index * 2 } else { 0 };
            body.extend(self.formats.get(offset..offset + 2).unwrap_or(&[0, 0]));
        }
        body.extend(1_u16.to_be_bytes());
        body.extend(count.to_be_bytes());
        body.extend(self.values);
        body.extend(8_i32.to_be_bytes());
        body.extend(start.to_be_bytes());
        body.extend(self.result);
        body
    }
}

pub(crate) fn refuse_generated_bind(body: &[u8]) -> io::Result<Vec<u8>> {
    let mut rest = body;
    name(&mut rest)?;
    name(&mut rest)?;
    let mut body = body[..body.len() - rest.len()].to_vec();
    // The native statement requires a hidden parameter; zero is always a Bind error.
    body.extend([0; 6]);
    Ok(body)
}

pub(crate) fn strip_generated_type(body: &mut Vec<u8>, client_count: u16) -> io::Result<()> {
    let mut input = body.as_slice();
    let count = take_u16(&mut input)?;
    if count != client_count + 1
        || input.len() != usize::from(count) * 4
        || !input.ends_with(&BIGINT_OID.to_be_bytes())
    {
        return Err(crate::wire::backend_error());
    }
    body.truncate(body.len() - 4);
    body[..2].copy_from_slice(&client_count.to_be_bytes());
    Ok(())
}
fn take_formats(body: &mut &[u8], maximum: usize) -> io::Result<()> {
    let count = take_u16(body)?;
    if usize::from(count) > maximum {
        return Err(protocol_error());
    }
    for _ in 0..count {
        if take_u16(body)? > 1 {
            return Err(protocol_error());
        }
    }
    Ok(())
}

fn validate_target(mut body: &[u8]) -> io::Result<()> {
    if !matches!(take::<1>(&mut body)?[0], b'S' | b'P') {
        return Err(protocol_error());
    }
    name(&mut body)?;
    end(body)
}

fn validate_execute(mut body: &[u8]) -> io::Result<()> {
    name(&mut body)?;
    if take_u32(&mut body)? > i32::MAX as u32 {
        return Err(protocol_error());
    }
    end(body)
}

pub(crate) fn name<'a>(body: &mut &'a [u8]) -> io::Result<&'a str> {
    let name = take_string(body)?;
    // Native handle lookup compares only the first 63 bytes; reject aliases
    // that would otherwise become indistinguishable after truncation.
    if name.len() > MAX_HANDLE_NAME_BYTES {
        return Err(protocol_error());
    }
    Ok(name)
}

pub(crate) fn execute_target(mut body: &[u8]) -> io::Result<(&str, u32)> {
    let portal = name(&mut body)?;
    Ok((portal, take_u32(&mut body)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unapproved_queries_and_compound_queries() {
        for sql in [
            "SELECT 1; DROP TABLE fixture_items",
            "/* hint */ SELECT 1",
            "SELECT * FROM public.fixture_items",
            "COPY fixture_items FROM STDIN",
            "LISTEN test",
        ] {
            assert!(fixture_sql(sql, true).is_none());
        }
        assert_eq!(fixture_sql(" select 1; ", true), Some("SELECT 1"));
    }

    #[test]
    fn preserves_prepared_name_and_parameter_types() -> io::Result<()> {
        let source = b"name\0SELECT id, payload FROM fixture_items WHERE id = $1\0\0\x01\0\0\0\x17";
        let mut frame = Frame {
            tag: b'P',
            body: source.to_vec(),
        };
        admit(&mut frame, None).map_err(|_| protocol_error())?;
        let mut body = frame.body.as_slice();
        assert_eq!(take_string(&mut body)?, "name");
        assert_eq!(take_string(&mut body)?, READ_ITEM);
        assert_eq!(body, &[0, 1, 0, 0, 0, 23]);
        Ok(())
    }

    #[test]
    fn applies_native_byte_limit_to_each_handle_field() {
        for (name, is_valid) in [
            (format!("{}é", "a".repeat(61)), true),
            (format!("{}é", "a".repeat(62)), false),
        ] {
            for (tag, body) in [
                (b'P', format!("{name}\0SELECT 1\0\0\0")),
                (b'B', format!("{name}\0short\0\0\0\0\0\0\0")),
                (b'B', format!("short\0{name}\0\0\0\0\0\0\0")),
                (b'E', format!("{name}\0\0\0\0\0")),
                (b'D', format!("S{name}\0")),
                (b'D', format!("P{name}\0")),
                (b'C', format!("S{name}\0")),
                (b'C', format!("P{name}\0")),
            ] {
                let result = admit(
                    &mut Frame {
                        tag,
                        body: body.into_bytes(),
                    },
                    None,
                );
                if is_valid {
                    assert!(
                        result.is_ok(),
                        "{} rejected a 63-byte name",
                        char::from(tag)
                    );
                } else {
                    assert!(matches!(result, Err(WireError::Protocol)));
                }
            }
        }
    }

    #[test]
    fn branch_parse_preserves_scalar_oids_and_rejects_custom_oids() -> io::Result<()> {
        use fg_protocol_common::{BranchBinding, CatalogColumn, CatalogEntry};
        use fg_rewrite::Dialect;

        let branch = BranchBinding {
            id: 2,
            generation_id: 1,
            engine: "postgresql".into(),
            name: "feature-branch".into(),
            default_schema: "app".into(),
            class: fg_protocol_common::BranchClass::Dev,
            access: fg_protocol_common::BranchAccess::ReadOnly,
            layout: fg_protocol_common::BranchLayout::SparseDelta,
            read_strategy: fg_protocol_common::ReadStrategy::Merge,
            audit_witness_ready: false,
            snapshot_manifest: None,
            expires_at: i64::MAX,
            write_schema: None,
            replay_origin: None,
            tables: vec![CatalogEntry {
                id: 1,
                baseline_rows: 4,
                generated_key: None,
                logical_schema: "app".into(),
                logical_table: "orders".into(),
                base_schema: "fg_g1".into(),
                base_table: "orders".into(),
                delta_schema: "forkget_delta".into(),
                delta_table: "_d_g1_t1".into(),
                columns: vec![CatalogColumn {
                    name: "id".into(),
                    type_name: "BIGINT".into(),
                    nullable: false,
                    primary_key_ordinal: Some(1),
                }],
            }],
        };
        let build_parse = |oid: u32| {
            let mut body =
                b"client_statement\0SELECT id FROM orders WHERE id = $1\0\0\x01".to_vec();
            body.extend_from_slice(&oid.to_be_bytes());
            Frame { tag: b'P', body }
        };
        let compiler =
            BoundCompiler::new(Dialect::PostgreSql, &branch).map_err(|_| protocol_error())?;
        let mut valid = build_parse(20);
        admit(&mut valid, Some(&compiler)).map_err(|_| protocol_error())?;
        let mut body = valid.body.as_slice();
        assert_eq!(take_string(&mut body)?, "client_statement");
        let lowered = take_string(&mut body)?;
        assert!(lowered.contains("\"fg_g1\".\"orders\""));
        assert!(lowered.contains("id = $1"));
        assert_eq!(body, &[0, 1, 0, 0, 0, 20]);
        assert!(matches!(
            admit(&mut build_parse(99_000), Some(&compiler)),
            Err(WireError::Unsupported)
        ));
        Ok(())
    }

    #[test]
    fn bind_formats_have_separate_parameter_and_result_limits() {
        let mut wide_result = b"\0\0\0\0\0\0\0\x11".to_vec();
        wide_result.extend([0; 34]);
        assert!(validate_bind(&wide_result).is_ok());

        let mut wide_input = b"\0\0".to_vec();
        wide_input.extend(((MAX_BIND_PARAMETERS + 1) as u16).to_be_bytes());
        wide_input.extend(vec![0; 2 * (MAX_BIND_PARAMETERS + 1) + 4]);
        assert!(validate_bind(&wide_input).is_err());
    }

    #[test]
    fn generated_bind_keeps_native_values_and_formats_hidden_from_client() -> io::Result<()> {
        use fg_protocol_common::GENERATED_ID_START;

        let mut input = b"portal\0statement\0".to_vec();
        // One shared binary format, followed by two values and one text result format.
        input.extend([
            0, 1, 0, 1, 0, 2, 0, 0, 0, 2, 0x12, 0x34, 0xff, 0xff, 0xff, 0xff,
        ]);
        input.extend([0, 1, 0, 0]);
        validate_bind(&input)?;
        assert!(BindWithGenerated::parse(&input, 1).is_err());
        let with_generated = BindWithGenerated::parse(&input, 2)?.with_start(GENERATED_ID_START);
        let mut expected = b"portal\0statement\0".to_vec();
        expected.extend([
            0, 3, 0, 1, 0, 1, 0, 1, 0, 3, 0, 0, 0, 2, 0x12, 0x34, 0xff, 0xff, 0xff, 0xff,
        ]);
        expected.extend([0, 0, 0, 8]);
        expected.extend(GENERATED_ID_START.to_be_bytes());
        expected.extend([0, 1, 0, 0]);
        assert_eq!(with_generated, expected);
        assert_eq!(
            refuse_generated_bind(&input)?,
            b"portal\0statement\0\0\0\0\0\0\0"
        );

        let input = b"\0\0\0\0\0\x01\0\0\0\x01a\0\0";
        validate_bind(input)?;
        let with_generated = BindWithGenerated::parse(input, 1)?.with_start(GENERATED_ID_START);
        assert_eq!(&with_generated[..10], b"\0\0\0\x02\0\0\0\x01\0\x02");
        Ok(())
    }

    #[test]
    fn hidden_bigint_type_round_trips_without_changing_client_oids() -> io::Result<()> {
        let mut types = Vec::new();
        append_generated_type(&mut types, &[0, 1, 0, 0, 0, 23], 2);
        assert_eq!(types, [0, 3, 0, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 20]);
        // Native inference filled in the second, unspecified client type.
        types[9] = 25;
        strip_generated_type(&mut types, 2)?;
        assert_eq!(types, [0, 2, 0, 0, 0, 23, 0, 0, 0, 25]);
        assert!(strip_generated_type(&mut types, 2).is_err());
        Ok(())
    }

    #[test]
    fn point_keys_refuse_approximate_and_non_numeric_declared_oids() {
        let float_oid = [0, 2, 0, 0, 0, 25, 0, 0, 2, 189];
        assert!(validate_bound_types(&float_oid, 2).is_ok());
        assert!(validate_point_types(&float_oid, &[2]).is_err());
        assert!(validate_point_types(&float_oid, &[1]).is_err());
        let int_oid = [0, 2, 0, 0, 0, 25, 0, 0, 0, 20];
        assert!(validate_point_types(&int_oid, &[2]).is_ok());
        assert!(validate_point_types(&[0, 0], &[2]).is_ok());
    }
}
