//! Native result sequence relay with logical column identities.

use std::io;

use fg_protocol_common::{BRANCH, IO_TIMEOUT, NativeErrorClass, WireError};
use fg_rewrite::{OutputColumn, PlanMapping};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;

use crate::handshake::{BackStream, ERR, OK, send_error, send_mapped_error};
use crate::packet::{self, Fields, MESSAGE_LIMIT, MetadataBatch, put_lenbytes};

const EOF: u8 = 0xfe;
const LOCAL_INFILE: u8 = 0xfb;
const MAX_COLUMNS: usize = 256;
const MAX_PARAMETERS: usize = 16_384;
const DUPLICATE_ENTRY: u16 = WireError::Unique.mysql().0;
const NO_REFERENCED_ROW_LEGACY: u16 = 1216;
const ROW_IS_REFERENCED_LEGACY: u16 = 1217;
const ROW_IS_REFERENCED: u16 = 1451;
const NO_REFERENCED_ROW: u16 = WireError::ForeignKey.mysql().0;
const BAD_NULL: u16 = 1048;
const DATA_OUT_OF_RANGE: u16 = 1264;
const DATA_TRUNCATED: u16 = 1265;
const TRUNCATED_WRONG_VALUE: u16 = 1292;
const NO_DEFAULT_FOR_FIELD: u16 = 1364;
const TRUNCATED_WRONG_VALUE_FOR_FIELD: u16 = 1366;
const DATA_TOO_LONG: u16 = 1406;
const CHECK_CONSTRAINT_VIOLATED: u16 = 3819;

pub(crate) struct Relay<'a, W, B = BackStream> {
    pub(crate) backend: &'a mut B,
    pub(crate) frontend: &'a mut W,
    pub(crate) metadata: &'a mut MetadataBatch,
    pub(crate) back_sequence: u8,
    pub(crate) front_sequence: u8,
    pub(crate) is_branch: bool,
    pub(crate) is_writable: bool,
    pub(crate) has_found_rows: bool,
}

impl<W: AsyncWrite + Unpin, B: AsyncRead + AsyncWrite + Unpin> Relay<'_, W, B> {
    pub(crate) async fn start(&mut self, command: &[u8]) -> io::Result<()> {
        self.back_sequence = 0;
        timeout(
            IO_TIMEOUT,
            packet::write(self.backend, &mut self.back_sequence, command),
        )
        .await?
    }

    pub(crate) async fn internal_ok(&mut self) -> io::Result<()> {
        let reply = self.read().await?;
        if reply.first() != Some(&OK) {
            return Err(packet::invalid());
        }
        Ok(())
    }

    pub(crate) async fn simple(&mut self) -> io::Result<()> {
        let first = self.read().await?;
        match first.first() {
            Some(&OK) => self.write(&first).await,
            Some(&ERR) => self.native_error(&first).await,
            _ => Err(packet::invalid()),
        }
    }

    pub(crate) async fn query(&mut self, output: Option<&[OutputColumn]>) -> io::Result<()> {
        self.query_mapped(output, None, false).await
    }

    pub(crate) async fn query_plan(
        &mut self,
        output: Option<&[OutputColumn]>,
        mapping: &PlanMapping,
        binary: bool,
    ) -> io::Result<()> {
        self.query_mapped(output, Some(mapping), binary).await
    }

    async fn query_mapped(
        &mut self,
        output: Option<&[OutputColumn]>,
        mapping: Option<&PlanMapping>,
        binary: bool,
    ) -> io::Result<()> {
        let first = self.read().await?;
        match first.first() {
            Some(&OK) if output.is_some() => return self.inconsistent_metadata().await,
            Some(&OK) => return self.write(&first).await,
            Some(&ERR) => return self.native_error(&first).await,
            None | Some(&LOCAL_INFILE) => return Err(packet::invalid()),
            _ => {}
        }
        let mut fields = Fields(&first);
        let columns = fields.lenenc()?;
        if columns == 0 || columns > MAX_COLUMNS || !fields.0.is_empty() {
            return Err(packet::invalid());
        }
        if output.is_some_and(|output| output.len() != columns) {
            return self.inconsistent_metadata().await;
        }
        self.write_metadata(&first).await?;
        self.columns(columns, output).await?;
        loop {
            let row = self.read().await?;
            match row.first() {
                Some(&ERR) => return self.native_error(&row).await,
                Some(&EOF) if row.len() < 9 => return self.eof(&row).await,
                Some(_) => {
                    if let Some(mapping) = mapping {
                        let row = sanitize_plan_row(&row, mapping, binary)?;
                        self.write(&row).await?;
                    } else {
                        self.write(&row).await?;
                    }
                }
                None => return Err(packet::invalid()),
            }
        }
    }

    pub(crate) async fn prepare(
        &mut self,
        expected: Option<(usize, &[OutputColumn])>,
    ) -> io::Result<Option<u32>> {
        let first = self.read().await?;
        let mut fields = Fields(&first);
        match fields.byte()? {
            ERR => {
                self.native_error(&first).await?;
                return Ok(None);
            }
            OK => {}
            _ => return Err(packet::invalid()),
        }
        let id = fields.u32()?;
        let columns = usize::from(fields.u16()?);
        let parameters = usize::from(fields.u16()?);
        if fields.byte()? != 0
            || fields.u16().is_err()
            || !fields.0.is_empty()
            || columns > MAX_COLUMNS
            || parameters > MAX_PARAMETERS
        {
            return Err(packet::invalid());
        }
        if expected.is_some_and(|(binds, output)| binds != parameters || output.len() != columns) {
            return self.inconsistent_metadata().await;
        }
        self.write_metadata(&first).await?;
        self.columns(parameters, None).await?;
        self.columns(columns, expected.map(|(_, output)| output))
            .await?;
        self.flush_metadata().await?;
        Ok(Some(id))
    }

    async fn inconsistent_metadata<T>(&mut self) -> io::Result<T> {
        self.error(WireError::Backend).await?;
        Err(packet::invalid())
    }

    async fn columns(&mut self, count: usize, output: Option<&[OutputColumn]>) -> io::Result<()> {
        for index in 0..count {
            let column = self.read().await?;
            if column.first() == Some(&ERR) {
                self.native_error(&column).await?;
                return Err(packet::invalid());
            }
            let logical = output.and_then(|output| output.get(index));
            self.write_metadata(&logical_column(&column, self.is_branch, logical)?)
                .await?;
        }
        if count > 0 {
            let end = self.read().await?;
            if end.first() == Some(&ERR) {
                self.native_error(&end).await?;
                return Err(packet::invalid());
            }
            validate_eof(&end)?;
            self.write_metadata(&end).await?;
            // Flush before reading rows, or the next prepared metadata group.
            // A client or backend may wait for this completed group to arrive.
            self.flush_metadata().await?;
        }
        Ok(())
    }

    async fn eof(&mut self, message: &[u8]) -> io::Result<()> {
        validate_eof(message)?;
        self.write(message).await
    }

    pub(crate) async fn read(&mut self) -> io::Result<Vec<u8>> {
        timeout(
            IO_TIMEOUT,
            packet::read(self.backend, &mut self.back_sequence, MESSAGE_LIMIT),
        )
        .await?
    }

    pub(crate) async fn write(&mut self, message: &[u8]) -> io::Result<()> {
        self.flush_metadata().await?;
        timeout(
            IO_TIMEOUT,
            packet::write(self.frontend, &mut self.front_sequence, message),
        )
        .await?
    }

    pub(crate) async fn error(&mut self, error: WireError) -> io::Result<()> {
        self.flush_metadata().await?;
        timeout(
            IO_TIMEOUT,
            send_error(self.frontend, &mut self.front_sequence, error),
        )
        .await?
    }

    pub(crate) async fn native_error(&mut self, message: &[u8]) -> io::Result<()> {
        let native = native_error_code(message)?;
        let error = classify_native_error(native.0, self.is_writable);
        self.flush_metadata().await?;
        timeout(
            IO_TIMEOUT,
            send_mapped_error(self.frontend, &mut self.front_sequence, native, error),
        )
        .await?
    }

    async fn write_metadata(&mut self, message: &[u8]) -> io::Result<()> {
        timeout(
            IO_TIMEOUT,
            self.metadata
                .write(self.frontend, &mut self.front_sequence, message),
        )
        .await?
    }

    async fn flush_metadata(&mut self) -> io::Result<()> {
        timeout(IO_TIMEOUT, self.metadata.flush(self.frontend)).await?
    }
}

fn validate_eof(message: &[u8]) -> io::Result<()> {
    if message.len() != 5 || message.first() != Some(&EOF) {
        return Err(packet::invalid());
    }
    Ok(())
}

fn sanitize_plan_row(row: &[u8], mapping: &PlanMapping, binary: bool) -> io::Result<Vec<u8>> {
    let mut input = Fields(row);
    if binary && (input.byte()? != 0 || input.byte()? != 0) {
        return Err(packet::invalid());
    }
    let json = input.lenbytes()?;
    if !input.0.is_empty() {
        return Err(packet::invalid());
    }
    let sanitized = mapping.sanitize(json).map_err(|_| packet::invalid())?;
    let mut output = if binary { vec![0, 0] } else { Vec::new() };
    put_lenbytes(&mut output, &sanitized);
    Ok(output)
}

fn classify_native_error(errno: u16, is_writable: bool) -> WireError {
    match errno {
        1213 => WireError::NativeClass(NativeErrorClass::Deadlock),
        1205 => WireError::NativeClass(NativeErrorClass::LockTimeout),
        1044 | 1045 | 1142 | 1143 | 1227 => WireError::NativeClass(NativeErrorClass::Permission),
        2006 | 2013 | 2055 => WireError::NativeClass(NativeErrorClass::Connection),
        1040 | 1041 | 1203 => WireError::NativeClass(NativeErrorClass::Resource),
        DUPLICATE_ENTRY => WireError::Unique,
        NO_REFERENCED_ROW_LEGACY
        | ROW_IS_REFERENCED_LEGACY
        | ROW_IS_REFERENCED
        | NO_REFERENCED_ROW
            if is_writable =>
        {
            WireError::ForeignKey
        }
        BAD_NULL
        | DATA_OUT_OF_RANGE
        | DATA_TRUNCATED
        | TRUNCATED_WRONG_VALUE
        | NO_DEFAULT_FOR_FIELD
        | TRUNCATED_WRONG_VALUE_FOR_FIELD
        | DATA_TOO_LONG
        | CHECK_CONSTRAINT_VIOLATED
            if is_writable =>
        {
            WireError::InvalidValue
        }
        _ => WireError::Native,
    }
}

fn native_error_code(message: &[u8]) -> io::Result<(u16, &[u8])> {
    let mut fields = Fields(message);
    if fields.byte()? != ERR {
        return Err(packet::invalid());
    }
    let errno = fields.u16()?;
    if errno == 0 || fields.byte()? != b'#' {
        return Err(packet::invalid());
    }
    let sqlstate = fields.take(5)?;
    if !sqlstate
        .iter()
        .all(|byte| byte.is_ascii_digit() || byte.is_ascii_uppercase())
    {
        return Err(packet::invalid());
    }
    Ok((errno, sqlstate))
}

fn logical_column(
    column: &[u8],
    is_branch: bool,
    logical: Option<&OutputColumn>,
) -> io::Result<Vec<u8>> {
    let mut fields = Fields(column);
    let catalog = fields.lenbytes()?;
    let schema = fields.lenbytes()?;
    let table = fields.lenbytes()?;
    let original_table = fields.lenbytes()?;
    let label = fields.lenbytes()?;
    let original_column = fields.lenbytes()?;
    let mut output = Vec::with_capacity(column.len());
    put_lenbytes(&mut output, catalog);
    if is_branch {
        put_branch_identity(&mut output, logical, label);
    } else {
        let schema = if schema.is_empty() {
            &[][..]
        } else {
            BRANCH.as_bytes()
        };
        put_lenbytes(&mut output, schema);
        for name in [table, original_table] {
            match name {
                b"fixture_items" | b"fixture_events" => put_lenbytes(&mut output, name),
                _ => put_lenbytes(&mut output, &[]),
            }
        }
        put_lenbytes(&mut output, label);
        put_lenbytes(&mut output, original_column);
    }
    if fields.0.len() != 13 || fields.0[0] != 12 {
        return Err(packet::invalid());
    }
    output.extend_from_slice(fields.0);
    Ok(output)
}

fn put_branch_identity(output: &mut Vec<u8>, logical: Option<&OutputColumn>, native_label: &[u8]) {
    let origin = logical.and_then(|logical| logical.origin.as_ref());
    let label = logical
        .and_then(|logical| logical.name.as_deref())
        .map_or(native_label, str::as_bytes);
    let schema = origin.map_or("", |origin| origin.logical_schema.as_str());
    let table = origin.map_or("", |origin| origin.logical_table.as_str());
    let visible_table = origin
        .and_then(|origin| origin.table_alias.as_deref())
        .unwrap_or(table);
    let column = origin.map_or("", |origin| origin.logical_column.as_str());
    for field in [
        schema.as_bytes(),
        visible_table.as_bytes(),
        table.as_bytes(),
        label,
        column.as_bytes(),
    ] {
        put_lenbytes(output, field);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_fixture_and_read_branch_error_categories() {
        for (errno, writable) in [
            (1292, WireError::InvalidValue),
            (3819, WireError::InvalidValue),
            (1216, WireError::ForeignKey),
            (1452, WireError::ForeignKey),
        ] {
            assert_eq!(classify_native_error(errno, false), WireError::Native);
            assert_eq!(classify_native_error(errno, true), writable);
        }
        assert_eq!(
            classify_native_error(DUPLICATE_ENTRY, false),
            WireError::Unique
        );
    }
    use fg_rewrite::ColumnOrigin;

    #[test]
    fn reads_native_error_identity_without_the_message() -> io::Result<()> {
        assert_eq!(
            native_error_code(b"\xff\xb5\x04#HY000backend-specific details")?,
            (1205, b"HY000".as_slice()),
        );
        for malformed in [
            b"\xff\x00\x00#HY000".as_slice(),
            b"\xff\xb5\x04?HY000",
            b"\xff\xb5\x04#HY00",
            b"\xff\xb5\x04#hy000",
        ] {
            assert!(native_error_code(malformed).is_err());
        }
        Ok(())
    }

    #[test]
    fn native_metadata_exposes_only_logical_names() -> io::Result<()> {
        let mut native = Vec::new();
        for field in [
            b"def".as_slice(),
            b"p1_native",
            b"fixture_items",
            b"fixture_items",
            b"payload",
            b"payload",
        ] {
            put_lenbytes(&mut native, field);
        }
        native.extend_from_slice(&[12, 63, 0, 64, 0, 0, 0, 0xfd, 128, 0, 0, 0, 0]);
        let translated = logical_column(&native, false, None)?;
        let mut fields = Fields(&translated);
        assert_eq!(fields.lenbytes()?, b"def");
        assert_eq!(fields.lenbytes()?, BRANCH.as_bytes());
        assert_eq!(fields.lenbytes()?, b"fixture_items");
        assert_eq!(
            &translated[translated.len() - 13..],
            &native[native.len() - 13..]
        );
        Ok(())
    }

    #[test]
    fn branch_metadata_uses_catalog_identity_for_direct_columns() -> io::Result<()> {
        let mut native = Vec::new();
        for field in ["def", "forkget_delta", "_d_g1_t2", "_d_g1_t2", "id", "id"] {
            put_lenbytes(&mut native, field.as_bytes());
        }
        let native_type = [12, 63, 0, 8, 0, 0, 0, 0x08, 0, 0, 0, 0, 0];
        native.extend_from_slice(&native_type);
        let column = OutputColumn {
            name: Some("order_id".into()),
            origin: Some(ColumnOrigin {
                logical_schema: "app".into(),
                logical_table: "orders".into(),
                logical_column: "id".into(),
                table_alias: Some("o".into()),
            }),
        };
        let translated = logical_column(&native, true, Some(&column))?;
        let mut fields = Fields(&translated);
        for expected in ["def", "app", "o", "orders", "order_id", "id"] {
            assert_eq!(fields.lenbytes()?, expected.as_bytes());
        }
        assert_eq!(fields.0, native_type);
        Ok(())
    }
}

#[cfg(test)]
#[path = "result/batch_tests.rs"]
mod batch_tests;
