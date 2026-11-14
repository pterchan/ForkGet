use std::io;

use fg_protocol_common::WireError;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) const SSL_REQUEST: u32 = 80877103;
pub(crate) const CANCEL_REQUEST: u32 = 80877102;
pub(crate) const GSS_REQUEST: u32 = 80877104;
pub(crate) const VERSION: u32 = 3 << 16;
const MAX_STARTUP: usize = 8 * 1024;
const MAX_FRAME: usize = 2 * 1024 * 1024;
// Combine common frame headers and bodies without copying large responses.
const COALESCE_LIMIT: usize = 16 * 1024;

#[derive(Debug)]
pub(crate) struct Frame {
    pub(crate) tag: u8,
    pub(crate) body: Vec<u8>,
}

pub(crate) async fn read_startup(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    read_body(stream, MAX_STARTUP).await
}

pub(crate) async fn read_frame(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Frame> {
    let tag = stream.read_u8().await?;
    let body = read_body(stream, MAX_FRAME).await?;
    Ok(Frame { tag, body })
}

async fn read_body(stream: &mut (impl AsyncRead + Unpin), limit: usize) -> io::Result<Vec<u8>> {
    let length = stream.read_u32().await? as usize;
    if !(4..=limit).contains(&length) {
        return Err(protocol_error());
    }
    let mut body = vec![0; length - 4];
    stream.read_exact(&mut body).await?;
    Ok(body)
}

pub(crate) async fn write_startup(
    stream: &mut (impl AsyncWrite + Unpin),
    body: &[u8],
) -> io::Result<()> {
    write_body(stream, None, body).await
}

pub(crate) async fn write_frame(
    stream: &mut (impl AsyncWrite + Unpin),
    tag: u8,
    body: &[u8],
) -> io::Result<()> {
    write_body(stream, Some(tag), body).await
}

async fn write_body(
    stream: &mut (impl AsyncWrite + Unpin),
    tag: Option<u8>,
    body: &[u8],
) -> io::Result<()> {
    let length = u32::try_from(body.len() + 4).map_err(|_| protocol_error())?;
    let header_length = if tag.is_some() { 5 } else { 4 };
    let mut header = [0; 5];
    if let Some(tag) = tag {
        header[0] = tag;
    }
    header[header_length - 4..header_length].copy_from_slice(&length.to_be_bytes());
    let header = &header[..header_length];
    if body.is_empty() {
        stream.write_all(header).await?;
    } else if header.len() + body.len() <= COALESCE_LIMIT {
        let mut framed = Vec::with_capacity(header.len() + body.len());
        framed.extend_from_slice(header);
        framed.extend_from_slice(body);
        stream.write_all(&framed).await?;
    } else {
        stream.write_all(header).await?;
        stream.write_all(body).await?;
    }
    stream.flush().await
}

pub(crate) async fn write_error(
    stream: &mut (impl AsyncWrite + Unpin),
    error: WireError,
    fatal: bool,
) -> io::Result<()> {
    let severity = if fatal { "FATAL" } else { "ERROR" };
    let message = error.to_string();
    let mut body = Vec::new();
    for (tag, value) in [
        (b'S', severity),
        (b'V', severity),
        (b'C', error.postgres()),
        (b'M', message.as_str()),
    ] {
        body.push(tag);
        cstring(&mut body, value);
    }
    body.push(0);
    write_frame(stream, b'E', &body).await
}

pub(crate) fn protocol_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, WireError::Protocol.message())
}

pub(crate) fn backend_error() -> io::Error {
    io::Error::other(WireError::Backend.message())
}

pub(crate) fn cstring(target: &mut Vec<u8>, value: &str) {
    target.extend_from_slice(value.as_bytes());
    target.push(0);
}

pub(crate) fn take_string<'a>(body: &mut &'a [u8]) -> io::Result<&'a str> {
    let index = body
        .iter()
        .position(|value| *value == 0)
        .ok_or_else(protocol_error)?;
    let (value, rest) = body.split_at(index);
    *body = &rest[1..];
    std::str::from_utf8(value).map_err(|_| protocol_error())
}

pub(crate) fn take<const SIZE: usize>(body: &mut &[u8]) -> io::Result<[u8; SIZE]> {
    let prefix = body.get(..SIZE).ok_or_else(protocol_error)?;
    *body = &body[SIZE..];
    prefix.try_into().map_err(|_| protocol_error())
}

pub(crate) fn take_u32(body: &mut &[u8]) -> io::Result<u32> {
    Ok(u32::from_be_bytes(take(body)?))
}

pub(crate) fn take_u16(body: &mut &[u8]) -> io::Result<u16> {
    Ok(u16::from_be_bytes(take(body)?))
}

pub(crate) fn end(body: &[u8]) -> io::Result<()> {
    if body.is_empty() {
        Ok(())
    } else {
        Err(protocol_error())
    }
}

pub(crate) fn public_parameter_status(body: &mut Vec<u8>, frontend_user: &str) -> io::Result<bool> {
    let mut rest = body.as_slice();
    let key = take_string(&mut rest)?;
    take_string(&mut rest)?;
    end(rest)?;
    match key {
        "session_authorization" => replace_parameter(body, "session_authorization", frontend_user),
        "is_superuser" => replace_parameter(body, "is_superuser", "off"),
        "client_encoding"
        | "DateStyle"
        | "default_transaction_read_only"
        | "in_hot_standby"
        | "integer_datetimes"
        | "IntervalStyle"
        | "server_encoding"
        | "server_version"
        | "standard_conforming_strings"
        | "TimeZone" => (),
        _ => return Ok(false),
    }
    Ok(true)
}

fn replace_parameter(body: &mut Vec<u8>, key: &str, value: &str) {
    body.clear();
    cstring(body, key);
    cstring(body, value);
}

pub(crate) fn strip_row_identity(body: &mut [u8]) -> io::Result<()> {
    let count = u16::from_be_bytes(
        body.get(..2)
            .ok_or_else(protocol_error)?
            .try_into()
            .map_err(|_| protocol_error())?,
    );
    let mut rest = &mut body[2..];
    for _ in 0..count {
        let name_length = rest
            .iter()
            .position(|value| *value == 0)
            .ok_or_else(protocol_error)?;
        rest = rest.get_mut(name_length + 1..).ok_or_else(protocol_error)?;
        let (metadata, next) = rest.split_at_mut_checked(18).ok_or_else(protocol_error)?;
        metadata[..6].fill(0);
        rest = next;
    }
    end(rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn preserves_startup_and_tagged_frames_under_partial_io() -> io::Result<()> {
        for (tag, size) in [
            (None, 0),
            (None, 7),
            (Some(b'D'), 0),
            (Some(b'D'), 7),
            (Some(b'D'), COALESCE_LIMIT - 5),
            (Some(b'D'), COALESCE_LIMIT - 4),
        ] {
            let (mut sender, mut receiver) = tokio::io::duplex(3);
            let input = vec![0x45; size];
            let sending = async {
                match tag {
                    Some(tag) => write_frame(&mut sender, tag, &input).await?,
                    None => write_startup(&mut sender, &input).await?,
                }
                sender.shutdown().await
            };
            let receiving = async {
                let mut bytes = Vec::new();
                receiver.read_to_end(&mut bytes).await?;
                Ok::<_, io::Error>(bytes)
            };
            let (sent, received) = tokio::join!(sending, receiving);
            sent?;
            let bytes = received?;
            let prefix = usize::from(tag.is_some());
            assert_eq!(bytes.len(), prefix + 4 + size);
            if let Some(tag) = tag {
                assert_eq!(bytes[0], tag);
            }
            assert_eq!(
                &bytes[prefix..prefix + 4],
                &((size + 4) as u32).to_be_bytes()
            );
            assert_eq!(&bytes[prefix + 4..], input);
        }
        Ok(())
    }

    #[tokio::test]
    async fn row_budget_details_reach_postgres_clients() -> io::Result<()> {
        for error in [
            WireError::TransactionRowLimit { rows: 3, limit: 2 },
            WireError::TableRowLimit {
                rows: 2,
                limit: 1,
                baseline: 4,
                bps: 1000,
            },
        ] {
            let mut output = Vec::new();
            write_error(&mut output, error, false).await?;
            let frame = read_frame(&mut output.as_slice()).await?;
            assert_eq!(frame.tag, b'E');
            let mut fields = frame.body.as_slice();
            let mut sqlstate = None;
            let mut message = None;
            while let Some((&tag, rest)) = fields.split_first() {
                fields = rest;
                if tag == 0 {
                    end(fields)?;
                    break;
                }
                let value = take_string(&mut fields)?;
                match tag {
                    b'C' => sqlstate = Some(value),
                    b'M' => message = Some(value),
                    _ => (),
                }
            }
            assert_eq!(sqlstate, Some("54000"));
            assert_eq!(message, Some(error.to_string().as_str()));
        }
        Ok(())
    }

    #[tokio::test]
    async fn rejects_overlong_frames_before_payload() -> io::Result<()> {
        let mut buffer: &[u8] = &[b'Q', 0x7f, 0xff, 0xff, 0xff];
        assert_eq!(
            read_frame(&mut buffer)
                .await
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::InvalidData)
        );
        Ok(())
    }

    #[test]
    fn does_not_expose_native_session_identity_or_private_status() -> io::Result<()> {
        let mut identity = b"session_authorization\0p1_service\0".to_vec();
        assert!(public_parameter_status(&mut identity, "p1_user")?);
        assert_eq!(identity, b"session_authorization\0p1_user\0");

        let mut application = b"application_name\0fg-p1-fixture\0".to_vec();
        assert!(!public_parameter_status(&mut application, "p1_user")?);

        let mut encoding = b"client_encoding\0UTF8\0".to_vec();
        assert!(public_parameter_status(&mut encoding, "p1_user")?);
        assert_eq!(encoding, b"client_encoding\0UTF8\0");
        Ok(())
    }

    #[test]
    fn strips_only_physical_column_identity() -> io::Result<()> {
        let mut body = vec![0, 1, b'i', b'd', 0];
        body.extend_from_slice(&[1; 18]);
        strip_row_identity(&mut body)?;
        assert_eq!(&body[5..11], &[0; 6]);
        assert_eq!(&body[11..], &[1; 12]);
        Ok(())
    }
}
