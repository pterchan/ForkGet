//! Insert the private transaction witness without ending an extended cycle.

use std::io;

use tokio::io::{AsyncRead, AsyncWrite};

use super::bounded;
use crate::wire::{backend_error, cstring, read_frame, write_frame};

const STATEMENT: &str = "_fg_witness_s";
const PORTAL: &str = "_fg_witness_p";
const MAX_ASYNC_FRAMES: usize = 32;

/// False means PostgreSQL rejected the witness and the failed cycle was synced.
pub(super) async fn insert(
    backend: &mut (impl AsyncRead + AsyncWrite + Unpin),
    sql: &str,
) -> io::Result<bool> {
    let mut parse = Vec::new();
    cstring(&mut parse, STATEMENT);
    cstring(&mut parse, sql);
    parse.extend_from_slice(&0u16.to_be_bytes());
    bounded(write_frame(backend, b'P', &parse)).await??;
    let mut bind = Vec::new();
    cstring(&mut bind, PORTAL);
    cstring(&mut bind, STATEMENT);
    bind.extend_from_slice(&[0; 6]);
    bounded(write_frame(backend, b'B', &bind)).await??;
    let mut execute = Vec::new();
    cstring(&mut execute, PORTAL);
    execute.extend_from_slice(&0u32.to_be_bytes());
    bounded(write_frame(backend, b'E', &execute)).await??;
    for (kind, name) in [(b'P', PORTAL), (b'S', STATEMENT)] {
        let mut close = vec![kind];
        cstring(&mut close, name);
        bounded(write_frame(backend, b'C', &close)).await??;
    }
    bounded(write_frame(backend, b'H', &[])).await??;
    for expected in [b'1', b'2', b'C', b'3', b'3'] {
        let response = response(backend).await?;
        if response.tag == b'E' {
            return abort_cycle(backend).await;
        }
        if response.tag != expected
            || (expected == b'C' && response.body != b"INSERT 0 1\0")
            || (expected != b'C' && !response.body.is_empty())
        {
            return Err(backend_error());
        }
    }
    Ok(true)
}

async fn response(backend: &mut (impl AsyncRead + Unpin)) -> io::Result<crate::wire::Frame> {
    for _ in 0..MAX_ASYNC_FRAMES {
        let response = bounded(read_frame(backend)).await??;
        if !matches!(response.tag, b'N' | b'S') {
            return Ok(response);
        }
    }
    Err(backend_error())
}

async fn abort_cycle(backend: &mut (impl AsyncRead + AsyncWrite + Unpin)) -> io::Result<bool> {
    // Sync can only roll back this failed cycle. The success path never sends
    // one: doing so would commit an application's implicit extended transaction.
    bounded(write_frame(backend, b'S', &[])).await??;
    let ready = response(backend).await?;
    if ready.tag != b'Z' || !matches!(ready.body.as_slice(), b"I" | b"E") {
        return Err(backend_error());
    }
    // An Execute failure leaves its successfully parsed named statement alive.
    // Protocol Close is safe in a failed transaction and tolerates absent names.
    for (kind, name) in [(b'P', PORTAL), (b'S', STATEMENT)] {
        let mut close = vec![kind];
        cstring(&mut close, name);
        bounded(write_frame(backend, b'C', &close)).await??;
    }
    bounded(write_frame(backend, b'H', &[])).await??;
    for _ in 0..2 {
        let closed = response(backend).await?;
        if closed.tag != b'3' || !closed.body.is_empty() {
            return Err(backend_error());
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::take_string;

    async fn requests(peer: &mut tokio::io::DuplexStream) -> io::Result<()> {
        for tag in [b'P', b'B', b'E', b'C', b'C', b'H'] {
            let frame = read_frame(peer).await?;
            assert_eq!(frame.tag, tag);
            if tag == b'P' {
                let mut rest = frame.body.as_slice();
                assert_eq!(take_string(&mut rest)?, STATEMENT);
                assert_eq!(take_string(&mut rest)?, "INSERT witness");
                assert_eq!(rest, [0, 0]);
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn success_uses_only_private_extended_frames_and_consumes_all_replies() -> io::Result<()>
    {
        let (mut backend, mut peer) = tokio::io::duplex(4096);
        let server = async {
            requests(&mut peer).await?;
            for (tag, body) in [
                (b'1', &b""[..]),
                (b'2', b""),
                (b'C', b"INSERT 0 1\0"),
                (b'3', b""),
                (b'3', b""),
            ] {
                write_frame(&mut peer, tag, body).await?;
            }
            // The next application Sync belongs to the caller, not this helper.
            let sync = read_frame(&mut peer).await?;
            assert_eq!(sync.tag, b'S');
            write_frame(&mut peer, b'Z', b"I").await
        };
        let client = async {
            assert!(insert(&mut backend, "INSERT witness").await?);
            write_frame(&mut backend, b'S', &[]).await?;
            assert_eq!(read_frame(&mut backend).await?.tag, b'Z');
            Ok::<_, io::Error>(())
        };
        let (server, client) = tokio::join!(server, client);
        server?;
        client
    }

    #[tokio::test]
    async fn native_failure_syncs_only_the_aborted_cycle() -> io::Result<()> {
        let (mut backend, mut peer) = tokio::io::duplex(4096);
        let server = async {
            requests(&mut peer).await?;
            write_frame(&mut peer, b'E', b"SERROR\0C42501\0Mprivate\0\0").await?;
            assert_eq!(read_frame(&mut peer).await?.tag, b'S');
            write_frame(&mut peer, b'Z', b"E").await?;
            for tag in [b'C', b'C', b'H'] {
                assert_eq!(read_frame(&mut peer).await?.tag, tag);
            }
            write_frame(&mut peer, b'3', &[]).await?;
            write_frame(&mut peer, b'3', &[]).await
        };
        let client = async {
            assert!(!insert(&mut backend, "INSERT witness").await?);
            Ok::<_, io::Error>(())
        };
        let (server, client) = tokio::join!(server, client);
        server?;
        client
    }
}
