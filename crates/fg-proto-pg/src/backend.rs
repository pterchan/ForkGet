//! Each frontend owns a distinct verified TLS connection to native PostgreSQL.

use std::io;

use fg_protocol_common::{Config, HANDSHAKE_TIMEOUT};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::client::TlsStream;

use crate::{
    scram::{self, ClientExchange, MECHANISM},
    wire::{
        CANCEL_REQUEST, Frame, SSL_REQUEST, VERSION, backend_error, cstring, end, read_frame,
        take_string, take_u32, write_frame, write_startup,
    },
};

pub(crate) type Stream = TlsStream<TcpStream>;

pub(crate) struct Backend {
    pub(crate) stream: Stream,
    pub(crate) key: [u8; 8],
    pub(crate) parameters: Vec<Frame>,
}

impl Backend {
    pub(crate) async fn connect(config: &Config, is_branch: bool) -> io::Result<Self> {
        let mut stream = secure_stream(config).await?;
        write_startup(&mut stream, &startup(config, is_branch)).await?;
        authenticate(&mut stream, &config.backend_password).await?;
        collect_startup(stream).await
    }

    pub(crate) fn connection_id(&self) -> u32 {
        let [first, second, third, fourth, ..] = self.key;
        u32::from_be_bytes([first, second, third, fourth])
    }
}

fn startup(config: &Config, is_branch: bool) -> Vec<u8> {
    let mut body = VERSION.to_be_bytes().to_vec();
    for (key, value) in [
        ("user", config.backend_user.as_str()),
        ("database", config.backend_database.as_str()),
        ("client_encoding", "UTF8"),
        (
            "application_name",
            if is_branch {
                "fg-proxy"
            } else {
                "fg-p1-fixture"
            },
        ),
    ] {
        cstring(&mut body, key);
        cstring(&mut body, value);
    }
    if is_branch {
        // Logical resolution happens before lowering, and the parser
        // and engine must use the same lexical mode.
        for (key, value) in [
            ("search_path", "pg_catalog"),
            ("standard_conforming_strings", "on"),
            ("DateStyle", "ISO, MDY"),
            ("TimeZone", "UTC"),
        ] {
            cstring(&mut body, key);
            cstring(&mut body, value);
        }
    }
    body.push(0);
    body
}

async fn secure_stream(config: &Config) -> io::Result<Stream> {
    let mut stream = TcpStream::connect(config.backend).await?;
    stream.set_nodelay(true).ok();
    write_startup(&mut stream, &SSL_REQUEST.to_be_bytes()).await?;
    if stream.read_u8().await? != b'S' {
        return Err(backend_error());
    }
    config
        .backend_tls
        .connect(config.backend_name.clone(), stream)
        .await
}

async fn authenticate(stream: &mut Stream, password: &str) -> io::Result<()> {
    let mechanisms = auth_frame(stream, 10).await?;
    if !supports_scram(&mechanisms)? {
        return Err(backend_error());
    }
    let client = ClientExchange::start()?;
    let initial = client.initial_response();
    let mut body = Vec::new();
    cstring(&mut body, MECHANISM);
    body.extend_from_slice(&(initial.len() as u32).to_be_bytes());
    body.extend_from_slice(initial.as_bytes());
    write_frame(stream, b'p', &body).await?;
    let challenge = auth_frame(stream, 11).await?;
    let (response, signature) = client.answer(&challenge, password)?;
    write_frame(stream, b'p', response.as_bytes()).await?;
    scram::verify_server(&auth_frame(stream, 12).await?, signature)?;
    end(&auth_frame(stream, 0).await?)
}

async fn auth_frame(stream: &mut Stream, code: u32) -> io::Result<Vec<u8>> {
    let frame = read_frame(stream).await?;
    let mut body = frame.body.as_slice();
    if frame.tag != b'R' || take_u32(&mut body)? != code {
        return Err(backend_error());
    }
    Ok(body.to_vec())
}

fn supports_scram(mut body: &[u8]) -> io::Result<bool> {
    let mut supported = false;
    loop {
        match take_string(&mut body)? {
            "" => {
                end(body)?;
                return Ok(supported);
            }
            MECHANISM => supported = true,
            _ => (),
        }
    }
}

async fn collect_startup(mut stream: Stream) -> io::Result<Backend> {
    let mut key = None;
    let mut parameters = Vec::new();
    for _ in 0..32 {
        let frame = read_frame(&mut stream).await?;
        match frame.tag {
            b'K' if key.is_none() => {
                key = Some(frame.body.try_into().map_err(|_| backend_error())?);
            }
            b'S' => parameters.push(frame),
            b'N' => (),
            b'Z' if frame.body == b"I" => {
                return Ok(Backend {
                    stream,
                    key: key.ok_or_else(backend_error)?,
                    parameters,
                });
            }
            _ => return Err(backend_error()),
        }
    }
    Err(backend_error())
}

pub(crate) async fn cancel(config: &Config, key: [u8; 8]) -> io::Result<()> {
    timeout(HANDSHAKE_TIMEOUT, send_cancel(config, key))
        .await
        .map_err(|_| backend_error())?
}

async fn send_cancel(config: &Config, key: [u8; 8]) -> io::Result<()> {
    let mut stream = secure_stream(config).await?;
    let mut body = CANCEL_REQUEST.to_be_bytes().to_vec();
    body.extend_from_slice(&key);
    write_startup(&mut stream, &body).await?;
    // PostgreSQL closes without a response. Wait so the next query cannot
    // overtake cancellation on its independent connection.
    let mut unexpected = [0];
    match stream.read(&mut unexpected).await {
        Ok(0) => (),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => (),
        _ => return Err(backend_error()),
    }
    let _ = stream.shutdown().await;
    Ok(())
}
