//! The backend connection shared by the spike passthrough and the branch
//! admission session: SCRAM-SHA-256 client authentication, single-command
//! round trips, and byte-exact frame forwarding.

use std::io;
use std::net::SocketAddr;

use fg_protocol_common::{Config, HANDSHAKE_TIMEOUT};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::scram::{self};
use crate::wire::{self, Message, OpMsg, op_msg_body};
use crate::{Error, MAX_READ_BUFFER, OPCODE_MSG};

/// The backend connection. The spike authenticates with a 1:1 mirror of the
/// frontend account; the branch session authenticates with the deployment
/// service account, keeping frontend credentials out of native authentication.
pub(crate) struct Backend {
    reader: Box<dyn AsyncRead + Unpin + Send>,
    writer: Box<dyn AsyncWrite + Unpin + Send>,
    request_id: i32,
    /// mongod's identifier for this connection; the drain registry keys on
    /// it, mirroring the SQL frontends' native connection ids.
    connection_id: u32,
    usable: bool,
}

impl Backend {
    pub(crate) async fn connect(
        addr: SocketAddr,
        auth_db: &str,
        user: &str,
        password: &str,
    ) -> Result<Self, Error> {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true).ok();
        Self::from_stream(stream, auth_db, user, password).await
    }

    pub(crate) async fn connect_tls(config: &Config, auth_db: &str) -> Result<Self, Error> {
        let stream = TcpStream::connect(config.backend).await?;
        stream.set_nodelay(true).ok();
        let stream = timeout(
            HANDSHAKE_TIMEOUT,
            config
                .backend_tls
                .connect(config.backend_name.clone(), stream),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "MongoDB backend TLS timed out"))??;
        Self::from_stream(
            stream,
            auth_db,
            &config.backend_user,
            &config.backend_password,
        )
        .await
    }

    async fn from_stream(
        stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
        auth_db: &str,
        user: &str,
        password: &str,
    ) -> Result<Self, Error> {
        let (reader, writer) = tokio::io::split(stream);
        let mut backend = Self {
            reader: Box::new(reader),
            writer: Box::new(writer),
            request_id: 10_000,
            connection_id: 0,
            usable: true,
        };
        backend.authenticate(auth_db, user, password).await?;
        // mongod reports this connection's id in hello; the drain registry
        // needs it to distinguish this session from others of the same user.
        let hello = backend
            .command(&bson::doc! { "hello": 1i32, "$db": "admin" })
            .await?;
        backend.connection_id = connection_id(&hello).ok_or(Error::Invalid)?;
        Ok(backend)
    }

    /// Run one command and accept only its complete, correlated response.
    /// A failed exchange poisons the socket: its unread response cannot be
    /// mistaken for the acknowledgment of a later write.
    pub(crate) async fn command(
        &mut self,
        document: &bson::Document,
    ) -> Result<bson::Document, Error> {
        if !self.usable {
            return Err(Error::Invalid);
        }
        let Some(request_id) = self.request_id.checked_add(1) else {
            self.usable = false;
            return Err(Error::Invalid);
        };
        self.request_id = request_id;
        let message = Message {
            request_id: self.request_id,
            response_to: 0,
            opcode: OPCODE_MSG,
            body: op_msg_body(0, document)?,
        };
        let frame = message.into_bytes();
        self.usable = false;
        write_message(&mut self.writer, &frame).await?;
        let reply = read_message(&mut self.reader).await?;
        let document = command_reply(&reply, self.request_id)?;
        self.usable = true;
        Ok(document)
    }

    pub(crate) fn is_usable(&self) -> bool {
        self.usable
    }

    pub(crate) fn invalidate(&mut self) {
        self.usable = false;
    }

    #[cfg(test)]
    pub(crate) fn test_stream(stream: tokio::io::DuplexStream) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: Box::new(reader),
            writer: Box::new(writer),
            request_id: 10,
            connection_id: 1,
            usable: true,
        }
    }

    async fn authenticate(
        &mut self,
        auth_db: &str,
        user: &str,
        password: &str,
    ) -> Result<(), Error> {
        let client = scram::ClientExchange::start(user).map_err(|_| Error::Invalid)?;
        let start = bson::doc! {
            "saslStart": 1i32,
            "mechanism": scram::MECHANISM,
            "payload": bson::Binary {
                bytes: client.initial_payload().into_bytes(),
                subtype: bson::spec::BinarySubtype::Generic,
            },
            "options": { "skipEmptyExchange": true },
            "$db": auth_db,
        };
        let first = self.command(&start).await?;
        let server_first = binary_payload(&first)?;
        let (client_final, server_signature) = client
            .finish(&server_first, user, password)
            .map_err(|_| Error::Invalid)?;
        let continue_command = bson::doc! {
            "saslContinue": 1i32,
            "conversationId": first.get_i32("conversationId").unwrap_or(1),
            "payload": bson::Binary {
                bytes: client_final.into_bytes(),
                subtype: bson::spec::BinarySubtype::Generic,
            },
            "$db": auth_db,
        };
        let final_reply = self.command(&continue_command).await?;
        let payload = binary_payload(&final_reply)?;
        scram::verify_server(&payload, &server_signature).map_err(|_| Error::Invalid)?;
        if !final_reply.get_bool("done").unwrap_or(true) {
            // Without skipEmptyExchange mongod expects one empty exchange.
            let empty = bson::doc! {
                "saslContinue": 1i32,
                "conversationId": first.get_i32("conversationId").unwrap_or(1),
                "payload": bson::Binary {
                    bytes: Vec::new(),
                    subtype: bson::spec::BinarySubtype::Generic,
                },
                "$db": auth_db,
            };
            let reply = self.command(&empty).await?;
            if !reply.get_bool("done").unwrap_or(false) {
                return Err(Error::Invalid);
            }
        }
        Ok(())
    }

    /// Forward one client frame byte-exact (with optional/unknown request
    /// flags cleared) and relay mongod's reply; moreToCome writes expect no
    /// reply at all.
    pub(crate) async fn forward(
        &mut self,
        request: &Message,
        op_msg: &OpMsg,
    ) -> Result<Vec<u8>, Error> {
        let mut body = Vec::with_capacity(4 + op_msg.sections.len());
        body.extend_from_slice(&op_msg.flags.to_le_bytes());
        body.extend_from_slice(&op_msg.sections);
        let message = Message {
            request_id: request.request_id,
            response_to: request.response_to,
            opcode: OPCODE_MSG,
            body,
        };
        let frame = message.into_bytes();
        write_message(&mut self.writer, &frame).await?;
        if op_msg.more_to_come {
            return Ok(Vec::new());
        }
        let reply = read_message(&mut self.reader).await?;
        Ok(reply.into_bytes())
    }

    pub(crate) fn connection_id(&self) -> u32 {
        self.connection_id
    }
}

fn command_reply(reply: &Message, request_id: i32) -> Result<bson::Document, Error> {
    if reply.opcode != OPCODE_MSG || reply.response_to != request_id {
        return Err(Error::Invalid);
    }
    let message = wire::parse_op_msg(&reply.body)?;
    if message.flags != 0 || message.sections.first() != Some(&0) {
        return Err(Error::Invalid);
    }
    let mut cursor = io::Cursor::new(&message.sections[1..]);
    let document = bson::Document::from_reader(&mut cursor).map_err(|_| Error::Invalid)?;
    if usize::try_from(cursor.position()).ok() != Some(message.sections.len() - 1) {
        return Err(Error::Invalid);
    }
    Ok(document)
}

/// mongod reports `connectionId` as NumberInt on some versions and NumberLong
/// on others; accept both.
pub(crate) fn connection_id(document: &bson::Document) -> Option<u32> {
    let id = match document.get_i32("connectionId") {
        Ok(id) => i64::from(id),
        Err(_) => document.get_i64("connectionId").ok()?,
    };
    u32::try_from(id).ok()
}

pub(crate) async fn write_message(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin),
    frame: &[u8],
) -> io::Result<()> {
    stream.write_all(frame).await
}

pub(crate) async fn read_message(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
) -> Result<Message, Error> {
    let mut header = [0u8; wire::HEADER_LEN];
    stream.read_exact(&mut header).await?;
    let length = i32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
    if !(wire::HEADER_LEN..=MAX_READ_BUFFER).contains(&length) {
        return Err(Error::Oversize(length));
    }
    let mut frame = header.to_vec();
    frame.resize(length, 0);
    stream.read_exact(&mut frame[wire::HEADER_LEN..]).await?;
    if frame.len() < wire::HEADER_LEN {
        return Err(Error::Invalid);
    }
    wire::parse(&frame)
}

pub(crate) fn binary_payload(document: &bson::Document) -> Result<Vec<u8>, Error> {
    match document.get("payload") {
        Some(bson::Bson::Binary(binary)) => Ok(binary.bytes.clone()),
        _ => Err(Error::Invalid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(response_to: i32) -> Result<Message, Error> {
        Ok(Message {
            request_id: 9,
            response_to,
            opcode: OPCODE_MSG,
            body: op_msg_body(0, &bson::doc! {"ok": 1, "n": 1})?,
        })
    }

    #[test]
    fn write_ack_must_match_request_and_complete_message() -> Result<(), Error> {
        let reply = response(17)?;
        assert!(command_reply(&reply, 17).is_ok());
        assert!(command_reply(&reply, 18).is_err());
        let mut extra = response(17)?;
        extra.body.extend_from_slice(&[0, 5, 0, 0, 0, 0]);
        assert!(command_reply(&extra, 17).is_err());
        let mut continued = response(17)?;
        continued.body[0] = wire::FLAG_MORE_TO_COME as u8;
        assert!(command_reply(&continued, 17).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn lost_or_unrelated_ack_prevents_a_second_native_send() -> Result<(), Error> {
        let (stream, mut peer) = tokio::io::duplex(4096);
        let (reader, writer) = tokio::io::split(stream);
        let mut backend = Backend {
            reader: Box::new(reader),
            writer: Box::new(writer),
            request_id: 10,
            connection_id: 1,
            usable: true,
        };
        let server = tokio::spawn(async move {
            let request = read_message(&mut peer).await?;
            let wrong = response(request.request_id + 1)?;
            write_message(&mut peer, &wrong.into_bytes()).await?;
            Ok::<_, Error>(peer)
        });
        assert!(backend.command(&bson::doc! {"insert":"t"}).await.is_err());
        assert!(!backend.is_usable());
        let mut peer = server.await.map_err(|_| Error::Invalid)??;
        assert!(backend.command(&bson::doc! {"insert":"t"}).await.is_err());
        assert!(
            timeout(
                std::time::Duration::from_millis(20),
                read_message(&mut peer)
            )
            .await
            .is_err()
        );
        Ok(())
    }
}
