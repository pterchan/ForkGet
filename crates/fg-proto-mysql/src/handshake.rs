//! Independent frontend and backend TLS and authentication exchanges.

use std::io;
use std::sync::atomic::{AtomicU32, Ordering};

use fg_protocol_common::{Config, FrontendAccount, WireError, check_mysql_backend_version};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::packet::{self, Fields, HANDSHAKE_LIMIT, MESSAGE_LIMIT};

const LONG_PASSWORD: u32 = 1;
pub(crate) const FOUND_ROWS: u32 = 1 << 1;
const LONG_FLAG: u32 = 1 << 2;
const CONNECT_WITH_DB: u32 = 1 << 3;
const PROTOCOL_41: u32 = 1 << 9;
const SSL: u32 = 1 << 11;
const TRANSACTIONS: u32 = 1 << 13;
const SECURE_CONNECTION: u32 = 1 << 15;
const PLUGIN_AUTH: u32 = 1 << 19;
const CONNECT_ATTRS: u32 = 1 << 20;
const LENENC_AUTH: u32 = 1 << 21;
const REQUIRED_FLAGS: u32 = PROTOCOL_41 | SSL | SECURE_CONNECTION | PLUGIN_AUTH;
const FRONT_FLAGS: u32 = REQUIRED_FLAGS
    | LONG_PASSWORD
    | LONG_FLAG
    | CONNECT_WITH_DB
    | TRANSACTIONS
    | FOUND_ROWS
    | CONNECT_ATTRS
    | LENENC_AUTH;
const BACK_FLAGS: u32 = REQUIRED_FLAGS | LONG_PASSWORD | LONG_FLAG | CONNECT_WITH_DB | TRANSACTIONS;
const CHARSET: u8 = 45; // utf8mb4_general_ci
const AUTH_MORE_DATA: u8 = 0x01;
const AUTH_FULL: u8 = 0x04;
const AUTH_FAST_SUCCESS: u8 = 0x03;
const AUTH_SWITCH: u8 = 0xfe;
const AUTH_PLUGIN: &[u8] = b"caching_sha2_password";
const NONCE_LEN: usize = 20;
const CONNECTION_HEADER_LEN: usize = 32;
const FIXTURE_VERSION: &[u8] = b"8.0.43-forkget-fixture";
const BRANCH_VERSION: &[u8] = b"8.0.43-forkget";
pub(crate) const OK: u8 = 0x00;
pub(crate) const ERR: u8 = 0xff;
const AUTOCOMMIT: u16 = 0x0002;
static NEXT_ID: AtomicU32 = AtomicU32::new(1);

pub(crate) type FrontStream = tokio_rustls::server::TlsStream<TcpStream>;
pub(crate) type BackStream = tokio_rustls::client::TlsStream<TcpStream>;

pub(crate) struct Authenticated {
    pub(crate) stream: FrontStream,
    pub(crate) sequence: u8,
    pub(crate) flags: u32,
    pub(crate) branch: String,
    pub(crate) principal: String,
    pub(crate) expires_at: Option<i64>,
}

pub(crate) async fn frontend(
    mut stream: TcpStream,
    config: &Config,
    accounts: Option<&[FrontendAccount]>,
) -> io::Result<Authenticated> {
    let mut sequence = 0;
    packet::write(&mut stream, &mut sequence, &greeting(accounts.is_some())?).await?;
    let request = packet::read(&mut stream, &mut sequence, HANDSHAKE_LIMIT).await?;
    let Ok(request_flags) = read_ssl_request(&request) else {
        return reject(&mut stream, &mut sequence, WireError::Auth).await;
    };

    let mut stream = config.frontend_tls.accept(stream).await?;
    let response = packet::read(&mut stream, &mut sequence, HANDSHAKE_LIMIT).await?;
    let Ok(login) = Login::parse(&response, request_flags) else {
        return reject(&mut stream, &mut sequence, WireError::Protocol).await;
    };

    // Always ask for full authentication on the verified TLS session. The
    // fixture does not need a fast-auth cache or an insecure RSA fallback.
    packet::write(&mut stream, &mut sequence, &[AUTH_MORE_DATA, AUTH_FULL]).await?;
    let password = packet::read(&mut stream, &mut sequence, HANDSHAKE_LIMIT).await?;
    let Some((principal, expires_at)) = authenticated_user(config, accounts, login.user, &password)
    else {
        return reject(&mut stream, &mut sequence, WireError::Auth).await;
    };
    let Some(branch) = login.branch.and_then(|name| str::from_utf8(name).ok()) else {
        return reject(&mut stream, &mut sequence, WireError::Branch).await;
    };
    Ok(Authenticated {
        stream,
        sequence,
        flags: login.flags,
        branch: branch.to_owned(),
        principal: principal.to_owned(),
        expires_at,
    })
}

fn authenticated_user<'a>(
    config: &'a Config,
    accounts: Option<&'a [FrontendAccount]>,
    user: &[u8],
    password: &[u8],
) -> Option<(&'a str, Option<i64>)> {
    let password = password.strip_suffix(&[0])?;
    if let Some(accounts) = accounts {
        let account = accounts
            .iter()
            .find(|account| account.user.as_bytes() == user)?;
        return (bool::from(password.ct_eq(account.password.as_bytes())) && account.is_current())
            .then_some((account.user.as_str(), Some(account.expires_at)));
    }
    (bool::from(password.ct_eq(config.frontend_password.as_bytes()))
        && user == config.frontend_user.as_bytes())
    .then_some((config.frontend_user.as_str(), None))
}

fn greeting(is_branch: bool) -> io::Result<Vec<u8>> {
    let mut nonce = [0; NONCE_LEN];
    OsRng.try_fill_bytes(&mut nonce).map_err(io::Error::other)?;
    const NONCE_ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for byte in &mut nonce {
        *byte = NONCE_ALPHABET[usize::from(*byte & 0x3f)];
    }
    let mut message = vec![10];
    push_cstring(
        &mut message,
        if is_branch {
            BRANCH_VERSION
        } else {
            FIXTURE_VERSION
        },
    );
    message.extend(NEXT_ID.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    message.extend_from_slice(&nonce[..8]);
    message.push(0);
    message.extend((FRONT_FLAGS as u16).to_le_bytes());
    message.push(CHARSET);
    message.extend(AUTOCOMMIT.to_le_bytes());
    message.extend(((FRONT_FLAGS >> 16) as u16).to_le_bytes());
    message.push((NONCE_LEN + 1) as u8);
    message.extend([0; 10]);
    push_cstring(&mut message, &nonce[8..]);
    push_cstring(&mut message, AUTH_PLUGIN);
    Ok(message)
}

fn read_ssl_request(request: &[u8]) -> io::Result<u32> {
    if request.len() != CONNECTION_HEADER_LEN {
        return Err(packet::invalid());
    }
    let flags = Fields(request).u32()? & FRONT_FLAGS;
    if flags & REQUIRED_FLAGS != REQUIRED_FLAGS {
        return Err(packet::invalid());
    }
    Ok(flags)
}

struct Login<'a> {
    flags: u32,
    user: &'a [u8],
    branch: Option<&'a [u8]>,
}

impl<'a> Login<'a> {
    fn parse(response: &'a [u8], ssl_flags: u32) -> io::Result<Self> {
        let mut fields = Fields(response);
        let flags = fields.u32()? & FRONT_FLAGS;
        if flags != ssl_flags {
            return Err(packet::invalid());
        }
        fields.take(CONNECTION_HEADER_LEN - 4)?;
        let user = fields.cstring()?;
        if flags & LENENC_AUTH != 0 {
            fields.lenbytes()?;
        } else {
            let length = usize::from(fields.byte()?);
            fields.take(length)?;
        }
        let branch = if flags & CONNECT_WITH_DB != 0 {
            Some(fields.cstring()?)
        } else {
            None
        };
        if fields.cstring()? != AUTH_PLUGIN {
            return Err(packet::invalid());
        }
        if flags & CONNECT_ATTRS != 0 {
            let mut attributes = Fields(fields.lenbytes()?);
            while !attributes.0.is_empty() {
                attributes.lenbytes()?;
                attributes.lenbytes()?;
            }
        }
        if !fields.0.is_empty() {
            return Err(packet::invalid());
        }
        Ok(Self {
            flags,
            user,
            branch,
        })
    }
}

pub(crate) async fn backend(
    config: &Config,
    frontend_flags: u32,
) -> io::Result<(BackStream, Vec<u8>, u32)> {
    let mut stream = TcpStream::connect(config.backend).await?;
    stream.set_nodelay(true).ok();
    let mut sequence = 0;
    let greeting = packet::read(&mut stream, &mut sequence, HANDSHAKE_LIMIT).await?;
    let (server_flags, nonce, connection_id) = parse_backend_greeting(&greeting)?;
    let flags = (BACK_FLAGS | (frontend_flags & FOUND_ROWS)) & server_flags;
    if flags & (REQUIRED_FLAGS | CONNECT_WITH_DB) != REQUIRED_FLAGS | CONNECT_WITH_DB {
        return Err(packet::invalid());
    }

    let header = response_header(flags);
    packet::write(&mut stream, &mut sequence, &header).await?;
    let mut stream = config
        .backend_tls
        .connect(config.backend_name.clone(), stream)
        .await?;
    let mut response = header.to_vec();
    push_cstring(&mut response, config.backend_user.as_bytes());
    let scramble = scramble(config.backend_password.as_bytes(), &nonce);
    response.push(scramble.len() as u8);
    response.extend(scramble);
    push_cstring(&mut response, config.backend_database.as_bytes());
    push_cstring(&mut response, AUTH_PLUGIN);
    packet::write(&mut stream, &mut sequence, &response).await?;
    let accepted = backend_auth(
        &mut stream,
        &mut sequence,
        config.backend_password.as_bytes(),
    )
    .await?;
    Ok((stream, accepted, connection_id))
}

fn parse_backend_greeting(greeting: &[u8]) -> io::Result<(u32, [u8; NONCE_LEN], u32)> {
    let mut fields = Fields(greeting);
    if fields.byte()? != 10 {
        return Err(packet::invalid());
    }
    let version = fields.cstring()?;
    check_mysql_backend_version(version).map_err(io::Error::other)?;
    let connection_id = fields.u32()?;
    let mut nonce = [0; NONCE_LEN];
    nonce[..8].copy_from_slice(fields.take(8)?);
    if fields.byte()? != 0 {
        return Err(packet::invalid());
    }
    let lower = fields.u16()?;
    fields.take(3)?;
    let upper = fields.u16()?;
    let flags = u32::from(lower) | (u32::from(upper) << 16);
    if usize::from(fields.byte()?) != NONCE_LEN + 1 {
        return Err(packet::invalid());
    }
    fields.take(10)?;
    nonce[8..].copy_from_slice(fields.take(NONCE_LEN - 8)?);
    if fields.byte()? != 0 {
        return Err(packet::invalid());
    }
    // The greeting names the server's default plugin (MySQL 8.0 ships
    // caching_sha2_password; TiDB defaults to mysql_native_password). The
    // response below declares caching_sha2_password either way — the
    // deployment recipe creates backend users with it, and backend_auth
    // rejects any auth switch to a different plugin.
    fields.cstring()?;
    Ok((flags, nonce, connection_id))
}

async fn backend_auth(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    sequence: &mut u8,
    password: &[u8],
) -> io::Result<Vec<u8>> {
    for _ in 0..4 {
        let message = packet::read(stream, sequence, HANDSHAKE_LIMIT).await?;
        match message.as_slice() {
            [OK, _, _, _, _, _, _, ..] => return Ok(message),
            [AUTH_MORE_DATA, AUTH_FAST_SUCCESS] => {}
            [AUTH_MORE_DATA, AUTH_FULL] => {
                let mut response = Vec::new();
                push_cstring(&mut response, password);
                packet::write(stream, sequence, &response).await?;
            }
            [AUTH_SWITCH, data @ ..] => {
                let mut fields = Fields(data);
                if fields.cstring()? != AUTH_PLUGIN {
                    return Err(packet::invalid());
                }
                let nonce = fields.take(NONCE_LEN)?;
                if fields.0 != [0] && !fields.0.is_empty() {
                    return Err(packet::invalid());
                }
                packet::write(stream, sequence, &scramble(password, nonce)).await?;
            }
            _ => return Err(packet::invalid()),
        }
    }
    Err(packet::invalid())
}

fn scramble(password: &[u8], nonce: &[u8]) -> [u8; 32] {
    let stage_one = Sha256::digest(password);
    let stage_two = Sha256::digest(stage_one);
    let mut hasher = Sha256::new();
    hasher.update(stage_two);
    hasher.update(nonce);
    let stage_three = hasher.finalize();
    std::array::from_fn(|index| stage_one[index] ^ stage_three[index])
}

fn response_header(flags: u32) -> [u8; CONNECTION_HEADER_LEN] {
    let mut header = [0; CONNECTION_HEADER_LEN];
    header[..4].copy_from_slice(&flags.to_le_bytes());
    header[4..8].copy_from_slice(&(MESSAGE_LIMIT as u32).to_le_bytes());
    header[8] = CHARSET;
    header
}

fn push_cstring(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(value);
    output.push(0);
}

pub(crate) async fn send_error(
    stream: &mut (impl AsyncWrite + Unpin),
    sequence: &mut u8,
    error: WireError,
) -> io::Result<()> {
    let (errno, sqlstate) = error.mysql();
    send_mapped_error(stream, sequence, (errno, sqlstate.as_bytes()), error).await
}

pub(crate) async fn send_mapped_error(
    stream: &mut (impl AsyncWrite + Unpin),
    sequence: &mut u8,
    native: (u16, &[u8]),
    error: WireError,
) -> io::Result<()> {
    let (errno, sqlstate) = native;
    let mut message = vec![ERR];
    message.extend(errno.to_le_bytes());
    message.push(b'#');
    message.extend_from_slice(sqlstate);
    message.extend_from_slice(error.to_string().as_bytes());
    packet::write(stream, sequence, &message).await
}

async fn reject<T>(
    stream: &mut (impl AsyncWrite + Unpin),
    sequence: &mut u8,
    error: WireError,
) -> io::Result<T> {
    send_error(stream, sequence, error).await?;
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "MySQL login rejected",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admits_tidb_greeting_only_in_experimental_build() -> io::Result<()> {
        let mysql = greeting(false)?;
        assert!(parse_backend_greeting(&mysql).is_ok());
        let mut tidb = vec![10];
        push_cstring(&mut tidb, b"8.0.11-TiDB-v8.5.8");
        tidb.extend_from_slice(&mysql[FIXTURE_VERSION.len() + 2..]);
        assert_eq!(
            parse_backend_greeting(&tidb).is_ok(),
            fg_protocol_common::TIDB_BACKEND_AVAILABLE,
        );
        Ok(())
    }

    #[tokio::test]
    async fn row_budget_details_reach_mysql_clients() -> io::Result<()> {
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
            send_error(&mut output, &mut 0, error).await?;
            let message = packet::read(&mut output.as_slice(), &mut 0, MESSAGE_LIMIT).await?;
            assert_eq!(
                message[..9],
                [ERR, 0x6c, 0x06, b'#', b'4', b'5', b'0', b'0', b'0']
            );
            assert_eq!(&message[9..], error.to_string().as_bytes());
        }
        Ok(())
    }

    #[test]
    fn unsupported_layout_capabilities_are_never_negotiated() -> io::Result<()> {
        const UNSUPPORTED: u32 = (1 << 5) | (1 << 7) | (1 << 16) | (1 << 26) | (1 << 27);
        let requested = read_ssl_request(&response_header(FRONT_FLAGS | UNSUPPORTED))?;
        assert_eq!(requested, FRONT_FLAGS);
        assert_eq!(requested & UNSUPPORTED, 0);
        assert!(read_ssl_request(&response_header(FRONT_FLAGS & !SSL)).is_err());
        Ok(())
    }

    #[test]
    fn missing_branch_is_distinct_from_a_malformed_login() -> io::Result<()> {
        let flags = REQUIRED_FLAGS;
        let mut login = response_header(flags).to_vec();
        push_cstring(&mut login, b"p1_user");
        login.push(0);
        push_cstring(&mut login, AUTH_PLUGIN);
        assert_eq!(Login::parse(&login, flags)?.branch, None);
        login.pop();
        assert!(Login::parse(&login, flags).is_err());
        Ok(())
    }
}
