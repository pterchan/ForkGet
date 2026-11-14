//! MongoDB SCRAM-SHA-256, per RFC 5802 and RFC 7677. The
//! messages are the standard SCRAM exchanges; Mongo wraps them as BSON
//! binary payloads inside `saslStart`/`saslContinue`. Unlike
//! SCRAM-SHA-1, the key derivation uses the literal password.

use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const MECHANISM: &str = "SCRAM-SHA-256";
pub const ITERATIONS: u32 = 4096;
const MAX_ITERATIONS: u32 = 100_000;
const KEY_LENGTH: usize = 32;
pub type Key = [u8; KEY_LENGTH];

/// The password verifier held by the proxy for a frontend account.
pub struct Verifier {
    salt: [u8; 16],
    stored_key: Key,
    server_key: Key,
    iterations: u32,
}

impl Verifier {
    pub fn new(password: &str) -> Result<Self, ScramError> {
        let mut salt = [0; 16];
        OsRng
            .try_fill_bytes(&mut salt)
            .map_err(|_| ScramError::Protocol)?;
        let (client_key, server_key) = keys(password, &salt, ITERATIONS)?;
        Ok(Self {
            salt,
            stored_key: Sha256::digest(client_key).into(),
            server_key,
            iterations: ITERATIONS,
        })
    }
}

/// Server-side conversation state between `saslStart` and `saslContinue`.
pub struct ServerExchange {
    stored_key: Key,
    server_key: Key,
    channel: Vec<u8>,
    first: String,
    challenge: String,
    nonce: String,
}

impl ServerExchange {
    /// Consume the client-first message from `saslStart` (the gs2 header is
    /// part of the payload) and produce the server-first challenge.
    pub fn start(verifier: &Verifier, payload: &[u8]) -> Result<(Self, String), ScramError> {
        let input = std::str::from_utf8(payload).map_err(|_| ScramError::Protocol)?;
        let (channel, first) = input.split_once(",,").ok_or(ScramError::Protocol)?;
        // gs2 header: "n" (no channel binding) or "y" (client supports but
        // believes the server does not). Channel binding ("p") is unsupported.
        if !matches!(channel, "n" | "y") {
            return Err(ScramError::Protocol);
        }
        let user = attribute(first, "n=")?;
        let client_nonce = attribute(first, "r=")?;
        validate_nonce(client_nonce)?;
        if user.is_empty() {
            return Err(ScramError::Protocol);
        }
        let nonce = format!("{client_nonce}{}", STANDARD.encode(random::<18>()?));
        let salt = STANDARD.encode(verifier.salt);
        let challenge = format!("r={nonce},s={salt},i={}", verifier.iterations);
        Ok((
            Self {
                stored_key: verifier.stored_key,
                server_key: verifier.server_key,
                channel: format!("{channel},,").into_bytes(),
                first: first.to_owned(),
                challenge: challenge.clone(),
                nonce,
            },
            challenge,
        ))
    }

    /// Consume the client-final message from `saslContinue`; verify the
    /// client proof and return the server-final "v=..." signature.
    pub fn finish(self, payload: &[u8]) -> Result<String, ScramError> {
        let auth = self.auth_message_for(payload)?;
        let client_key = self.client_key_from(payload, &auth)?;
        let recovered: Key = Sha256::digest(client_key).into();
        if !bool::from(recovered.ct_eq(&self.stored_key)) {
            return Err(ScramError::Mismatch);
        }
        let signature = mac(&self.server_key, &auth)?;
        Ok(format!("v={}", STANDARD.encode(signature)))
    }

    /// A hostile server can always sign its own server-final with its own
    /// keys without verifying the client proof; that reply must fail the
    /// client's server-signature check.
    pub fn finish_unverified(self, payload: &[u8]) -> Result<String, ScramError> {
        let auth = self.auth_message_for(payload)?;
        let signature = mac(&self.server_key, &auth)?;
        Ok(format!("v={}", STANDARD.encode(signature)))
    }

    fn auth_message_for(&self, payload: &[u8]) -> Result<Vec<u8>, ScramError> {
        let input = std::str::from_utf8(payload).map_err(|_| ScramError::Protocol)?;
        let channel = attribute(input, "c=")?;
        let nonce = attribute(input, "r=")?;
        if nonce != self.nonce || decode(channel)? != self.channel {
            return Err(ScramError::Protocol);
        }
        let (last, _) = input.rsplit_once(',').ok_or(ScramError::Protocol)?;
        Ok(auth_message(&self.first, &self.challenge, last))
    }

    fn client_key_from(&self, payload: &[u8], auth: &[u8]) -> Result<Key, ScramError> {
        let input = std::str::from_utf8(payload).map_err(|_| ScramError::Protocol)?;
        let proof = attribute(input, "p=")?;
        let proof: Key = decode(proof)?
            .try_into()
            .map_err(|_| ScramError::Protocol)?;
        Ok(xor(proof, mac(&self.stored_key, auth)?))
    }
}

/// Client-side conversation used to authenticate to the backend mongod.
pub struct ClientExchange {
    first: String,
    nonce: String,
}

impl ClientExchange {
    pub fn start(user: &str) -> Result<Self, ScramError> {
        validate_nonce(user)?;
        let nonce = STANDARD.encode(random::<18>()?);
        Ok(Self {
            first: format!("n={user},r={nonce}"),
            nonce,
        })
    }

    /// The payload for `saslStart` (gs2 header + client-first-bare).
    pub fn initial_payload(&self) -> String {
        format!("n,,{}", self.first)
    }

    /// Consume the server-first challenge; return the client-final payload
    /// and the server signature to verify in the server-final reply.
    pub fn finish(
        self,
        server_first: &[u8],
        _user: &str,
        password: &str,
    ) -> Result<(String, Key), ScramError> {
        let input = std::str::from_utf8(server_first).map_err(|_| ScramError::Protocol)?;
        let nonce = attribute(input, "r=")?;
        let salt = attribute(input, "s=")?;
        let iterations = attribute(input, "i=")?;
        validate_nonce(nonce)?;
        if !nonce.starts_with(&self.nonce) || nonce.len() <= self.nonce.len() {
            return Err(ScramError::Protocol);
        }
        let salt = decode(salt)?;
        let iterations = iterations
            .parse::<u32>()
            .map_err(|_| ScramError::Protocol)?;
        let (client_key, server_key) = keys(password, &salt, iterations)?;
        let stored_key: Key = Sha256::digest(client_key).into();
        // The channel-binding flag "c=" is base64 of the gs2 header only
        // ("n,," without channel binding or authzid) — "biws".
        let final_bare = format!("c={},r={nonce}", STANDARD.encode(b"n,,"));
        let auth = auth_message(&self.first, input, &final_bare);
        let proof = STANDARD.encode(xor(client_key, mac(&stored_key, &auth)?));
        Ok((format!("{final_bare},p={proof}"), mac(&server_key, &auth)?))
    }
}

/// Verify the server-final "v=..." against the expected server signature.
pub fn verify_server(payload: &[u8], expected: &Key) -> Result<(), ScramError> {
    let input = std::str::from_utf8(payload).map_err(|_| ScramError::Protocol)?;
    let signature = attribute(input, "v=")?;
    let signature: Key = decode(signature)?
        .try_into()
        .map_err(|_| ScramError::Protocol)?;
    if bool::from(signature.ct_eq(expected)) {
        Ok(())
    } else {
        Err(ScramError::Mismatch)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ScramError {
    #[error("malformed SCRAM exchange")]
    Protocol,
    #[error("credential mismatch")]
    Mismatch,
}

fn attribute<'a>(input: &'a str, prefix: &str) -> Result<&'a str, ScramError> {
    input
        .split(',')
        .find_map(|part| part.strip_prefix(prefix))
        .ok_or(ScramError::Protocol)
}

fn validate_nonce(value: &str) -> Result<(), ScramError> {
    if value.is_empty()
        || value.len() > 256
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'!'..=b'~') || byte == b',')
    {
        return Err(ScramError::Protocol);
    }
    Ok(())
}

fn decode(encoded: &str) -> Result<Vec<u8>, ScramError> {
    STANDARD.decode(encoded).map_err(|_| ScramError::Protocol)
}

fn random<const LENGTH: usize>() -> Result<[u8; LENGTH], ScramError> {
    let mut bytes = [0; LENGTH];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| ScramError::Protocol)?;
    Ok(bytes)
}

fn keys(password: &str, salt: &[u8], iterations: u32) -> Result<(Key, Key), ScramError> {
    if !(ITERATIONS..=MAX_ITERATIONS).contains(&iterations)
        || !(8..=64).contains(&salt.len())
        || !password.is_ascii()
    {
        return Err(ScramError::Protocol);
    }
    let mut salted = [0; KEY_LENGTH];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut salted);
    Ok((mac(&salted, b"Client Key")?, mac(&salted, b"Server Key")?))
}

fn mac(key: &Key, input: &[u8]) -> Result<Key, ScramError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| ScramError::Protocol)?;
    mac.update(input);
    Ok(mac.finalize().into_bytes().into())
}

fn xor(mut left: Key, right: Key) -> Key {
    for (left, right) in left.iter_mut().zip(right) {
        *left ^= right;
    }
    left
}

fn auth_message(first: &str, challenge: &str, last: &str) -> Vec<u8> {
    format!("{first},{challenge},{last}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PBKDF2-HMAC-SHA256("password", "salt", 1) per the widely published
    /// test vector.
    #[test]
    fn pbkdf2_single_iteration_matches_published_vector() {
        let mut out = [0; 32];
        pbkdf2_hmac::<Sha256>(b"password", b"salt", 1, &mut out);
        let expected: [u8; 32] = [
            0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4,
            0xf8, 0x37, 0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48, 0x08, 0x05, 0x98, 0x7c,
            0xb7, 0x0b, 0xe1, 0x7b,
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn full_exchange_round_trips_with_matching_password() -> Result<(), ScramError> {
        let verifier = Verifier::new("pencil")?;
        let client = ClientExchange::start("user")?;
        let first = client.initial_payload();
        let (server, challenge) = ServerExchange::start(&verifier, first.as_bytes())?;
        assert!(challenge.contains("i=4096"));
        let (client_final, server_signature) =
            client.finish(challenge.as_bytes(), "user", "pencil")?;
        let server_final = server.finish(client_final.as_bytes())?;
        verify_server(server_final.as_bytes(), &server_signature)
    }

    #[test]
    fn server_rejects_wrong_password_proof() -> Result<(), ScramError> {
        let verifier = Verifier::new("pencil")?;
        let client = ClientExchange::start("user")?;
        let first = client.initial_payload();
        let (server, challenge) = ServerExchange::start(&verifier, first.as_bytes())?;
        let (client_final, _) = client.finish(challenge.as_bytes(), "user", "wrong")?;
        assert!(matches!(
            server.finish(client_final.as_bytes()),
            Err(ScramError::Mismatch)
        ));
        Ok(())
    }

    #[test]
    fn client_rejects_rogue_server_signature() -> Result<(), ScramError> {
        // A server holding a verifier for a different password produces a
        // server-final the client must reject.
        let rogue = Verifier::new("other")?;
        let client = ClientExchange::start("user")?;
        let first = client.initial_payload();
        let (server, challenge) = ServerExchange::start(&rogue, first.as_bytes())?;
        let (client_final, server_signature) =
            client.finish(challenge.as_bytes(), "user", "pencil")?;
        // The rogue server skips proof verification and signs with its own
        // ("other") keys.
        let server_final = server.finish_unverified(client_final.as_bytes())?;
        assert!(matches!(
            verify_server(server_final.as_bytes(), &server_signature),
            Err(ScramError::Mismatch)
        ));
        Ok(())
    }
}
