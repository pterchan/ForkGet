//! SCRAM exchange using the algorithms in RFC 5802 and RFC 7677.

use std::io;

use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::wire::{protocol_error, take_string, take_u32};

pub(crate) const MECHANISM: &str = "SCRAM-SHA-256";
const ITERATIONS: u32 = 4096;
const MAX_ITERATIONS: u32 = 100_000;
const KEY_LENGTH: usize = 32;
type Key = [u8; KEY_LENGTH];

pub(crate) struct Verifier {
    salt: [u8; 16],
    stored_key: Key,
    server_key: Key,
}

impl Verifier {
    pub(crate) fn new(password: &str) -> io::Result<Self> {
        let salt = random()?;
        let (client_key, server_key) = keys(password, &salt, ITERATIONS)?;
        Ok(Self {
            salt,
            stored_key: Sha256::digest(client_key).into(),
            server_key,
        })
    }
}

pub(crate) struct ServerExchange<'a> {
    verifier: &'a Verifier,
    channel: &'a [u8],
    first: &'a str,
    challenge: String,
    nonce: String,
}

impl<'a> ServerExchange<'a> {
    pub(crate) fn start(verifier: &'a Verifier, mut input: &'a [u8]) -> io::Result<Self> {
        if take_string(&mut input)? != MECHANISM || take_u32(&mut input)? as usize != input.len() {
            return Err(protocol_error());
        }
        let input = std::str::from_utf8(input).map_err(|_| protocol_error())?;
        let (channel, first) = input.split_at_checked(3).ok_or_else(protocol_error)?;
        if !matches!(channel, "n,," | "y,,") {
            return Err(protocol_error());
        }
        let [_, client_nonce] = attributes(first, ["n=", "r="])?;
        validate_nonce(client_nonce)?;
        let nonce = format!("{client_nonce}{}", nonce()?);
        let salt = STANDARD.encode(verifier.salt);
        let challenge = format!("r={nonce},s={salt},i={ITERATIONS}");
        Ok(Self {
            verifier,
            channel: channel.as_bytes(),
            first,
            challenge,
            nonce,
        })
    }

    pub(crate) fn challenge(&self) -> &[u8] {
        self.challenge.as_bytes()
    }

    pub(crate) fn finish(self, input: &[u8]) -> io::Result<Option<String>> {
        let input = std::str::from_utf8(input).map_err(|_| protocol_error())?;
        let [channel, nonce, proof] = attributes(input, ["c=", "r=", "p="])?;
        if nonce != self.nonce || decode(channel)? != self.channel {
            return Err(protocol_error());
        }
        let proof: Key = decode(proof)?.try_into().map_err(|_| protocol_error())?;
        let (last, _) = input.rsplit_once(',').ok_or_else(protocol_error)?;
        let auth = auth_message(self.first, &self.challenge, last);
        let client_key = xor(proof, mac(&self.verifier.stored_key, &auth)?);
        let recovered: Key = Sha256::digest(client_key).into();
        if !bool::from(recovered.ct_eq(&self.verifier.stored_key)) {
            return Ok(None);
        }
        let signature = mac(&self.verifier.server_key, &auth)?;
        Ok(Some(format!("v={}", STANDARD.encode(signature))))
    }
}

pub(crate) struct ClientExchange {
    first: String,
    nonce: String,
}

impl ClientExchange {
    pub(crate) fn start() -> io::Result<Self> {
        let nonce = nonce()?;
        Ok(Self {
            first: format!("n=,r={nonce}"),
            nonce,
        })
    }

    pub(crate) fn initial_response(&self) -> String {
        format!("n,,{}", self.first)
    }

    pub(crate) fn answer(self, input: &[u8], password: &str) -> io::Result<(String, Key)> {
        let input = std::str::from_utf8(input).map_err(|_| protocol_error())?;
        let [nonce, salt, iterations] = attributes(input, ["r=", "s=", "i="])?;
        validate_nonce(nonce)?;
        if !nonce.starts_with(&self.nonce) || nonce.len() <= self.nonce.len() {
            return Err(protocol_error());
        }
        let salt = decode(salt)?;
        let iterations = iterations.parse::<u32>().map_err(|_| protocol_error())?;
        let (client_key, server_key) = keys(password, &salt, iterations)?;
        let stored_key: Key = Sha256::digest(client_key).into();
        let final_bare = format!("c=biws,r={nonce}");
        let auth = auth_message(&self.first, input, &final_bare);
        let proof = STANDARD.encode(xor(client_key, mac(&stored_key, &auth)?));
        Ok((format!("{final_bare},p={proof}"), mac(&server_key, &auth)?))
    }
}

pub(crate) fn verify_server(input: &[u8], expected: Key) -> io::Result<()> {
    let input = std::str::from_utf8(input).map_err(|_| protocol_error())?;
    let [signature] = attributes(input, ["v="])?;
    let signature: Key = decode(signature)?
        .try_into()
        .map_err(|_| protocol_error())?;
    if bool::from(signature.ct_eq(&expected)) {
        Ok(())
    } else {
        Err(protocol_error())
    }
}

pub(crate) fn random<const LENGTH: usize>() -> io::Result<[u8; LENGTH]> {
    let mut bytes = [0; LENGTH];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| io::Error::other("Unable to generate PostgreSQL authentication randomness"))?;
    Ok(bytes)
}

fn nonce() -> io::Result<String> {
    Ok(STANDARD.encode(random::<18>()?))
}

fn validate_nonce(value: &str) -> io::Result<()> {
    if value.is_empty()
        || value.len() > 256
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'!'..=b'~') || byte == b',')
    {
        return Err(protocol_error());
    }
    Ok(())
}

fn attributes<'a, const COUNT: usize>(
    input: &'a str,
    prefixes: [&str; COUNT],
) -> io::Result<[&'a str; COUNT]> {
    let mut parts = input.split(',');
    let mut attributes = [""; COUNT];
    for (value, prefix) in attributes.iter_mut().zip(prefixes) {
        *value = parts
            .next()
            .and_then(|part| part.strip_prefix(prefix))
            .ok_or_else(protocol_error)?;
    }
    if parts.next().is_some() {
        return Err(protocol_error());
    }
    Ok(attributes)
}

fn decode(encoded: &str) -> io::Result<Vec<u8>> {
    STANDARD.decode(encoded).map_err(|_| protocol_error())
}

fn keys(password: &str, salt: &[u8], iterations: u32) -> io::Result<(Key, Key)> {
    if !(ITERATIONS..=MAX_ITERATIONS).contains(&iterations)
        || !(8..=64).contains(&salt.len())
        || !password.is_ascii()
    {
        return Err(protocol_error());
    }
    let mut salted = [0; KEY_LENGTH];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut salted);
    let result = (mac(&salted, b"Client Key")?, mac(&salted, b"Server Key")?);
    Ok(result)
}

fn mac(key: &Key, input: &[u8]) -> io::Result<Key> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| protocol_error())?;
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
    use crate::wire::cstring;

    fn exchange(password: &str) -> io::Result<Option<String>> {
        let verifier = Verifier::new("fixture password")?;
        let client = ClientExchange::start()?;
        let mut packet = Vec::new();
        cstring(&mut packet, MECHANISM);
        let initial = client.initial_response();
        packet.extend_from_slice(&(initial.len() as u32).to_be_bytes());
        packet.extend_from_slice(initial.as_bytes());
        let server = ServerExchange::start(&verifier, &packet)?;
        let (answer, signature) = client.answer(server.challenge(), password)?;
        let result = server.finish(answer.as_bytes())?;
        if let Some(response) = result.as_ref() {
            verify_server(response.as_bytes(), signature)?;
        }
        Ok(result)
    }

    #[test]
    fn verifies_valid_proof_and_rejects_wrong_password() -> io::Result<()> {
        assert!(exchange("fixture password")?.is_some());
        assert!(exchange("wrong password")?.is_none());
        Ok(())
    }

    #[test]
    fn matches_rfc_7677_proof_and_signature() -> io::Result<()> {
        let nonce = "rOprNGfwEbeRWgbNEkqO";
        let client = ClientExchange {
            first: format!("n=user,r={nonce}"),
            nonce: nonce.to_owned(),
        };
        let challenge = b"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        let (answer, signature) = client.answer(challenge, "pencil")?;
        assert_eq!(
            answer,
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        );
        verify_server(b"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=", signature)
    }
}
