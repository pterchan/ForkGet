use std::{collections::HashMap, fs::File, io::Read, path::Path, time::Duration};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use fg_meta::GitHubSource;
use jiff::Timestamp;
use reqwest::{Client, Method, RequestBuilder, StatusCode, Url, redirect::Policy};
use ring::{
    rand::SystemRandom,
    signature::{RSA_PKCS1_SHA256, RsaKeyPair},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;

use super::Repository;
use crate::ControlError;

const API_VERSION: &str = "2026-03-10";
const API_TIMEOUT: Duration = Duration::from_secs(5);
const RESPONSE_LIMIT: usize = 256 * 1024;
const KEY_LIMIT: u64 = 16 * 1024;
const CLOCK_SKEW_SECONDS: i64 = 60;
const JWT_LIFETIME_SECONDS: i64 = 9 * 60;

pub(super) struct GitHubClient {
    origin: Url,
    client: Client,
    app_id: String,
    key: RsaKeyPair,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum RemoteError {
    Access,
    Unauthorized,
    Unavailable,
    RateLimited(u32),
}

#[derive(Deserialize)]
struct TokenResponse {
    token: String,
    expires_at: String,
    permissions: HashMap<String, String>,
    repositories: Option<Vec<RepositoryIdentity>>,
}

pub(super) struct Token {
    value: String,
    expires_at: i64,
}

#[derive(Deserialize)]
struct RepositoryIdentity {
    id: i64,
}

#[derive(Deserialize)]
struct Reference {
    #[serde(rename = "ref")]
    name: String,
}

#[derive(Deserialize)]
struct PullRequest {
    id: i64,
    number: i64,
    state: String,
    base: PullBase,
}

#[derive(Deserialize)]
struct PullBase {
    repo: RepositoryIdentity,
}

impl GitHubClient {
    pub(super) fn new(origin: Url, app_id: String, path: &Path) -> Result<Self, ControlError> {
        let client = Client::builder()
            .timeout(API_TIMEOUT)
            .redirect(Policy::none())
            .no_proxy()
            .user_agent("forkget-github-app")
            .build()
            .map_err(|_| ControlError::Config("GitHub App REST client"))?;
        Ok(Self {
            origin,
            client,
            app_id,
            key: load_key(path)?,
        })
    }

    pub(super) async fn observe(
        &self,
        repository: &Repository,
        source: &GitHubSource,
        tokens: &mut HashMap<i64, Token>,
    ) -> Result<bool, RemoteError> {
        let id = repository.repository_id;
        if tokens.get(&id).is_none_or(|token| {
            token.expires_at <= Timestamp::now().as_second() + CLOCK_SKEW_SECONDS
        }) {
            tokens.insert(id, self.installation_token(repository).await?);
        }
        let token = &tokens.get(&id).ok_or(RemoteError::Access)?.value;
        let result = self.observe_with_token(repository, source, token).await;
        if !matches!(result, Err(RemoteError::Unauthorized)) {
            return result;
        }
        tokens.remove(&id);
        let token = self.installation_token(repository).await?;
        let result = self
            .observe_with_token(repository, source, &token.value)
            .await;
        if !matches!(result, Err(RemoteError::Unauthorized)) {
            tokens.insert(id, token);
        }
        result
    }

    async fn observe_with_token(
        &self,
        repository: &Repository,
        source: &GitHubSource,
        token: &str,
    ) -> Result<bool, RemoteError> {
        match source.source_kind.as_str() {
            "ref" => {
                self.observe_ref(repository, &source.source_key, token)
                    .await
            }
            "pull_request" => {
                self.observe_pull(repository, &source.source_key, token)
                    .await
            }
            _ => Err(RemoteError::Unavailable),
        }
    }

    async fn installation_token(&self, repository: &Repository) -> Result<Token, RemoteError> {
        let installation = repository.installation_id.to_string();
        let jwt = self.jwt(Timestamp::now().as_second())?;
        let request = self
            .request(
                Method::POST,
                &["app", "installations", &installation, "access_tokens"],
            )?
            .bearer_auth(jwt)
            .json(&json!({
                "repository_ids": [repository.repository_id],
                "permissions": {"contents": "read", "pull_requests": "read"},
            }));
        let response: TokenResponse = read_response(request, StatusCode::CREATED).await?;
        let expires_at = response
            .expires_at
            .parse::<Timestamp>()
            .map_err(|_| RemoteError::Unavailable)?
            .as_second();
        if response.token.is_empty()
            || response.token.len() > 4096
            || !response.token.bytes().all(|byte| byte.is_ascii_graphic())
            || expires_at <= Timestamp::now().as_second() + CLOCK_SKEW_SECONDS
            || !has_required_permissions(&response.permissions)
            || response.repositories.is_some_and(|repositories| {
                repositories.len() != 1 || repositories[0].id != repository.repository_id
            })
        {
            return Err(RemoteError::Access);
        }
        Ok(Token {
            value: response.token,
            expires_at,
        })
    }

    async fn observe_ref(
        &self,
        repository: &Repository,
        name: &str,
        token: &str,
    ) -> Result<bool, RemoteError> {
        let mut path = vec!["repos", &repository.owner, &repository.repo];
        let identity = self.request(Method::GET, &path)?.bearer_auth(token);
        let short = name
            .strip_prefix("refs/heads/")
            .ok_or(RemoteError::Unavailable)?;
        path.extend(["git", "matching-refs", "heads"]);
        path.extend(short.split('/'));
        let references = self.request(Method::GET, &path)?.bearer_auth(token);
        let (identity, references): (RepositoryIdentity, Vec<Reference>) = tokio::try_join!(
            read_response(identity, StatusCode::OK),
            read_response(references, StatusCode::OK),
        )?;
        if identity.id != repository.repository_id {
            return Err(RemoteError::Access);
        }
        Ok(references.iter().any(|reference| reference.name == name))
    }

    async fn observe_pull(
        &self,
        repository: &Repository,
        number: &str,
        token: &str,
    ) -> Result<bool, RemoteError> {
        let request = self
            .request(
                Method::GET,
                &[
                    "repos",
                    &repository.owner,
                    &repository.repo,
                    "pulls",
                    number,
                ],
            )?
            .bearer_auth(token);
        let pull: PullRequest = read_response(request, StatusCode::OK).await?;
        if pull.id <= 0
            || Some(pull.number) != number.parse().ok()
            || pull.base.repo.id != repository.repository_id
        {
            return Err(RemoteError::Access);
        }
        match pull.state.as_str() {
            "open" => Ok(true),
            "closed" => Ok(false),
            _ => Err(RemoteError::Unavailable),
        }
    }

    fn request(&self, method: Method, path: &[&str]) -> Result<RequestBuilder, RemoteError> {
        let mut url = self.origin.clone();
        url.path_segments_mut()
            .map_err(|_| RemoteError::Unavailable)?
            .pop_if_empty()
            .extend(path.iter().copied());
        Ok(self
            .client
            .request(method, url)
            .header("X-GitHub-Api-Version", API_VERSION)
            .header("Accept", "application/vnd.github+json")
            .header("Cache-Control", "no-cache"))
    }

    fn jwt(&self, now: i64) -> Result<String, RemoteError> {
        #[derive(Serialize)]
        struct Claims<'a> {
            iss: &'a str,
            iat: i64,
            exp: i64,
        }
        let claims = serde_json::to_vec(&Claims {
            iss: &self.app_id,
            iat: now - CLOCK_SKEW_SECONDS,
            exp: now + JWT_LIFETIME_SECONDS,
        })
        .map_err(|_| RemoteError::Access)?;
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let message = format!("{header}.{}", URL_SAFE_NO_PAD.encode(claims));
        let mut signature = vec![0; self.key.public().modulus_len()];
        self.key
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                message.as_bytes(),
                &mut signature,
            )
            .map_err(|_| RemoteError::Access)?;
        Ok(format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature)))
    }
}

fn has_required_permissions(permissions: &HashMap<String, String>) -> bool {
    ["contents", "pull_requests"].iter().all(|name| {
        permissions
            .get(*name)
            .is_some_and(|access| access == "read")
    }) && permissions.iter().all(|(name, access)| {
        matches!(name.as_str(), "contents" | "pull_requests" | "metadata") && access == "read"
    })
}

fn load_key(path: &Path) -> Result<RsaKeyPair, ControlError> {
    let invalid = || ControlError::Config("GitHub App private key PEM file");
    let mut pem = String::new();
    File::open(path)
        .map_err(|_| invalid())?
        .take(KEY_LIMIT + 1)
        .read_to_string(&mut pem)
        .map_err(|_| invalid())?;
    if pem.len() as u64 > KEY_LIMIT {
        return Err(invalid());
    }
    let mut lines = pem.trim().lines();
    let (pkcs8, footer) = match lines.next() {
        Some("-----BEGIN PRIVATE KEY-----") => (true, "-----END PRIVATE KEY-----"),
        Some("-----BEGIN RSA PRIVATE KEY-----") => (false, "-----END RSA PRIVATE KEY-----"),
        _ => return Err(invalid()),
    };
    if lines.next_back() != Some(footer) {
        return Err(invalid());
    }
    let der = STANDARD
        .decode(lines.collect::<String>())
        .map_err(|_| invalid())?;
    if pkcs8 {
        RsaKeyPair::from_pkcs8(&der)
    } else {
        RsaKeyPair::from_der(&der)
    }
    .map_err(|_| invalid())
}

async fn read_response<T: DeserializeOwned>(
    request: RequestBuilder,
    expected: StatusCode,
) -> Result<T, RemoteError> {
    let mut response = request.send().await.map_err(|_| RemoteError::Unavailable)?;
    let status = response.status();
    if status != expected {
        let retry = response
            .headers()
            .get("Retry-After")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u32>().ok());
        if status == StatusCode::TOO_MANY_REQUESTS
            || (status == StatusCode::FORBIDDEN && retry.is_some())
        {
            return Err(RemoteError::RateLimited(retry.unwrap_or(60).clamp(1, 300)));
        }
        return Err(match status {
            StatusCode::UNAUTHORIZED => RemoteError::Unauthorized,
            StatusCode::FORBIDDEN | StatusCode::NOT_FOUND => RemoteError::Access,
            _ => RemoteError::Unavailable,
        });
    }
    if response
        .content_length()
        .is_some_and(|size| size > RESPONSE_LIMIT as u64)
    {
        return Err(RemoteError::Unavailable);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| RemoteError::Unavailable)?
    {
        if body.len().saturating_add(chunk.len()) > RESPONSE_LIMIT {
            return Err(RemoteError::Unavailable);
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| RemoteError::Unavailable)
}
