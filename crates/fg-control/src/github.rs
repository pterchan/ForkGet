mod client;

use std::{collections::HashMap, path::Path};

use fg_meta::{GitHubFailure, GitHubSignal, GitHubSource};
use fg_protocol_common::{BranchClass, loopback_http, valid_branch_name};
use hmac::{Hmac, Mac};
use reqwest::Url;
use serde::Deserialize;
use sha2::Sha256;

use crate::{ControlError, optional, required};

const API_ORIGIN: &str = "https://api.github.com/";
const CONFIG_REPOSITORY_LIMIT: usize = 32;
const REF_LIMIT: usize = 255;

pub(crate) struct GitHub {
    secret: String,
    repositories: Vec<Repository>,
    client: client::GitHubClient,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Repository {
    repository_id: i64,
    installation_id: i64,
    owner: String,
    repo: String,
    principal: String,
    #[serde(default)]
    pr_write: bool,
}

pub(crate) struct Incoming<'a> {
    repository: &'a Repository,
    source_kind: &'static str,
    source_key: String,
    name: Option<String>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum WebhookError {
    Signature,
    Access,
    Invalid,
}

#[derive(Deserialize)]
struct Envelope<T> {
    repository: RepositoryIdentity,
    installation: Id,
    #[serde(flatten)]
    event: T,
}

#[derive(Deserialize)]
struct Id {
    id: i64,
}

#[derive(Deserialize)]
struct RepositoryIdentity {
    id: i64,
    full_name: String,
}

#[derive(Deserialize)]
struct Push {
    #[serde(rename = "ref")]
    name: String,
    created: bool,
    deleted: bool,
}

#[derive(Deserialize)]
struct PullEvent {
    action: String,
    number: i64,
    pull_request: PullSignal,
}

#[derive(Deserialize)]
struct PullSignal {
    number: i64,
    base: PullBase,
}

#[derive(Deserialize)]
struct PullBase {
    repo: Id,
}

#[derive(Default)]
pub(crate) struct TokenCache(HashMap<i64, client::Token>);

pub(crate) struct LookupFailure {
    pub(crate) kind: GitHubFailure,
    pub(crate) delay: Option<u32>,
}

impl GitHub {
    pub(crate) fn from_env() -> Result<Option<Self>, ControlError> {
        let settings = [
            "FG_GITHUB_WEBHOOK_SECRET",
            "FG_GITHUB_APP_ID",
            "FG_GITHUB_REPOSITORIES",
            "FG_GITHUB_APP_PRIVATE_KEY",
            "FG_GITHUB_TEST_APP_PRIVATE_KEY",
            "FG_GITHUB_TEST_API_URL",
        ];
        if settings.iter().all(|setting| optional(setting).is_none()) {
            return Ok(None);
        }
        let secret = required("FG_GITHUB_WEBHOOK_SECRET")?;
        let app_id = required("FG_GITHUB_APP_ID")?;
        if !(16..=4096).contains(&secret.len()) || !app_id.parse::<i64>().is_ok_and(|id| id > 0) {
            return Err(ControlError::Config("GitHub App ID or webhook secret"));
        }
        let repositories: Vec<Repository> =
            serde_json::from_str(&required("FG_GITHUB_REPOSITORIES")?)
                .map_err(|_| ControlError::Config("FG_GITHUB_REPOSITORIES"))?;
        validate_repositories(&repositories)?;
        let (origin, path) = api_settings()?;
        Ok(Some(Self {
            secret,
            repositories,
            client: client::GitHubClient::new(origin, app_id, Path::new(&path))?,
        }))
    }

    pub(crate) fn receive(
        &self,
        signature: &str,
        event: &str,
        body: &[u8],
    ) -> Result<Option<Incoming<'_>>, WebhookError> {
        if !valid_signature(self.secret.as_bytes(), signature, body) {
            return Err(WebhookError::Signature);
        }
        match event {
            "push" => {
                let delivery = decode::<Push>(body)?;
                if !delivery.event.name.starts_with("refs/heads/")
                    || !delivery.event.created && !delivery.event.deleted
                {
                    return Ok(None);
                }
                if delivery.event.created && delivery.event.deleted {
                    return Err(WebhookError::Invalid);
                }
                let repo = self.authorized(&delivery)?;
                Incoming::reference(repo, delivery.event.name).map(Some)
            }
            "pull_request" => {
                let delivery = decode::<PullEvent>(body)?;
                if !matches!(
                    delivery.event.action.as_str(),
                    "opened" | "reopened" | "closed"
                ) {
                    return Ok(None);
                }
                let repo = self.authorized(&delivery)?;
                let pull = &delivery.event;
                if pull.number <= 0
                    || pull.pull_request.number != pull.number
                    || pull.pull_request.base.repo.id != repo.repository_id
                {
                    return Err(WebhookError::Invalid);
                }
                Ok(Some(Incoming {
                    repository: repo,
                    source_kind: "pull_request",
                    source_key: pull.number.to_string(),
                    name: Some(format!("gh-pr-{}-{}", repo.repository_id, pull.number)),
                }))
            }
            _ => Ok(None),
        }
    }

    fn authorized<T>(&self, delivery: &Envelope<T>) -> Result<&Repository, WebhookError> {
        self.repositories
            .iter()
            .find(|repository| {
                delivery.repository.id == repository.repository_id
                    && delivery.installation.id == repository.installation_id
                    && delivery
                        .repository
                        .full_name
                        .eq_ignore_ascii_case(&format!("{}/{}", repository.owner, repository.repo))
            })
            .ok_or(WebhookError::Access)
    }

    pub(crate) async fn observe(
        &self,
        source: &GitHubSource,
        cache: &mut TokenCache,
    ) -> Result<(bool, bool), LookupFailure> {
        let repository = self
            .repositories
            .iter()
            .find(|repo| {
                repo.repository_id == source.repository_id
                    && repo.installation_id == source.installation_id
                    && repo.principal == source.principal
            })
            .ok_or(LookupFailure {
                kind: GitHubFailure::AccessUnavailable,
                delay: None,
            })?;
        self.client
            .observe(repository, source, &mut cache.0)
            .await
            .map(|present| (present, repository.pr_write))
            .map_err(|error| {
                use client::RemoteError::{Access, RateLimited, Unauthorized, Unavailable};
                let delay = retry_seconds(source.attempts);
                match error {
                    Access | Unauthorized => LookupFailure {
                        kind: GitHubFailure::AccessUnavailable,
                        delay: Some(delay),
                    },
                    Unavailable => LookupFailure {
                        kind: GitHubFailure::SourceUnavailable,
                        delay: Some(delay),
                    },
                    RateLimited(seconds) => LookupFailure {
                        kind: GitHubFailure::SourceUnavailable,
                        delay: Some(delay.max(seconds)),
                    },
                }
            })
    }
}

impl Incoming<'_> {
    fn reference(
        repository: &Repository,
        source_key: String,
    ) -> Result<Incoming<'_>, WebhookError> {
        let name = source_key
            .strip_prefix("refs/heads/")
            .ok_or(WebhookError::Invalid)?;
        let label = ref_label(name).ok_or(WebhookError::Invalid)?;
        let name = format!("gh-dev-{}-{label}", repository.repository_id);
        Ok(Incoming {
            repository,
            source_kind: "ref",
            source_key,
            name: valid_branch_name(&name).then_some(name),
        })
    }

    pub(crate) fn class(&self) -> BranchClass {
        source_class(self.source_kind)
    }

    pub(crate) fn signal(&self) -> GitHubSignal<'_> {
        GitHubSignal {
            repository_id: self.repository.repository_id,
            installation_id: self.repository.installation_id,
            source_kind: self.source_kind,
            source_key: &self.source_key,
            principal: &self.repository.principal,
            name: self.name.as_deref(),
        }
    }
}

pub(crate) fn source_class(kind: &str) -> BranchClass {
    if kind == "ref" {
        BranchClass::Dev
    } else {
        BranchClass::Ci
    }
}

pub(crate) fn retry_seconds(attempts: i32) -> u32 {
    2_u32.pow(attempts.clamp(0, 6) as u32)
}

fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<Envelope<T>, WebhookError> {
    serde_json::from_slice(body).map_err(|_| WebhookError::Invalid)
}

fn api_settings() -> Result<(Url, String), ControlError> {
    match (
        optional("FG_GITHUB_APP_PRIVATE_KEY"),
        optional("FG_GITHUB_TEST_APP_PRIVATE_KEY"),
        optional("FG_GITHUB_TEST_API_URL"),
    ) {
        (Some(path), None, None) => Ok((
            Url::parse(API_ORIGIN).map_err(|_| ControlError::Config("GitHub API origin"))?,
            path,
        )),
        (None, Some(path), Some(origin)) => Ok((
            loopback_http(&origin).ok_or(ControlError::Config("FG_GITHUB_TEST_API_URL"))?,
            path,
        )),
        _ => Err(ControlError::Config(
            "GitHub App private key or isolated fixture settings",
        )),
    }
}

fn validate_repositories(repositories: &[Repository]) -> Result<(), ControlError> {
    if repositories.is_empty()
        || repositories.len() > CONFIG_REPOSITORY_LIMIT
        || repositories.iter().enumerate().any(|(index, repository)| {
            repository.repository_id <= 0
                || repository.installation_id <= 0
                || repository.principal.is_empty()
                || !valid_path(&repository.owner)
                || !valid_path(&repository.repo)
                || repositories[..index].iter().any(|prior| {
                    prior.repository_id == repository.repository_id
                        || (prior.owner.eq_ignore_ascii_case(&repository.owner)
                            && prior.repo.eq_ignore_ascii_case(&repository.repo))
                })
        })
    {
        return Err(ControlError::Config("FG_GITHUB_REPOSITORIES"));
    }
    Ok(())
}

fn valid_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn ref_label(value: &str) -> Option<String> {
    if value.len() > REF_LIMIT
        || value.contains("..")
        || value.contains("@{")
        || value == "@"
        || value.split('/').any(|segment| {
            segment.is_empty()
                || segment.starts_with('.')
                || segment.ends_with('.')
                || segment.ends_with(".lock")
                || !segment.bytes().all(|byte| {
                    byte.is_ascii_graphic()
                        && !matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
                })
        })
    {
        return None;
    }
    let mut label = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() {
            label.push(char::from(byte.to_ascii_lowercase()));
        } else if !label.is_empty() && !label.ends_with('-') {
            label.push('-');
        }
    }
    let label = label.trim_end_matches('-');
    (!label.is_empty()).then(|| label.to_owned())
}

fn valid_signature(secret: &[u8], signature: &str, body: &[u8]) -> bool {
    let Some(digest) = signature
        .strip_prefix("sha256=")
        .filter(|digest| digest.len() == 64)
    else {
        return false;
    };
    let mut expected = [0_u8; 32];
    for (slot, pair) in expected.iter_mut().zip(digest.as_bytes().chunks_exact(2)) {
        let (Some(high), Some(low)) = (
            char::from(pair[0]).to_digit(16),
            char::from(pair[1]).to_digit(16),
        ) else {
            return false;
        };
        *slot = (high * 16 + low) as u8;
    }
    Hmac::<Sha256>::new_from_slice(secret).is_ok_and(|mut mac| {
        mac.update(body);
        mac.verify_slice(&expected).is_ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticates_raw_github_webhook_bytes() {
        let signature = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";
        assert!(valid_signature(
            b"It's a Secret to Everybody",
            signature,
            b"Hello, World!"
        ));
        assert!(!valid_signature(
            b"It's a Secret to Everybody",
            signature,
            b"Hello, World!\n"
        ));
    }

    #[test]
    fn labels_preserve_collisions_for_metadata_to_refuse() {
        assert_eq!(
            ref_label("Feature/API_Review").as_deref(),
            Some("feature-api-review")
        );
        assert_eq!(
            ref_label("feature-api-review").as_deref(),
            Some("feature-api-review")
        );
        assert_eq!(ref_label("feature/../main"), None);
    }
}
