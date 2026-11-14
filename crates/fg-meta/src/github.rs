use fg_protocol_common::BranchClass;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgConnection};

use crate::{BranchMode, ForkBranch, MetaError, Metadata, lifecycle};

const GITHUB_ACTOR: &str = "system:github";
const BINDING_LIMIT: i64 = 200;
// Matches the attempts check in migration 0007.
const MAX_RECONCILIATION_ATTEMPTS: i32 = 16;

pub struct GitHubSignal<'a> {
    pub repository_id: i64,
    pub installation_id: i64,
    pub source_kind: &'a str,
    pub source_key: &'a str,
    pub principal: &'a str,
    pub name: Option<&'a str>,
}

#[derive(FromRow)]
pub struct GitHubSource {
    pub repository_id: i64,
    pub installation_id: i64,
    pub source_kind: String,
    pub source_key: String,
    pub principal: String,
    pub revision: i64,
    pub attempts: i32,
}

#[derive(FromRow)]
struct BoundSource {
    name: String,
    branch_id: Option<i64>,
    observed_present: Option<bool>,
    waiting_for_cleanup: bool,
}

#[derive(FromRow, Serialize)]
pub struct GitHubBinding {
    repository_id: i64,
    installation_id: i64,
    source_kind: String,
    source_key: String,
    name: Option<String>,
    branch_id: Option<i64>,
    branch_status: Option<String>,
    state: String,
    last_error: Option<String>,
    environment_state: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubRecreate {
    pub repository_id: i64,
    pub source_kind: String,
    pub source_key: String,
    pub expected_branch_id: i64,
}

impl GitHubBinding {
    pub fn cursor(&self) -> Result<String, MetaError> {
        serde_json::to_string(&(self.repository_id, &self.source_kind, &self.source_key))
            .map_err(|_| MetaError::InvalidCatalog)
    }
}

#[derive(Clone, Copy)]
pub enum GitHubFailure {
    SourceUnavailable,
    AccessUnavailable,
    NameConflict,
    NameTooLong,
    MetadataUnavailable,
}

impl GitHubFailure {
    fn as_str(self) -> &'static str {
        match self {
            Self::SourceUnavailable => "source_unavailable",
            Self::AccessUnavailable => "access_unavailable",
            Self::NameConflict => "name_conflict",
            Self::NameTooLong => "name_too_long",
            Self::MetadataUnavailable => "metadata_unavailable",
        }
    }
}

pub struct GitHubObservation<'a> {
    pub source: &'a GitHubSource,
    pub engine: &'a str,
    pub present: bool,
    pub pr_write: bool,
}

impl Metadata {
    pub async fn enqueue_github(
        &self,
        signal: GitHubSignal<'_>,
    ) -> Result<Option<GitHubFailure>, MetaError> {
        let failure = if signal.name.is_none() {
            GitHubFailure::NameTooLong
        } else {
            match self.write_github_signal(&signal, None).await {
                Ok(()) => return Ok(None),
                Err(MetaError::GitHubBindingConflict) => GitHubFailure::NameConflict,
                Err(error) => return Err(error),
            }
        };
        self.write_github_signal(&signal, Some(failure)).await?;
        Ok(Some(failure))
    }

    async fn write_github_signal(
        &self,
        signal: &GitHubSignal<'_>,
        failure: Option<GitHubFailure>,
    ) -> Result<(), MetaError> {
        let name = if failure.is_none() { signal.name } else { None };
        let result = sqlx::query(
            "INSERT INTO github_source
                 (repository_id, installation_id, source_kind, source_key, principal, name, last_error, retry_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, CASE WHEN $7 IS NULL THEN clock_timestamp() END)
             ON CONFLICT (repository_id, source_kind, source_key) DO UPDATE
                 SET revision = github_source.revision + 1, name = EXCLUDED.name,
                     retry_at = EXCLUDED.retry_at, attempts = 0, last_error = EXCLUDED.last_error
             WHERE github_source.installation_id = EXCLUDED.installation_id
               AND github_source.principal = EXCLUDED.principal
               AND (github_source.name IS NULL OR github_source.name = EXCLUDED.name)",
        )
        .bind(signal.repository_id).bind(signal.installation_id).bind(signal.source_kind)
        .bind(signal.source_key).bind(signal.principal).bind(name)
        .bind(failure.map(GitHubFailure::as_str)).execute(&self.pool).await;
        match result {
            Ok(result) if result.rows_affected() == 1 => Ok(()),
            Ok(_) => Err(MetaError::GitHubBindingConflict),
            Err(sqlx::Error::Database(error))
                if error.constraint() == Some("github_source_name_key") =>
            {
                Err(MetaError::GitHubBindingConflict)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub async fn next_github(&self) -> Result<Option<GitHubSource>, MetaError> {
        sqlx::query_as(
            "SELECT s.repository_id, s.installation_id, s.source_kind, s.source_key,
                    s.principal, s.revision, s.attempts
             FROM github_source s LEFT JOIN branch b ON b.id = s.branch_id
             WHERE s.retry_at <= clock_timestamp()
               AND (NOT s.waiting_for_cleanup OR s.revision <> s.applied_revision
                    OR b.status IS DISTINCT FROM 'dropping')
             ORDER BY s.retry_at, s.repository_id, s.source_kind, s.source_key LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn github_bindings(&self, principal: &str) -> Result<Vec<GitHubBinding>, MetaError> {
        self.github_binding_page(principal, None).await
    }

    pub async fn github_binding_page(
        &self,
        principal: &str,
        after: Option<&str>,
    ) -> Result<Vec<GitHubBinding>, MetaError> {
        let cursor: Option<(i64, String, String)> = after
            .map(|value| serde_json::from_str(value).map_err(|_| MetaError::InvalidCatalog))
            .transpose()?;
        sqlx::query_as(
            "SELECT s.repository_id, s.installation_id, s.source_kind, s.source_key, s.name,
                    s.branch_id, b.status AS branch_status, s.last_error,
                    CASE WHEN s.retry_at IS NULL AND s.last_error IS NOT NULL THEN 'blocked'
                         WHEN s.last_error IS NOT NULL THEN 'retrying'
                         WHEN s.waiting_for_cleanup THEN 'waiting_for_cleanup'
                         WHEN s.retry_at IS NOT NULL THEN 'queued'
                         WHEN s.observed_present THEN 'present' ELSE 'absent' END AS state,
                    CASE WHEN b.status='dropped' AND s.observed_present THEN 'expired'
                         WHEN b.status IN ('active','provisioning') AND b.expires_at<=clock_timestamp() THEN 'expired'
                         WHEN b.status IS NULL THEN 'not_created' ELSE b.status END AS environment_state
             FROM github_source s LEFT JOIN branch b ON b.id = s.branch_id WHERE s.principal = $1
               AND ($3::bigint IS NULL OR (s.repository_id,s.source_kind,s.source_key)>($3,$4,$5))
             ORDER BY s.repository_id, s.source_kind, s.source_key LIMIT $2",
        )
        .bind(principal)
        .bind(BINDING_LIMIT)
        .bind(cursor.as_ref().map(|item|item.0))
        .bind(cursor.as_ref().map(|item|item.1.as_str()))
        .bind(cursor.as_ref().map(|item|item.2.as_str()))
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn recreate_github(
        &self,
        principal: &str,
        request: &GitHubRecreate,
    ) -> Result<(), MetaError> {
        if request.repository_id <= 0
            || request.expected_branch_id <= 0
            || !matches!(request.source_kind.as_str(), "ref" | "pull_request")
            || request.source_key.is_empty()
            || request.source_key.len() > 1024
        {
            return Err(MetaError::GitHubBindingConflict);
        }
        let mut tx = self.pool.begin().await?;
        let result=sqlx::query("UPDATE github_source s SET observed_present=NULL,waiting_for_cleanup=FALSE,revision=revision+1,retry_at=clock_timestamp(),attempts=0,last_error=NULL WHERE s.principal=$1 AND s.repository_id=$2 AND s.source_kind=$3 AND s.source_key=$4 AND s.branch_id=$5 AND EXISTS(SELECT 1 FROM branch b WHERE b.id=s.branch_id AND b.created_by=$1 AND b.status='dropped')")
            .bind(principal).bind(request.repository_id).bind(&request.source_kind).bind(&request.source_key).bind(request.expected_branch_id)
            .execute(&mut *tx).await?;
        if result.rows_affected() != 1 {
            return Err(MetaError::GitHubBindingConflict);
        }
        sqlx::query("INSERT INTO audit_event(actor,branch_id,event_type,payload) VALUES($1,$2,'github_recreate_requested',jsonb_build_object('repository_id',$3::bigint,'source_kind',$4::text))")
            .bind(principal).bind(request.expected_branch_id).bind(request.repository_id).bind(&request.source_kind).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn reconcile_github(
        &self,
        observation: GitHubObservation<'_>,
    ) -> Result<bool, MetaError> {
        let mut tx = self.pool.begin().await?;
        let Some(binding) = lock_source(&mut tx, observation.source).await? else {
            return Ok(false);
        };
        let (branch_id, waiting, changed) = if observation.present {
            ensure_present(&mut tx, &observation, &binding).await?
        } else {
            if let Some(id) = binding.branch_id {
                lifecycle::begin_drop_in(&mut tx, &observation.source.principal, id, GITHUB_ACTOR)
                    .await?;
            }
            (binding.branch_id, false, binding.branch_id.is_some())
        };
        commit_observation(&mut tx, &observation, branch_id, waiting).await?;
        tx.commit().await?;
        Ok(changed)
    }

    pub async fn github_failed(
        &self,
        source: &GitHubSource,
        error: GitHubFailure,
        retry_seconds: Option<u32>,
    ) -> Result<(), MetaError> {
        sqlx::query(
            "UPDATE github_source SET attempts = LEAST(attempts + 1, $7), last_error = $5,
                 retry_at = CASE WHEN $6::double precision IS NULL THEN NULL
                     ELSE clock_timestamp() + make_interval(secs => $6) END
             WHERE repository_id = $1 AND source_kind = $2 AND source_key = $3 AND revision = $4",
        )
        .bind(source.repository_id)
        .bind(&source.source_kind)
        .bind(&source.source_key)
        .bind(source.revision)
        .bind(error.as_str())
        .bind(retry_seconds.map(f64::from))
        .bind(MAX_RECONCILIATION_ATTEMPTS)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

async fn lock_source(
    connection: &mut PgConnection,
    source: &GitHubSource,
) -> Result<Option<BoundSource>, MetaError> {
    sqlx::query_as(
        "SELECT name, branch_id, observed_present, waiting_for_cleanup FROM github_source
         WHERE repository_id = $1 AND source_kind = $2 AND source_key = $3 AND revision = $4
           AND retry_at IS NOT NULL FOR UPDATE",
    )
    .bind(source.repository_id)
    .bind(&source.source_kind)
    .bind(&source.source_key)
    .bind(source.revision)
    .fetch_optional(connection)
    .await
    .map_err(Into::into)
}

async fn ensure_present(
    connection: &mut PgConnection,
    observation: &GitHubObservation<'_>,
    binding: &BoundSource,
) -> Result<(Option<i64>, bool, bool), MetaError> {
    if binding.observed_present == Some(true) && !binding.waiting_for_cleanup {
        return Ok((binding.branch_id, false, false));
    }
    let source = observation.source;
    if let Some(id) = binding.branch_id {
        let status: String = sqlx::query_scalar(
            "SELECT status FROM branch WHERE id = $1 AND created_by = $2 FOR UPDATE",
        )
        .bind(id)
        .bind(&source.principal)
        .fetch_one(&mut *connection)
        .await?;
        match status.as_str() {
            "dropping" => return Ok((Some(id), true, false)),
            "provisioning" | "active" => return Ok((Some(id), false, false)),
            "dropped" => (),
            _ => return Err(MetaError::InvalidCatalog),
        }
    }
    let class = if source.source_kind == "ref" {
        BranchClass::Dev
    } else {
        BranchClass::Ci
    };
    let branch = lifecycle::fork_in(
        connection,
        &ForkBranch {
            engine: observation.engine,
            principal: &source.principal,
            name: &binding.name,
            ttl_seconds: class.default_ttl_seconds(),
            class,
            mode: if class == BranchClass::Ci && observation.pr_write {
                BranchMode::NativeWrite
            } else {
                BranchMode::ReadOnly
            },
            expected_generation: None,
        },
        GITHUB_ACTOR,
    )
    .await?;
    Ok((Some(branch.id), false, true))
}

async fn commit_observation(
    connection: &mut PgConnection,
    observation: &GitHubObservation<'_>,
    branch_id: Option<i64>,
    waiting: bool,
) -> Result<(), MetaError> {
    let source = observation.source;
    sqlx::query(
        "UPDATE github_source SET observed_present = $5, branch_id = $6,
             waiting_for_cleanup = $7, applied_revision = $4, attempts = 0, last_error = NULL,
             retry_at = CASE WHEN $7 THEN clock_timestamp() ELSE NULL END
         WHERE repository_id = $1 AND source_kind = $2 AND source_key = $3 AND revision = $4",
    )
    .bind(source.repository_id)
    .bind(&source.source_kind)
    .bind(&source.source_key)
    .bind(source.revision)
    .bind(observation.present)
    .bind(branch_id)
    .bind(waiting)
    .execute(connection)
    .await?;
    Ok(())
}
