CREATE TABLE github_source (
    repository_id BIGINT NOT NULL CHECK (repository_id > 0),
    installation_id BIGINT NOT NULL CHECK (installation_id > 0),
    source_kind TEXT NOT NULL CHECK (source_kind IN ('ref', 'pull_request')),
    source_key TEXT NOT NULL CHECK (source_key <> ''),
    principal TEXT NOT NULL CHECK (principal <> ''),
    name TEXT UNIQUE CHECK (name ~ '^[a-z][a-z0-9-]{2,62}$'),
    branch_id BIGINT UNIQUE REFERENCES branch(id),
    observed_present BOOLEAN,
    waiting_for_cleanup BOOLEAN NOT NULL DEFAULT FALSE,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    applied_revision BIGINT NOT NULL DEFAULT 0 CHECK (applied_revision >= 0 AND applied_revision <= revision),
    retry_at TIMESTAMPTZ DEFAULT clock_timestamp(),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 16),
    last_error TEXT CHECK (last_error IN ('source_unavailable', 'access_unavailable', 'name_conflict', 'name_too_long', 'metadata_unavailable')),
    PRIMARY KEY (repository_id, source_kind, source_key),
    CHECK (name IS NOT NULL OR (retry_at IS NULL AND branch_id IS NULL)),
    CHECK (NOT waiting_for_cleanup OR (branch_id IS NOT NULL AND observed_present IS TRUE))
);

CREATE INDEX github_source_due ON github_source(retry_at) WHERE retry_at IS NOT NULL;
CREATE INDEX github_source_owner ON github_source(principal, repository_id, source_kind, source_key);
