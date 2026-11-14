CREATE TABLE replay_job (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    branch_id BIGINT NOT NULL UNIQUE REFERENCES branch(id),
    principal TEXT NOT NULL,
    generation_id BIGINT NOT NULL REFERENCES generation(id),
    state TEXT NOT NULL DEFAULT 'staged' CHECK (state IN ('staged','running','verifying','verified','failed','unknown')),
    native_session_id BIGINT,
    session_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    failure_code TEXT,
    artifact_cleaned BOOLEAN NOT NULL DEFAULT FALSE
);
