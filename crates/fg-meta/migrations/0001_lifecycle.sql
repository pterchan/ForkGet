CREATE TABLE generation (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY CHECK (id > 0),
    engine TEXT NOT NULL CHECK (engine IN ('mysql', 'postgresql')),
    schema_name TEXT GENERATED ALWAYS AS ('fg_g' || id::text) STORED UNIQUE NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('importing', 'active', 'retiring', 'retired', 'failed')),
    native_claimed BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at TIMESTAMPTZ,
    retired_at TIMESTAMPTZ,
    CHECK (status NOT IN ('active', 'retiring', 'retired') OR (native_claimed AND activated_at IS NOT NULL))
);

CREATE UNIQUE INDEX one_active_generation ON generation ((TRUE)) WHERE status = 'active';
CREATE UNIQUE INDEX one_importing_generation ON generation ((TRUE)) WHERE status = 'importing';

CREATE TABLE branch (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY CHECK (id > 0),
    name TEXT NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{2,62}$'),
    class TEXT NOT NULL CHECK (class = 'dev'),
    generation_id BIGINT NOT NULL REFERENCES generation(id),
    created_by TEXT NOT NULL CHECK (created_by <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'dropping', 'dropped')),
    CHECK (expires_at > created_at AND expires_at <= created_at + INTERVAL '24 hours')
);

CREATE UNIQUE INDEX live_branch_name ON branch (name) WHERE status IN ('active', 'dropping');
CREATE INDEX branch_generation ON branch (generation_id, status);

CREATE TABLE audit_event (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor TEXT NOT NULL,
    branch_id BIGINT REFERENCES branch(id),
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL
);
