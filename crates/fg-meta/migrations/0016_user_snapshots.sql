ALTER TABLE generation DROP CONSTRAINT generation_snapshot_check;
ALTER TABLE generation ADD CONSTRAINT generation_snapshot_check CHECK (
    snapshot IN ('v1','v2','v3') OR snapshot ~ '^[a-z][a-z0-9-]{2,62}$'
);
ALTER TABLE generation ADD COLUMN snapshot_manifest JSONB;
ALTER TABLE catalog_table ADD COLUMN definition JSONB;

CREATE TABLE snapshot_job (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    generation_id BIGINT UNIQUE REFERENCES generation(id),
    snapshot_name TEXT NOT NULL,
    engine TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('allocated','staging','loading','verifying','active','cleanup_pending','failed')),
    failure_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
