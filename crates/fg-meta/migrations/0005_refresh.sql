CREATE TABLE refresh_job (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY CHECK (id > 0),
    target_generation_id BIGINT NOT NULL UNIQUE REFERENCES generation(id),
    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'succeeded', 'failed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    CHECK (status NOT IN ('running', 'succeeded') OR started_at IS NOT NULL),
    CHECK ((status IN ('succeeded', 'failed')) = (finished_at IS NOT NULL))
);

-- The prior controller only marked an import failed after confirmed cleanup
-- or before claiming any native objects.
UPDATE generation SET native_claimed = FALSE WHERE status = 'failed';
