CREATE TABLE replay_deployment (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    id UUID NOT NULL DEFAULT pg_catalog.gen_random_uuid()
);

INSERT INTO replay_deployment DEFAULT VALUES;
