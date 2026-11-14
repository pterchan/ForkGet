ALTER TABLE generation
    ADD COLUMN snapshot TEXT NOT NULL DEFAULT 'v1' CHECK (snapshot IN ('v1', 'v2', 'v3'));

ALTER TABLE catalog_table
    ADD COLUMN generated_key TEXT CHECK (generated_key <> '');

ALTER TABLE branch
    ADD COLUMN mode TEXT NOT NULL DEFAULT 'read_only' CHECK (mode IN ('read_only', 'native_write')),
    ADD COLUMN native_claimed BOOLEAN NOT NULL DEFAULT FALSE,
    DROP CONSTRAINT branch_status_check,
    ADD CONSTRAINT branch_status_check CHECK (status IN ('provisioning', 'active', 'dropping', 'dropped')),
    ADD CHECK (status <> 'provisioning' OR mode = 'native_write'),
    ADD CHECK (NOT native_claimed OR mode = 'native_write'),
    ADD CHECK (status <> 'active' OR mode = 'read_only' OR native_claimed);

DROP INDEX live_branch_name;
CREATE UNIQUE INDEX live_branch_name ON branch (name) WHERE status <> 'dropped';
CREATE INDEX branch_expiry ON branch (expires_at, id) WHERE status IN ('provisioning', 'active');
