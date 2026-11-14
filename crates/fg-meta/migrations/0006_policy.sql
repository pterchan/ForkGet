ALTER TABLE branch
    DROP CONSTRAINT branch_class_check,
    ADD CHECK (class IN ('dev', 'ci', 'agent', 'staging')),
    ADD CHECK (class <> 'staging' OR mode = 'read_only');

ALTER TABLE catalog_table ADD COLUMN baseline_rows BIGINT NOT NULL DEFAULT 0
    CHECK (baseline_rows >= 0);

UPDATE catalog_table SET baseline_rows = CASE logical_table
    WHEN 'orders' THEN 4 WHEN 'customers' THEN 3 WHEN 'parents' THEN 3 WHEN 'children' THEN 3 ELSE 0 END
WHERE logical_schema = 'app';

CREATE TABLE policy_version (
    class TEXT NOT NULL CHECK (class IN ('dev', 'ci', 'agent', 'staging')),
    version BIGINT NOT NULL CHECK (version > 0),
    max_transaction_rows BIGINT NOT NULL CHECK (max_transaction_rows >= 0),
    table_limit_bps INTEGER CHECK (table_limit_bps BETWEEN 1 AND 10000),
    approval_after_rows BIGINT CHECK (approval_after_rows >= 0),
    PRIMARY KEY (class, version)
);

INSERT INTO policy_version (class, version, max_transaction_rows, table_limit_bps, approval_after_rows) VALUES
    ('dev', 1, 50000, 1000, NULL), ('ci', 1, 20000, 100, NULL),
    ('agent', 1, 10000, 100, 1), ('staging', 1, 0, NULL, NULL);

CREATE TABLE policy_proxy_epoch (
    singleton BOOLEAN PRIMARY KEY CHECK (singleton),
    epoch TEXT
);
INSERT INTO policy_proxy_epoch (singleton) VALUES (TRUE);

CREATE TABLE policy_approval (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY CHECK (id > 0),
    branch_id BIGINT NOT NULL REFERENCES branch(id),
    generation_id BIGINT NOT NULL REFERENCES generation(id),
    principal TEXT NOT NULL CHECK (principal <> ''),
    session_id TEXT NOT NULL CHECK (session_id <> ''),
    class TEXT NOT NULL,
    policy_version BIGINT NOT NULL,
    table_id BIGINT NOT NULL REFERENCES catalog_table(id),
    kind TEXT NOT NULL CHECK (kind IN ('insert', 'update', 'delete')),
    rows BIGINT NOT NULL CHECK (rows >= 0),
    expires_at TIMESTAMPTZ NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'approved', 'denied', 'expired', 'invalidated', 'consumed')),
    FOREIGN KEY (class, policy_version) REFERENCES policy_version(class, version)
);

CREATE UNIQUE INDEX one_live_invocation_approval ON policy_approval(session_id)
    WHERE state IN ('pending', 'approved');
CREATE INDEX live_approval_branch ON policy_approval(branch_id, id)
    WHERE state IN ('pending', 'approved');
CREATE INDEX audit_branch_order ON audit_event(branch_id, id);
