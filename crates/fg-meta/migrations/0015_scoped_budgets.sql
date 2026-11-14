ALTER TABLE policy_version ADD COLUMN small_table_floor BIGINT NOT NULL DEFAULT 1
    CHECK (small_table_floor >= 1);

-- Only untouched built-in templates move to the new automatic defaults.
-- A new version preserves the old policy and all customized versions.
INSERT INTO policy_version
    (class, version, max_transaction_rows, table_limit_bps, approval_after_rows, small_table_floor)
SELECT p.class, p.version + 1, p.max_transaction_rows, p.table_limit_bps, NULL, 10
FROM policy_version p
WHERE p.version = 1
  AND NOT EXISTS (SELECT 1 FROM policy_version newer WHERE newer.class = p.class AND newer.version > p.version)
  AND ((p.class = 'dev' AND p.max_transaction_rows = 50000 AND p.table_limit_bps = 1000 AND p.approval_after_rows IS NULL)
    OR (p.class = 'ci' AND p.max_transaction_rows = 20000 AND p.table_limit_bps = 100 AND p.approval_after_rows IS NULL)
    OR (p.class = 'agent' AND p.max_transaction_rows = 10000 AND p.table_limit_bps = 100 AND p.approval_after_rows = 1)
    OR (p.class = 'staging' AND p.max_transaction_rows = 0 AND p.table_limit_bps IS NULL AND p.approval_after_rows IS NULL));

ALTER TABLE policy_approval ADD COLUMN effective_revision BIGINT NOT NULL DEFAULT 0
    CHECK (effective_revision >= 0);
UPDATE policy_approval a SET state = 'invalidated'
WHERE state IN ('pending', 'approved')
  AND policy_version <> (SELECT max(version) FROM policy_version p WHERE p.class = a.class);

CREATE TABLE branch_budget_revision (
    branch_id BIGINT PRIMARY KEY REFERENCES branch(id),
    revision BIGINT NOT NULL DEFAULT 0 CHECK (revision BETWEEN 0 AND 4611686018427387902)
);

CREATE TABLE budget_request (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    branch_id BIGINT NOT NULL REFERENCES branch(id),
    generation_id BIGINT NOT NULL REFERENCES generation(id),
    principal TEXT NOT NULL,
    class TEXT NOT NULL,
    policy_version BIGINT NOT NULL,
    effective_revision BIGINT NOT NULL CHECK (effective_revision >= 0),
    max_transaction_rows BIGINT NOT NULL CHECK (max_transaction_rows >= 0),
    table_limit_bps INTEGER CHECK (table_limit_bps BETWEEN 1 AND 10000),
    small_table_floor BIGINT NOT NULL CHECK (small_table_floor >= 1),
    ttl_seconds INTEGER NOT NULL CHECK (ttl_seconds BETWEEN 1 AND 3600),
    reason TEXT NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 512),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'approved', 'denied', 'expired', 'invalidated')),
    reviewed_by TEXT,
    FOREIGN KEY (class, policy_version) REFERENCES policy_version(class, version)
);
CREATE INDEX budget_request_branch ON budget_request(branch_id, id);

CREATE TABLE budget_grant (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    request_id BIGINT NOT NULL UNIQUE REFERENCES budget_request(id),
    branch_id BIGINT NOT NULL REFERENCES branch(id),
    generation_id BIGINT NOT NULL REFERENCES generation(id),
    principal TEXT NOT NULL,
    class TEXT NOT NULL,
    policy_version BIGINT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    max_transaction_rows BIGINT NOT NULL CHECK (max_transaction_rows >= 0),
    table_limit_bps INTEGER CHECK (table_limit_bps BETWEEN 1 AND 10000),
    small_table_floor BIGINT NOT NULL CHECK (small_table_floor >= 1),
    approved_by TEXT NOT NULL CHECK (approved_by <> principal),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoked_by TEXT,
    FOREIGN KEY (class, policy_version) REFERENCES policy_version(class, version),
    UNIQUE (branch_id, revision)
);
CREATE UNIQUE INDEX one_unrevoked_branch_grant ON budget_grant(branch_id) WHERE revoked_at IS NULL;

-- The low bit changes immediately when a grant expires, without a sweep or
-- cache timeout. The counter prevents revoked/replaced contexts reappearing.
CREATE FUNCTION forkget_budget_revision(target BIGINT) RETURNS BIGINT
LANGUAGE SQL VOLATILE AS $$
    SELECT COALESCE(r.revision, 0) * 2 + CASE WHEN EXISTS (
        SELECT 1 FROM budget_grant x
        WHERE x.branch_id = b.id AND x.revoked_at IS NULL
          AND x.expires_at > clock_timestamp() AND x.expires_at <= b.expires_at
          AND x.generation_id = b.generation_id AND x.principal = b.created_by
          AND x.class = b.class
          AND x.policy_version = (SELECT max(version) FROM policy_version WHERE class = b.class)
    ) THEN 1 ELSE 0 END
    FROM branch b LEFT JOIN branch_budget_revision r ON r.branch_id = b.id
    WHERE b.id = target
$$;
