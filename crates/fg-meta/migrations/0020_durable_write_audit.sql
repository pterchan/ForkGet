ALTER TABLE branch ADD COLUMN audit_witness_version SMALLINT NOT NULL DEFAULT 0
    CHECK (audit_witness_version IN (0, 1));
ALTER TABLE branch ADD COLUMN audit_witness_incarnation TEXT
    CHECK (audit_witness_incarnation ~ '^[0-9a-f]{32}$');
ALTER TABLE branch ADD COLUMN audit_witness_ready BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE branch ADD COLUMN audit_storage_invalidated BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE branch ADD COLUMN audit_storage_reclaim_started BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE branch ADD CONSTRAINT audit_storage_reclaim_state CHECK (
    NOT audit_storage_reclaim_started OR (NOT audit_witness_ready AND status IN ('dropping','dropped')));
ALTER TABLE branch ADD CONSTRAINT audit_witness_identity CHECK (
    (audit_witness_version=0 AND audit_witness_incarnation IS NULL AND NOT audit_witness_ready)
    OR (audit_witness_version=1 AND audit_witness_incarnation IS NOT NULL));

CREATE TABLE audit_attempt (
    attempt_id TEXT PRIMARY KEY CHECK (attempt_id ~ '^[0-9a-f]{32}:[1-9][0-9]{0,19}:[1-9][0-9]{0,19}$'),
    branch_id BIGINT NOT NULL REFERENCES branch(id),
    generation_id BIGINT NOT NULL REFERENCES generation(id),
    engine TEXT NOT NULL CHECK (engine IN ('mysql','postgresql','tidb','mongodb')),
    principal TEXT NOT NULL CHECK (principal<>''),
    session_id TEXT NOT NULL,
    native_session_id BIGINT NOT NULL CHECK (native_session_id>0 AND native_session_id<=4294967295),
    replay_job_id BIGINT REFERENCES replay_job(id),
    mode TEXT NOT NULL CHECK (mode IN ('sql_transaction','mongo_command')),
    witness JSONB,
    policy_version BIGINT NOT NULL CHECK (policy_version>0),
    effective_revision BIGINT NOT NULL CHECK (effective_revision>=0),
    last_verdict TEXT NOT NULL CHECK (last_verdict IN ('allowed','limit','native_error','await_approval')),
    approval_id BIGINT REFERENCES policy_approval(id),
    sealed BOOLEAN NOT NULL DEFAULT FALSE,
    outcome TEXT CHECK (outcome IN ('committed','rolled_back','unknown')),
    outcome_event_id BIGINT UNIQUE REFERENCES audit_event(id),
    outcome_payload JSONB,
    resolution TEXT CHECK (resolution IN ('committed','rolled_back')),
    resolution_event_id BIGINT UNIQUE REFERENCES audit_event(id),
    armed_step INTEGER NOT NULL DEFAULT 0 CHECK (armed_step>=0),
    witness_collected BOOLEAN NOT NULL DEFAULT FALSE,
    storage_history_trusted BOOLEAN NOT NULL DEFAULT TRUE,
    quiescence_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
    retention_ack_event_id BIGINT UNIQUE REFERENCES audit_event(id),
    late_payload JSONB,
    late_event_id BIGINT UNIQUE REFERENCES audit_event(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK ((mode='sql_transaction' AND engine<>'mongodb' AND (witness IS NOT NULL OR outcome IS NOT DISTINCT FROM 'rolled_back'))
        OR (mode='mongo_command' AND engine='mongodb' AND witness IS NULL)),
    CHECK ((outcome IS NULL)=(outcome_event_id IS NULL)),
    CHECK ((outcome IS NULL)=(outcome_payload IS NULL)),
    CHECK ((resolution IS NULL)=(resolution_event_id IS NULL)),
    CHECK ((late_payload IS NULL)=(late_event_id IS NULL)),
    CHECK (late_payload IS NULL OR (mode='mongo_command' AND sealed AND quiescence_confirmed AND outcome IS NOT DISTINCT FROM 'unknown')),
    CHECK (resolution IS NULL OR (sealed AND outcome IS NOT DISTINCT FROM 'unknown'))
);
CREATE TABLE audit_mongo_step (
    attempt_id TEXT NOT NULL REFERENCES audit_attempt(attempt_id),
    step INTEGER NOT NULL CHECK (step>0),
    observation JSONB,
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (attempt_id,step),
    CHECK ((observation IS NULL)=(completed_at IS NULL))
);

CREATE FUNCTION forkget_audit_pending(candidate audit_attempt) RETURNS BOOLEAN
LANGUAGE SQL IMMUTABLE AS $$
    SELECT candidate.outcome IS NULL
        OR (candidate.mode='sql_transaction' AND candidate.outcome='unknown'
            AND candidate.resolution IS NULL AND candidate.retention_ack_event_id IS NULL)
        OR (candidate.mode='mongo_command' AND candidate.outcome='unknown'
            AND NOT candidate.quiescence_confirmed)
$$;

CREATE INDEX audit_attempt_pending ON audit_attempt(engine,updated_at,attempt_id)
    WHERE outcome IS NULL
        OR (mode='sql_transaction' AND outcome='unknown'
            AND resolution IS NULL AND retention_ack_event_id IS NULL)
        OR (mode='mongo_command' AND outcome='unknown' AND NOT quiescence_confirmed);
CREATE INDEX audit_attempt_witness_collection ON audit_attempt(engine,branch_id,created_at)
    WHERE mode='sql_transaction' AND NOT witness_collected AND outcome IS NOT NULL
        AND (outcome<>'unknown' OR resolution IS NOT NULL);
