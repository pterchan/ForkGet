ALTER TABLE branch ADD COLUMN lifecycle_phase TEXT NOT NULL DEFAULT 'queued'
    CHECK (lifecycle_phase IN ('queued','preflight','copying','validating','granting','ready',
                              'draining','removing','removed','provision_retry','cleanup_retry'));
ALTER TABLE branch ADD COLUMN lifecycle_reason TEXT;
ALTER TABLE branch ADD COLUMN lifecycle_updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp();
ALTER TABLE branch ADD COLUMN capture_active BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE branch ADD COLUMN capture_version BIGINT NOT NULL DEFAULT 0 CHECK(capture_version>=0);
ALTER TABLE branch ADD COLUMN storage_preflight JSONB NOT NULL DEFAULT '{}'
    CHECK(jsonb_typeof(storage_preflight)='object');
ALTER TABLE snapshot_job ADD COLUMN storage_preflight JSONB NOT NULL DEFAULT '{}'
    CHECK(jsonb_typeof(storage_preflight)='object');

UPDATE branch SET lifecycle_phase=CASE status WHEN 'active' THEN 'ready'
    WHEN 'dropping' THEN 'draining' WHEN 'dropped' THEN 'removed' ELSE 'queued' END;

CREATE FUNCTION forkget_lifecycle_state() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='INSERT' OR NEW.status IS DISTINCT FROM OLD.status THEN
        NEW.lifecycle_phase=CASE NEW.status WHEN 'active' THEN 'ready'
            WHEN 'dropping' THEN 'draining' WHEN 'dropped' THEN 'removed' ELSE 'queued' END;
        NEW.lifecycle_updated_at=clock_timestamp();
        IF NEW.status IN ('active','dropped') THEN NEW.lifecycle_reason=NULL; END IF;
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER branch_lifecycle_state BEFORE INSERT OR UPDATE OF status ON branch
    FOR EACH ROW EXECUTE FUNCTION forkget_lifecycle_state();
