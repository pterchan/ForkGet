-- Access is independent of physical storage and read optimization.
ALTER TABLE branch
    ADD COLUMN access TEXT,
    ADD COLUMN layout TEXT,
    ADD COLUMN read_strategy TEXT;

UPDATE branch b SET
    access = CASE
        WHEN b.class <> 'staging' AND (b.mode = 'native_write' OR g.engine = 'mongodb')
            THEN 'read_write'
        ELSE 'read_only'
    END,
    layout = CASE WHEN b.mode = 'native_write' THEN 'native_copy' ELSE 'sparse_delta' END,
    read_strategy = 'merge'
FROM generation g WHERE g.id = b.generation_id;

-- Replace old checks which conflated the compatibility mode with permission.
DO $$
DECLARE constraint_name TEXT;
BEGIN
    FOR constraint_name IN
        SELECT c.conname FROM pg_constraint c
        JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
        WHERE c.conrelid = 'branch'::regclass AND c.contype = 'c' AND a.attname = 'mode'
    LOOP
        EXECUTE format('ALTER TABLE branch DROP CONSTRAINT %I', constraint_name);
    END LOOP;
END
$$;

ALTER TABLE branch
    ALTER COLUMN access SET NOT NULL,
    ALTER COLUMN layout SET NOT NULL,
    ALTER COLUMN read_strategy SET NOT NULL,
    ADD CONSTRAINT branch_access_check CHECK (access IN ('read_only', 'read_write')),
    ADD CONSTRAINT branch_layout_check CHECK (layout IN ('sparse_delta', 'native_copy')),
    ADD CONSTRAINT branch_read_strategy_check CHECK (read_strategy IN ('merge', 'base_only')),
    ADD CONSTRAINT branch_mode_compatibility CHECK (
        (mode = 'read_only' AND layout = 'sparse_delta')
        OR (mode = 'native_write' AND layout = 'native_copy')),
    ADD CONSTRAINT branch_staging_access CHECK (class <> 'staging' OR access = 'read_only'),
    ADD CONSTRAINT branch_base_only_access CHECK (
        read_strategy <> 'base_only' OR (access = 'read_only' AND layout = 'sparse_delta')),
    ADD CONSTRAINT branch_provisioning_layout CHECK (status <> 'provisioning' OR layout = 'native_copy'),
    ADD CONSTRAINT branch_native_claim_layout CHECK (NOT native_claimed OR layout = 'native_copy'),
    ADD CONSTRAINT branch_active_storage CHECK (status <> 'active' OR layout = 'sparse_delta' OR native_claimed),
    ADD CONSTRAINT branch_shared_layout CHECK (NOT uses_mysql_shared_schema OR layout = 'native_copy');

-- Legacy callers may omit the new fields, but never obtain base_only implicitly.
CREATE FUNCTION enforce_branch_storage_contract() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE branch_engine TEXT;
BEGIN
    IF TG_OP = 'UPDATE' AND (
        NEW.access IS DISTINCT FROM OLD.access OR NEW.layout IS DISTINCT FROM OLD.layout
        OR NEW.read_strategy IS DISTINCT FROM OLD.read_strategy) THEN
        RAISE EXCEPTION 'Branch access, layout and read strategy are immutable'
            USING ERRCODE = '23514';
    END IF;
    NEW.access := COALESCE(NEW.access, CASE WHEN NEW.mode = 'native_write' THEN 'read_write' ELSE 'read_only' END);
    NEW.layout := COALESCE(NEW.layout, CASE WHEN NEW.mode = 'native_write' THEN 'native_copy' ELSE 'sparse_delta' END);
    NEW.read_strategy := COALESCE(NEW.read_strategy, 'merge');
    SELECT engine INTO branch_engine FROM generation WHERE id = NEW.generation_id;
    IF (NEW.read_strategy = 'base_only' AND branch_engine NOT IN ('mysql', 'postgresql', 'tidb'))
        OR (NEW.access = 'read_write' AND NEW.layout = 'sparse_delta' AND branch_engine <> 'mongodb') THEN
        RAISE EXCEPTION 'Unsupported branch access and storage combination' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER branch_storage_contract BEFORE INSERT OR UPDATE ON branch
    FOR EACH ROW EXECUTE FUNCTION enforce_branch_storage_contract();
