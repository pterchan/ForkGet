ALTER TABLE branch ADD COLUMN lease_version BIGINT NOT NULL DEFAULT 1 CHECK (lease_version > 0);
ALTER TABLE branch ADD COLUMN lease_renewed_at TIMESTAMPTZ;
UPDATE branch SET lease_renewed_at = created_at;
ALTER TABLE branch ALTER COLUMN lease_renewed_at SET DEFAULT clock_timestamp();
ALTER TABLE branch ALTER COLUMN lease_renewed_at SET NOT NULL;

DO $$
DECLARE item RECORD;
BEGIN
    FOR item IN SELECT conname FROM pg_constraint
        WHERE conrelid = 'branch'::regclass AND contype = 'c'
          AND pg_get_constraintdef(oid) LIKE '%expires_at%created_at%'
    LOOP
        EXECUTE format('ALTER TABLE branch DROP CONSTRAINT %I', item.conname);
    END LOOP;
END $$;
ALTER TABLE branch ADD CONSTRAINT branch_lifetime_bound CHECK (
    expires_at > created_at AND expires_at <= created_at + INTERVAL '7 days'
    AND expires_at <= lease_renewed_at + INTERVAL '24 hours'
);

ALTER TABLE generation ADD COLUMN reclaim_started_at TIMESTAMPTZ;
-- An older controller may have partially removed an unpinned generation.
-- Do not open it to new replay pins after upgrading.
UPDATE generation g SET reclaim_started_at = clock_timestamp()
WHERE status = 'retiring' AND NOT EXISTS (
    SELECT 1 FROM branch b WHERE b.generation_id = g.id AND b.status <> 'dropped'
);
