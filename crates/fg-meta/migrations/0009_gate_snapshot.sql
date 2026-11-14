ALTER TABLE generation DROP CONSTRAINT generation_snapshot_check;
ALTER TABLE generation ADD CONSTRAINT generation_snapshot_check CHECK (
    snapshot IN ('v1', 'v2', 'v3') OR
    CASE WHEN snapshot ~ '^gate-v2-[1-9][0-9]{0,7}$'
        THEN substring(snapshot FROM 9)::integer <= 20000000
        ELSE FALSE
    END
);
