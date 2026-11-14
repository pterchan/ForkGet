-- Admit TiDB as a generation engine.
ALTER TABLE generation DROP CONSTRAINT generation_engine_check;
ALTER TABLE generation ADD CONSTRAINT generation_engine_check CHECK (
    engine IN ('mysql', 'postgresql', 'tidb')
);
