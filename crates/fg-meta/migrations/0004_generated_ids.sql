CREATE TABLE generated_id_cursor (
    branch_id BIGINT NOT NULL REFERENCES branch(id),
    table_id BIGINT NOT NULL REFERENCES catalog_table(id),
    next_id BIGINT NOT NULL CHECK (next_id >= 4611686018427387904),
    PRIMARY KEY (branch_id, table_id)
);
