CREATE TABLE catalog_table (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY CHECK (id > 0),
    generation_id BIGINT NOT NULL REFERENCES generation(id),
    logical_schema TEXT NOT NULL CHECK (logical_schema <> ''),
    logical_table TEXT NOT NULL CHECK (logical_table <> ''),
    base_schema TEXT GENERATED ALWAYS AS ('fg_g' || generation_id::text) STORED NOT NULL,
    base_table TEXT NOT NULL CHECK (base_table <> ''),
    delta_schema TEXT NOT NULL DEFAULT 'forkget_delta' CHECK (delta_schema = 'forkget_delta'),
    delta_table TEXT GENERATED ALWAYS AS ('_d_g' || generation_id::text || '_t' || id::text)
        STORED NOT NULL,
    UNIQUE (generation_id, logical_schema, logical_table),
    UNIQUE (base_schema, base_table),
    UNIQUE (delta_schema, delta_table)
);

CREATE TABLE catalog_column (
    table_id BIGINT NOT NULL REFERENCES catalog_table(id),
    ordinal INTEGER NOT NULL CHECK (ordinal > 0),
    name TEXT NOT NULL CHECK (name <> ''),
    data_type TEXT NOT NULL CHECK (data_type <> ''),
    collation_name TEXT,
    is_nullable BOOLEAN NOT NULL,
    key_ordinal INTEGER CHECK (key_ordinal IS NULL OR (key_ordinal > 0 AND NOT is_nullable)),
    PRIMARY KEY (table_id, ordinal),
    UNIQUE (table_id, name),
    UNIQUE (table_id, key_ordinal)
);
