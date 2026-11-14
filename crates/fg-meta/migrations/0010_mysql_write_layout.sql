ALTER TABLE branch
    ADD COLUMN uses_mysql_shared_schema BOOLEAN NOT NULL DEFAULT FALSE,
    ADD CHECK (NOT uses_mysql_shared_schema OR mode = 'native_write');
