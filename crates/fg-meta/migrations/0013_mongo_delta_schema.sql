-- MongoDB delta collections live in the generation
-- database so branch reads can merge base and delta with same-database
-- $lookup/$unionWith (cross-database aggregation stages do not exist).
ALTER TABLE catalog_table DROP CONSTRAINT catalog_table_delta_schema_check;
ALTER TABLE catalog_table ADD CONSTRAINT catalog_table_delta_schema_check CHECK (
    delta_schema = 'forkget_delta'
    OR delta_schema LIKE 'fg\_g%' ESCAPE '\'
);
