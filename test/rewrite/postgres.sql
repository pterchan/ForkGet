CREATE SCHEMA fg_g1;
CREATE SCHEMA forkget_delta;
CREATE TABLE fg_g1.orders (
    tenant_id BIGINT NOT NULL,
    id BIGINT NOT NULL,
    amount NUMERIC(12, 2),
    note TEXT,
    PRIMARY KEY (tenant_id, id)
);
CREATE TABLE forkget_delta._d_g1_t1 (
    _fg_branch BIGINT NOT NULL,
    _fg_op CHAR(1) NOT NULL CHECK (_fg_op IN ('I', 'U', 'D')),
    tenant_id BIGINT NOT NULL,
    id BIGINT NOT NULL,
    amount NUMERIC(12, 2),
    note TEXT,
    PRIMARY KEY (_fg_branch, tenant_id, id)
);
INSERT INTO fg_g1.orders VALUES
    (1, 1, 10, 'untouched'),
    (1, 2, 20, 'old value'),
    (1, 3, 30, 'deleted'),
    (2, 2, 40, 'other tenant'),
    (1, 5, 50, 'deleted then reinserted'),
    (1, 6, 10, 'untouched');
CREATE TEMP TABLE original_base AS TABLE fg_g1.orders;
INSERT INTO forkget_delta._d_g1_t1 VALUES
    (7, 'U', 1, 2, NULL, 'updated to null'),
    (7, 'D', 1, 3, NULL, NULL),
    (7, 'I', 1, 4, 60, 'inserted'),
    (7, 'D', 1, 5, NULL, NULL),
    (7, 'D', 1, 99, NULL, NULL),
    (8, 'U', 1, 1, 999, 'other branch'),
    (8, 'I', 1, 9, 99, 'other branch insert');

-- Temporary test view only; the product embeds the relation in the query AST.
CREATE TEMP VIEW branch_rows AS
-- GENERATED_VISIBLE_RELATION
;
CREATE TEMP TABLE expected (LIKE fg_g1.orders);
INSERT INTO expected VALUES
    (1, 1, 10, 'untouched'),
    (1, 2, NULL, 'updated to null'),
    (2, 2, 40, 'other tenant'),
    (1, 4, 60, 'inserted'),
    (1, 6, 10, 'untouched');

DO $$ BEGIN
    IF EXISTS ((TABLE branch_rows EXCEPT ALL TABLE expected)
               UNION ALL (TABLE expected EXCEPT ALL TABLE branch_rows)) THEN
        RAISE EXCEPTION 'Visible rows differ: base, insert, update, NULL, tombstone, composite key or branch isolation';
    END IF;
    IF (SELECT count(*) FROM branch_rows WHERE amount = 10 AND note = 'untouched') <> 2 THEN
        RAISE EXCEPTION 'Duplicate projected payloads were lost';
    END IF;
    IF (SELECT sum(amount) FROM branch_rows) IS DISTINCT FROM 120 THEN
        RAISE EXCEPTION 'Aggregate visibility differs';
    END IF;
    IF (SELECT array_agg(id ORDER BY amount DESC, tenant_id, id)
        FROM (SELECT * FROM branch_rows ORDER BY amount DESC NULLS LAST, tenant_id, id LIMIT 2) AS top_rows)
       IS DISTINCT FROM ARRAY[4, 2]::BIGINT[] THEN
        RAISE EXCEPTION 'Outer ORDER BY / LIMIT visibility differs';
    END IF;
END $$;
\echo 'PASS: row visibility, composite keys, branch isolation, NULL, duplicates, aggregation, ORDER BY/LIMIT'

UPDATE forkget_delta._d_g1_t1
SET _fg_op = 'I', amount = 55, note = 'reinserted'
WHERE _fg_branch = 7 AND tenant_id = 1 AND id = 5;
INSERT INTO expected VALUES (1, 5, 55, 'reinserted');
DO $$ BEGIN
    IF EXISTS ((TABLE branch_rows EXCEPT ALL TABLE expected)
               UNION ALL (TABLE expected EXCEPT ALL TABLE branch_rows)) THEN
        RAISE EXCEPTION 'Tombstone resurrection differs';
    END IF;
END $$;
\echo 'PASS: tombstone resurrection'

BEGIN;
UPDATE forkget_delta._d_g1_t1 SET amount = 600
WHERE _fg_branch = 7 AND tenant_id = 1 AND id = 4;
DO $$ BEGIN
    IF (SELECT amount FROM branch_rows WHERE tenant_id = 1 AND id = 4) IS DISTINCT FROM 600 THEN
        RAISE EXCEPTION 'Read-your-own-delta-write differs';
    END IF;
END $$;
ROLLBACK;
DO $$ BEGIN
    IF EXISTS ((TABLE branch_rows EXCEPT ALL TABLE expected)
               UNION ALL (TABLE expected EXCEPT ALL TABLE branch_rows)) THEN
        RAISE EXCEPTION 'Rolled-back delta write remains visible';
    END IF;
    IF EXISTS ((TABLE fg_g1.orders EXCEPT ALL TABLE original_base)
               UNION ALL (TABLE original_base EXCEPT ALL TABLE fg_g1.orders)) THEN
        RAISE EXCEPTION 'Base rows changed';
    END IF;
END $$;
\echo 'PASS: native delta transaction visibility, rollback and unchanged base'
