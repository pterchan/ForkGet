-- Regression for the generated visibility relation on MySQL 8.0.
-- Executed by test/rewrite/mysql.py against a disposable local database.
-- The runner substitutes the generated-relation marker line below with the
-- rendered SELECT before execution; the marker literal appears exactly once.

DROP SCHEMA IF EXISTS fg_g1;
DROP SCHEMA IF EXISTS forkget_delta;
CREATE SCHEMA fg_g1;
CREATE SCHEMA forkget_delta;
CREATE TABLE fg_g1.orders (
    tenant_id BIGINT NOT NULL,
    id BIGINT NOT NULL,
    amount DECIMAL(12, 2),
    note VARCHAR(64),
    PRIMARY KEY (tenant_id, id)
);
CREATE TABLE forkget_delta._d_g1_t1 (
    _fg_branch BIGINT NOT NULL,
    _fg_op CHAR(1) NOT NULL CHECK (_fg_op IN ('I', 'U', 'D')),
    tenant_id BIGINT NOT NULL,
    id BIGINT NOT NULL,
    amount DECIMAL(12, 2),
    note VARCHAR(64),
    PRIMARY KEY (_fg_branch, tenant_id, id)
);
INSERT INTO fg_g1.orders VALUES
    (1, 1, 10, 'untouched'),
    (1, 2, 20, 'old value'),
    (1, 3, 30, 'deleted'),
    (2, 2, 40, 'other tenant'),
    (1, 5, 50, 'deleted then reinserted'),
    (1, 6, 10, 'untouched');
INSERT INTO forkget_delta._d_g1_t1 VALUES
    (7, 'U', 1, 2, NULL, 'updated to null'),
    (7, 'D', 1, 3, NULL, NULL),
    (7, 'I', 1, 4, 60, 'inserted'),
    (7, 'D', 1, 5, NULL, NULL),
    (7, 'D', 1, 99, NULL, NULL),
    (8, 'U', 1, 1, 999, 'other branch'),
    (8, 'I', 1, 9, 99, 'other branch insert');

-- Test view only; the product embeds the relation in the query AST.
CREATE VIEW fg_g1.branch_rows AS
-- GENERATED_VISIBLE_RELATION
;

DELIMITER //
CREATE PROCEDURE fg_g1.fg_assert_equal(IN label VARCHAR(128), IN got LONGTEXT, IN want LONGTEXT)
BEGIN
    IF NOT (got <=> want) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = label;
    END IF;
END//
CREATE PROCEDURE fg_g1.fg_assert_true(IN label VARCHAR(128), IN is_condition_true BOOLEAN)
BEGIN
    IF NOT is_condition_true THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = label;
    END IF;
END//
DELIMITER ;

-- The composite primary key makes (tenant_id, id) a total order, so the
-- grouped concatenation is a canonical multiset encoding of the visible rows.
SET SESSION group_concat_max_len = 1048576;
CREATE TABLE fg_g1.expected (LIKE fg_g1.orders);
INSERT INTO fg_g1.expected VALUES
    (1, 1, 10, 'untouched'),
    (1, 2, NULL, 'updated to null'),
    (2, 2, 40, 'other tenant'),
    (1, 4, 60, 'inserted'),
    (1, 6, 10, 'untouched');

SET @base_before = (
    SELECT GROUP_CONCAT(
        CONCAT_WS('#', tenant_id, id, IFNULL(CAST(amount AS CHAR), '<NULL>'), IFNULL(note, '<NULL>'))
        ORDER BY tenant_id, id SEPARATOR ' | ')
    FROM fg_g1.orders);
SET @got_rows = (
    SELECT GROUP_CONCAT(
        CONCAT_WS('#', tenant_id, id, IFNULL(CAST(amount AS CHAR), '<NULL>'), IFNULL(note, '<NULL>'))
        ORDER BY tenant_id, id SEPARATOR ' | ')
    FROM fg_g1.branch_rows);
SET @want_rows = (
    SELECT GROUP_CONCAT(
        CONCAT_WS('#', tenant_id, id, IFNULL(CAST(amount AS CHAR), '<NULL>'), IFNULL(note, '<NULL>'))
        ORDER BY tenant_id, id SEPARATOR ' | ')
    FROM fg_g1.expected);
CALL fg_g1.fg_assert_equal('Visible rows differ: base, insert, update, NULL, tombstone, composite key or branch isolation', @got_rows, @want_rows);

SELECT COUNT(*) INTO @duplicate_payloads
FROM fg_g1.branch_rows WHERE amount = 10 AND note = 'untouched';
CALL fg_g1.fg_assert_true('Duplicate projected payloads were lost', @duplicate_payloads = 2);

SELECT IFNULL(SUM(amount), -1) INTO @visible_total FROM fg_g1.branch_rows;
CALL fg_g1.fg_assert_true('Aggregate visibility differs', @visible_total = 120);

SELECT GROUP_CONCAT(id ORDER BY amount DESC, tenant_id, id) INTO @top_rows
FROM (SELECT * FROM fg_g1.branch_rows ORDER BY amount DESC, tenant_id, id LIMIT 2) AS top_rows;
CALL fg_g1.fg_assert_equal('Outer ORDER BY / LIMIT visibility differs', @top_rows, '4,2');
SELECT 'PASS: row visibility, composite keys, branch isolation, NULL, duplicates, aggregation, ORDER BY/LIMIT' AS check_result;

UPDATE forkget_delta._d_g1_t1
SET _fg_op = 'I', amount = 55, note = 'reinserted'
WHERE _fg_branch = 7 AND tenant_id = 1 AND id = 5;
INSERT INTO fg_g1.expected VALUES (1, 5, 55, 'reinserted');
SET @got_rows = (
    SELECT GROUP_CONCAT(
        CONCAT_WS('#', tenant_id, id, IFNULL(CAST(amount AS CHAR), '<NULL>'), IFNULL(note, '<NULL>'))
        ORDER BY tenant_id, id SEPARATOR ' | ')
    FROM fg_g1.branch_rows);
SET @want_rows = (
    SELECT GROUP_CONCAT(
        CONCAT_WS('#', tenant_id, id, IFNULL(CAST(amount AS CHAR), '<NULL>'), IFNULL(note, '<NULL>'))
        ORDER BY tenant_id, id SEPARATOR ' | ')
    FROM fg_g1.expected);
CALL fg_g1.fg_assert_equal('Tombstone resurrection differs', @got_rows, @want_rows);
SELECT 'PASS: tombstone resurrection' AS check_result;

START TRANSACTION;
UPDATE forkget_delta._d_g1_t1 SET amount = 600
WHERE _fg_branch = 7 AND tenant_id = 1 AND id = 4;
SELECT CAST(amount AS CHAR) INTO @read_own_write
FROM fg_g1.branch_rows WHERE tenant_id = 1 AND id = 4;
CALL fg_g1.fg_assert_equal('Read-your-own-delta-write differs', @read_own_write, '600.00');
ROLLBACK;
SET @got_rows = (
    SELECT GROUP_CONCAT(
        CONCAT_WS('#', tenant_id, id, IFNULL(CAST(amount AS CHAR), '<NULL>'), IFNULL(note, '<NULL>'))
        ORDER BY tenant_id, id SEPARATOR ' | ')
    FROM fg_g1.branch_rows);
SET @want_rows = (
    SELECT GROUP_CONCAT(
        CONCAT_WS('#', tenant_id, id, IFNULL(CAST(amount AS CHAR), '<NULL>'), IFNULL(note, '<NULL>'))
        ORDER BY tenant_id, id SEPARATOR ' | ')
    FROM fg_g1.expected);
CALL fg_g1.fg_assert_equal('Rolled-back delta write remains visible', @got_rows, @want_rows);
SET @base_after = (
    SELECT GROUP_CONCAT(
        CONCAT_WS('#', tenant_id, id, IFNULL(CAST(amount AS CHAR), '<NULL>'), IFNULL(note, '<NULL>'))
        ORDER BY tenant_id, id SEPARATOR ' | ')
    FROM fg_g1.orders);
CALL fg_g1.fg_assert_equal('Base rows changed', @base_after, @base_before);
SELECT 'PASS: native delta transaction visibility, rollback and unchanged base' AS check_result;

DROP SCHEMA fg_g1;
DROP SCHEMA forkget_delta;
