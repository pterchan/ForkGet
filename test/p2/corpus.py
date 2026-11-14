"""Build the two branch comparison corpus from deterministic query families."""

import json
from pathlib import Path

from data import table


def reads(engine):
    yield "all-visible", "SELECT tenant_id, id, customer_id, amount, note, payload FROM orders ORDER BY tenant_id, id"
    yield "qualified-columns", "SELECT app.orders.id, app.orders.tenant_id FROM app.orders ORDER BY app.orders.tenant_id, app.orders.id"
    yield "qualified-star", "SELECT app.orders.* FROM app.orders ORDER BY tenant_id, id"
    yield "null-payload", "SELECT tenant_id, id, payload FROM orders WHERE payload IS NULL ORDER BY tenant_id, id"
    yield "non-null-payload", "SELECT tenant_id, id, payload FROM orders WHERE payload IS NOT NULL ORDER BY tenant_id, id"
    yield "distinct-buyers", "SELECT DISTINCT customer_id FROM orders ORDER BY customer_id"
    yield "correlated-exists", "SELECT c.id FROM customers c WHERE EXISTS (SELECT 1 FROM orders o WHERE o.customer_id = c.id AND o.tenant_id = 1) ORDER BY c.id"
    yield "in-subquery", "SELECT c.id FROM customers c WHERE c.id IN (SELECT o.customer_id FROM orders o WHERE o.amount >= 20) ORDER BY c.id"
    yield "derived", "SELECT p.id FROM (SELECT o.id FROM orders o WHERE o.tenant_id = 2) AS p ORDER BY p.id"
    yield "shadowed-table", "WITH orders AS (SELECT id FROM app.orders WHERE tenant_id = 1) SELECT id FROM orders ORDER BY id"
    yield "ordered-ctes", "WITH a AS (SELECT id FROM orders WHERE tenant_id = 1), b AS (SELECT id FROM a WHERE id >= 1) SELECT id FROM b ORDER BY id"
    yield "union-all", "SELECT id FROM orders WHERE tenant_id = 1 UNION ALL SELECT id FROM orders WHERE tenant_id = 2 ORDER BY id"
    yield "union-distinct", "SELECT id FROM orders WHERE tenant_id = 1 UNION SELECT id FROM orders WHERE tenant_id = 2 ORDER BY id"
    yield "rank", "SELECT tenant_id, id, ROW_NUMBER() OVER (PARTITION BY tenant_id ORDER BY id) AS seq FROM orders ORDER BY tenant_id, id"
    yield "self-join", "SELECT left_o.id, right_o.id AS right_id FROM orders left_o JOIN orders right_o ON left_o.id = right_o.id WHERE left_o.tenant_id = 1 AND right_o.tenant_id = 2 ORDER BY left_o.id"
    yield "left-join", "SELECT o.tenant_id, o.id, c.name FROM orders o LEFT JOIN customers c ON o.customer_id = c.id ORDER BY o.tenant_id, o.id"
    yield "string-fallback", "SELECT tenant_id, id, COALESCE(note, 'missing') AS label FROM orders ORDER BY tenant_id, id"
    yield "decimal-cast", "SELECT tenant_id, id, CAST(amount AS DECIMAL(12,2)) AS value FROM orders ORDER BY tenant_id, id"
    yield "explicit-alias", "SELECT o.id AS order_id, o.tenant_id FROM app.orders AS o ORDER BY o.tenant_id, o.id"
    yield "text-case", "SELECT tenant_id, id, LOWER(note) AS label FROM orders ORDER BY tenant_id, id"
    for tenant in (1, 2, 3):
        for floor in (0, 10, 20, 40):
            yield f"tenant-{tenant}-floor-{floor}", f"SELECT id, amount, note FROM orders WHERE tenant_id = {tenant} AND amount >= {floor} ORDER BY id"
    for buyer in (10, 20, 30):
        for floor in (0, 30):
            yield f"buyer-{buyer}-floor-{floor}", f"SELECT o.tenant_id, o.id, c.name FROM orders o JOIN customers c ON o.customer_id = c.id WHERE c.id = {buyer} AND o.amount >= {floor} ORDER BY o.tenant_id, o.id"
    for agg in ("SUM", "MIN", "MAX", "AVG"):
        for count in (1, 2):
            yield f"groups-{agg.lower()}-{count}", f"SELECT tenant_id, {agg}(amount) AS total FROM orders GROUP BY tenant_id HAVING COUNT(*) >= {count} ORDER BY tenant_id"
    for limit in (1, 2, 3):
        for offset in (0, 1, 2):
            yield f"page-{limit}-{offset}", f"SELECT tenant_id, id FROM orders ORDER BY tenant_id, id LIMIT {limit} OFFSET {offset}"
    for offset in (0, 1, 2):
        for comparison in ("IS NULL", "IS NOT NULL"):
            yield f"nullable-{comparison.replace(' ', '-').lower()}-{offset}", f"SELECT tenant_id, id, note FROM orders WHERE note {comparison} ORDER BY tenant_id, id LIMIT 2 OFFSET {offset}"
    if engine == "postgresql":
        yield "fetch-page", "SELECT tenant_id, id FROM orders ORDER BY tenant_id, id OFFSET 1 ROW FETCH NEXT 2 ROWS ONLY"
    quote = "`" if engine in MYSQL_FAMILY else '"'
    yield "dialect-identifier", f"SELECT {quote}id{quote} FROM {quote}orders{quote} ORDER BY tenant_id, id"
    yield "literal-quote", "SELECT 'it''s' AS sample, id FROM orders ORDER BY tenant_id, id"


REFUSALS = (
    ("insert", "INSERT INTO orders (tenant_id,id) VALUES (9,9)", 2002),
    ("update", "UPDATE orders SET amount = 1", 2002),
    ("delete", "DELETE FROM orders", 2002),
    ("drop", "DROP TABLE orders", 2002),
    ("create", "CREATE TABLE extra (id INT)", 2002),
    ("alter", "ALTER TABLE orders ADD COLUMN extra INT", 2002),
    ("truncate", "TRUNCATE TABLE orders", 2002),
    ("transaction-mode", "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE", 2002),
    ("arbitrary-set", "SET search_path = forkget_delta", 2002),
    ("recursive", "WITH RECURSIVE a AS (SELECT 1 UNION ALL SELECT 1 FROM a) SELECT * FROM a", 2002),
    ("nested-lock", "SELECT id FROM orders WHERE id IN (SELECT id FROM orders FOR UPDATE)", 2002),
    ("lock", "SELECT * FROM orders FOR UPDATE", 2002),
    ("missing-table", "SELECT * FROM missing_table", 2003),
    ("missing-schema", "SELECT * FROM missing_schema.orders", 2003),
    ("physical-base", "SELECT * FROM fg_g1.orders", 2003),
    ("physical-delta", "SELECT * FROM forkget_delta._d_g1_t1", 2003),
    ("internal-column", "SELECT _fg_branch FROM orders", 2003),
    ("unknown-column", "SELECT unavailable_column FROM orders", 2003),
    ("unsafe-function", "SELECT dangerous_function(id) AS value FROM orders", 2004),
    ("qualified-function", "SELECT malicious.abs(id) AS value FROM orders", 2004),
    ("function-nested", "SELECT id FROM orders WHERE EXISTS (SELECT dangerous_function(id) AS value FROM customers)", 2004),
    ("system-tables", "SELECT * FROM information_schema.tables", 2003),
    ("multiple", "SELECT 1; SELECT 2", 2001),
    ("unbalanced", "SELECT (1", 2001),
    ("unterminated", "SELECT 'open", 2001),
    ("unexpected-eof", "SELECT id FROM", 2001),
    ("bad-join", "SELECT * FROM orders JOIN", 2001),
    ("token-hint", "SELECT /*+ SET_VAR(sql_mode='ANSI_QUOTES') */ id FROM orders", 2001),
    ("explain", "EXPLAIN SELECT id FROM orders", 2002),
    ("table-function", "SELECT * FROM dangerous_function()", 2002),
    ("bare-text-bind", "SELECT id FROM orders WHERE tenant_id = {}", 2001),
)


MYSQL_FAMILY = ("mysql", "tidb")


def cases():
    for engine in ("mysql", "postgresql", "tidb"):
        prefix = {"mysql": "mysql", "postgresql": "pg", "tidb": "tidb"}[engine]
        def make(case_id, sql, expect):
            return {"id": f"p2-{prefix}-{case_id}", "tags": ["p2-alpha", "p2-beta"],
                    "engines": [engine], "capabilities": ["sql.parser"],
                    "fixture": "materialized-branch", "steps": [{"sql": sql, "expect": expect}]}

        for name, sql in reads(engine):
            yield make(name, sql, {"kind": "rows", "order": "total"})
        codes = {2001: (1064, "42000", "42601"), 2002: (1235, "42000", "0A000"),
                 2003: (1146, "42S02", "42P01"), 2004: (1235, "42000", "0A000")}
        for name, sql, fg in REFUSALS:
            sql = sql.format("?" if engine in MYSQL_FAMILY else "$1")
            number, mysql_state, pg_state = codes[fg]
            expect = {"kind": "proxy_refusal", "fg": f"FG-{fg}",
                      "sqlstate": mysql_state if engine in MYSQL_FAMILY else pg_state}
            if engine in MYSQL_FAMILY:
                expect["errno"] = number
            yield make(f"refuse-{name}", sql, expect)


def write_corpus(directory: Path, binding):
    directory.mkdir()
    corpus = list(cases())
    entry = next(item for item in binding["tables"] if item["logical_table"] == "orders")
    engine = binding["engine"]
    for case in corpus:
        if case["engines"] != [engine]:
            continue
        step = case["steps"][0]
        step["sql"] = step["sql"].replace(
            "fg_g1.orders", table(engine, entry["base_schema"], entry["base_table"])
        ).replace(
            "forkget_delta._d_g1_t1", table(engine, entry["delta_schema"], entry["delta_table"])
        )
    assert sum(case["steps"][0]["expect"]["kind"] == "rows" for case in corpus) >= 120
    assert sum(case["steps"][0]["expect"]["kind"] == "proxy_refusal" for case in corpus) >= 60
    (directory / "p2.json").write_text(json.dumps(corpus, indent=2) + "\n")
