"""Compare guarded wire results with an independent native reference schema."""

from concurrent.futures import ThreadPoolExecutor
import json
import select
import subprocess

from run_p2 import ROOT, json_file, require

from pg_wire import abandon_generated_portal


START = 1 << 62
MAX = (1 << 63) - 2
REFERENCE = "p34_reference"
PARENTS = "SELECT id, tenant_id, code, parent_code, label FROM parents ORDER BY id"
CHILDREN = "SELECT id, tenant_id, parent_code, label FROM children ORDER BY id"
INSERT_PARENT = "INSERT INTO parents (id, tenant_id, code, label) VALUES ({}, 9, '{}', '{}')"


def seed_reference(run):
    schema = REFERENCE
    pg_deferred = " DEFERRABLE INITIALLY IMMEDIATE" if run.family == "postgresql" else ""
    pg_unique = f", UNIQUE (label){pg_deferred}" if run.family == "postgresql" else ""
    grants = (" ".join(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {schema}.{table} TO 'p2_ref'@'%';"
                       for table in ("parents", "children", "orders")) if run.family != "postgresql" else
              f"GRANT USAGE ON SCHEMA {schema} TO p2_ref; "
              f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {schema} TO p2_ref;")
    run.native(f"""
        CREATE SCHEMA {schema};
        CREATE TABLE {schema}.parents (
            id BIGINT PRIMARY KEY, tenant_id INT NOT NULL, code VARCHAR(64) NOT NULL,
            parent_code VARCHAR(64), label VARCHAR(64), UNIQUE (tenant_id, code),
            FOREIGN KEY (tenant_id, parent_code) REFERENCES {schema}.parents (tenant_id, code)
                ON UPDATE CASCADE {pg_deferred}{pg_unique}
        );
        CREATE TABLE {schema}.children (
            id BIGINT PRIMARY KEY, tenant_id INT NOT NULL, parent_code VARCHAR(64) NOT NULL,
            label VARCHAR(64), FOREIGN KEY (tenant_id, parent_code)
                REFERENCES {schema}.parents (tenant_id, code)
                ON UPDATE CASCADE ON DELETE CASCADE {pg_deferred}
        );
        CREATE TABLE {schema}.orders (
            tenant_id INT NOT NULL, id BIGINT NOT NULL, note VARCHAR(64),
            PRIMARY KEY (tenant_id, id)
        );
        INSERT INTO {schema}.orders (tenant_id,id,note) VALUES
            (1,1,'base-v2-one'),(1,2,'base-two'),(2,1,NULL),(2,2,'base-four');
        INSERT INTO {schema}.parents (id, tenant_id, code, parent_code, label) VALUES
            (100, 1, 'root', NULL, 'v2-root'), (101, 1, 'leaf', 'root', 'v2-leaf'),
            (102, 2, 'root', NULL, NULL);
        INSERT INTO {schema}.children (id, tenant_id, parent_code, label) VALUES
            (1000, 1, 'leaf', 'seed-child'), (1001, 1, 'root', NULL),
            (1002, 2, 'root', 'other-child');
        {grants}
    """)


class Probe:
    def __init__(self, run, label, branch=None, port=None, metadata=False):
        self.run = run
        self.label = label
        self.pending = False
        self.process = None
        if metadata:
            url = run.dsn("postgres", run.secret["meta"], run.metadata_port, "forkget_meta", "postgresql")
            ca = "backend-ca.pem"
        elif branch is None:
            native_db = run.backend_database if run.family == "postgresql" else REFERENCE
            url = run.dsn("p2_ref", run.secret["reference"], run.native_port, native_db)
            ca = "backend-ca.pem"
        else:
            owner, name = branch
            url = run.dsn(owner, run.frontend_passwords[owner], port or run.proxy_port, name)
            ca = "frontend-ca.pem"
        environment = run.base_env | {"FG_WRITE_PROBE_URL": url, "FG_WRITE_PROBE_CA": str(run.certs / ca)}
        self.process = subprocess.Popen([run.executable("fg-write-probe")], cwd=ROOT, env=environment,
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        text=True, bufsize=1)
        try:
            require(self.line() == "ready", f"{label}: TLS driver did not connect")
            if branch is None and run.family == "postgresql" and not metadata:
                require(self.sql(f"SET search_path TO {REFERENCE}") == {"affected": 0},
                        "Reference search path could not be set")
        except Exception:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        if self.process is None:
            return
        if self.process.poll() is None:
            if self.pending:
                self.process.terminate()
            else:
                self.process.stdin.close()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        error = self.process.stderr.read()
        if error:
            (self.run.report / f"{self.label}.log").write_text(self.run.safe(error), encoding="utf-8")
        for pipe in (self.process.stdin, self.process.stdout, self.process.stderr):
            pipe.close()
        self.process = None

    def readable(self, seconds):
        return bool(select.select([self.process.stdout], [], [], seconds)[0])

    def line(self):
        require(self.readable(20), f"{self.label}: driver response timed out")
        line = self.process.stdout.readline().strip()
        require(line, f"{self.label}: driver closed unexpectedly")
        return line

    def send(self, sql, op="text", params=()):
        require(not self.pending, f"{self.label}: previous request still pending")
        request = json.dumps(dict(sql=sql, op=op, params=params))
        self.process.stdin.write(request + "\n")
        self.process.stdin.flush()
        self.pending = True

    def receive(self):
        result = json.loads(self.line())
        self.pending = False
        return result

    def sql(self, sql, op="text", params=()):
        self.send(sql, op, params)
        return self.receive()


def compare(proxy, reference, sql, op="text", params=(), fg=None, state=None, affected=None):
    native = reference.sql(sql, op, params)
    observed = proxy.sql(sql, op, params)
    if fg:
        check_error(observed, native, fg, state)
    else:
        require(observed == native and any(key in native for key in ("affected", "rows", "parameters")),
                f"{proxy.label} {sql}: expected {native}, observed {observed}")
        if affected is not None:
            require(observed.get("affected") == affected, f"Expected affected count {affected}: {observed}")
    return observed


def check_error(proxy, native, fg, state=None):
    require("sqlstate" in native and native["sqlstate"] == proxy.get("sqlstate") and
            native["errno"] == proxy.get("errno") and proxy.get("fg") == fg and
            not proxy.get("physical_leak") and (state is None or proxy["sqlstate"] == state),
            f"Native error fields differ: {native} vs {proxy}, expected {fg}")


def check_count(probe, sql, count, op="text", params=()):
    observed = probe.sql(sql, op, params)
    require(observed.get("affected") == count, f"{probe.label} {sql}: expected {count}, observed {observed}")
    return observed


def int64(value):
    return {"i64": value}


def i32(value):
    return {"i32": value}


def string(value):
    return {"text": value}


def begin(probe, engine, level):
    if engine in ("mysql", "tidb"):
        check_count(probe, f"SET TRANSACTION ISOLATION LEVEL {level}", 0)
        check_count(probe, "START TRANSACTION", 0)
    else:
        check_count(probe, f"BEGIN ISOLATION LEVEL {level}", 0)


def differential(run, branch, level, ordinal):
    floor = ordinal * 100
    with Probe(run, f"proxy-{ordinal}", branch) as proxy, Probe(run, f"reference-{ordinal}") as reference:
        require(proxy.sql("SELECT * FROM app.parents ORDER BY id", "read").get("rows") ==
                reference.sql(PARENTS, "read").get("rows"), "Logical wildcard exposed hidden columns")
        for connection in (reference, proxy):
            begin(connection, run.engine, level)
        suffix = f"local-{ordinal}"
        compare(proxy, reference, INSERT_PARENT.format(floor + 1, suffix, suffix), affected=1)
        update = "UPDATE parents SET label = ? WHERE id = ?" if run.family != "postgresql" else "UPDATE parents SET label = $2 WHERE id = $1"
        params = (string(suffix), int64(floor + 1)) if run.family != "postgresql" else (int64(floor + 1), string(suffix))
        compare(proxy, reference, update, "execute", params, affected=1)
        changed = (string(suffix + "-edited"), int64(floor + 1)) if run.family != "postgresql" else (int64(floor + 1), string(suffix + "-edited"))
        compare(proxy, reference, update, "execute", changed, affected=1)
        compare(proxy, reference, "SAVEPOINT before_insert")
        compare(proxy, reference, INSERT_PARENT.format(floor + 2, suffix + "-undo", suffix + "-undo"), affected=1)
        compare(proxy, reference, "ROLLBACK TO SAVEPOINT before_insert")
        compare(proxy, reference, "RELEASE SAVEPOINT before_insert")
        compare(proxy, reference, "COMMIT")
        compare(proxy, reference, PARENTS, "read")
        if run.family == "postgresql":
            returning = "UPDATE parents SET label = $2 WHERE id = $1 RETURNING id, label"
            compare(proxy, reference, returning, "fetch", changed)
            compare(proxy, reference, returning, "fetch", (int64(floor + 99), string("empty")))
        first = f"({floor + 3},9,'{suffix}-atomic')"
        second = f"({floor + 1},9,'{suffix}-duplicate')"
        compare(proxy, reference, f"INSERT INTO parents (id,tenant_id,code) VALUES {first},{second}",
                fg="FG-3001", state="23000" if run.family != "postgresql" else "23505")
        compare(proxy, reference, PARENTS, "read")
        compare(proxy, reference, f"DELETE FROM parents WHERE id={floor + 1}", affected=1)
        compare(proxy, reference, f"DELETE FROM parents WHERE id={floor + 1}", affected=0)
        compare(proxy, reference, PARENTS, "read")
        compare(proxy, reference, CHILDREN, "read")
        prepared_points(run, proxy, reference, level, floor)
    run.record(f"{level}: text/prepared exact rows, found rows, atomic failure and savepoints")
    constraint_cases(run, branch, level, floor)
    if run.family == "mysql":
        # MySQL's cross-transaction foreign-key check blocks competing DML
        # at this boundary.
        concurrency(run, branch, level, floor)


def prepared_points(run, proxy, reference, level, floor):
    for connection in (reference, proxy):
        begin(connection, run.engine, level)
    if run.family != "postgresql":
        insert = "INSERT INTO parents (id,tenant_id,code) VALUES (?,?,?)"
        point = "UPDATE orders SET note = ? WHERE tenant_id = ? AND id = ?"
        remove = "DELETE FROM parents WHERE id = ?"
        params = (string("new-note"), i32(2), int64(1))
    else:
        insert = "INSERT INTO parents (id,tenant_id,code) VALUES ($1,$2,$3)"
        point = "UPDATE orders SET note = $3 WHERE tenant_id = $1 AND id = $2"
        remove = "DELETE FROM parents WHERE id = $1"
        params = (i32(2), int64(1), string("new-note"))
    compare(proxy, reference, insert, "execute", (int64(floor + 5), i32(9), string(f"prepared-{floor}")), affected=1)
    compare(proxy, reference, point, "execute", params, affected=1)
    compare(proxy, reference, remove, "execute", (int64(floor + 5),), affected=1)
    query = "SELECT tenant_id, id, note FROM orders ORDER BY tenant_id,id"
    compare(proxy, reference, query, "read")
    compare(proxy, reference, "ROLLBACK")
    compare(proxy, reference, query, "read")
    for connection in (reference, proxy):
        begin(connection, run.engine, level)
    compare(proxy, reference, "INSERT INTO parents (id,tenant_id,code) VALUES (100,9,'duplicate')", fg="FG-3001")
    if run.family != "postgresql":
        compare(proxy, reference, PARENTS, "read")
    else:
        compare(proxy, reference, PARENTS, "read", fg="FG-1005", state="25P02")
    compare(proxy, reference, "ROLLBACK")
    compare(proxy, reference, PARENTS, "read")


def constraint_cases(run, branch, level, floor):
    parent, child = floor + 10, floor + 11
    code = f"cascade-{floor}"
    with Probe(run, f"proxy-constraints-{floor}", branch) as proxy, Probe(run, f"ref-constraints-{floor}") as reference:
        for connection in (reference, proxy):
            begin(connection, run.engine, level)
        compare(proxy, reference, INSERT_PARENT.format(parent, code, code), affected=1)
        compare(proxy, reference, f"INSERT INTO children (id,tenant_id,parent_code) VALUES ({child},9,'{code}')", affected=1)
        compare(proxy, reference, f"UPDATE parents SET code='{code}-new' WHERE id={parent}", affected=1)
        compare(proxy, reference, CHILDREN, "read")
        compare(proxy, reference, f"DELETE FROM parents WHERE id={parent}", affected=1)
        compare(proxy, reference, CHILDREN, "read")
        compare(proxy, reference, "COMMIT")
        compare(proxy, reference, "DELETE FROM parents WHERE id=100", fg="FG-3002",
                state="23000" if run.family != "postgresql" else "23503")
        self_update = "UPDATE parents SET code='updated-root' WHERE id=100"
        if run.family == "mysql":
            compare(proxy, reference, self_update, fg="FG-3002", state="23000")
        else:
            # TiDB cascades the self-referential update like PostgreSQL;
            # MySQL alone refuses the chain.
            compare(proxy, reference, self_update, affected=1)
            require(compare(proxy, reference, PARENTS, "read")["rows"][1][3] == "updated-root",
                    "Self-referential cascade did not update the child key")
            compare(proxy, reference, CHILDREN, "read")
            compare(proxy, reference, "UPDATE parents SET code='root' WHERE id=100", affected=1)
        compare(proxy, reference, f"INSERT INTO parents (id,tenant_id,code) VALUES ({parent},1,'leaf')",
                fg="FG-3001")
        compare(proxy, reference, f"INSERT INTO children (id,tenant_id,parent_code) VALUES ({child},8,'missing')",
                fg="FG-3002")
        if run.family == "postgresql":
            deferred_cases(proxy, reference, level, parent, child, code)
        compare(proxy, reference, PARENTS, "read")
        compare(proxy, reference, CHILDREN, "read")
    run.record(f"{level}: composite unique, foreign keys, self reference and native cascades")


def deferred_cases(proxy, reference, level, parent, child, code):
    for connection in (reference, proxy):
        begin(connection, "postgresql", level)
    compare(proxy, reference, "SET CONSTRAINTS ALL DEFERRED")
    compare(proxy, reference, f"INSERT INTO children (id,tenant_id,parent_code) VALUES ({child},9,'{code}')", affected=1)
    compare(proxy, reference, INSERT_PARENT.format(parent, code, code), affected=1)
    compare(proxy, reference, "COMMIT")
    for violation, code_fg in [(f"INSERT INTO children (id,tenant_id,parent_code) VALUES ({child + 1},9,'missing')", "FG-3002"),
                               (INSERT_PARENT.format(parent + 2, code + "-duplicate", code), "FG-3001")]:
        for connection in (reference, proxy):
            begin(connection, "postgresql", level)
        compare(proxy, reference, "SET CONSTRAINTS ALL DEFERRED")
        compare(proxy, reference, violation, affected=1)
        compare(proxy, reference, "COMMIT", fg=code_fg)
    for connection in (reference, proxy):
        begin(connection, "postgresql", level)
    compare(proxy, reference, "SET CONSTRAINTS ALL DEFERRED")
    compare(proxy, reference, f"INSERT INTO children (id,tenant_id,parent_code) VALUES ({child + 1},9,'missing')", affected=1)
    compare(proxy, reference, "SET CONSTRAINTS ALL IMMEDIATE", fg="FG-3002")
    compare(proxy, reference, "ROLLBACK")
    compare(proxy, reference, f"DELETE FROM parents WHERE id={parent}", affected=1)
    proxy.run.record(f"{level}: PostgreSQL deferred unique/FK and failing commit recovery")


def contention(run, branch, level, floor, against_proxy):
    connection_branch = branch if against_proxy else None
    label = f"{'proxy' if against_proxy else 'ref'}-contention-{floor}"
    with Probe(run, label + "-left", connection_branch) as left, Probe(run, label + "-right", connection_branch) as right:
        parent = floor + 20
        key = f"race-{floor}"
        begin(left, run.engine, level)
        insert = INSERT_PARENT.format(parent, key, key)
        check_count(left, insert, 1)
        right.send(insert)
        require(not right.readable(0.3), "Duplicate writer escaped native uniqueness barrier")
        check_count(left, "COMMIT", 0)
        duplicate = right.receive()
        begin(left, run.engine, level)
        check_count(left, f"DELETE FROM parents WHERE id={parent}", 1)
        right.send(f"INSERT INTO children (id,tenant_id,parent_code) VALUES ({parent},9,'{key}')")
        early = right.readable(0.3)
        if early:
            response = right.receive()
            observation = {
                "engine": run.engine, "isolation": level, "through_proxy": against_proxy,
                "response": {key: value for key, value in response.items()
                             if key in ("affected", "sqlstate", "errno", "fg", "physical_leak", "transport")},
                "deleting_transaction_parent_count": left.sql(
                    f"SELECT COUNT(*) FROM parents WHERE id={parent}", "read"),
                "other_connection_parent_count": right.sql(
                    f"SELECT COUNT(*) FROM parents WHERE id={parent}", "read"),
                "other_connection_child_count": right.sql(
                    f"SELECT COUNT(*) FROM children WHERE id={parent}", "read"),
            }
            if run.family == "tidb":
                commit = left.sql("COMMIT")
                observation["delete_commit"] = {key: value for key, value in commit.items()
                    if key in ("affected", "sqlstate", "errno", "fg", "physical_leak", "transport")}
                observation["committed_parent_count"] = right.sql(
                    f"SELECT COUNT(*) FROM parents WHERE id={parent}", "read")
                observation["committed_child_count"] = right.sql(
                    f"SELECT COUNT(*) FROM children WHERE id={parent}", "read")
            json_file(run.report / f"{label}-early-child.json", observation)
        require(not early, "Child insert escaped native parent delete barrier")
        check_count(left, "COMMIT", 0)
        foreign_key = right.receive()
        begin(left, run.engine, level)
        query = f"SELECT id FROM parents WHERE id={parent}"
        require(left.sql(query, "read").get("rows") == [], "Isolation witness must start empty")
        check_count(right, insert, 1)
        visible = [[parent]] if level == "READ COMMITTED" else []
        require(left.sql(query, "read").get("rows") == visible, f"{level} native visibility differs")
        check_count(left, "ROLLBACK", 0)
        check_count(right, f"DELETE FROM parents WHERE id={parent}", 1)
        return duplicate, foreign_key, left.sql(PARENTS, "read"), left.sql(CHILDREN, "read")


def concurrency(run, branch, level, floor):
    constraint_links(run, branch, floor)
    native = contention(run, branch, level, floor, False)
    proxy = contention(run, branch, level, floor, True)
    check_error(proxy[0], native[0], "FG-3001")
    check_error(proxy[1], native[1], "FG-3002")
    require(proxy[2:] == native[2:], "Concurrent proxy state differs from reference")
    run.record(f"{level}: duplicate-key and parent-child transaction barriers")


def constraint_links(run, branch, floor):
    if run.family not in ("mysql", "tidb"):
        return
    status, body = run.request("POST", "/internal/v1/resolve", run.secret["internal"],
                               {"principal": branch[0], "branch": branch[1]})
    require(status == 200, "Could not resolve the concurrency fixture")
    binding = json.loads(body)
    schema, prefix = run.branch_namespace(binding["id"])
    witnesses = {}
    for label, namespace, name_prefix in (("reference", REFERENCE, ""), ("branch", schema, prefix)):
        observed = run.native(
            "SELECT COUNT(*), SUM(referenced_table_schema="
            f"'{namespace}' AND referenced_table_name='{name_prefix}parents') "
            "FROM information_schema.key_column_usage "
            f"WHERE table_schema='{namespace}' "
            f"AND table_name IN ('{name_prefix}parents','{name_prefix}children') "
            "AND referenced_table_name IS NOT NULL;")
        counts = [int(value) for value in observed.split()]
        require(counts == [4, 4], f"{label} foreign keys do not target their own parent table")
        witnesses[label] = {"foreign_key_columns": counts[0], "branch_local_parent_columns": counts[1]}
    json_file(run.report / f"foreign-key-links-{floor}.json", witnesses)


def generated_sql(mysql):
    return ("INSERT INTO parents (tenant_id, code, label) VALUES (?, ?, ?)" if mysql else
            "INSERT INTO parents (tenant_id, code, label) VALUES ($2, $1, $3) RETURNING id, code, label")


def generated_one(probe, mysql, label, expected=None):
    sql = generated_sql(mysql)
    tenant, code, note = i32(8), string(label), "null_text"
    params = (tenant, code, note) if mysql else (code, tenant, note)
    observed = probe.sql(sql, "execute" if mysql else "fetch", params)
    if mysql:
        require(observed.get("affected") == 1, f"Generated MySQL write failed: {observed}")
        key = observed["insert_id"]
    else:
        require(observed.get("columns") == [["id", "INT8"], ["code", "VARCHAR"], ["label", "VARCHAR"]],
                f"Generated PostgreSQL RETURNING metadata differs: {observed}")
        row, = observed["rows"]
        key, result_label, result_note = row
        require(result_label == label and result_note is None, f"PostgreSQL bind order/NULL differs: {observed}")
    require(START <= key <= MAX and (expected is None or key == expected),
            f"Generated key {key} is outside the expected range or sequence ({expected})")
    return key


def generated_cases(run, branch, branch_id, parent_table):
    with Probe(run, "generated-first", branch) as one, Probe(run, "generated-second", branch) as two:
        statement = one.sql(generated_sql(run.family != "postgresql"), "prepare")
        signature = statement.get("parameters")
        require(signature == 3 if run.family != "postgresql" else signature == ["VARCHAR", "INT4", "VARCHAR"],
                f"Internal bind leaked into prepared metadata: {statement}")
        if run.family == "postgresql":
            require(statement["columns"] == [["id", "INT8"], ["code", "VARCHAR"], ["label", "VARCHAR"]],
                    f"Prepared RETURNING fields differ: {statement}")
        text = "INSERT INTO parents (tenant_id,code) VALUES (8,'generated-a'),(8,'generated-b')"
        if run.family != "postgresql":
            result = check_count(one, text, 2)
            require(result.get("insert_id") == START, f"First generated ID missing in OK: {result}")
            require(one.sql("SELECT LAST_INSERT_ID()", "read").get("rows") == [[START]],
                    "MySQL LAST_INSERT_ID() did not keep the first ID")
            require(one.sql("SELECT LAST_INSERT_ID()", "fetch").get("rows") == [[START]],
                    "Prepared MySQL LAST_INSERT_ID() changed the session value")
        else:
            result = one.sql(text + " RETURNING id, code", "read")
            require(result.get("rows") == [[START, "generated-a"], [START + 1, "generated-b"]],
                    f"Generated text RETURNING failed: {result}")
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(generated_one, connection, run.family != "postgresql", name) for connection, name in
                       [(one, "generated-c"), (two, "generated-d")]]
            values = {future.result() for future in futures}
        require(values == {START + 2, START + 3}, f"Generated ranges overlap or gap on successful allocation: {values}")
        for invalid_key in (0, -1, START + 31):
            invalid = one.sql(INSERT_PARENT.format(invalid_key, "forbidden", "forbidden"))
            require(invalid.get("fg") == "FG-3004", f"Explicit reserved key was not rejected: {invalid}")
        for sql in ("UPDATE parents SET id=99 WHERE id=100", "DELETE FROM parents WHERE tenant_id=1",
                    "UPDATE parents SET label=LOWER(label) WHERE id=100", "TRUNCATE TABLE parents",
                    "SELECT _fg_generated FROM parents", "UPDATE parents SET label='x' WHERE id=100 OR id=101"):
            refusal = one.sql(sql)
            require(refusal.get("fg") in {"FG-2002", "FG-2003"}, f"Unsafe SQL escaped admission: {sql}: {refusal}")
        begin(one, run.engine, "READ COMMITTED")
        generated_one(one, run.family != "postgresql", "generated-rolled-back", START + 4)
        check_count(one, "ROLLBACK", 0)
        insert = "INSERT INTO parents (tenant_id,code) VALUES (8,'generated-failed'),(8,'generated-a')"
        conflict = one.sql(insert)
        require(conflict.get("fg") == "FG-3001", f"Generated duplicate did not fail atomically: {conflict}")
        generated_one(one, run.family != "postgresql", "generated-gap-proof", START + 7)
        key_col = "?" if run.family != "postgresql" else "$1"
        check_count(one, f"UPDATE parents SET label='precise' WHERE id={key_col}", 1, "execute", (int64(START + 1),))
        keys = one.sql("SELECT id, label FROM parents WHERE tenant_id=8 ORDER BY id", "read").get("rows")
        require(keys == [[START, None], [START + 1, "precise"], [START + 2, None], [START + 3, None],
                         [START + 7, None]], f"Generated adjacent keys or rollback state differs: {keys}")
    run.record("Generated text/prepared metadata, concurrent ranges, atomic gaps and exact high-key lookup")
    run.stop("proxy")
    run.stop("control")
    run.start_control()
    run.start_proxy()
    with Probe(run, "generated-restart", branch) as probe:
        generated_one(probe, run.family != "postgresql", "generated-after-restart", START + 8)
        require(run.metadata(f"SELECT next_id FROM generated_id_cursor WHERE branch_id={branch_id} AND table_id={parent_table};")
                == str(START + 9), "Metadata cursor did not commit before returning the ID")
        if run.family == "postgresql":
            abandon_generated_portal(run, branch, START + 9)
            generated_one(probe, False, "after-abandoned-portal", START + 10)
            run.record("PostgreSQL abandoned Bind leaves a gap and rejected Parse recovers at savepoint")
        run.metadata(f"UPDATE generated_id_cursor SET next_id={MAX} WHERE branch_id={branch_id} AND table_id={parent_table};")
        generated_one(probe, run.family != "postgresql", "generated-final", MAX)
        result = probe.sql("INSERT INTO parents (tenant_id,code) VALUES (8,'generated-exhausted')")
        require(result.get("fg") == "FG-3003", f"Allocator exhaustion was not reported: {result}")
        require(run.metadata(f"SELECT next_id FROM generated_id_cursor WHERE branch_id={branch_id} AND table_id={parent_table};")
                == str(MAX + 1), "Allocator overflowed or rewound the persisted cursor")
    run.record("Generated key allocator restart persistence, last key and exhaustion")


def disconnect_rollback(run, branch):
    with Probe(run, "transaction-abandoned", branch) as abandoned:
        begin(abandoned, run.engine, "REPEATABLE READ")
        check_count(abandoned, INSERT_PARENT.format(9900, "abandoned", "abandoned"), 1)
    with Probe(run, "after-disconnect", branch) as observer:
        check_count(observer, INSERT_PARENT.format(9900, "abandoned", "abandoned"), 1)
        check_count(observer, "DELETE FROM parents WHERE id=9900", 1)
    run.record("Uncommitted write rolls back on disconnect")
