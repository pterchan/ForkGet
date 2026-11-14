"""Measure and verify a small repository snapshot on disposable local engines."""

from hashlib import sha256
import importlib.util
from itertools import product
import json
from pathlib import Path
import random

P6 = Path(__file__).resolve().parents[1] / "p6" / "run.py"
spec = importlib.util.spec_from_file_location("run_p6", P6)
p6 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p6)
from run_p2 import OWNER_A, require
from write_cases import Probe, REFERENCE, begin, check_count, seed_reference

WORKLOADS = ("point", "range", "insert", "update", "mixed")
WARMUP = 10
MEASURE = 40
REPETITIONS = 3
SEED = 7042026


def operation(workload, index):
    if workload == "mixed":
        workload = ("insert" if index % 10 == 8 else "update" if index % 10 == 9
                    else "range" if index % 10 == 7 else "point")
    if workload == "point":
        return dict(op="read", sql=f"SELECT tenant_id,id,note FROM orders WHERE tenant_id=1 AND id={index % 2 + 1}")
    if workload == "range":
        return dict(op="read", sql=f"SELECT tenant_id,id,note FROM orders WHERE tenant_id>={index % 2 + 1} ORDER BY tenant_id,id")
    if workload == "insert":
        return dict(op="text", sql=f"INSERT INTO parents (id,tenant_id,code) VALUES ({20000 + index},8,'bench-{index}')")
    return dict(op="text", sql=f"UPDATE parents SET label='bench-{index % 2}' WHERE id=100")


class EngineRun(p6.p5.EngineRun):
    def __init__(self, *args):
        super().__init__(*args)
        self.bin_dir = self.bin_dir.parent / "release"
        # Select SQL shapes by wire family: MySQL and TiDB share the MySQL
        # dialect, while PostgreSQL uses its own.
        self.mysql = self.family in ("mysql", "tidb")

    def execute(self):
        self.start_deployment()
        old, _, generation = self.refresh_to_v2()
        self.drop(OWNER_A, old["id"])
        self.set_policy("dev", 50_000)
        witness, _ = self.create("p7-baseline", write=False)
        binding = self.binding(OWNER_A, witness)
        baseline = self.baseline_digest(binding)
        self.reference_data()
        self.benchmarks(generation)
        self.compare_seeded()
        self.isolation(binding, baseline)
        self.drop(OWNER_A, witness["id"])

    def reference_data(self):
        seed_reference(self)
        binary = "VARBINARY(16)" if self.mysql else "BYTEA"
        empty, byte_value, final = (p6.p5.p34.p2.data.binary(self.engine, value)
                                    for value in ("", "00FF41", "6F6B"))
        self.native(f"""
            ALTER TABLE {REFERENCE}.orders ADD COLUMN customer_id INT NOT NULL DEFAULT 10;
            ALTER TABLE {REFERENCE}.orders ADD COLUMN amount DECIMAL(12,2);
            ALTER TABLE {REFERENCE}.orders ADD COLUMN payload {binary};
            UPDATE {REFERENCE}.orders SET customer_id=20, amount=20.00,payload={empty} WHERE tenant_id=1 AND id=2;
            UPDATE {REFERENCE}.orders SET amount=110.00 WHERE tenant_id=1 AND id=1;
            UPDATE {REFERENCE}.orders SET amount=30.00,payload={byte_value} WHERE tenant_id=2 AND id=1;
            UPDATE {REFERENCE}.orders SET customer_id=30,amount=40.00,payload={final} WHERE tenant_id=2 AND id=2;
        """)

    def size(self, schema, prefix=""):
        names = f"'{prefix}orders','{prefix}parents'"
        if self.family == "tidb":
            self.native(f"ANALYZE TABLE {schema}.{prefix}orders, {schema}.{prefix}parents;", timeout=180)
        if self.mysql:
            prepare = "SET SESSION information_schema_stats_expiry=0; " if self.family == "mysql" else ""
            sql = (prepare +
                   "SELECT table_name,CAST(data_length+index_length AS SIGNED) FROM information_schema.tables "
                   f"WHERE table_schema='{schema}' AND table_name IN ({names}) ORDER BY table_name;")
        else:
            sql = ("SELECT relname,pg_total_relation_size(c.oid) FROM pg_class c JOIN pg_namespace n "
                   f"ON n.oid=c.relnamespace WHERE n.nspname='{schema}' AND c.relname IN ({names}) ORDER BY relname;")
        sizes = {table.removeprefix(prefix): int(size)
                 for table, size in (line.split() if self.mysql else line.split("|")
                                     for line in self.native(sql).splitlines())}
        require(sizes.keys() == {"orders", "parents"} and all(sizes.values()), f"Dataset measurement missing: {sizes}")
        return sizes

    def run_bench(self, workload, branch=None):
        if branch is None:
            user, password, port = "p2_ref", self.secret["reference"], self.native_port
            database = REFERENCE if self.mysql else self.backend_database
            ca = "backend-ca.pem"
            setup = None if self.mysql else f"SET search_path TO {REFERENCE}"
        else:
            user, password, port = OWNER_A, self.frontend_passwords[OWNER_A], self.proxy_port
            database, ca, setup = branch, "frontend-ca.pem", None
        env = self.base_env | {"FG_WRITE_PROBE_URL": self.dsn(user, password, port, database),
                               "FG_WRITE_PROBE_CA": str(self.certs / ca)}
        plan = {"setup": setup, "warmup": [operation(workload, i) for i in range(WARMUP)],
                "measure": [operation(workload, i) for i in range(WARMUP, WARMUP + MEASURE)]}
        return json.loads(self.call("benchmark-client", [self.executable("fg-write-probe"), "benchmark"],
                                   env=env, stdin=json.dumps(plan), timeout=45))

    def benchmarks(self, generation):
        schema = f"fg_g{generation}"
        counts = [int(line) for line in self.native(
            f"SELECT COUNT(*) FROM {schema}.orders; SELECT COUNT(*) FROM {schema}.parents;").splitlines()]
        evidence = {"profile": "local-smoke", "build": "release", "concurrency": 1,
                    "warmup_operations": WARMUP, "measured_operations": MEASURE,
                    "repetitions": REPETITIONS, "baseline_rows": dict(zip(("orders", "parents"), counts, strict=True)),
                    "dataset_bytes": {"reference": self.size(REFERENCE), "baseline": self.size(schema)},
                    "runs": []}
        for workload in WORKLOADS:
            for repetition in range(REPETITIONS):
                name = f"bench-{workload}-{repetition}"
                branch, _ = self.create(name)
                self.native(f"DELETE FROM {REFERENCE}.parents WHERE tenant_id=8 AND id>=20000; "
                            f"UPDATE {REFERENCE}.parents SET label='v2-root' WHERE id=100;")
                order = ("reference", "proxy") if repetition % 2 == 0 else ("proxy", "reference")
                result = {"workload": workload, "repetition": repetition + 1, "order": order,
                          "initial_branch_bytes": self.size(*self.branch_namespace(branch["id"]))}
                try:
                    for side in order:
                        result[side] = self.run_bench(workload, None if side == "reference" else name)
                    evidence["runs"].append(result)
                    p6.p5.p34.p2.json_file(self.report / "benchmark.json", evidence)
                    require(all(result[side]["executed"] == MEASURE and
                                not result[side]["errors"] and not result[side]["timeouts"] for side in order),
                            "Native or proxy benchmark recorded an error")
                finally:
                    self.drop(OWNER_A, branch["id"])
        self.record("Five release-mode reference/proxy workloads with warmup and three reset repetitions")

    def compare_seeded(self):
        branch, credentials = self.create("p7-differential")
        rng = random.Random(SEED)
        cases = list(product(("tenant_id,id,note", "note", "id,tenant_id"),
                             ("tenant_id>=1", "tenant_id=2", "tenant_id=1 AND id=1", "note IS NULL"),
                             ("tenant_id,id", "tenant_id DESC,id DESC"), range(1, 6)))
        rng.shuffle(cases)
        with Probe(self, "p7-diff-proxy", credentials) as proxy, Probe(self, "p7-diff-reference") as reference:
            for index, (fields, where, ordering, limit) in enumerate(cases):
                query = f"SELECT {fields} FROM orders WHERE {where} ORDER BY {ordering} LIMIT {limit}"
                actual = proxy.sql(query, "read")
                expected = reference.sql(query, "read")
                if actual != expected or "rows" not in actual:
                    path = self.report / "repro.json"
                    failure = {"seed": SEED, "case": index, "sql": query, "engine": self.engine,
                               "expected": expected, "observed": actual, "minimized_sql": query}
                    p6.p5.p34.p2.json_file(path, failure)
                    if "rows" in actual and "rows" in expected:
                        failure["minimized_sql"] = self.minimize_case(proxy, reference, fields, where, ordering, limit)
                        p6.p5.p34.p2.json_file(path, failure)
                    require(False, "A differential case failed; see repro.json for the standalone statement")
        p6.p5.p34.p2.json_file(self.report / "differential.json", {"seed": SEED, "executed": len(cases), "skipped": 0})
        self.drop(OWNER_A, branch["id"])
        self.record("120 seeded typed SQL comparisons with standalone mismatch reproduction")

    @staticmethod
    def minimize_case(proxy, reference, fields, where, ordering, limit):
        suffix = f"ORDER BY {ordering} LIMIT {limit}"
        candidates = [f"SELECT {projection} FROM orders {predicate} {suffix}".replace("  ", " ")
                      for projection in [fields, *fields.split(",")]
                      for predicate in [f"WHERE {where}", ""]]
        for sql in sorted(set(candidates), key=lambda query: (len(query), query)):
            actual = proxy.sql(sql, "read")
            expected = reference.sql(sql, "read")
            if "rows" in actual and "rows" in expected and actual != expected:
                return sql
        return f"SELECT {fields} FROM orders WHERE {where} {suffix}"

    def isolation(self, binding, before):
        left, first = self.create("p7-isolation-a")
        right, second = self.create("p7-isolation-b")
        with Probe(self, "p7-left", first) as writer, Probe(self, "p7-right", second) as peer, \
                Probe(self, "p7-same-branch", first) as contender:
            begin(writer, self.engine, "READ COMMITTED")
            check_count(writer, "INSERT INTO parents (id,tenant_id,code) VALUES (19000,8,'left')", 1)
            contender.send("INSERT INTO parents (id,tenant_id,code) VALUES (19000,8,'contender')")
            check_count(peer, "INSERT INTO parents (id,tenant_id,code) VALUES (19000,8,'right')", 1)
            require(not contender.readable(0.2), "Same-key contender escaped the transaction barrier")
            check_count(writer, "COMMIT", 0)
            require(contender.receive().get("fg") == "FG-3001", "Same-branch duplicate did not fail")
            begin(writer, self.engine, "REPEATABLE READ")
            check_count(writer, "INSERT INTO parents (id,tenant_id,code) VALUES (19001,8,'uncommitted')", 1)
            process = self.processes.pop("proxy")
            process.kill()
            process.wait(timeout=5)
        self.start_proxy()
        for branch, code in ((first, "left"), (second, "right")):
            with Probe(self, f"p7-after-crash-{code}", branch) as observer:
                rows = observer.sql("SELECT id,code FROM parents WHERE id>=19000 ORDER BY id", "read").get("rows")
                require(rows == [[19000, code]], "Crash recovery failed to isolate committed and uncommitted writes")
        p6.p5.p34.lost_commit_response(self, first)
        after = self.baseline_digest(binding)
        p6.p5.p34.p2.json_file(self.report / "immutable-baseline.json", {"encoding": "typed-length-prefixed-v1",
            "generation_id": binding["generation_id"], "before": before, "after": after})
        require(before == after, "Typed immutable baseline changed")
        for branch in (left, right):
            self.drop(OWNER_A, branch["id"])
        self.record("Same-key and cross-branch isolation, SIGKILL rollback, acknowledged durability and unchanged baseline")

    def baseline_digest(self, binding):
        digest = sha256()

        def field(value):
            digest.update(len(value).to_bytes(8, "big"))
            digest.update(value)

        for entry in binding["tables"]:
            field(entry["logical_table"].encode())
            columns = entry["columns"]
            field(len(columns).to_bytes(8, "big"))
            keys = sorted((col for col in columns if col["primary_key_ordinal"]), key=lambda col: col["primary_key_ordinal"])
            projections = []
            for col in columns:
                name, kind = col["name"], col["type_name"]
                field(name.encode())
                field(kind.encode())
                if kind in {"bytea", "varbinary(16)"}:
                    projections.append(f"HEX({name})" if self.mysql else f"encode({name},'hex')")
                else:
                    projections.append(f"CAST({name} AS {'CHAR' if self.mysql else 'text'})")
            array = "JSON_ARRAY" if self.mysql else "json_build_array"
            relation = f"{entry['base_schema']}.{entry['base_table']}"
            order = ",".join(col["name"] for col in keys)
            rows = self.native(f"SELECT {array}({','.join(projections)}) FROM {relation} ORDER BY {order};").splitlines()
            field(len(rows).to_bytes(8, "big"))
            for line in rows:
                for value, column in zip(json.loads(line), columns, strict=True):
                    if value is None:
                        field(b"\x00")
                    elif column["type_name"] in {"bytea", "varbinary(16)"}:
                        field(b"\x01" + bytes.fromhex(value))
                    else:
                        field(b"\x01" + value.encode())
        return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(p6.run_profile("p7", "P7 local measurement and isolation smoke", EngineRun))
