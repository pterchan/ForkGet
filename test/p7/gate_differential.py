"""Run a reproducible, engine-native reference versus product corpus."""

from collections import Counter
from itertools import cycle, islice
import random

from gate_fixture import TENANT
from run_p2 import OWNER_A, json_file, require
from write_cases import Probe

SEED = 7042026
SESSION_CASES = 100
FAMILIES = ("text", "prepared", "transaction", "policy", "rejection")
READ_COLUMNS = ("id,note", "tenant_id,id", "customer_id,note")
REFUSALS = (
    ("CREATE TABLE rejected_gate (id INT)", "FG-2002"),
    ("SELECT id FROM orders FOR UPDATE", "FG-2002"),
    ("SELECT id FROM forkget_delta.unknown_internal_table", "FG-2003"),
    ("SELECT dangerous_function(id) AS value FROM orders", "FG-2004"),
)


class Case:
    def __init__(self, path, seed, index, family):
        self.path = path
        self.witness = {"seed": seed, "index": index, "family": family, "requests": []}

    def call(self, side, probe, sql, op="text", params=()):
        request = {"side": side, "sql": sql, "op": op, "params": params}
        self.witness["requests"].append(request)
        result = probe.sql(sql, op, params)
        request["result"] = result
        return result

    def compare(self, proxy, reference, sql, op="text", params=(), affected=None):
        expected = self.call("reference", reference, sql, op, params)
        observed = self.call("proxy", proxy, sql, op, params)
        require(observed == expected, "Reference and proxy observations differ")
        if affected is not None:
            require(observed.get("affected") == affected, "Unexpected matched row count")
        elif op in ("read", "fetch"):
            require("rows" in observed, "Comparison did not execute a read")
        return observed

    def expect_fg(self, probe, sql, code):
        result = self.call("proxy", probe, sql)
        require(result.get("fg") == code and not result.get("physical_leak"),
                f"Expected sanitized {code} refusal")

    def fail(self):
        # Requests stop at the failed assertion and preserve the dependent
        # transaction prefix. The last statement is the isolated witness.
        if self.witness["requests"]:
            self.witness["failing_statement"] = self.witness["requests"][-1]["sql"]
        json_file(self.path, self.witness)


def read(case, proxy, reference, sample, columns, prepared, mysql):
    if prepared:
        parameter = "?" if mysql else "$1"
        sql = f"SELECT {columns} FROM orders WHERE tenant_id={TENANT} AND id={parameter}"
        if case.witness["index"] % 3 == 0:
            case.compare(proxy, reference, sql, "prepare")
        case.compare(proxy, reference, sql, "fetch", [{"i64": sample}])
    else:
        sql = (f"SELECT {columns} FROM orders WHERE tenant_id={TENANT} AND id>={sample} "
               "ORDER BY tenant_id,id LIMIT 3")
        case.compare(proxy, reference, sql, "read")


def statement(key, label):
    return (f"INSERT INTO orders (tenant_id,id,customer_id,amount,note) "
            f"VALUES (9,{key},10,12.34,'{label}')")


def read_temporary(case, proxy, reference, key, expected):
    sql = f"SELECT id,note FROM orders WHERE tenant_id=9 AND id={key} ORDER BY id"
    observed = case.compare(proxy, reference, sql, "read")
    require(observed["rows"] == expected, "Unexpected final rows")


def transaction(case, proxy, reference, key, mysql, sample):
    isolation = "READ COMMITTED" if sample % 2 else "REPEATABLE READ"
    if mysql:
        case.compare(proxy, reference, f"SET TRANSACTION ISOLATION LEVEL {isolation}", affected=0)
        begin = "START TRANSACTION"
    else:
        begin = f"BEGIN ISOLATION LEVEL {isolation}"
    case.compare(proxy, reference, begin, affected=0)
    case.compare(proxy, reference, statement(key, "seeded-tx"), affected=1)
    case.compare(proxy, reference, "SAVEPOINT gate_case", affected=0)
    case.compare(proxy, reference,
                 f"UPDATE orders SET note='rolled-back' WHERE tenant_id=9 AND id={key}", affected=1)
    case.compare(proxy, reference, "ROLLBACK TO SAVEPOINT gate_case", affected=0)
    if sample % 3:
        case.compare(proxy, reference, "COMMIT", affected=0)
        read_temporary(case, proxy, reference, key, [[key, "seeded-tx"]])
        case.compare(proxy, reference, f"DELETE FROM orders WHERE tenant_id=9 AND id={key}", affected=1)
    else:
        case.compare(proxy, reference, "ROLLBACK", affected=0)
    read_temporary(case, proxy, reference, key, [])


def policy(case, proxy, reference, key, sample):
    insert = statement(key, "gate-policy")
    if sample % 2:
        case.compare(proxy, reference, insert, affected=1)
        case.compare(proxy, reference, f"DELETE FROM orders WHERE tenant_id=9 AND id={key}", affected=1)
    else:
        batch = f"{insert},(9,{key + 1},10,12.34,'gate-policy')"
        case.call("reference", reference, "BEGIN")
        result = case.call("reference", reference, batch)
        require(result.get("affected") == 2, "Independent native batch did not execute")
        case.call("reference", reference, "ROLLBACK")
        case.expect_fg(proxy, batch, "FG-5002")
        read_temporary(case, proxy, reference, key + 1, [])
    read_temporary(case, proxy, reference, key, [])


def run_case(case, proxy, policy_proxy, reference, sample, columns, mysql):
    family, index = case.witness["family"], case.witness["index"]
    key = 10_000_000 + index * 2
    if family in ("text", "prepared"):
        read(case, proxy, reference, sample, columns, family == "prepared", mysql)
    elif family == "transaction":
        transaction(case, proxy, reference, key, mysql, sample)
    elif family == "policy":
        policy(case, policy_proxy, reference, key, sample)
    else:
        sql, code = REFUSALS[sample % len(REFUSALS)]
        case.expect_fg(proxy, sql, code)
        read(case, proxy, reference, sample, columns, False, mysql)


def run_differential(run, cases, order_rows):
    rng = random.Random(SEED)
    counts = Counter()
    completed = 0
    families = list(islice(cycle(FAMILIES), cases))
    rng.shuffle(families)
    dev_policy = run.set_policy("dev", 50_000)
    ci_policy = run.set_policy("ci", 1)
    main, credentials = run.create("gate-differential")
    branches = [main]
    try:
        restricted, policy_credentials = run.create("gate-differential-policy", "ci")
        branches.append(restricted)
        for offset in range(0, cases, SESSION_CASES):
            run.check_deadline(30)
            with (Probe(run, "gate-differential-proxy", credentials) as proxy,
                  Probe(run, "gate-differential-policy", policy_credentials) as policy_proxy,
                  Probe(run, "gate-differential-reference") as reference):
                end = min(offset + SESSION_CASES, cases)
                for index in range(offset, end):
                    family = families[index]
                    case = Case(run.report / "repro.json", SEED, index, family)
                    try:
                        run_case(case, proxy, policy_proxy, reference,
                                 rng.randrange(1, order_rows + 2), rng.choice(READ_COLUMNS), run.mysql)
                    except Exception:
                        case.fail()
                        raise
                    counts[family] += 1
                    completed += 1
    finally:
        json_file(run.report / "differential.json", {"seed": SEED, "requested": cases,
                  "executed": completed, "families": dict(counts), "skipped": [],
                  "not_run": cases - completed, "policy": {"dev": dev_policy, "ci": ci_policy}})
        run.drop_many(branches)
    run.record(f"{completed} seeded native versus proxy scenarios across five families")
