"""Reproduce the TiDB parent-delete race without exporting row values."""

import argparse
from functools import partial
import os
from pathlib import Path
import sys

os.environ["PATH"] = str(Path.home() / ".cargo/bin") + os.pathsep + os.environ["PATH"]
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/p7"))
import gate
from gate_fixture import refresh_gate
from run_p2 import json_file, require
from write_cases import Probe, constraint_links, contention
import write_cases

parser = argparse.ArgumentParser()
parser.add_argument("mode", choices=("default", "pessimistic", "optimistic"))
parser.add_argument("target", choices=("native", "proxy"))
parser.add_argument("--lock-parent", action="store_true")
parser.add_argument("--foreign-key-only", action="store_true")
parser.add_argument("--store", choices=("unistore", "tikv"), default="unistore")
parser.add_argument("--shared-lock", choices=("default", "on", "off"), default="default")
parser.add_argument("--matrix", action="store_true", help="Observe RC/RR commit, rollback, timeout and cascade without stopping at the first failure")
parser.add_argument("--diagnostic-native-image", help="Explicit local diagnostic build only; never release qualification")
options = parser.parse_args()


class Diagnostic(gate.LocalGate):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if options.diagnostic_native_image:
            self.image = options.diagnostic_native_image
            self.compose_env["P2_NATIVE_IMAGE"] = self.image
        if options.store != "tikv":
            return
        suite = self.certs.parent / "tikv-suite"
        suite.mkdir(mode=0o700)
        engine = (ROOT / "test/p2/engine.sh").read_text()
        require('--store=unistore --path=""' in engine, "TiDB fixture entry point changed")
        (suite / "engine.sh").write_text(engine.replace('--store=unistore --path=""', '--store=tikv --path=pd:2379'))
        (suite / "pd.toml").write_text('[replication]\nmax-replicas = 1\n')
        compose = (ROOT / "test/p2/compose.yml").read_text().replace(
            "  native:\n", "  native:\n    depends_on: [tikv]\n")
        compose += """
  pd:
    image: pingcap/pd:v8.5.8
    command: ["--name=pd", "--client-urls=http://0.0.0.0:2379", "--peer-urls=http://0.0.0.0:2380", "--advertise-client-urls=http://pd:2379", "--advertise-peer-urls=http://pd:2380", "--initial-cluster=pd=http://pd:2380", "--data-dir=/data/pd", "--config=/suite/pd.toml"]
    volumes: [".:/suite:ro"]
    mem_limit: 512m
    cpus: 1
  tikv:
    image: pingcap/tikv:v8.5.8
    command: ["--addr=0.0.0.0:20160", "--advertise-addr=tikv:20160", "--pd=pd:2379", "--data-dir=/data/tikv"]
    depends_on: [pd]
    mem_limit: 3g
    cpus: 2
"""
        (suite / "compose.yml").write_text(compose)
        self.compose_command[-1] = str(suite / "compose.yml")

    def native_roles(self):
        super().native_roles()
        if options.matrix:
            self.native("SET GLOBAL innodb_lock_wait_timeout=2")
        if options.shared_lock != "default":
            self.native("SET GLOBAL tidb_foreign_key_check_in_shared_lock=" + options.shared_lock.upper())

    def dump_native_state(self):
        if options.store == "tikv":
            self.compose("tikv-pd-failure", "logs", "--no-color", "--tail", "250", "pd", "tikv", log=True)
            self.compose("tikv-container-state", "ps", "--all", "--format", "json", log=True)
        super().dump_native_state()

    def foreign_key_matrix(self, credentials):
        results = []
        for isolation in ("READ COMMITTED", "REPEATABLE READ"):
            for outcome in ("commit", "rollback", "timeout", "cascade"):
                identity = 51000 + len(results)
                key = f"matrix-{identity}"
                label = f"matrix-{identity}-{outcome}"
                connection = credentials if options.target == "proxy" else None
                with Probe(self, label + "-left", connection) as left, Probe(self, label + "-right", connection) as right:
                    write_cases.check_count(left, f"INSERT INTO parents(id,tenant_id,code) VALUES({identity},9,'{key}')", 1)
                    if outcome == "cascade":
                        write_cases.check_count(left, f"INSERT INTO children(id,tenant_id,parent_code) VALUES({identity+100},9,'{key}')", 1)
                    write_cases.begin(left, "tidb", isolation)
                    # Preserve the original oracle's autocommit child. An
                    # explicit child transaction can defer FK checks until
                    # COMMIT and exercises a different native code path.
                    write_cases.check_count(right, "SET TRANSACTION ISOLATION LEVEL " + isolation, 0)
                    write_cases.check_count(left, f"DELETE FROM parents WHERE id={identity}", 1)
                    right.send(f"INSERT INTO children(id,tenant_id,parent_code) VALUES({identity},9,'{key}')")
                    early = right.readable(0.3)
                    response = right.receive() if early else None
                    timed_out = False
                    if outcome == "timeout" and response is None:
                        timed_out = right.readable(3)
                        if timed_out:
                            response = right.receive()
                    left_end = left.sql("ROLLBACK" if outcome == "rollback" else "COMMIT")
                    if response is None:
                        response = right.receive()
                    parent = right.sql(f"SELECT COUNT(*) FROM parents WHERE id={identity}", "read")["rows"][0][0]
                    children = right.sql(f"SELECT COUNT(*) FROM children WHERE parent_code='{key}'", "read")["rows"][0][0]
                    errors = []
                    if early:
                        errors.append("Child completed before the parent transaction released its barrier")
                    if parent == 0 and children != 0:
                        errors.append("Committed orphan")
                    if left_end.get("affected") != 0:
                        errors.append("Transaction finalization failed")
                    if outcome == "rollback":
                        if parent != 1 or children != 1 or response.get("affected") != 1:
                            errors.append("Rollback did not preserve parent and admit one child")
                    elif parent != 0 or children != 0:
                        errors.append("Committed delete left surviving rows")
                    if outcome == "timeout":
                        if not timed_out or response.get("errno") != 1205:
                            errors.append("Child did not time out at the native lock boundary")
                    elif outcome != "rollback":
                        if response.get("errno") != 1452 or response.get("sqlstate") != "23000":
                            errors.append("Child did not receive the native foreign-key violation")
                        if options.target == "proxy" and (response.get("fg") != "FG-3002" or response.get("physical_leak")):
                            errors.append("Proxy lost the safe FK error category")
                    fields = ("affected", "sqlstate", "errno", "fg", "physical_leak", "transport")
                    results.append({"isolation": isolation, "outcome": outcome, "target": options.target,
                        "child_autocommit": True, "early_child": early, "native_timeout_observed": timed_out,
                        "child_response": {k:v for k,v in response.items() if k in fields},
                        "parent_finalization": {k:v for k,v in left_end.items() if k in fields},
                        "parent_count": parent, "child_count": children, "errors": errors,
                        "status": "failed" if errors else "passed"})
                    json_file(self.report / "foreign-key-matrix.json", {"cases": results, "complete": False})
        json_file(self.report / "foreign-key-matrix.json", {"cases": results, "complete": True})
        require(all(not item["errors"] for item in results), "Concurrent FK matrix failed; all observations were preserved")
        self.record("RC/RR native barriers, commit, rollback, timeout and cascade preserve zero orphan rows")

    def execute(self):
        self.start_deployment()
        self.gate_generation = refresh_gate(self, 1)
        self.reference_data()
        settings = "SELECT @@tidb_txn_mode, @@global.tidb_txn_mode, @@transaction_isolation, @@foreign_key_checks, @@tidb_foreign_key_check_in_shared_lock"
        runtime = {
            "store": options.store,
            "native_image": self.image,
            "image_kind": "custom_diagnostic" if options.diagnostic_native_image else "official_stable",
            "public_release_eligible": False,
            "store_process_arguments": self.compose("native-process", "exec", "-T", "native",
                                                     "cat", "/proc/1/cmdline").replace("\0", " "),
            "default_client_settings": self.native(settings),
        }
        if options.store == "tikv":
            for service, binary in (("pd", "/pd-server"), ("tikv", "/tikv-server")):
                runtime[f"{service}_version"] = self.compose(f"{service}-version", "exec", "-T", service,
                                                             binary, "--version")
        json_file(self.report / "native-runtime.json", runtime)
        original = Probe.__init__

        def observed_init(probe, run, label, branch=None, port=None, metadata=False):
            original(probe, run, label, branch, port, metadata)
            if branch is None and not metadata:
                before = probe.sql(settings, "read")
                if options.mode != "default":
                    require(probe.sql(f"SET SESSION tidb_txn_mode='{options.mode}'").get("affected") == 0,
                            "Native transaction mode was not accepted")
                json_file(run.report / f"{label}-settings.json", {
                    "before": before, "after": probe.sql(settings, "read"),
                })

        Probe.__init__ = observed_init
        original_count = write_cases.check_count
        original_begin = write_cases.begin

        def observed_begin(probe, engine, level):
            original_begin(probe, engine, level)
            if options.target == "native":
                json_file(self.report / f"{probe.label}-active-settings.json", probe.sql(settings, "read"))

        def observed_count(probe, sql, count, op="text", params=()):
            if options.lock_parent and sql.startswith("DELETE FROM parents WHERE id="):
                where = sql.removeprefix("DELETE FROM parents ")
                rows = probe.sql(f"SELECT id FROM parents {where} FOR UPDATE", "read").get("rows")
                require(rows is not None and len(rows) == 1, "Parent pre-lock did not find one row")
                json_file(self.report / f"{probe.label}-prelock.json", {"locked_parent_rows": len(rows)})
            return original_count(probe, sql, count, op, params)

        write_cases.begin = observed_begin
        write_cases.check_count = observed_count
        branch, credentials = self.create("gate-native-constraints")
        try:
            constraint_links(self, credentials, 50100)
            if options.matrix:
                self.foreign_key_matrix(credentials)
            elif options.foreign_key_only:
                connection = credentials if options.target == "proxy" else None
                with Probe(self, "fk-left", connection) as left, Probe(self, "fk-right", connection) as right:
                    write_cases.check_count(left, "INSERT INTO parents(id,tenant_id,code) VALUES(50120,9,'race-50100')", 1)
                    write_cases.begin(left, "tidb", "READ COMMITTED")
                    write_cases.check_count(left, "DELETE FROM parents WHERE id=50120", 1)
                    right.send("INSERT INTO children(id,tenant_id,parent_code) VALUES(50120,9,'race-50100')")
                    early = right.readable(0.3)
                    response = right.receive() if early else None
                    commit = left.sql("COMMIT")
                    if not early:
                        response = right.receive()
                    parent = right.sql("SELECT COUNT(*) FROM parents WHERE id=50120", "read")["rows"][0][0]
                    child = right.sql("SELECT COUNT(*) FROM children WHERE id=50120", "read")["rows"][0][0]
                    fields = ("affected", "sqlstate", "errno", "fg", "physical_leak", "transport")
                    json_file(self.report / "foreign-key-result.json", {
                        "mode": options.mode, "target": options.target, "prelocked": options.lock_parent,
                        "child_completed_before_delete_commit": early,
                        "child_response": {key:value for key,value in response.items() if key in fields},
                        "delete_commit": {key:value for key,value in commit.items() if key in fields},
                        "committed_parent_count": parent, "committed_child_count": child,
                    })
                    require(not (parent == 0 and child != 0), "Native foreign-key race committed an orphan")
                    require(not early, "Child insert escaped native parent delete barrier")
                    require(commit.get("affected") == 0 and parent == 0 and child == 0,
                            "Delete did not commit without a surviving child")
                    require(response.get("errno") == 1452 and response.get("sqlstate") == "23000",
                            "The concurrent child did not receive the native foreign-key error")
                    if options.target == "proxy":
                        require(response.get("fg") == "FG-3002" and not response.get("physical_leak"),
                                "The proxy foreign-key error was not safely categorized")
            else:
                contention(self, credentials, "READ COMMITTED", 50100, options.target == "proxy")
        finally:
            self.drop_many([branch])
            Probe.__init__ = original
            write_cases.begin = original_begin
            write_cases.check_count = original_count


raise SystemExit(gate.smoke.p6.run_profile(
    "p7gate", f"TiDB {options.mode} {options.target} concurrency diagnostic",
    partial(Diagnostic, profile="local"), ["tidb"]))
