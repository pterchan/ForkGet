#!/usr/bin/env python3
"""Verify native non-fixture snapshot capture/import on disposable deployments."""

import argparse
from datetime import UTC, datetime
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time

SUITE = Path(__file__).resolve().parent
sys.path.insert(0, str(SUITE.parent / "p3p4"))
spec = importlib.util.spec_from_file_location("snapshot_p34", SUITE.parent / "p3p4/run.py")
p34 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p34)
from run_p2 import ROOT, Failure, json_file, require


class SnapshotRun(p34.EngineRun):
    def __init__(self, engine, report, workspace, certs, run_id):
        super().__init__(engine, report, workspace, certs, run_id)
        self.workspace = workspace
        # Checkouts may use CRLF. Normalize only the two disposable runtime
        # fixture files; product sources stay in place.
        runtime = workspace / "runtime"
        runtime.mkdir()
        for name in ("compose.yml", "engine.sh"):
            (runtime / name).write_text((ROOT / "test/p2" / name).read_text(), encoding="utf-8", newline="\n")
        self.compose_command = ["docker", "compose", "--project-name", self.project,
                                "--file", str(runtime / "compose.yml")]
        self.tool_path = workspace / "tools"
        self.tool_path.mkdir()
        # Native tool output is intentionally absent from product logs. This
        # fixture-only wrapper records redacted diagnostics for a failed test.
        wrapper = self.tool_path / "mysqlsh"
        wrapper.write_text("""#!/usr/bin/python3
import json,os,subprocess,sys
from pathlib import Path
from urllib.parse import urlsplit,unquote
result=subprocess.run(['setpriv','--pdeathsig','KILL','--','/usr/bin/mysqlsh',*sys.argv[1:]],capture_output=True)
details=(result.stdout+result.stderr).decode('utf-8','replace')
for name in ('FG_SOURCE_DSN','FG_BACKEND_ADMIN_DSN','FG_META_DSN'):
    value=os.environ.get(name,'')
    if value:
        password=urlsplit(value).password
        if password: details=details.replace(password,'[redacted]').replace(unquote(password),'[redacted]')
with Path(os.environ['FG_SNAPSHOT_TEST_TOOL_LOG']).open('a') as log: log.write(details+'\\n')
sys.stdout.buffer.write(result.stdout)
sys.stderr.buffer.write(result.stderr)
raise SystemExit(result.returncode)
""", encoding="utf-8", newline="\n")
        wrapper.chmod(0o700)
        dumpling = self.tool_path / "fg-dumpling-run"
        native_dumpling = shutil.which("fg-dumpling-run") or "fg-dumpling-run"
        dumpling.write_text(wrapper.read_text().replace("'/usr/bin/mysqlsh'", repr(native_dumpling)).replace("details=(result.stdout+result.stderr).decode('utf-8','replace')", "details=(result.stdout+result.stderr).decode('utf-8','replace')\nif '--config' in sys.argv:\n    config=json.loads(Path(sys.argv[sys.argv.index('--config')+1]).read_text())\n    for name in ('native-private.log','launcher-private.log'):\n        diagnostic=Path(config['output'])/name\n        if diagnostic.exists(): details+='\\n'+diagnostic.read_text()"), encoding="utf-8", newline="\n")
        dumpling.chmod(0o700)

    def environment(self):
        admin = "postgres" if self.family == "postgresql" else "root"
        source = self.dsn(admin, self.secret["native"], self.native_port, "p2_native")
        return self.base_env | {"FG_BACKEND_CA": str(self.certs / "backend-ca.pem"),
                               "FG_SOURCE_CA": str(self.certs / "backend-ca.pem"),
                               "FG_META_CA": str(self.certs / "backend-ca.pem"),
                               "FG_META_DSN": self.dsn("postgres", self.secret["meta"], self.metadata_port, "forkget_meta", "postgresql"),
                               "FG_BACKEND_ADMIN_DSN": source, "FG_SOURCE_DSN": source,
                               "FG_REFRESH_COOLDOWN_SECONDS": "0",
                               "PATH": str(self.tool_path) + os.pathsep + os.environ["PATH"],
                               "FG_SNAPSHOT_TEST_TOOL_LOG": str(self.report / "mysqlsh-native.log")}

    def snapshot(self, label, *arguments, succeeds=True):
        output = self.call(label, [self.executable("fg-control"), "snapshot", *arguments],
                           env=self.environment(), log=True, succeeds=succeeds, timeout=180)
        if succeeds and arguments[0] == "capture":
            # This fixture constructs a disposable synthetic source. Retain its
            # exact captured catalog before temporary-workspace compensation.
            bundle = Path(arguments[arguments.index("--output") + 1])
            captured = json.loads((bundle / "manifest.json").read_text())
            descriptor = os.open(self.report / f"{label}-manifest.json",
                                 os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as report:
                json.dump(captured, report, indent=2)
                report.write("\n")
        return json.loads(output) if succeeds and output else None

    def source(self):
        generated = "BIGINT GENERATED BY DEFAULT AS IDENTITY" if self.family == "postgresql" else "BIGINT AUTO_INCREMENT"
        binary = "BYTEA" if self.family == "postgresql" else "VARBINARY(64)"
        boolean = "BOOLEAN"
        timestamp = "TIMESTAMP(6) WITH TIME ZONE" if self.family == "postgresql" else "TIMESTAMP(6)"
        binary_value = "decode('00017f80ff','hex')" if self.family == "postgresql" else "X'00017F80FF'"
        charset = "" if self.family == "postgresql" else (" CHARACTER SET utf8mb4 COLLATE utf8mb4_bin" if self.family == "tidb" else " CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci")
        self.native(f"""
            CREATE SCHEMA shop{charset};
            CREATE TABLE shop.client_book (id {generated} PRIMARY KEY, name VARCHAR(96) NOT NULL,
                CONSTRAINT client_name_key UNIQUE(name));
            CREATE TABLE shop.stock_card (id BIGINT PRIMARY KEY, revision BIGINT NOT NULL,
                amount DECIMAL(19,4) NOT NULL, enabled {boolean} NOT NULL DEFAULT TRUE,
                order_day DATE, changed_at {timestamp} DEFAULT CURRENT_TIMESTAMP(6),
                note VARCHAR(96), payload {binary}, CONSTRAINT stock_positive CHECK(amount>=0));
            CREATE TABLE shop.purchase_log (id BIGINT PRIMARY KEY, client_id BIGINT NOT NULL,
                revision BIGINT NOT NULL, CONSTRAINT purchase_client_fk FOREIGN KEY(client_id) REFERENCES shop.client_book(id));
            CREATE INDEX purchase_client_index ON shop.purchase_log(client_id);
            CREATE TABLE shop.empty_buffer(id BIGINT PRIMARY KEY);
            CREATE TABLE shop.empty_attachment(id {generated} PRIMARY KEY, payload {binary});
            INSERT INTO shop.client_book(name) VALUES('Native buyer');
            INSERT INTO shop.stock_card(id,revision,amount,order_day,note,payload)
                VALUES(1,0,123456789.0123,'2026-11-12','Unicode 🛠 and quote ''',{binary_value});
            INSERT INTO shop.purchase_log(id,client_id,revision) VALUES(1,1,0);
        """)
        self.record("non-fixture source: five tables including two empty, generated BIGINT, FK, unique/index/check, decimal/date/time/Boolean/Unicode/binary")

    def writer(self, stop, failures):
        while not stop.is_set():
            try:
                self.native("BEGIN; UPDATE shop.stock_card SET revision=revision+1 WHERE id=1; "
                            "UPDATE shop.purchase_log SET revision=revision+1 WHERE id=1; COMMIT;")
            except Exception as error:
                failures.append(type(error).__name__)
                return
            stop.wait(0.01)

    def execute(self):
        self.start_databases()
        self.native_roles()
        if self.family == "mysql":
            self.native("SET GLOBAL local_infile=ON;")
        self.call("migrate", [self.executable("fg-control"), "migrate"], env=self.environment(), log=True)
        self.source()
        plan = self.workspace / "plan.json"
        self.snapshot("inspect", "inspect", "--source-env", "FG_SOURCE_DSN", "--schema", "shop", "--name", "customer-native", "--output", str(plan))
        inspected = json.loads(plan.read_text())
        require(inspected["status"] == "admitted" and len(inspected["manifest"]["tables"]) == 5,
                "Preflight did not admit the five-table native source")
        bundle = self.workspace / "bundle"
        stop, failures = threading.Event(), []
        writer = threading.Thread(target=self.writer, args=(stop, failures), daemon=True)
        writer.start()
        try:
            p34.p2.wait_until("active source writer", lambda: int(self.native("SELECT revision FROM shop.stock_card WHERE id=1;")) > 0)
            self.snapshot("capture", "capture", "--source-env", "FG_SOURCE_DSN", "--schema", "shop", "--name", "customer-native", "--output", str(bundle))
        finally:
            stop.set()
            writer.join(timeout=30)
        require(not writer.is_alive() and not failures, "Concurrent source writer failed or did not stop")
        self.base_env["FG_NATIVE_FREE_BYTES"] = "0"
        try:
            self.snapshot("capacity-refusal", "import", "--input", str(bundle), succeeds=False)
            require(self.metadata("SELECT count(*) FROM generation;") == "0", "Capacity refusal allocated a native generation")
        finally:
            self.base_env.pop("FG_NATIVE_FREE_BYTES", None)
        result = self.snapshot("import", "import", "--input", str(bundle))
        require(result["storage_preflight"]["native_assurance"] == "estimated_only", "Unknown native space was reported as guaranteed")
        require(result["storage_preflight"]["local_available_bytes"] > 0, "Local available space was not measured")
        active = result["generation_id"]
        require(self.metadata("SELECT id FROM generation WHERE status='active';") == str(active), "User snapshot did not become active")
        self.witness(active)
        self.record("capture under concurrent atomic source writes restores a consistent immutable native generation")
        self.negative_sources()
        self.failure_cleanup(bundle, active)
        self.record("source admission and failed import preserve the previous active generation")

    def witness(self, generation):
        schema = f"fg_g{generation}"
        left = self.native(f"SELECT revision FROM {schema}.stock_card WHERE id=1;")
        right = self.native(f"SELECT revision FROM {schema}.purchase_log WHERE id=1;")
        require(left == right, "Capture mixed committed source transactions across tables")
        payload = "encode(payload,'hex')" if self.family == "postgresql" else "LOWER(HEX(payload))"
        require(self.native(f"SELECT {payload} FROM {schema}.stock_card WHERE id=1;") == "00017f80ff", "Binary values changed in native import")
        require(self.native(f"SELECT amount FROM {schema}.stock_card WHERE id=1;") == "123456789.0123", "Decimal precision changed in native import")
        self.restored_check(schema)
        require(self.native(f"SELECT order_day FROM {schema}.stock_card WHERE id=1;") == "2026-11-12", "Date changed in native import")
        require(self.native(f"SELECT note FROM {schema}.stock_card WHERE id=1;") == "Unicode 🛠 and quote '", "Unicode or quote changed in native import")
        require(self.metadata(f"SELECT count(*) FROM catalog_table WHERE generation_id={generation};") == "5", "Owned catalog omitted user tables")
        count = self.native(f"SELECT count(*) FROM information_schema.tables WHERE table_schema='{schema}';")
        require(count == "5", "Restored generation contains unexpected tables")
        for table in ("empty_buffer", "empty_attachment"):
            require(self.native(f"SELECT count(*) FROM {schema}.{table};") == "0", "Native capture/import lost an empty table")
        self.record("native values, empty tables and owned catalog preserve all five admitted user tables")

    def restored_check(self, schema):
        try:
            self.native(f"UPDATE {schema}.stock_card SET amount=-1 WHERE id=1;")
        except Failure:
            diagnostic = (self.report / "native-sql.log").read_text()
            require("stock_positive" in diagnostic and
                    ("3819" in diagnostic or "violates check constraint" in diagnostic),
                    "Native rejection did not identify the restored CHECK constraint")
        else:
            raise Failure("The restored CHECK constraint accepted an invalid amount")
        require(self.native(f"SELECT amount FROM {schema}.stock_card WHERE id=1;") == "123456789.0123",
                "A refused CHECK violation changed the captured baseline")

    def negative_sources(self):
        self.native("INSERT INTO shop.client_book(id,name) VALUES(-1,'outside-key-range');")
        try:
            self.snapshot("reject-generated-domain", "inspect", "--source-env", "FG_SOURCE_DSN", "--schema", "shop", "--name", "reject-native", "--output", str(self.workspace / "bad-generated.json"), succeeds=False)
        finally:
            self.native("DELETE FROM shop.client_book WHERE id=-1;")
        self.native("CREATE VIEW shop.unsupported_view AS SELECT id FROM shop.client_book;")
        try:
            self.snapshot("reject-view", "inspect", "--source-env", "FG_SOURCE_DSN", "--schema", "shop", "--name", "reject-native", "--output", str(self.workspace / "bad-plan.json"), succeeds=False)
            require(not (self.workspace / "bad-plan.json").exists(), "Unsupported view published an admitted plan")
        finally:
            self.native("DROP VIEW shop.unsupported_view;")
        if self.family != "postgresql":
            self.native("UPDATE shop.stock_card SET enabled=2 WHERE id=1;")
            try:
                self.snapshot("reject-bool-domain", "inspect", "--source-env", "FG_SOURCE_DSN", "--schema", "shop", "--name", "reject-native", "--output", str(self.workspace / "bad-bool.json"), succeeds=False)
            finally:
                self.native("UPDATE shop.stock_card SET enabled=1 WHERE id=1;")
        else:
            for label, create, remove in [
                ("nulls-not-distinct", "CREATE UNIQUE INDEX unsupported_native_index ON shop.stock_card(note) NULLS NOT DISTINCT", "DROP INDEX shop.unsupported_native_index"),
                ("descending-index", "CREATE INDEX unsupported_native_index ON shop.stock_card(id DESC)", "DROP INDEX shop.unsupported_native_index"),
                ("unvalidated-check", "ALTER TABLE shop.empty_buffer ADD CONSTRAINT unsupported_native_check CHECK(id>0) NOT VALID", "ALTER TABLE shop.empty_buffer DROP CONSTRAINT unsupported_native_check"),
                ("no-inherit-check", "ALTER TABLE shop.empty_buffer ADD CONSTRAINT unsupported_native_check CHECK(id>0) NO INHERIT", "ALTER TABLE shop.empty_buffer DROP CONSTRAINT unsupported_native_check"),
                ("match-full", "ALTER TABLE shop.empty_buffer ADD CONSTRAINT unsupported_native_fk FOREIGN KEY(id) REFERENCES shop.client_book(id) MATCH FULL", "ALTER TABLE shop.empty_buffer DROP CONSTRAINT unsupported_native_fk"),
            ]:
                self.native(create)
                try:
                    self.snapshot("reject-" + label, "inspect", "--source-env", "FG_SOURCE_DSN", "--schema", "shop", "--name", "reject-native", "--output", str(self.workspace / (label + ".json")), succeeds=False)
                finally:
                    self.native(remove)

    def failure_cleanup(self, bundle, active):
        bad = self.workspace / "bad-bundle"
        shutil.copytree(bundle, bad)
        manifest = json.loads((bad / "manifest.json").read_text())
        manifest["tables"][0]["rows"] += 1
        json_file(bad / "manifest.json", manifest)
        self.snapshot("bad-import", "import", "--input", str(bad), succeeds=False)
        require(self.metadata("SELECT id FROM generation WHERE status='active';") == str(active), "Failed import replaced the previous active generation")
        failed = int(self.metadata("SELECT max(generation_id) FROM snapshot_job WHERE phase='failed';"))
        require(self.metadata(f"SELECT native_claimed FROM generation WHERE id={failed};") == "f", "Failed import kept a claimed native generation")
        require(self.native(f"SELECT count(*) FROM information_schema.schemata WHERE schema_name='fg_g{failed}';") == "0", "Failed import left native generation objects")
        if self.family == "postgresql":
            require(self.native(f"SELECT count(*) FROM pg_database WHERE datname='fg_stage_snapshot_{failed}';") == "0", "Failed import left its staging database")
        self.witness(active)
        self.snapshot("status", "status")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=["mysql", "postgresql", "tidb", "all"], default="all")
    parser.add_argument("--report-dir", type=Path, required=True)
    arguments = parser.parse_args()
    report = arguments.report_dir.resolve()
    report.mkdir(parents=True, exist_ok=False)
    results = {}
    started = datetime.now(UTC)
    for engine in (["mysql", "postgresql", "tidb"] if arguments.engine == "all" else [arguments.engine]):
        detail = report / engine
        detail.mkdir()
        with tempfile.TemporaryDirectory(prefix="fg-snapshot-native-") as temporary:
            workspace = Path(temporary)
            certs = workspace / "certs"
            p34.p2.build_certs(certs)
            runner = SnapshotRun(engine, detail, workspace, certs, f"fgsnapshot-{started:%H%M%S}-{os.getpid()}")
            errors = []
            try:
                runner.execute()
            except Exception as error:
                errors.append(runner.safe(str(error)))
            finally:
                try:
                    runner.cleanup()
                except Exception as error:
                    errors.append(runner.safe(str(error)))
            results[engine] = {"status": "failed" if errors else "passed", "version": runner.engine_version,
                               "checks": runner.cases, "errors": errors, "cleaned_up": not runner.compose_started}
            print(json.dumps({engine: results[engine]}), flush=True)
    revision, state = p34.p2.git_state()
    json_file(report / "env.json", {"source_revision": revision, "source_state": state, "started_at": started.isoformat()})
    passed = all(result["status"] == "passed" for result in results.values())
    json_file(report / "report.json", {"status": "passed" if passed else "failed", "engines": results})
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
