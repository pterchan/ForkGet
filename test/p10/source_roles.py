#!/usr/bin/env python3
"""Verify independent source backup credentials on disposable native SQL engines."""

import argparse
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import tempfile
import threading

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "p7"))
import snapshot_import as fixture

p34 = fixture.p34
require = fixture.require
BACKUP = "fg_source_backup"


class SourceRun(fixture.SnapshotRun):
    def __init__(self, *arguments):
        super().__init__(*arguments)
        self.secret["source_backup"] = secrets.token_hex(24)
        self.source_account = None
        self.query_number = 0

    def environment(self):
        environment = super().environment()
        if self.source_account:
            environment["FG_SOURCE_DSN"] = self.dsn(self.source_account, self.secret["source_backup"], self.native_port, "p2_native" if self.family == "postgresql" else "shop")
        return environment

    def source_sql(self, label, sql, succeeds=True):
        environment = self.environment()
        if self.family == "postgresql":
            environment |= {"PGHOST": "127.0.0.1", "PGPORT": str(self.native_port), "PGUSER": BACKUP, "PGPASSWORD": self.secret["source_backup"], "PGDATABASE": "p2_native", "PGSSLMODE": "verify-full", "PGSSLROOTCERT": str(self.certs / "backend-ca.pem")}
            command = [shutil.which("psql") or "psql", "-XqAt", "-v", "ON_ERROR_STOP=1"]
            result = self.call(label, command, env=environment, stdin=sql, succeeds=succeeds, log=True)
        else:
            self.query_number += 1
            script = self.workspace / f"source-query-{self.query_number}.py"
            session = {"scheme": "mysql", "host": "127.0.0.1", "port": self.native_port, "user": BACKUP, "password": self.secret["source_backup"], "ssl-mode": "VERIFY_IDENTITY", "ssl-ca": str(self.certs / "backend-ca.pem")}
            content = "import json\nshell.connect(json.loads(" + json.dumps(json.dumps(session)) + "))\nresult=shell.get_session().run_sql(" + json.dumps(sql) + ")\nprint(json.dumps([list(row) for row in result.fetch_all()]))\n"
            with script.open("x", encoding="utf-8") as output:
                script.chmod(0o600)
                output.write(content)
            result = self.call(label, [shutil.which("mysqlsh") or "mysqlsh", "--no-defaults", "--py", "--quiet-start=2", "--file", str(script)], env=environment, succeeds=succeeds, log=True)
            script.unlink()
        return result

    def create_backup_account(self):
        password = self.secret["source_backup"]
        if self.family == "postgresql":
            self.native(f"CREATE ROLE {BACKUP} LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; GRANT CONNECT ON DATABASE p2_native TO {BACKUP}; GRANT USAGE ON SCHEMA shop TO {BACKUP}; GRANT SELECT ON ALL TABLES IN SCHEMA shop TO {BACKUP}; GRANT SELECT ON ALL SEQUENCES IN SCHEMA shop TO {BACKUP};")
        else:
            self.native(f"CREATE USER '{BACKUP}'@'%' IDENTIFIED WITH caching_sha2_password BY '{password}' REQUIRE SSL; GRANT SELECT, SHOW VIEW, TRIGGER, EVENT ON shop.* TO '{BACKUP}'@'%'; GRANT RELOAD, BACKUP_ADMIN, SHOW_ROUTINE ON *.* TO '{BACKUP}'@'%'; GRANT SELECT ON mysql.default_roles TO '{BACKUP}'@'%';")
        self.source_account = BACKUP
        environment = self.environment()
        require(environment["FG_SOURCE_DSN"] != environment["FG_BACKEND_ADMIN_DSN"], "Source backup and target administrator DSNs are identical")
        identity = self.source_sql("backup-identity", "SELECT CURRENT_USER")
        require(BACKUP in identity, "Native source query used the serving administrator")
        for label, statement in (("insert", "INSERT INTO shop.empty_buffer(id) VALUES(1000001)"), ("update", "UPDATE shop.stock_card SET revision=999 WHERE id=1"), ("delete", "DELETE FROM shop.purchase_log WHERE id=1")):
            self.source_sql("deny-source-" + label, statement, succeeds=False)
            diagnostic = (self.report / ("deny-source-" + label + ".log")).read_text()
            require(("permission denied" in diagnostic.lower()) if self.family == "postgresql" else ("1142" in diagnostic), "Source DML failed for a reason other than native permission denial")
        require(self.native("SELECT revision FROM shop.stock_card WHERE id=1") == "0" and self.native("SELECT count(*) FROM shop.purchase_log") == "1" and self.native("SELECT count(*) FROM shop.empty_buffer") == "0", "Denied source DML changed source data")
        if self.family == "mysql":
            self.source_sql("deny-mysql-auth-table", "SELECT user FROM mysql.user", succeeds=False)
            require("1142" in (self.report / "deny-mysql-auth-table.log").read_text(), "Backup account could read mysql.user or failed for an unrelated reason")
        self.record("An independent TLS backup account reads source data while native INSERT/UPDATE/DELETE are denied; target administration uses separate credentials")

    def refuse_inspection(self, label, reason=None):
        output = self.workspace / (label + ".json")
        self.snapshot(label, "inspect", "--source-env", "FG_SOURCE_DSN", "--schema", "shop", "--name", "source-role-refused", "--output", str(output), succeeds=False)
        require(not output.exists(), "Unsupported or invisible source catalog published an admitted plan")
        diagnostic = (self.report / (label + ".log")).read_text()
        require("Snapshot object" in diagnostic, "Source preflight failed without a typed catalog refusal")
        if reason:
            require(reason in diagnostic, "Source preflight did not identify the missing catalog visibility")

    def catalog_refusals(self):
        objects = [("view", "CREATE VIEW shop.backup_reject_view AS SELECT id FROM shop.client_book", "DROP VIEW shop.backup_reject_view")]
        if self.family == "mysql":
            objects += [("trigger", "CREATE TRIGGER shop.backup_reject_trigger BEFORE UPDATE ON shop.stock_card FOR EACH ROW SET NEW.revision=NEW.revision", "DROP TRIGGER shop.backup_reject_trigger"), ("routine", "CREATE PROCEDURE shop.backup_reject_routine() SELECT 1", "DROP PROCEDURE shop.backup_reject_routine"), ("event", "CREATE EVENT shop.backup_reject_event ON SCHEDULE AT CURRENT_TIMESTAMP+INTERVAL 1 DAY DISABLE DO SET @backup_event=1", "DROP EVENT shop.backup_reject_event")]
        else:
            objects += [("trigger", "CREATE TRIGGER backup_reject_trigger BEFORE UPDATE ON shop.stock_card FOR EACH ROW EXECUTE FUNCTION pg_catalog.suppress_redundant_updates_trigger()", "DROP TRIGGER backup_reject_trigger ON shop.stock_card"), ("routine", "CREATE FUNCTION shop.backup_reject_routine() RETURNS INTEGER LANGUAGE SQL IMMUTABLE AS 'SELECT 1'", "DROP FUNCTION shop.backup_reject_routine()")]
        for kind, create, remove in objects:
            self.native(create)
            try:
                if self.family == "mysql" and kind in ("trigger", "event", "routine"):
                    privilege, scope = {"trigger": ("TRIGGER", "shop.*"), "event": ("EVENT", "shop.*"), "routine": ("SHOW_ROUTINE", "*.*")}[kind]
                    self.native(f"REVOKE {privilege} ON {scope} FROM '{BACKUP}'@'%'")
                    try:
                        self.refuse_inspection("missing-" + kind + "-visibility", "mysql_source_" + kind + "_visibility_unproven")
                    finally:
                        self.native(f"GRANT {privilege} ON {scope} TO '{BACKUP}'@'%'")
                self.refuse_inspection("reject-" + kind)
            finally:
                self.native(remove)
        if self.family == "mysql":
            partial = "fg_source_partial"
            self.native(f"CREATE USER '{partial}'@'%' IDENTIFIED WITH caching_sha2_password BY '{self.secret['source_backup']}' REQUIRE SSL; GRANT SELECT ON shop.client_book TO '{partial}'@'%';")
            self.source_account = partial
            try:
                self.refuse_inspection("partial-table-visibility", "mysql_source_schema_select_coverage_unproven")
            finally:
                self.source_account = BACKUP
        self.record("Administrator-created views, triggers and routines are rejected under the independent backup account")
        if self.family == "mysql":
            self.record("Missing trigger/event/routine visibility and table-only SELECT fail closed; mysql.user remains unreadable")

    def execute(self):
        self.start_databases()
        self.native_roles()
        if self.family == "mysql":
            self.native("SET GLOBAL local_infile=ON")
        self.call("migrate", [self.executable("fg-control"), "migrate"], env=self.environment(), log=True)
        self.source()
        self.snapshot("administrator-source-inspect", "inspect", "--source-env", "FG_SOURCE_DSN", "--schema", "shop", "--name", "operator-source", "--output", str(self.workspace / "administrator-plan.json"))
        self.create_backup_account()
        self.catalog_refusals()
        plan = self.workspace / "source-plan.json"
        self.snapshot("source-inspect", "inspect", "--source-env", "FG_SOURCE_DSN", "--schema", "shop", "--name", "independent-backup", "--output", str(plan))
        require(len(json.loads(plan.read_text())["manifest"]["tables"]) == 5, "Backup account omitted source tables")
        stop, failures = threading.Event(), []
        writer = threading.Thread(target=self.writer, args=(stop, failures), daemon=True)
        writer.start()
        bundle = self.workspace / "backup-bundle"
        try:
            p34.wait_until("independent source writer", lambda: int(self.native("SELECT revision FROM shop.stock_card WHERE id=1")) > 0)
            self.snapshot("backup-capture", "capture", "--source-env", "FG_SOURCE_DSN", "--schema", "shop", "--name", "independent-backup", "--output", str(bundle))
        finally:
            stop.set()
            writer.join(timeout=30)
        require(not writer.is_alive() and not failures, "Independent source writer failed")
        imported = self.snapshot("administrator-import", "import", "--input", str(bundle))
        self.witness(imported["generation_id"])
        self.source_sql("deny-target-read", f"SELECT count(*) FROM fg_g{imported['generation_id']}.stock_card", succeeds=False)
        self.record("A genuine consistent native dump under concurrent source writes captures all five typed tables and imports through the independent serving administrator")
        fixture.json_file(self.report / "source-role-evidence.json", {"source_account": BACKUP, "target_account": "postgres" if self.family == "postgresql" else "root", "dsn_credentials_distinct": True, "source_dml_denied": ["insert", "update", "delete"], "source_role_can_read_imported_target": False, "native_tool_versions": json.loads((bundle / "capture.json").read_text())["tools"], "mysql_source_role_is_ddl_read_only": False if self.family == "mysql" else None, "mysql_auth_table_select_denied": True if self.family == "mysql" else None})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=["all", "mysql", "postgresql"], default="all")
    parser.add_argument("--report-dir", required=True, type=Path)
    arguments = parser.parse_args()
    report = arguments.report_dir.resolve()
    report.mkdir(parents=True, exist_ok=False)
    started, results = datetime.now(UTC), {}
    revision, source_state = p34.p2.git_state()
    for engine in (["mysql", "postgresql"] if arguments.engine == "all" else [arguments.engine]):
        detail = report / engine
        detail.mkdir()
        with tempfile.TemporaryDirectory(prefix="fg-source-role-", dir=Path.home()) as temporary:
            workspace = Path(temporary)
            certs = workspace / "certs"
            p34.p2.build_certs(certs)
            runner = SourceRun(engine, detail, workspace, certs, f"fgsourcerole-{started:%H%M%S}-{os.getpid()}")
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
            results[engine] = {"status": "failed" if errors else "passed", "version": runner.engine_version, "checks": runner.cases, "errors": errors, "cleaned_up": not runner.compose_started}
            print(json.dumps({engine: results[engine]}), flush=True)
    passed = all(result["status"] == "passed" for result in results.values())
    environment = {"source_revision": revision, "source_state": source_state, "started_at": started.isoformat(), "finished_at": datetime.now(UTC).isoformat(), "run_kind": "focused_native_acceptance"}
    fixture.json_file(report / "env.json", environment)
    fixture.json_file(report / "report.json", environment | {"status": "passed" if passed else "failed", "engines": results, "backup_role_scope": ["mysql", "postgresql"], "unverified_backup_role_profiles": ["tidb", "mongodb"]})
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
