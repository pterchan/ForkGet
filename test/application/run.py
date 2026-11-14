#!/usr/bin/env python3
"""Run the unmodified ORM business profile through an imported proxy snapshot."""

import argparse
from datetime import UTC, datetime
import importlib.util
from importlib.metadata import version
import json
import os
import shutil
from pathlib import Path
import sys
import tempfile
import traceback

from sqlalchemy import Column, MetaData, Table, create_engine, event, func, select
from sqlalchemy.engine import URL
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, registry

from business import (APP_COUNTS, Base, Customer, Line, MODELS, SEED_UPDATED_TITLE,
                      assert_seed, canonical, constraint_checks, exercise, next_allocations,
                      observe, read_state, reflect, seed_source, typed_json)

SUITE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("application_snapshot", SUITE.parent / "p7/snapshot_import.py")
snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshot)
from run_p2 import OWNER_A, OWNER_B, Failure, json_file, require, wait_until


def net_changes(baseline, current):
    """Derive changed keys from complete typed states, independently of export."""
    require(set(baseline) == set(current) == set(Base.metadata.tables),
            "Net diff is missing one of the five business tables")
    changes = {}
    for name in baseline:
        before = {row["id"]: row for row in baseline[name]}
        after = {row["id"]: row for row in current[name]}
        changes[name] = {}
        for key in sorted(before.keys() | after.keys()):
            if before.get(key) == after.get(key):
                continue
            operation = "insert" if key not in before else "delete" if key not in after else "update"
            changes[name][str(key)] = operation
    return changes


def generated_key_ranges(baseline, current):
    """Keep imported native low IDs and require new branch keys in its high range."""
    result = {}
    for name in baseline:
        imported = {row["id"] for row in baseline[name]}
        present = {row["id"] for row in current[name]}
        added = present - imported
        require(imported <= present and all(0 < key < 1 << 62 for key in imported),
                "A low native seed key was removed or replaced")
        require(len(added) == APP_COUNTS[name] and all(key >= 1 << 62 for key in added),
                "New ordinary branch keys lost their isolated generated range")
        result[name] = {"imported_low_ids": sorted(imported), "new_count": len(added),
                        "new_high_min": min(added), "new_high_max": max(added)}
    return result


class ApplicationRun(snapshot.SnapshotRun):
    def __init__(self,*arguments):
        super().__init__(*arguments)
        self.base_env["FG_STATE_DIR"]=str(self.workspace / "private-replay-state")

    def policy_account(self, user):
        return {"policy_admin": True, "approver_for": [OWNER_A]} if user == OWNER_B else {}

    def environment(self):
        environment = super().environment()
        database = "p2_native" if self.family == "postgresql" else "business"
        account = "postgres" if self.family == "postgresql" else "root"
        environment["FG_SOURCE_DSN"] = self.dsn(account, self.secret["native"], self.native_port, database)
        return environment

    def db_engine(self, branch=None):
        native = branch is None
        database = ("p2_native" if self.family == "postgresql" else "business") if native else branch["name"]
        user = ("postgres" if self.family == "postgresql" else "root") if native else OWNER_A
        password = self.secret["native"] if native else self.frontend_passwords[OWNER_A]
        ca = str(self.certs / ("backend-ca.pem" if native else "frontend-ca.pem"))
        options = ({"sslmode": "verify-full", "sslrootcert": ca} if self.family == "postgresql"
                   else {"ssl": {"ca": ca, "check_hostname": True}})
        url = URL.create("postgresql+psycopg" if self.family == "postgresql" else "mysql+pymysql",
                         username=user, password=password, host="127.0.0.1",
                         port=self.native_port if native else self.proxy_port, database=database)
        return create_engine(url, connect_args=options)

    def source(self):
        if self.family == "postgresql":
            self.native("CREATE SCHEMA business; ALTER DATABASE p2_native SET search_path TO business;")
        else:
            collation="utf8mb4_bin" if self.family=="tidb" else "utf8mb4_0900_ai_ci"
            self.native(f"CREATE DATABASE business CHARACTER SET utf8mb4 COLLATE {collation};")
        engine = self.db_engine()
        try:
            Base.metadata.create_all(engine)
            self.baseline = seed_source(engine)
            require(all(self.baseline.values()), "Every native business source table must be nonempty before capture")
            json_file(self.report / "seed-source-state.json", typed_json(self.baseline))
        finally:
            engine.dispose()
        self.record("real SQLAlchemy creates and populates the linked five-table native source with typed low generated keys before capture")

    def native_branch_state(self, branch):
        """Operator-side ORM witness reads the owned physical copy independently."""
        schema, prefix = self.branch_namespace(branch["id"])
        engine = self.db_engine()
        mappings = registry()
        metadata = MetaData()
        state = {}
        try:
            with Session(engine) as session:
                for model in MODELS:
                    name = model.__tablename__
                    # Reuse the application's declared domain types, including
                    # Boolean on the MySQL wire, while addressing the fixture's
                    # actual owned table. No application SQL or dialect changes.
                    table = Table(prefix + name, metadata,
                                  *(Column(column.name, column.type, primary_key=column.primary_key)
                                    for column in model.__table__.columns), schema=schema)
                    native_model = type("Native" + model.__name__, (), {})
                    mappings.map_imperatively(native_model, table)
                    rows = session.scalars(select(native_model).order_by(native_model.id)).all()
                    state[name] = [{column.name: getattr(row, column.name) for column in model.__table__.columns}
                                   for row in rows]
        finally:
            mappings.dispose()
            engine.dispose()
        return state

    def readonly(self, branch):
        engine = self.db_engine(branch)
        try:
            reflect(engine)
            imported = assert_seed(engine, updated=False)
            require(imported == self.baseline,
                    "Ordinary read-only ORM did not preserve the imported five-table typed chain and exact low IDs")
            json_file(self.report / "imported-readonly-state.json", typed_json(imported))
            with Session(engine) as session:
                session.add(Customer(code="readonly-denied"))
                try:
                    session.commit()
                    raise Failure("Read-only application write succeeded")
                except DBAPIError as error:
                    require("5001" in str(error.orig), "Read-only write did not return FG-5001")
                    session.rollback()
            require(read_state(engine) == self.baseline, "Read-only refusal changed imported business data")
        finally:
            engine.dispose()
        self.record("default read-only branch normally reflects and reads the complete imported business chain; mutation returns FG-5001 without changing seed data")

    def reject_default_budget(self, branch):
        engine = self.db_engine(branch)
        written = set()
        imported_order_updated = False

        @event.listens_for(engine, "after_cursor_execute")
        def inserted(connection, cursor, statement, parameters, context, executemany):
            nonlocal imported_order_updated
            if context.isinsert and context.compiled is not None:
                written.add(context.compiled.statement.table.name)
            if context.isupdate and context.compiled is not None and context.compiled.statement.table.name == "orders":
                imported_order_updated |= any(SEED_UPDATED_TITLE in values.values()
                                              for values in context.compiled_parameters)

        try:
            before = assert_seed(engine, updated=False)
            require(before == self.baseline, "Writable branch did not start from the captured populated baseline")
            json_file(self.report / "imported-writable-state.json", typed_json(before))
            with engine.connect() as connection:
                original_connection = connection.connection.driver_connection
            try:
                exercise(engine, "budget-denied")
                raise Failure("Default budget unexpectedly admitted 1001-row business transaction")
            except DBAPIError as error:
                require("5002" in str(error.orig), "Bulk default limit did not return FG-5002")
            require(written == set(Base.metadata.tables),
                    "Budget refusal did not occur after successful writes to all five business tables")
            require(imported_order_updated, "The existing seed Order UPDATE was not flushed before the budget refusal")
            with engine.connect() as connection:
                require(connection.connection.driver_connection is original_connection,
                        "Budget recovery silently replaced the failed DBAPI connection")
            recovered = assert_seed(engine, updated=False)
            require(recovered == self.baseline and self.native_branch_state(branch) == self.baseline,
                    "Budget refusal retained new rows or changed existing typed business data")
            json_file(self.report / "budget-rollback-state.json", typed_json(recovered))
        finally:
            engine.dispose()
        json_file(self.report / "budget-denied.json", {"successful_insert_tables_before_refusal": sorted(written),
                  "existing_seed_order_update_flushed_before_refusal": imported_order_updated,
                  "all_five_tables_match_seed_after_rollback": True, "seed_state_unchanged_after_rollback": True,
                  "same_dbapi_connection": True, "error": "FG-5002"})
        self.record("default budget refuses the normal 1001-line flush after a real imported Order UPDATE and inserts to all five tables; one DBAPI rollback restores the exact populated baseline")

    def aborted_recovery(self, branch):
        if self.family not in ("mysql","tidb"):
            return
        engine=self.db_engine(branch)
        try:
            with engine.connect() as connection:
                for number in range(11):
                    try:
                        connection.exec_driver_sql("INSERT INTO customers(code,active) VALUES (%s,TRUE)",(f"aborted-{number}",))
                        require(number<10,"Default table budget was not enforced")
                    except DBAPIError as error:
                        require(number==10 and "5002" in str(error.orig),"Unexpected default refusal in aborted-transaction fixture")
                for statement in ("SELECT 1","COMMIT","INSERT INTO customers(code,active) VALUES ('blocked',TRUE)"):
                    try:
                        connection.exec_driver_sql(statement)
                        raise Failure("Aborted native transaction accepted more work before rollback")
                    except DBAPIError as error:
                        require("transaction_requires_rollback" in str(error.orig),"Aborted transaction lost its recovery reason")
                connection.rollback()
                require(connection.scalar(select(func.count()).select_from(Customer))==len(self.baseline["customers"]),
                        "Aborted transaction retained inserted customers after recovery")
            require(assert_seed(engine, updated=False) == self.baseline
                    and self.native_branch_state(branch) == self.baseline,
                    "Aborted connection recovery changed existing seed values or retained partial writes")
        finally:
            engine.dispose()
        self.record("MySQL keeps the refused connection, blocks reads/writes/COMMIT until ROLLBACK, then recovers with no partial rows")

    def grant(self, branch):
        status,raw=self.request("GET", f"/v1/branches/{branch['id']}/policy", self.owner_tokens[OWNER_A])
        before=json.loads(raw)
        require(status==200,"Could not capture the branch's default policy before its reviewed grant")
        json_file(self.report / f"policy-before-grant-{branch['id']}.json",before)
        if not hasattr(self,"default_policy"):
            self.default_policy=before
        status, raw = self.request("POST", f"/v1/branches/{branch['id']}/budget-requests",
                                   self.owner_tokens[OWNER_A], {
                                       "max_transaction_rows": 2000, "table_limit_bps": None,
                                       "small_table_floor": 2000, "ttl_seconds": 900,
                                       "reason": "Pinned SQLAlchemy business acceptance with 1001 default bulk rows",
                                   })
        require(status == 200, f"Scoped budget request failed: {status} {raw}")
        request = json.loads(raw)
        status, raw = self.request("POST", f"/v1/branches/{branch['id']}/budget-requests/{request['id']}/review",
                                   self.owner_tokens[OWNER_B], {"approve": True})
        require(status == 200 and json.loads(raw)["state"] == "approved", "Independent reviewer did not approve the branch budget")
        status, raw = self.request("GET", f"/v1/branches/{branch['id']}/policy", self.owner_tokens[OWNER_A])
        policy = json.loads(raw)
        require(status == 200 and policy["max_transaction_rows"] == 2000 and policy["grant_expires_at"],
                "Effective policy did not contain the temporary branch grant")
        json_file(self.report / "effective-policy.json", policy)
        json_file(self.report / f"effective-policy-{branch['id']}.json", policy)
        self.record("independent authorized reviewer grants a temporary budget scoped to this branch; global policy is unchanged")

    def plans(self, engine):
        statement = ("EXPLAIN (FORMAT JSON) SELECT id, reference FROM lines WHERE id=%s" if self.family == "postgresql"
                     else "EXPLAIN FORMAT=JSON SELECT id, reference FROM lines WHERE id=%s")
        plans = []
        with engine.connect() as connection:
            for _ in range(7):
                raw = connection.exec_driver_sql(statement, (1,)).scalar_one()
                plan = json.loads(raw) if isinstance(raw, str) else raw
                encoded = json.dumps(plan)
                require("Forkget" in encoded and all(private not in encoded for private in ("fg_g", "fg_b", "fgwrite", "_fg_generated")),
                        "EXPLAIN exposed native storage identity")
                plans.append(plan)
        json_file(self.report / "explain.json", plans[-1])
        for statement in ("EXPLAIN ANALYZE SELECT id FROM lines", "EXPLAIN DELETE FROM lines WHERE id=1"):
            try:
                with engine.connect() as connection:
                    connection.exec_driver_sql(statement)
                raise Failure("Unsafe EXPLAIN was admitted")
            except DBAPIError as error:
                require("2002" in str(error.orig), "Unsafe EXPLAIN did not return the support boundary")
        execution = "default driver preparation" if self.family == "postgresql" else "text execution"
        self.record(f"native JSON EXPLAIN maps storage identities to logical names during repeated {execution}; ANALYZE/DML stay refused")

    def artifact_cli(self,label,*arguments):
        environment=self.base_env | {"FG_CONTROL_URL":self.control_url,"FG_OWNER_TOKEN":self.owner_tokens[OWNER_A]}
        return json.loads(self.call(label,[self.executable("forkget"),*arguments],env=environment,timeout=350,log=True))

    def replay_business(self,source,expected):
        path=self.report / "business.ndjson"
        receipt=self.artifact_cli("export-business","export","--id",str(source["id"]),"--output",str(path))
        delta = net_changes(self.baseline, expected)
        expected_count = sum(len(changes) for changes in delta.values())
        seed_order_id = str(self.baseline["orders"][0]["id"])
        require(delta["orders"].get(seed_order_id) == "update", "The exported plan lost the imported existing Order update")
        require(receipt["complete"] and receipt["replayable"] and receipt["changes"] == expected_count,
                "Business export count differs from complete typed baseline/final net changes")
        observed = {name: {} for name in delta}
        with path.open() as stream:
            header = json.loads(next(stream))
            require(header["record"] == "header", "Business artifact lacks its typed header")
            tables = {table["id"]: table["table"] for table in header["value"]["tables"]}
            footer = None
            for line in stream:
                record = json.loads(line)
                if record["record"] == "end":
                    footer = record["value"]
                    continue
                require(record["record"] == "change" and footer is None,
                        "Business artifact has an unexpected record or data after its footer")
                change = record["value"]
                name = tables[change["table_id"]]
                require(len(change["key"]) == 1 and change["key"][0] not in observed[name],
                        "Business artifact duplicates a changed key")
                observed[name][change["key"][0]] = change["operation"]
        require(footer and footer["complete"] and footer["changes"] == expected_count
                and observed == delta, "Artifact operation/key set differs from the independent baseline diff")
        json_file(self.report / "expected-net-diff.json", {"changes": delta, "count": expected_count,
                  "baseline_rows": {name: len(rows) for name, rows in self.baseline.items()},
                  "final_rows": {name: len(rows) for name, rows in expected.items()}})
        checked=self.artifact_cli("preflight-business","replay","--engine",self.engine,"--input",str(path),"--check")
        require(checked["checked"],"Business artifact preflight failed")
        staged=self.artifact_cli("stage-business","replay","--engine",self.engine,"--input",str(path),
                                 "--name","application-replayed","--stage-only")
        require(staged["staged"] and staged["transaction"]=="not_started" and not staged["verified"],
                "CLI stage-only mutated the target before independent budget approval")
        target=staged["branch"]
        wait_until("business replay target activation",lambda:self.branch_status(target)=="active")
        status,raw=self.request("GET", f"/v1/branches/{target['id']}/policy", self.owner_tokens[OWNER_A])
        target_policy=json.loads(raw)
        policy_fields=("class","version","max_transaction_rows","table_limit_bps","approval_after_rows","small_table_floor")
        require(status==200 and not target_policy.get("grant_expires_at")
                and all(target_policy[key]==self.default_policy[key] for key in policy_fields),
                "Fresh replay target does not retain the independently captured default policy")
        quarantined=self.db_engine(target)
        try:
            try:
                with quarantined.connect():
                    raise Failure("Staged replay target accepted an ordinary ORM session before verification")
            except DBAPIError as error:
                require("2003" in str(error.orig),"Staged ordinary ORM session lost its FG-2003 quarantine refusal")
        finally:
            quarantined.dispose()
        staged_native=self.native_branch_state(target)
        require(staged_native == self.baseline,
                "CLI stage-only lost or mutated the imported native seed before its separate reviewed grant")
        json_file(self.report / "staged-native-state.json",typed_json(staged_native))
        self.record("CLI stage-only preserves the full populated seed baseline and quarantines ordinary ORM sessions with FG-2003 before verified apply")
        # The fresh target has its own automatic budget. Approval of the source
        # does not authorize a different branch, including an internal replay.
        self.grant(target)
        result=self.artifact_cli("apply-business","replay","--engine",self.engine,"--apply-job",str(staged["job_id"]))
        require(result["verified"] and result["result"]["transaction"]=="committed",f"Business replay failed: {result}")
        engine=self.db_engine(target)
        try:
            actual=observe(engine)
            require(actual==expected,"Replayed ORM state changed generated IDs, foreign keys or typed business values")
            native_actual=self.native_branch_state(target)
            require(native_actual==expected,"Direct native ORM replay witness differs from source IDs or proxy typed rows")
            constraints = constraint_checks(engine, actual)
            allocations = next_allocations(engine, actual)
            require(self.native_branch_state(target)==expected,
                    "Native replay target retained rows from failed constraints or rolled-back generated-key probes")
            json_file(self.report / "replayed-business-state.json", typed_json(actual))
            json_file(self.report / "replayed-native-state.json", typed_json(native_actual))
        finally:
            engine.dispose()
        json_file(self.report / "replay.json",{"export":receipt,"stage":staged,"apply":result,"job_id":staged["job_id"],
                                               "branch_id":target["id"],"verified":True,"same_business_state":True,
                                               "direct_native_orm_equals_proxy": True,
                                               "native_rollback_after_generated_key_probes": True,
                                               "target_default_policy_before_grant": target_policy,
                                               "constraints": constraints,"next_allocations": allocations,
                                               "expected_net_changes": expected_count,
                                               "populated_baseline_preserved_before_apply": True,
                                               "generated_key_ranges": generated_key_ranges(self.baseline, expected)})
        self.record("complete five-table typed export, staged target, separate reviewed target grant and verified replay preserve exact generated IDs and typed ORM rows; next ordinary keys are collision-free on all five tables")

    def capture_source(self):
        self.start_databases()
        self.native_roles()
        if self.family == "mysql":
            self.native("SET GLOBAL local_infile=ON;")
        self.call("migrate", [self.executable("fg-control"), "migrate"], env=self.environment(), log=True)
        self.source()
        plan = self.workspace / "source-plan.json"
        self.snapshot("inspect", "inspect", "--source-env", "FG_SOURCE_DSN", "--schema", "business",
                      "--name", "business-v1", "--output", str(plan))
        admitted = json.loads(plan.read_text())
        require(admitted["status"] == "admitted"
                and {table["name"] for table in admitted["manifest"]["tables"]} == set(Base.metadata.tables),
                "Native preflight did not admit all five real business tables")
        require({table["name"]: table["rows"] for table in admitted["manifest"]["tables"]}
                == {name: len(rows) for name, rows in self.baseline.items()}
                and all(table["rows"] > 0 for table in admitted["manifest"]["tables"]),
                "Native inspection must report every populated business source table with its exact row count")
        json_file(self.report / "source-plan.json", admitted)
        bundle = self.workspace / "bundle"
        self.snapshot("capture", "capture", "--source-env", "FG_SOURCE_DSN", "--schema", "business",
                      "--name", "business-v1", "--output", str(bundle))
        captured = json.loads((bundle / "manifest.json").read_text())
        require({table["name"]: table["rows"] for table in captured["tables"]}
                == {name: len(rows) for name, rows in self.baseline.items()}
                and all(table["rows"] > 0 for table in captured["tables"]),
                "Captured manifest lost a populated business source table")
        shutil.copyfile(bundle / "manifest.json",self.report / "source-manifest.json")
        self.record("native inspect/capture preserves the populated five-table business chain, exact row counts, foreign keys and generated keys")
        return bundle

    def native_preflight(self):
        self.capture_source()
        engine = self.db_engine()
        try:
            schema = reflect(engine)
            result = exercise(engine)
            state = observe(engine)
            constraints = constraint_checks(engine, state)
            json_file(self.report / "native-business.json", {"result": result, "schema": schema,
                      "constraints": constraints, "state": typed_json(state)})
        finally:
            engine.dispose()
        self.record("native five-table business profile passes unchanged reflection, 1001-line bulk, five unique and five FK refusals, version conflict and exact typed-state assertions")

    def execute(self):
        bundle = self.capture_source()
        self.snapshot("import", "import", "--input", str(bundle))
        self.metadata_role()
        self.start_control()
        self.start_proxy()
        readonly, _ = self.fork("application-read")
        self.readonly(readonly)
        branch, _ = self.fork("application-write", write=True)
        self.reject_default_budget(branch)
        self.aborted_recovery(branch)
        self.grant(branch)
        engine = self.db_engine(branch)
        measurements = {"statements": 0, "largest_sql_bytes": 0, "largest_parameters": 0, "bulk_pages": []}

        @event.listens_for(engine, "before_cursor_execute")
        def measure(connection, cursor, statement, parameters, context, executemany):
            measurements["statements"] += 1
            measurements["largest_sql_bytes"] = max(measurements["largest_sql_bytes"], len(statement.encode()))
            measurements["largest_parameters"] = max(measurements["largest_parameters"], len(parameters))
            if "imp_sen" in statement and "INSERT INTO lines " in statement:
                measurements["bulk_pages"].append(len(parameters) // 7)

        try:
            result = exercise(engine)
            self.plans(engine)
            engine.dispose()
            with Session(engine) as session:
                require(session.scalar(select(func.count()).select_from(Line)) == len(self.baseline["lines"]) + APP_COUNTS["lines"],
                        "Reconnect did not retain the imported line and all newly committed application lines")
            committed=observe(engine)
            key_ranges = generated_key_ranges(self.baseline, committed)
            native_copy=self.native_branch_state(branch)
            require(native_copy==committed,
                    "Direct native ORM source witness differs from proxy generated IDs or typed business rows")
            json_file(self.report / "native-copy-state.json",typed_json(native_copy))
            proxy_constraints = constraint_checks(engine, committed)
            proxy_schema = reflect(engine)
            if self.family == "postgresql":
                require(measurements["bulk_pages"] == [1000, 1],
                        "Default PostgreSQL 1001-line insertmanyvalues paging changed")
        finally:
            engine.dispose()
        native = self.db_engine()
        try:
            require(assert_seed(native, updated=False) == self.baseline,
                    "Native reference source changed after capture and before its ordinary business flow")
            reference = exercise(native)
            native_state = observe(native)
            native_constraints = constraint_checks(native, native_state)
            native_schema = reflect(native)
        finally:
            native.dispose()
        immutable = self.db_engine(readonly)
        try:
            require(assert_seed(immutable, updated=False) == self.baseline,
                    "Later native reference updates polluted the captured immutable read-only branch")
        finally:
            immutable.dispose()
        require(reference == result, "Proxy business result differs from the native reference")
        require(canonical(committed) == canonical(native_state),
                "Complete typed business state or foreign-key relationships differ between native and proxy")
        json_file(self.report / "business.json", {"proxy": result, "native": reference, "measurements": measurements,
                  "constraints": {"proxy": proxy_constraints, "native": native_constraints},
                  "schemas": {"proxy": proxy_schema, "native": native_schema},
                  "native_proxy_equal_by_business_keys": True,
                  "generated_key_ranges": key_ranges,
                  "captured_readonly_baseline_unchanged_after_native_reference": True,
                  "steps": ["read the populated imported five-table typed seed and update its existing versioned Order",
                            "create customer and two priced products", "book versioned order and linked payment",
                            "replace draft line", "flush 1001 generated order lines with product quantities",
                            "reject stale optimistic update", "delete final line and settle adjusted payment",
                            "reconnect and compare every typed row and relationship", "reject five duplicates and five orphan FKs"]})
        json_file(self.report / "proxy-business-state.json", typed_json(committed))
        json_file(self.report / "native-business-state.json", typed_json(native_state))
        self.record("identical five-table SQLAlchemy code matches all native/proxy typed business rows and FK relationships, normal 1001-line paging, generated keys, optimistic lock, Decimal/date/Boolean/datetime(6), reconnect and native constraint refusals")
        self.replay_business(branch,committed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=["mysql", "postgresql", "tidb", "all"], default="all")
    parser.add_argument("--report-dir", type=Path, required=True)
    parser.add_argument("--native-preflight", action="store_true",
                        help="only inspect/capture the native schema and exercise the direct ORM; do not start control/proxy")
    options = parser.parse_args()
    pinned={"SQLAlchemy":"2.1.8","PyMySQL":"1.1.1","psycopg":"3.2.9"}
    installed={name:version(name) for name in pinned}
    require(installed==pinned,f"Application acceptance requires the exact pinned ORM/drivers: {installed}")
    report = options.report_dir.resolve()
    report.mkdir(parents=True, exist_ok=False)
    results, started = {}, datetime.now(UTC)
    for engine in (["mysql", "postgresql", "tidb"] if options.engine == "all" else [options.engine]):
        detail = report / engine
        detail.mkdir()
        with tempfile.TemporaryDirectory(prefix="fg-application-") as temporary:
            workspace = Path(temporary)
            certs = workspace / "certs"
            snapshot.p34.p2.build_certs(certs)
            runner = ApplicationRun(engine, detail, workspace, certs, f"fgapplication-{started:%H%M%S}-{os.getpid()}")
            errors = []
            try:
                runner.native_preflight() if options.native_preflight else runner.execute()
            except Exception as error:
                errors.append(runner.safe(str(error)))
                (detail / "error.log").write_text(runner.safe(traceback.format_exc()), encoding="utf-8")
            finally:
                try:
                    runner.cleanup()
                except Exception as error:
                    errors.append(runner.safe(str(error)))
            results[engine] = {"status": "failed" if errors else "passed", "version": runner.engine_version,
                               "checks": runner.cases, "errors": errors, "cleaned_up": not runner.compose_started}
            print(json.dumps({engine: results[engine]}), flush=True)
    revision, state = snapshot.p34.p2.git_state()
    json_file(report / "env.json", {"source_revision": revision, "source_state": state, "started_at": started.isoformat(),
                                   "profile": "native-preflight" if options.native_preflight else "five-table-application",
                                   "orm": "SQLAlchemy "+installed["SQLAlchemy"],
                                   "drivers": {name:installed[name] for name in ("PyMySQL","psycopg")}})
    passed = all(result["status"] == "passed" for result in results.values())
    json_file(report / "report.json", {"status": "passed" if passed else "failed", "engines": results})
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
