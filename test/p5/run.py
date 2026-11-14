"""Exercise local policy enforcement on both pinned engines over verified TLS."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import platform
import secrets
import ssl
import struct
import subprocess
import sys
from threading import Event, Lock, Thread
import time

P5 = Path(__file__).resolve().parent
P34 = P5.parent / "p3p4"
sys.path.extend((str(P5), str(P34)))
spec = importlib.util.spec_from_file_location("run_p34", P34 / "run.py")
p34 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p34)
from pg_wire import RAW_CLIENT
from run_p2 import OWNER_A, OWNER_B, ROOT, require, wait_until
from write_cases import Probe, begin, check_count, int64, string
import mysql_review
import pg_review

OUTSIDER = "p5_outsider"


def insert(key, code="policy-witness"):
    return f"INSERT INTO parents (id,tenant_id,code) VALUES ({key},8,'{code}')"


def read_key(probe, key):
    return probe.sql(f"SELECT id FROM parents WHERE id={key}", "read").get("rows")


def fg(observation, expected):
    require(observation.get("fg") == expected, f"Expected {expected}, observed {observation}")
    require(not observation.get("physical_leak"), "Policy response exposed a physical name")


def budget_error(observation, expected):
    fg(observation, "FG-5002")
    require(observation.get("policy_detail") == f"[FORKGET FG-5002] {expected}",
            f"Policy response omitted counts, named the wrong budget, or exposed statement values: {observation}")


class EngineRun(p34.EngineRun):
    def __init__(self, *args):
        super().__init__(*args)
        self.secret["outsider_token"] = secrets.token_hex(24)
        self.owner_tokens[OUTSIDER] = self.secret["outsider_token"]

    def policy_account(self, user):
        if user == OWNER_A:
            return {"policy_admin": True, "allowed_classes": ["dev", "ci", "agent", "staging"]}
        if user == OWNER_B:
            return {"approver_for": [OWNER_A], "allowed_classes": ["agent"]}
        return {}

    def legacy_migration(self):
        super().legacy_migration()
        if self.family == "tidb":
            # The replayed rows predate engine 'tidb'; TiDB deployments have
            # no pre-migration history for that engine.
            return
        migrations = sorted((ROOT / "crates/fg-meta/migrations").glob("*.sql"))
        initial = "\n".join(path.read_text(encoding="utf-8") for path in migrations[:5])
        upgrade = "\n".join(path.read_text(encoding="utf-8") for path in migrations[5:])
        result = self.metadata(f"""
            BEGIN;
            CREATE SCHEMA legacy_write_upgrade;
            SET LOCAL search_path TO legacy_write_upgrade;
            {initial}
            INSERT INTO generation (engine,status,snapshot,native_claimed,activated_at)
                VALUES ('{self.engine}','active','v2',true,now());
            INSERT INTO branch (name,class,generation_id,created_by,status,expires_at,mode,native_claimed)
                VALUES ('legacy-write','dev',1,'{OWNER_A}','active',now()+INTERVAL '1 hour','native_write',true);
            {upgrade}
            SELECT b.id,b.mode,b.status,p.version,p.table_limit_bps,p.small_table_floor
                FROM branch b JOIN policy_version p ON p.class=b.class WHERE b.name='legacy-write'
                ORDER BY p.version DESC LIMIT 1;
            ROLLBACK;
        """)
        require(result == "1|native_write|active|2|1000|10", "Migration bypassed the current default policy for a preexisting dev write branch")
        self.record("Forward policy migration applies the current budget to a preexisting dev write branch")

    def create(self, name, branch_class="dev", write=True):
        args = ["fork", name, "--class", branch_class]
        if write:
            args.append("--write")
        branch = self.cli(OWNER_A, *args)
        require(branch["class"] == branch_class, "Fork did not pin its policy class")
        wait_until(f"{name} activation", lambda: self.branch_status(branch) == "active")
        return branch, (OWNER_A, name)

    def defaults(self):
        status, raw = self.request("GET", "/v1/policies/dev", self.owner_tokens[OWNER_A])
        require(status == 200 and json.loads(raw)["table_limit_bps"] == 1000, "Dev default is not 10 percent")
        forbidden, _ = self.request("POST", "/v1/branches", self.owner_tokens[OWNER_B], {"name": "bypass", "class": "dev"})
        require(forbidden == 403, f"An agent account can select dev ({forbidden})")
        denied, _ = self.request("PUT", "/v1/policies/dev", self.owner_tokens[OUTSIDER],
                                 {"expected_version": 1, "max_transaction_rows": 50000})
        require(denied == 403, "A nonadministrator changed policy")
        status, _ = self.request("POST", "/v1/branches", self.owner_tokens[OWNER_A],
                                 {"name": "bad-staging", "class": "staging", "mode": "native_write"})
        require(status in {400, 403, 409}, "Writable staging was accepted")
        stage, credentials = self.create("read-staging", "staging", False)
        with Probe(self, "staging", credentials) as probe:
            refusal = probe.sql(insert(501))
            require(refusal.get("fg") in {"FG-5001", "FG-2002"}, "Staging allowed a write")
        self.drop(OWNER_A, stage["id"])
        default_policy=self.cli(OWNER_A,"policy","get","agent")
        require(default_policy["small_table_floor"]==10 and default_policy["approval_after_rows"] is None,
                "Untouched default Agent policy requires statement approval or lacks the ten-row floor")
        automatic, credentials=self.create("automatic-agent","agent")
        with Probe(self,"automatic-agent",credentials) as probe:
            check_count(probe,insert(509,"automatic-agent"),1)
        self.drop(OWNER_A,automatic["id"])
        self.set_policy("dev",50_000,1000,floor=1)
        self.set_policy("agent",10000,100,1,floor=1)
        self.record("Class grants, automatic Agent default, ten-row floor and read-only staging; explicit custom one-row floor retained for budget regression")

    def budget(self, branch):
        with Probe(self, "default-budget", branch) as probe:
            budget_error(probe.sql(insert(500, "budget-a") + ",(501,8,'budget-b')"),
                         "Table row share budget exceeded: cumulative table rows 2 > limit 1 "
                         "(baseline_rows=3, table_limit_bps=1000); request a temporary branch budget (reason=table_row_budget)")
            require(read_key(probe, 500) == [] and read_key(probe, 501) == [], "Denied batch committed a row")
            check_count(probe, insert(500, "budget-a"), 1)
            check_count(probe, "DELETE FROM parents WHERE id=500", 1)
        self.set_policy("dev", 2)
        for offset, level in enumerate(("READ COMMITTED", "REPEATABLE READ")):
            key = 510 + offset
            with Probe(self, f"budget-{offset}", branch) as probe:
                begin(probe, self.engine, level)
                check_count(probe, insert(key, "budget-rollback"), 1)
                check_count(probe, "SAVEPOINT policy_point", 0)
                update = ("UPDATE parents SET label=? WHERE id=?" if self.family != "postgresql"
                          else "UPDATE parents SET label=$2 WHERE id=$1")
                parameters = (("null_text", int64(key)) if self.family != "postgresql"
                              else (int64(key), "null_text"))
                check_count(probe, update, 1, "execute", parameters)
                check_count(probe, "ROLLBACK TO SAVEPOINT policy_point", 0)
                if self.family != "postgresql":
                    check_count(probe, "SET AUTOCOMMIT=1", 0)
                budget_error(probe.sql(update, "execute", parameters),
                             "Transaction row budget exceeded: cumulative rows 3 > max_transaction_rows 2; "
                             "request a temporary branch budget (reason=transaction_row_budget)")
                refusal=probe.sql("SELECT 1", "read")
                require(refusal.get("fg")=="FG-5001" or refusal.get("sqlstate")=="25P02",
                        "Denied transaction did not retain its aborted state")
                check_count(probe,"ROLLBACK",0)
                require(probe.sql("SELECT 1","read").get("rows")==[[1]],"ROLLBACK did not recover the same connection")
            with Probe(self, f"budget-verify-{offset}", branch) as observer:
                require(read_key(observer, key) == [], "Denial preserved work before a savepoint")
        with Probe(self, "prepared-policy-version", branch) as probe:
            placeholders = "?,?,?" if self.family != "postgresql" else "$1,$2,$3"
            sql = f"INSERT INTO parents (id,tenant_id,code) VALUES ({placeholders})"
            values = (int64(521), {"i32": 8}, string("frozen-prepare"))
            check_count(probe, sql, 1, "execute", values)
            self.set_policy("dev", 1)
            begin(probe, self.engine, "READ COMMITTED")
            check_count(probe, insert(522, "budget-current"), 1)
            values = (int64(523), {"i32": 8}, string("must-rollback"))
            budget_error(probe.sql(sql, "execute", values),
                         "Transaction row budget exceeded: cumulative rows 2 > max_transaction_rows 1; "
                         "request a temporary branch budget (reason=transaction_row_budget)")
        with Probe(self, "check-prepare-policy", branch) as probe:
            require(read_key(probe, 521) == [[521]] and read_key(probe, 522) == [] and read_key(probe, 523) == [],
                    "A cached prepared statement used a stale policy")
        if self.family == "postgresql":
            self.extended_budget(branch)
        self.record("Default percentage, text and prepared RC/RR counts, savepoints, policy updates and whole rollback")

    def outage(self, branch):
        with Probe(self, "control-loss", branch) as probe:
            begin(probe, self.engine, "READ COMMITTED")
            check_count(probe, insert(525, "control-loss"), 1)
            self.stop("control")
            fg(probe.sql("COMMIT"), "FG-1004")
        self.start_control()
        with Probe(self, "control-loss-state", branch) as probe:
            require(read_key(probe, 525) == [], "Control outage committed an open guarded transaction")
        self.record("Control loss fails closed and disconnect rolls back guarded work")

    def approvals(self, branch, token=None):
        path = f"/v1/branches/{branch['id']}/approvals"
        status, data = self.request("GET", path, token or self.owner_tokens[OWNER_B])
        require(status == 200, f"Approval lookup returned {status}")
        return json.loads(data)["approvals"]

    def pending(self, branch, seen):
        return wait_until("live approval", lambda: next((record for record in self.approvals(branch)
            if record["id"] not in seen and record["state"] == "pending"), None))

    def decide(self, branch, approval, user, accept=True):
        path = f"/v1/branches/{branch['id']}/approvals/{approval['id']}"
        return self.request("POST", path, self.owner_tokens[user], {"approve": accept})[0]

    def approval_checks(self, branch, credentials):
        seen = set()
        with Probe(self, "approve-one", credentials) as probe:
            probe.send(insert(600, "approved-once"))
            approval = self.pending(branch, seen)
            seen.add(approval["id"])
            require(self.decide(branch, approval, OWNER_A) in {403, 404}, "Writer approved itself")
            require(self.decide(branch, approval, OUTSIDER) in {403, 404}, "Unrelated account approved a write")
            require(self.decide(branch | {"id": branch["id"] + 1}, approval, OWNER_B) == 404,
                    "Approval crossed immutable branch IDs")
            with Probe(self, "approval-invisible", credentials) as observer:
                require(read_key(observer, 600) == [], "Pending approval was visible before commit")
            require(self.decide(branch, approval, OWNER_B) == 200, "Delegated approver could not approve")
            require(probe.receive().get("affected") == 1, "Approved write failed")
            require(self.decide(branch, approval, OWNER_B) == 409, "An approval was consumed twice")
            probe.send(insert(601, "denied-once"))
            refusal = self.pending(branch, seen)
            seen.add(refusal["id"])
            require(self.decide(branch, refusal, OWNER_B, False) == 200, "Could not deny approval")
            fg(probe.receive(), "FG-5003")
            require(read_key(probe, 601) == [], "Denied write committed")
            probe.send(insert(602, "old-policy"))
            stale = self.pending(branch, seen)
            seen.add(stale["id"])
            self.set_policy("agent", 10000, 100, 1)
            fg(probe.receive(), "FG-5003")
            require(self.decide(branch, stale, OWNER_B) == 409 and read_key(probe, 602) == [], "Stale policy approval survived")
        with Probe(self, "abandon-approval", credentials) as probe:
            probe.send(insert(603, "disconnected"))
            abandoned = self.pending(branch, seen)
            seen.add(abandoned["id"])
        wait_until("approval disconnect invalidation", lambda: any(item["id"] == abandoned["id"] and item["state"] == "invalidated" for item in self.approvals(branch)))
        with Probe(self, "proxy-epoch", credentials) as probe:
            probe.send(insert(604, "proxy-restart"))
            stale = self.pending(branch, seen)
            seen.add(stale["id"])
            self.stop("proxy")
            self.start_proxy()
            require(self.decide(branch, stale, OWNER_B) == 409, "A previous proxy epoch could approve")
        with Probe(self, "approval-rollback-state", credentials) as probe:
            require(all(read_key(probe, key) == [] for key in (601, 602, 603, 604)), "An invalidated write committed")
        self.record("Approval isolation, once-only consumption, policy invalidation, disconnect and proxy restart")
        if self.family == "postgresql":
            self.cancel_approval(branch, credentials, seen)
        self.approval_timeout_and_drop(branch, credentials, seen)

    def approval_timeout_and_drop(self, branch, credentials, seen):
        with Probe(self, "approval-timeout", credentials) as probe:
            started_wall = time.time()
            started = time.monotonic()
            probe.send(insert(605, "timeout-secret"))
            pending = self.pending(branch, seen)
            seen.add(pending["id"])
            require(probe.readable(68), "Approval deadline did not terminate the wait")
            fg(probe.receive(), "FG-5003")
            observed_monotonic = time.monotonic()
            observed_wall = time.time()
            elapsed = observed_monotonic - started
            diagnostic = {"started_wall": started_wall, "started_monotonic": started,
                          "observed_wall": observed_wall, "observed_monotonic": observed_monotonic,
                          "elapsed_seconds": elapsed, "wall_elapsed_seconds": observed_wall - started_wall,
                          "pending": pending}
            try:
                diagnostic["database"] = json.loads(self.metadata(f"""
                    SELECT jsonb_build_object(
                        'approval_id', a.id, 'state', a.state,
                        'created_at', (SELECT min(e.occurred_at) FROM audit_event e
                            WHERE e.branch_id=a.branch_id AND e.event_type='policy_decision'
                              AND e.payload->>'approval_id'=a.id::text),
                        'created_at_source', 'policy_decision_audit',
                        'expires_at', a.expires_at, 'observed_clock', clock_timestamp(),
                        'branch_id', b.id, 'branch_status', b.status,
                        'branch_expires_at', b.expires_at)::text
                    FROM policy_approval a JOIN branch b ON b.id=a.branch_id
                    WHERE a.id={pending['id']} AND b.id={branch['id']};
                """))
            except (p34.p2.Failure, OSError, ValueError) as error:
                diagnostic["database"] = {"diagnostic_error": type(error).__name__}
            p34.p2.json_file(self.report / "approval-window.json", diagnostic)
            require(55 <= elapsed <= 68,
                    f"Approval did not use its 60-second window (elapsed={elapsed:.6f}s)")
            require(read_key(probe, 605) == [], "Timed-out approval committed")
            probe.send(insert(606, "branch-drop"))
            pending = self.pending(branch, seen)
            self.drop(OWNER_A, branch["id"])
            require("transport" in probe.receive(), "Branch drop left the approval writer connected")
            require(self.decide(branch, pending, OWNER_B) in {404, 409}, "Dropped branch can still approve")
        self.record("Bounded approval wait and branch-drop cancellation")

    def raw_connection(self, raw, branch):
        owner, database = branch
        raw.USER = owner.encode()
        plain = raw.connect(self.proxy_port)
        plain.sendall(struct.pack("!II", 8, raw.PG_SSL))
        require(raw.read_exact(plain, 1) == b"S", "PostgreSQL refused frontend TLS")
        context = ssl.create_default_context(cafile=self.certs / "frontend-ca.pem")
        connection = context.wrap_socket(plain, server_hostname="localhost")
        connection.settimeout(20)
        connection.sendall(raw.pg_startup(database.encode()))
        raw.scram(connection, self.frontend_passwords[owner].encode())
        raw.pg_auth_frame(connection, 0)
        startup = raw.pg_until_ready(connection)
        return connection, next(body for tag, body in startup if tag == b"K")

    @staticmethod
    def raw_module():
        spec = importlib.util.spec_from_file_location("p5_raw", RAW_CLIENT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def extended_budget(self, branch):
        raw = self.raw_module()
        connection, _ = self.raw_connection(raw, branch)
        with connection:
            for key in (530, 531):
                query = insert(key, f"sync-{key}").encode()
                raw.pg_send(connection, b"P", b"\0" + query + b"\0\0\0")
                raw.pg_send(connection, b"B", b"\0" * 8)
                raw.pg_send(connection, b"E", b"\0" * 5)
                require(raw.pg_read(connection) == (b"1", b""), "Write Parse did not complete")
                require(raw.pg_read(connection) == (b"2", b""), "Write Bind did not complete")
                tag, body = raw.pg_read(connection)
                if key == 530:
                    require(tag == b"C", "First extended execution did not pass")
                else:
                    require(tag == b"E", "Second extended execution escaped the transaction cap")
                    raw.pg_error(body, b"54000", b"FG-5002")
            raw.pg_send(connection, b"S")
            require(raw.pg_read(connection) == (b"Z", b"I"), "Sync did not recover after denial")
        with Probe(self, "extended-rollback-state", branch) as probe:
            require(all(read_key(probe, key) == [] for key in (530, 531)), "Sync committed an earlier Execute after denial")
        self.record("PostgreSQL extended Sync rolls back prior successful Execute after policy denial")

    def cancel_approval(self, branch, credentials, seen):
        raw = self.raw_module()
        connection, cancel_key = self.raw_connection(raw, credentials)
        with connection:
            raw.pg_send(connection, b"Q", insert(607, "cancel-request").encode() + b"\0")
            pending = self.pending(branch, seen)
            seen.add(pending["id"])
            with raw.connect(self.proxy_port) as socket:
                socket.sendall(struct.pack("!II", 16, 80877102) + cancel_key)
            tag, body = raw.pg_read(connection)
            require(tag == b"E", "CancelRequest did not interrupt approval")
            raw.pg_error(body, b"57014", b"FG-5003")
            require(raw.pg_read(connection) == (b"Z", b"I"), "Cancelled approval left the native transaction open")
        with Probe(self, "cancel-rollback-state", credentials) as probe:
            require(read_key(probe, 607) == [], "Cancelled approval committed")
        self.record("PostgreSQL CancelRequest invalidates a waiting approval and rolls back")

    def audit(self, branch):
        path = f"/v1/branches/{branch['id']}/audit?limit=3"
        status, data = self.request("GET", path, self.owner_tokens[OWNER_A])
        page = json.loads(data)
        require(status == 200 and page["next_after"] and len(page["events"]) == 3,
                "Audit did not paginate events for a dropped owned branch")
        next_status, next_data = self.request("GET", path + f"&after={page['next_after']}", self.owner_tokens[OWNER_A])
        require(next_status == 200 and json.loads(next_data)["events"][0]["id"] > page["next_after"],
                "Audit keyset pagination repeated an event")
        require(self.request("GET", path, self.owner_tokens[OWNER_B])[0] == 404,
                "Approval delegation granted audit access to another owner's rows")
        output = self.certs.parent / "audit.jsonl"
        self.cli(OWNER_A, "audit", "--id", str(branch["id"]), "--output", str(output))
        lines = output.read_text().splitlines()
        require(lines and all(isinstance(json.loads(line), dict) for line in lines), "Audit export is not JSONL")
        require(all(secret not in "\n".join(lines) for secret in ("timeout-secret", "cancel-request", "INSERT INTO", self.secret["internal"])),
                "Audit exposed SQL or row data")
        self.record("Owned audit pagination, JSONL export and redaction after branch deletion")

    def rowdiff(self, branch):
        output = self.certs.parent / f"diff-{branch['id']}.json"
        self.cli(OWNER_A, "diff", "--id", str(branch["id"]), "--output", str(output))
        require(output.stat().st_mode & 0o777 == 0o600, "Rowdiff output is not private")
        report = json.loads(output.read_text())
        require(report["branch_id"] == branch["id"] and report["generation_id"] == branch["generation_id"],
                "Rowdiff changed its pinned identity")
        return {item["table"]: item["changes"] for item in report["tables"]}

    def diffs(self):
        alpha = self.merge_fixture(OWNER_A,"p5-sparse-alpha")
        beta = self.merge_fixture(OWNER_A,"p5-sparse-beta")
        binding = self.binding(OWNER_A, alpha)
        p34.p2.data.seed_delta(self.engine, self.native, binding, alpha["id"], beta["id"])
        changes = self.rowdiff(alpha)["orders"]
        keyed = {tuple(change["key"]): change for change in changes}
        require(keyed[("2", "1")]["operation"] == "delete" and keyed[("2", "2")]["operation"] == "update"
                and keyed[("3", "1")]["after"][-1] == "00ff41" and keyed[("1", "1")]["after"][-2:] == [None, None],
                "Sparse diff did not preserve composite keys, bytes, NULL or tombstones")
        path = f"/v1/branches/{alpha['id']}/diff"
        require(self.request("GET", path, self.owner_tokens[OWNER_B])[0] == 404, "Diff leaked across owners")
        self.drop(OWNER_A, alpha["id"])
        self.drop(OWNER_A, beta["id"])
        native, credentials = self.create("p5-native-diff")
        with Probe(self, "diff-writer", credentials) as probe:
            check_count(probe, "UPDATE parents SET code='leaf-new' WHERE id=101", 1)
            check_count(probe, "DELETE FROM parents WHERE id=102", 1)
            check_count(probe, insert(610, "net-zero"), 1)
            check_count(probe, "DELETE FROM parents WHERE id=610", 1)
        changes = self.rowdiff(native)
        require({(item["operation"], tuple(item["key"])) for item in changes["parents"]} ==
                {("update", ("101",)), ("delete", ("102",))}, "Native diff has incorrect net parent changes")
        require({(item["operation"], tuple(item["key"])) for item in changes["children"]} ==
                {("update", ("1000",)), ("delete", ("1002",))}, "Native diff missed cascades")
        self.drop(OWNER_A, native["id"])
        self.record("Owner-scoped sparse and native snapshot diff, cascades, net-zero, composite keys, NULL and bytes")

    def dryrun(self):
        environment = self.base_env | {
            "FG_CONTROL_URL": self.control_url, "FG_OWNER_TOKEN": self.owner_tokens[OWNER_A],
            "FG_DRYRUN_PROXY_DSN": self.dsn(OWNER_A, self.frontend_passwords[OWNER_A], self.proxy_port, "placeholder"),
            "FG_DRYRUN_PROXY_CA": str(self.certs / "frontend-ca.pem"),
        }
        times = {}
        for case, check, keep, okay in (("clean", "SELECT 1 = 1", False, True),
                                          ("keep", "SELECT 1", True, True),
                                          ("check-failure", "SELECT 0", False, False)):
            input_path = self.certs.parent / f"manifest-{case}.json"
            output = self.certs.parent / f"dryrun-{case}.json"
            p34.p2.json_file(input_path, {"changes": [insert(620, "artifact-row")], "checks": [check]})
            args = [self.executable("forkget"), "dryrun", "--engine", self.engine,
                    "--manifest", str(input_path), "--output", str(output)]
            if keep:
                args.append("--keep")
            started = time.monotonic()
            try:
                self.call(f"dryrun-{case}", args, env=environment, succeeds=okay, log=True, timeout=30)
            except RuntimeError:
                if output.exists():
                    (self.report / f"dryrun-{case}-artifact.json").write_text(output.read_text())
                raise
            times[case] = round((time.monotonic() - started) * 1000, 2)
            if not okay and output.exists():
                (self.report / f"dryrun-{case}-artifact.json").write_text(output.read_text())
            artifact = json.loads(output.read_text())
            require(output.stat().st_mode & 0o777 == 0o600, "Dry-run artifact is not private")
            require(artifact["cleanup"] == ("kept" if keep else "dropped"), f"Wrong dry-run cleanup: {artifact}")
            if okay:
                require(artifact["transaction"] == "committed" and artifact["rowdiff"] and artifact["policy_decisions"],
                        "Dry-run omitted a committed diff or policy decision")
            else:
                require(artifact["transaction"] == "rolled_back" and artifact["failure"]["phase"] == "check" and
                        artifact["rowdiff"] is None, "Failed dry-run check did not roll back")
            if keep:
                require(self.branch_status({"id": artifact["branch_id"]}) == "active" and artifact["expires_at"] > time.time(),
                        "Dry-run keep did not retain a finite-lived branch")
                self.drop(OWNER_A, artifact["branch_id"])
        p34.p2.json_file(self.report / "dryrun-timings.json", times)
        self.record("Dry-run normal commit and cleanup, --keep TTL, failed check rollback and private artifacts")
        self.dryrun_cleanup_recovery(environment)

    def dryrun_cleanup_recovery(self, environment):
        input_path = self.certs.parent / "manifest-interrupted.json"
        output = self.certs.parent / "dryrun-interrupted.json"
        p34.p2.json_file(input_path, {"changes": [insert(621, "interrupted-run")], "checks": ["SELECT 1"]})
        known = {branch["id"] for branch in self.cli(OWNER_A, "list")}
        process = self.start("dryrun-interrupted", "forkget",
                             ["dryrun", "--engine", self.engine, "--class", "agent",
                              "--manifest", str(input_path), "--output", str(output)], environment)
        branch = wait_until("temporary agent dry-run", lambda: next(
            (branch for branch in self.cli(OWNER_A, "list")
             if branch["id"] not in known and branch["class"] == "agent"), None))
        self.pending(branch, set())
        self.stop("proxy")
        require(process.wait(timeout=30) != 0, "Interrupted dry-run reported success")
        artifact = json.loads(output.read_text())
        require(artifact["branch_id"] == branch["id"] and artifact["cleanup"] == "dropping" and
                artifact["transaction"] != "committed" and artifact["rowdiff"] is None,
                "Interrupted dry-run lost its cleanup or transaction state")
        self.start_proxy()
        self.wait_dropped(OWNER_A, branch["id"])
        self.record("Dry-run preserves an interrupted cleanup ID and resumes after proxy restart")

    def execute(self):
        self.start_deployment()
        old, _, _ = self.refresh_to_v2()
        self.drop(OWNER_A, old["id"])
        self.defaults()
        branch, credentials = self.create("p5-budget")
        self.budget(credentials)
        if self.family == "mysql":
            mysql_review.run_cases(self, branch, p34.GENERATION_LOCK)
        elif self.family == "tidb":
            # The MySQL partial-revokes grant review has no TiDB analogue
            # TiDB writable grants are verified at activation.
            pass
        else:
            pg_review.run_cases(self, credentials)
        self.diff_expiry(branch)
        self.outage(credentials)
        self.drop(OWNER_A, branch["id"])
        self.set_policy("dev", 50_000)
        self.diffs()
        self.dryrun()
        branch, credentials = self.create("p5-approval", "agent")
        self.approval_conflicts(branch, credentials)
        self.approval_checks(branch, credentials)
        self.audit(branch)

    def diff_expiry(self, branch):
        path = f"/internal/v1/branches/{branch['id']}/diff"
        internal = self.secret["internal"]
        original_url = self.drain_url
        original_expiry = self.expires
        status, data = p34.p2.http("POST", original_url + path, internal,
                                   {"principal": OWNER_A, "expires_at": 1})
        require(status == 401 and json.loads(data)["code"] == "FG-1002",
                "Expired internal diff passed admission")
        snapshot = Event()

        class DelayReport(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                if self.path != path:
                    self.send_error(404)
                    return
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                status, body = p34.p2.http("POST", original_url + path, internal, request)
                if status == 200:
                    snapshot.set()
                    time.sleep(max(0, request["expires_at"] - time.time() + 0.05))
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.stop("control")
        with ThreadingHTTPServer(("127.0.0.1", 0), DelayReport) as relay:
            thread = Thread(target=relay.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
            thread.start()
            try:
                self.drain_url = f"http://127.0.0.1:{relay.server_address[1]}"
                self.expires = int(time.time()) + 5
                self.start_control()
                status, data = p34.p2.http("GET", self.control_url + f"/v1/branches/{branch['id']}/diff",
                                           self.owner_tokens[OWNER_A], timeout=9)
                require(snapshot.is_set() and status == 401 and json.loads(data)["code"] == "FG-1002",
                        "An admitted diff exposed rows after owner expiry")
            finally:
                self.stop("control")
                self.drain_url = original_url
                self.expires = original_expiry
                relay.shutdown()
                thread.join(timeout=5)
                self.start_control()
        self.record("Row difference checks owner expiry at snapshot admission and report delivery")

    def approval_conflicts(self, branch, credentials):
        branch_id = branch["id"]
        with Probe(self, "approval-conflict", credentials) as probe:
            check_count(probe, "UPDATE parents SET label='no-match' WHERE id=609", 0)
            path = f"/v1/branches/{branch_id}/audit?event_type=policy_decision"
            status, data = self.request("GET", path, self.owner_tokens[OWNER_A])
            require(status == 200, "Cannot correlate the approval test session")
            event = json.loads(data)["events"][-1]
            decision = event["payload"]
            source = json.loads(self.metadata(f"""
                SELECT jsonb_build_object('attempt_id',a.attempt_id,'principal',a.principal,
                    'session_id',a.session_id,'native_session_id',a.native_session_id,
                    'generation_id',a.generation_id,'replay_job_id',a.replay_job_id,
                    'mode',a.mode,'policy_version',a.policy_version,
                    'effective_revision',a.effective_revision)::text
                FROM audit_event e JOIN audit_attempt a ON a.attempt_id=e.payload->>'attempt_id'
                WHERE e.id={int(event['id'])} AND e.branch_id={int(branch_id)}
                    AND a.branch_id=e.branch_id AND e.event_type='policy_decision';
            """))
            require(source["principal"] == OWNER_A and source["session_id"] == decision["session_id"]
                    and source["attempt_id"] == decision["attempt_id"]
                    and source["generation_id"] == branch["generation_id"]
                    and source["policy_version"] == decision["policy_version"]
                    and source["effective_revision"] == decision["effective_revision"]
                    and source["native_session_id"] > 0 and source["mode"] == "sql_transaction",
                    "The synthetic approval lacks an actual matching native journal context")
            context = {key: source[key] for key in ("attempt_id", "principal", "session_id",
                "native_session_id", "generation_id", "replay_job_id", "mode")}
            request = {"principal": source["principal"], "session_id": source["session_id"],
                       "policy_version": source["policy_version"],
                       "effective_revision": source["effective_revision"], "rows": 1,
                       "operation": {"table_id": decision["table_id"], "kind": "insert"},
                       "verdict": "await_approval"}
            decision_path = f"/internal/v1/branches/{branch_id}/audit/decisions"
            attempts = []
            reservation_lock = Lock()

            def reserve():
                with reservation_lock:
                    # The real session's ordinary operation counter starts at
                    # one; these test-only attempts occupy distinct high u64s.
                    attempt = {**context, "attempt_id":
                               f"{context['session_id']}:{(1 << 64) - 1 - len(attempts)}"}
                    attempts.append(attempt)
                return self.request("POST", decision_path, self.secret["internal"],
                                    {"attempt": attempt, "decision": request})

            try:
                with ThreadPoolExecutor(max_workers=2) as pool:
                    first, second = sorted(pool.map(lambda _: reserve(), range(2)))
                require(first[0] == 200 and second[0] == 409 and json.loads(second[1])["code"] == "FG-5003",
                        "Concurrent invocation was misclassified")
                approval = {"id": json.loads(first[1])["approval_id"]}
                require(self.decide(branch, approval, OWNER_B) == 200 and reserve()[0] == 409,
                        "A live approved invocation did not reserve the slot")
                fg(probe.sql(insert(609, "conflicting-invocation")), "FG-5003")
                require(read_key(probe, 609) == [], "Conflicting approval left a native write")
                self.metadata(f"UPDATE policy_approval SET expires_at=clock_timestamp() WHERE id={approval['id']};")
                status, data = reserve()
                require(status == 200 and (new_id := json.loads(data)["approval_id"]) != approval["id"],
                        "Expired invocation still held the live slot")
                status, _ = self.request("POST", f"/internal/v1/branches/{branch_id}/approvals/{new_id}/invalidate",
                                         self.secret["internal"],
                                         {key: request[key] for key in ("principal", "session_id")})
                require(status == 204, "Could not release the test approval")
            finally:
                cleanup_errors = []
                for attempt in attempts:
                    status, raw = self.request("POST", f"/internal/v1/branches/{branch_id}/audit/outcome",
                        self.secret["internal"], {"attempt": attempt, "outcome": "rolled_back",
                                                  "armed_step": 0, "mongo": None})
                    ack = json.loads(raw) if status == 200 else {}
                    if (status != 200 or ack.get("attempt_id") != attempt["attempt_id"]
                            or ack.get("outcome") != "rolled_back" or ack.get("audit_event_id", 0) <= 0):
                        cleanup_errors.append(attempt["attempt_id"])
                require(not cleanup_errors, "Synthetic approval attempts did not close with durable rollback ACKs")
        self.record("Concurrent and approved invocation conflicts report FG-5003 and expire without writes")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("engine", nargs="?", choices=("mysql", "postgresql", "tidb", "all"), default="all")
    selected = parser.parse_args().engine
    engines = ("mysql", "postgresql", "tidb") if selected == "all" else (selected,)
    started = datetime.now(UTC)
    run_id = f"fgp5-{started:%H%M%S}-{os.getpid()}"
    root = Path(os.environ.get("FG_P5_REPORT_ROOT", ROOT / "test/reports")).resolve()
    report = root / f"{started:%Y%m%d}-p5-{started:%H%M%S}-{os.getpid()}"
    report.mkdir(parents=True)
    print(f"P5 report: {report}", flush=True)
    with ThreadPoolExecutor(max_workers=len(engines)) as workers:
        tasks = {engine: workers.submit(p34.run_engine, engine, report, run_id, EngineRun) for engine in engines}
        results = {engine: task.result() for engine, task in tasks.items()}
    passed = all(result["status"] == "passed" for result in results.values())
    status = "passed" if passed else "failed"
    p34.p2.json_file(report / "report.json", {"status": status, "engines": results,
        "started_at": started.isoformat(), "finished_at": datetime.now(UTC).isoformat()})
    revision, source_state = p34.p2.git_state()
    rust = subprocess.check_output(["rustc", "--version"], cwd=ROOT, text=True).strip()
    docker = subprocess.check_output(["docker", "--version"], cwd=ROOT, text=True).strip()
    p34.p2.json_file(report / "env.json", {"run_kind": "local", "source_revision": revision,
        "source_state": source_state, "host": platform.system(), "architecture": platform.machine(),
        "rust": rust, "docker": docker, "metadata_image": "postgres:16.14"})
    summary = ["# P5 local policy, approval and dry-run", "", f"Overall result: {status}.", ""]
    for engine, result in results.items():
        summary.append(f"- {engine}: {result['status']}, {len(result['checks'])} checks ({result['version']}).")
        summary.extend(f"  - {check}" for check in result["checks"])
        summary.extend(f"  - {error}" for error in result["errors"])
        timings = report / engine / "dryrun-timings.json"
        if timings.exists():
            summary.append(f"  - [Small snapshot timings]({engine}/dryrun-timings.json)")
    (report / "summary.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
