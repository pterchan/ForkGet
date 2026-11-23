#!/usr/bin/env python3
"""Exercise durable SQL audit attempts and real transaction boundaries over TLS."""

import argparse
from collections import Counter
from contextlib import contextmanager
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import select
import ssl
import struct
import subprocess
import sys
import time
from threading import Event
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/p6"))
import run as p6
from faults import CommandFrames, CommitReply, ControlRelay, mutation_kind
from faults import read_exact as read_exact
from run_p2 import OWNER_A, json_file, require, wait_until
from write_cases import Probe, check_count, generated_one
import mysql_review
import pg_review


class OutcomeRelay(ControlRelay):
    def __init__(self, run):
        self.blocked = Event()
        self.status_blocked = Event()
        self.lease_blocked = Event()
        self.drop_next = Event()
        self.dropped = Event()
        self.acks = []
        self.requests = []
        self.status_acks = []
        self.calls = []
        self.after_decision = None
        super().__init__(SimpleNamespace(control_url=run.control_url), self.fault)

    def fault(self, _method, path, status, body):
        if path.endswith("/audit/decisions") and status == 200 and self.after_decision is not None:
            action, self.after_decision = self.after_decision, None
            action()
        if path.endswith("/audit/status") and status == 200:
            self.status_acks.append(json.loads(body))
        if path.endswith("/audit/outcome") and status == 200:
            self.acks.append(json.loads(body))
            if self.drop_next.is_set():
                self.drop_next.clear()
                self.dropped.set()
                return True
        return False

    def forward(self, handler):
        if ((self.blocked.is_set() and handler.path.endswith("/audit/outcome"))
                or (self.status_blocked.is_set() and handler.path.endswith("/audit/status"))
                or (self.lease_blocked.is_set() and handler.path.endswith("/lease"))):
            self.request_body(handler)
            handler.send_response(503)
            handler.send_header("Content-Length", "0")
            handler.end_headers()
            return
        super().forward(handler)

    def request_body(self, handler):
        body = super().request_body(handler)
        self.calls.append(handler.path.split("?", 1)[0])
        if handler.path.endswith(("/audit/outcome", "/audit/status")):
            request = json.loads(body)
            self.requests.append({"path": handler.path, "attempt_id": request["attempt"]["attempt_id"],
                                  "outcome": request.get("outcome")})
        return body


class SqlFrameBuffer:
    def __init__(self, is_postgres):
        self.is_postgres = is_postgres
        self.data = bytearray()
        self.wants_write = False

    def receive(self, stream, is_startup):
        header_size = 5 if self.is_postgres and not is_startup else 4
        needed = header_size if len(self.data) < header_size else self.frame_size(is_startup)
        data = self.read_tls(stream, min(needed - len(self.data), 65536))
        if not data:
            return data
        self.data.extend(data)
        if len(self.data) < header_size or len(self.data) < self.frame_size(is_startup):
            return None
        frame = bytes(self.data)
        self.data.clear()
        return frame

    def frame_size(self, is_startup):
        if not self.is_postgres:
            return 4 + int.from_bytes(self.data[:3], "little")
        header_offset = 0 if is_startup else 1
        size = int.from_bytes(self.data[header_offset:header_offset + 4], "big")
        require(size >= 4, "Invalid PostgreSQL relay frame length")
        return header_offset + size

    def read_tls(self, stream, size):
        timeout = stream.gettimeout()
        try:
            # TLS control records can make select readable without application
            # bytes. A read on this leg must not block the opposite leg.
            stream.settimeout(0)
            data = stream.recv(size)
        except ssl.SSLWantReadError:
            self.wants_write = False
            return None
        except ssl.SSLWantWriteError:
            self.wants_write = True
            return None
        finally:
            stream.settimeout(timeout)
        self.wants_write = False
        return data


class NativeRelay(CommitReply):
    """Forward original complete frames; pause/drop only at real boundaries."""
    def __init__(self, run, mode):
        super().__init__(run, native=True)
        self.mode = mode
        self.witness = Event()
        self.cancel_seen = Event()
        self.release = Event()
        self.private_frames = []
        self.business_mutations = 0
        self.prepared_executions = 0
        self.witness_syncs = 0

    def forward(self, client, server):
        is_postgres = self.run.family == "postgresql"
        startup = is_postgres
        buffers = {stream: SqlFrameBuffer(is_postgres) for stream in (client, server)}
        commands = CommandFrames(self.run.family)
        withholding = private = witness_before_sync = False
        try:
            while not self.done.is_set():
                if withholding and self.drop_reply.is_set():
                    return
                readable = [stream for stream, buffer in buffers.items()
                            if not buffer.wants_write and stream.pending()]
                if not readable:
                    readable, writable, _ = select.select(
                        [stream for stream, buffer in buffers.items() if not buffer.wants_write],
                        [stream for stream, buffer in buffers.items() if buffer.wants_write], [], .05)
                    readable += writable
                for source in readable:
                    is_startup = source is client and startup
                    frame = buffers[source].receive(source, is_startup)
                    if frame is None:
                        continue
                    if not frame:
                        return
                    if is_startup:
                        startup = False
                        commands.scan(frame)
                        server.sendall(frame)
                        if frame[4:8] == struct.pack("!I", 80877102):
                            self.cancel_seen.set()
                            require(server.recv(1) == b"", "Native CancelRequest returned data")
                            return
                        continue
                    if is_postgres:
                        sql = None
                        if source is client and frame[0] == ord("Q"):
                            sql = frame[5:-1]
                        if source is client and frame[0] == ord("P"):
                            sql = frame[5:].split(b"\0", 2)[1]
                    else:
                        sql = frame[5:] if source is client and len(frame) > 4 and frame[3:5] == b"\0\x03" else None
                    if source is client:
                        if self.run.family != "postgresql" and frame[3:5] == b"\0\x17":
                            with self.lock:
                                self.prepared_executions += 1
                        commits, business, witnesses = commands.scan(frame)
                        if self.run.family == "postgresql":
                            if witnesses:
                                witness_before_sync = True
                            if commits or sql == b"ROLLBACK":
                                witness_before_sync = False
                            if frame[0] == ord("S") and witness_before_sync:
                                with self.lock:
                                    self.witness_syncs += 1
                                witness_before_sync = False
                        with self.lock:
                            self.commits += commits
                            self.mutations += business
                            self.business_mutations += business
                            self.witness_mutations += witnesses
                        if mutation_kind(sql, self.run.family) == "witness":
                            private = True
                            self.witness.set()
                            if self.mode == "pause-witness":
                                require(self.release.wait(10), "Witness pause was not released")
                        if private:
                            with self.lock:
                                self.private_frames.append(chr(frame[0]) if self.run.family == "postgresql" else "QUERY")
                            if self.run.family == "postgresql" and frame[0] == ord("H"):
                                private = False
                        if commits:
                            self.commit.set()
                            if self.mode == "pause-before-commit":
                                require(self.release.wait(30), "Pre-COMMIT cut was not released")
                                return
                            if self.mode == "before-commit":
                                return
                            withholding = self.mode == "after-commit"
                        server.sendall(frame)
                    elif withholding:
                        self.withheld.set()
                    else:
                        client.sendall(frame)
        except OSError:
            # Expected connection closure is the injected fault or normal QUIT.
            return
        except (ValueError, p6.p5.p34.p2.Failure) as error:
            self.errors.append(type(error).__name__)


class AuditRun(p6.p5.EngineRun):
    def __init__(self, *args):
        super().__init__(*args)
        self.bin_dir = self.bin_dir.parent / "release"

    def start_proxy(self):
        if not hasattr(self, "outcomes"):
            self.outcomes = OutcomeRelay(self)
            self.outcomes.__enter__()
        original = self.control_url
        self.control_url = self.outcomes.url
        try:
            super().start_proxy()
        finally:
            self.control_url = original

    def cleanup(self):
        before_cleanup = list(self.outcomes.errors) if hasattr(self, "outcomes") else []
        try:
            if hasattr(self, "outcomes"):
                self.outcomes.blocked.clear()
                self.outcomes.status_blocked.clear()
                self.outcomes.lease_blocked.clear()
            # Keep the controller and relay available until the proxy's audit
            # delivery worker and native sessions have finished shutting down.
            self.stop("proxy")
            super().cleanup()
        finally:
            if hasattr(self, "outcomes"):
                try:
                    self.outcomes.__exit__(None, None, None)
                finally:
                    json_file(self.report / "control-relay.json", {
                        "errors_before_cleanup": before_cleanup, "errors": self.outcomes.errors,
                        "requests": self.outcomes.requests, "acks": self.outcomes.acks,
                        "status_acks": self.outcomes.status_acks, "shutdown_order": "proxy_then_controller"})

    def dump_native_state(self):
        super().dump_native_state()
        evidence = {"scope": "only this fixture's internal witness relations", "engine": self.engine, "witnesses": []}
        try:
            ids = self.metadata("SELECT b.id FROM branch b JOIN generation g ON g.id=b.generation_id "
                                f"WHERE g.engine='{self.engine}' AND b.layout='native_copy' ORDER BY b.id;")
            for value in ids.splitlines():
                branch = int(value)
                schema, prefix = self.branch_namespace(branch)
                table = prefix + "_fg_txn_witness"
                if self.family == "postgresql":
                    checks = self.native("SELECT COALESCE(jsonb_agg(jsonb_build_object('name',tc.constraint_name,"
                        "'type',tc.constraint_type,'clause',cc.check_clause)),'[]'::jsonb)::text "
                        "FROM information_schema.table_constraints tc LEFT JOIN information_schema.check_constraints cc "
                        "ON cc.constraint_schema=tc.constraint_schema AND cc.constraint_name=tc.constraint_name "
                        f"WHERE tc.table_schema='{schema}' AND tc.table_name='{table}';")
                    columns = self.native("SELECT COALESCE(jsonb_agg(jsonb_build_object('ordinal',ordinal_position,"
                        "'name',column_name,'type',data_type,'udt',udt_name,'length',character_maximum_length,"
                        "'nullable',is_nullable,'default',column_default) ORDER BY ordinal_position),'[]'::jsonb)::text "
                        f"FROM information_schema.columns WHERE table_schema='{schema}' AND table_name='{table}';")
                else:
                    checks = self.native("SELECT COALESCE(JSON_ARRAYAGG(JSON_OBJECT('name',tc.CONSTRAINT_NAME,"
                        "'type',tc.CONSTRAINT_TYPE,'clause',cc.CHECK_CLAUSE)),JSON_ARRAY()) "
                        "FROM information_schema.TABLE_CONSTRAINTS tc LEFT JOIN information_schema.CHECK_CONSTRAINTS cc "
                        "ON cc.CONSTRAINT_SCHEMA=tc.CONSTRAINT_SCHEMA AND cc.CONSTRAINT_NAME=tc.CONSTRAINT_NAME "
                        f"WHERE tc.TABLE_SCHEMA='{schema}' AND tc.TABLE_NAME='{table}';")
                    columns = self.native("SELECT COALESCE(JSON_ARRAYAGG(JSON_OBJECT('ordinal',ORDINAL_POSITION,"
                        "'name',COLUMN_NAME,'type',COLUMN_TYPE,'nullable',IS_NULLABLE,'default',COLUMN_DEFAULT,"
                        "'extra',EXTRA,'charset',CHARACTER_SET_NAME,'collation',COLLATION_NAME)),JSON_ARRAY()) "
                        f"FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='{schema}' AND TABLE_NAME='{table}';")
                witness = {"branch_id": branch, "checks": json.loads(checks), "columns": json.loads(columns)}
                if self.family != "postgresql":
                    witness["show_create_table"] = self.native(f"SHOW CREATE TABLE {self.branch_relation(branch, '_fg_txn_witness')};")
                    definition = self.native("SHOW COLUMNS FROM information_schema.CHECK_CONSTRAINTS;")
                    witness["check_catalog_columns"] = definition.splitlines()
                    has_table = any(row.split("\t", 1)[0].upper() == "TABLE_NAME" for row in definition.splitlines())
                    predicate = f"CONSTRAINT_SCHEMA='{schema}'" + (f" AND TABLE_NAME='{table}'" if has_table else "")
                    table_field = ",'table',TABLE_NAME" if has_table else ""
                    direct = self.native("SELECT COALESCE(JSON_ARRAYAGG(JSON_OBJECT('name',CONSTRAINT_NAME,"
                        f"'schema',CONSTRAINT_SCHEMA,'clause',CHECK_CLAUSE{table_field})),JSON_ARRAY()) "
                        f"FROM information_schema.CHECK_CONSTRAINTS WHERE {predicate};")
                    witness["direct_check_catalog_rows"] = json.loads(direct)
                    witness["check_catalog_scope"] = "owned_witness_table" if has_table else "owned_fixture_schema_without_user_source"
                    witness["check_clause_hex"] = json.loads(self.native(
                        "SELECT COALESCE(JSON_ARRAYAGG(JSON_OBJECT('name',tc.CONSTRAINT_NAME,'hex',HEX(cc.CHECK_CLAUSE))),JSON_ARRAY()) "
                        "FROM information_schema.TABLE_CONSTRAINTS tc JOIN information_schema.CHECK_CONSTRAINTS cc "
                        "ON cc.CONSTRAINT_SCHEMA=tc.CONSTRAINT_SCHEMA AND cc.CONSTRAINT_NAME=tc.CONSTRAINT_NAME "
                        f"WHERE tc.TABLE_SCHEMA='{schema}' AND tc.TABLE_NAME='{table}' AND tc.CONSTRAINT_TYPE='CHECK';"))
                evidence["witnesses"].append(witness)
        except Exception as error:
            evidence["diagnostic_error"] = type(error).__name__
        json_file(self.report / "native-check-clauses.json", evidence)

    def journal(self, branch):
        value = self.metadata(f"""SELECT COALESCE(jsonb_agg(jsonb_build_object(
            'id',a.attempt_id,'outcome',a.outcome,'resolution',a.resolution,
            'sealed',a.sealed,'witness_collected',a.witness_collected,
            'native_session_id',a.native_session_id,'session_id',a.session_id,
            'decisions',(SELECT count(*) FROM audit_event e WHERE e.event_type='policy_decision'
                AND e.payload->>'attempt_id'=a.attempt_id),
            'outcomes',(SELECT count(*) FROM audit_event e WHERE e.event_type='policy_outcome'
                AND e.payload->>'attempt_id'=a.attempt_id),
            'resolutions',(SELECT count(*) FROM audit_event e WHERE e.event_type='policy_outcome_resolved'
                AND e.payload->>'attempt_id'=a.attempt_id)
            ) ORDER BY a.created_at,a.attempt_id),'[]'::jsonb)::text
            FROM audit_attempt a WHERE a.branch_id={int(branch['id'])};""")
        return json.loads(value)

    def settled(self, branch, expected):
        def complete():
            rows = self.journal(branch)
            return rows if len(rows) == expected and all(row["outcome"] is not None and (
                row["outcome"] != "unknown" or row["resolution"] is not None) for row in rows) else None
        rows = wait_until("durable audit recovery", complete, seconds=45)
        require(all(row["outcomes"] == 1 for row in rows), "Audit delivery duplicated or omitted an outcome")
        require(all(row["decisions"] > 0 for row in rows), "An audit attempt has no decision")
        return rows

    def native_count(self, branch, key):
        return int(self.native(f"SELECT count(*) FROM {self.branch_relation(branch['id'], 'parents')} WHERE id={key};"))

    def witness_count(self, branch):
        return int(self.native(f"SELECT count(*) FROM {self.branch_relation(branch['id'], '_fg_txn_witness')} WHERE attempt_id<>'';"))

    def runtime_identity(self):
        processes = {name: self.processes[name] for name in ("proxy", "control")}
        require(all(process.poll() is None for process in processes.values()), "An audit runtime process exited")
        return {"epoch": self.metadata("SELECT epoch FROM policy_proxy_epoch;"),
                **{name + "_pid": process.pid for name, process in processes.items()}}

    def native_alive(self, native_id):
        view, column = (("pg_stat_activity", "pid") if self.family == "postgresql"
                        else ("information_schema.PROCESSLIST", "ID"))
        return int(self.native(f"SELECT count(*) FROM {view} WHERE {column}={int(native_id)};"))

    def proxy_audit_health(self):
        status, raw = p6.p5.p34.p2.http("GET", self.drain_url + "/internal/v1/audit-health", self.secret["internal"])
        require(status == 200, "The proxy audit delivery health endpoint is unavailable")
        return json.loads(raw)

    def audit_reconcile(self, label):
        account = "postgres" if self.family == "postgresql" else "root"
        env = self.base_env | {
            "FG_META_DSN": self.dsn("postgres", self.secret["meta"], self.metadata_port, "forkget_meta", "postgresql"),
            "FG_META_CA": str(self.certs / "backend-ca.pem"), "FG_BACKEND_CA": str(self.certs / "backend-ca.pem"),
            "FG_BACKEND_GC_DSN": self.dsn("p2_gc", self.secret["collector"], self.native_port, self.backend_database),
            "FG_BACKEND_ADMIN_DSN": self.dsn(account, self.secret["native"], self.native_port, self.backend_database),
            "FG_PROXY_CONTROL_URL": self.drain_url, "FG_INTERNAL_TOKEN": self.secret["internal"],
        }
        return json.loads(self.call(label, [self.executable("fg-control"), "audit", "reconcile"],
                                    env=env, log=True, timeout=30))

    @contextmanager
    def pg_witness_ddl_lock(self, branch):
        relation = self.branch_relation(branch["id"], "_fg_txn_witness")
        command = self.compose_command + ["exec", "-T", "native", "sh", "-c", self.psql_command(),
                                          "sh", self.backend_database]
        process = subprocess.Popen(command, cwd=ROOT, env=self.compose_env, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        self.processes["audit-ddl-lock"] = process
        try:
            process.stdin.write(f"BEGIN;\nLOCK TABLE {relation} IN ACCESS EXCLUSIVE MODE;\nSELECT pg_backend_pid();\n")
            process.stdin.flush()
            require(select.select([process.stdout], [], [], 8)[0], "External witness DDL lock did not become ready")
            pid = int(process.stdout.readline().strip())
            require(self.native(f"SELECT count(*) FROM pg_locks WHERE pid={pid} "
                                f"AND relation='{relation}'::regclass AND mode='AccessExclusiveLock' AND granted;") == "1",
                    "The external admin did not hold the exact witness DDL lock")
            yield pid
        finally:
            if process.poll() is None:
                try:
                    process.stdin.write("ROLLBACK;\n\\q\n")
                    process.stdin.flush()
                    process.stdin.close()
                    process.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    process.kill()
                    process.wait(timeout=5)
            self.processes.pop("audit-ddl-lock", None)
            errors = process.stderr.read()
            if errors:
                (self.report / "audit-ddl-lock.log").write_text(self.safe(errors))

    @contextmanager
    def native_relay(self, mode):
        self.stop("proxy")
        native_port = self.native_port
        try:
            with NativeRelay(self, mode) as relay:
                try:
                    self.native_port = relay.port
                    self.start_proxy()
                    self.native_port = native_port
                    yield relay
                finally:
                    self.native_port = native_port
                    self.stop("proxy")
        finally:
            self.native_port = native_port
            self.start_proxy()

    @contextmanager
    def wire(self, branch):
        if self.family == "postgresql":
            with pg_review.session(self, (OWNER_A, branch["name"])) as client:
                yield client
        else:
            with mysql_review.Client(self, branch) as client:
                yield client

    def count(self, client, sql, expected=0):
        if self.family == "postgresql":
            result = client.query(sql.encode(), b"I" if sql in ("COMMIT", "ROLLBACK") else b"T")
            require(b"C" in result, "PostgreSQL command did not complete")
        else:
            client.count(sql, expected)

    @staticmethod
    def insert(key):
        return f"INSERT INTO parents (id,tenant_id,code) VALUES ({key},8,'audit-{key}')"

    def legacy_protocol(self, branch):
        binding = self.binding(OWNER_A, branch)
        table = next(table for table in binding["tables"] if table["logical_table"] == "parents")
        status, body = self.request("GET", f"/v1/branches/{branch['id']}/policy", self.owner_tokens[OWNER_A])
        require(status == 200, "Could not construct a valid legacy policy DTO")
        policy = json.loads(body)
        session = self.metadata("SELECT epoch FROM policy_proxy_epoch;") + ":999"
        before = self.metadata(f"SELECT count(*) FROM audit_event WHERE branch_id={branch['id']};")
        decision = {"principal": OWNER_A, "session_id": session, "policy_version": policy["version"],
                    "effective_revision": policy["effective_revision"],
                    "operation": {"table_id": table["id"], "kind": "insert"}, "rows": 1, "verdict": "allowed"}
        outcome = {"principal": OWNER_A, "session_id": session, "outcome": "committed"}
        observed = []
        for route, request in (("decisions", decision), ("outcome", outcome)):
            status, body = self.request("POST", f"/internal/v1/branches/{branch['id']}/{route}",
                                        self.secret["internal"], request)
            error = json.loads(body)
            require(status == 409 and error.get("code") == "FG-2003"
                    and error.get("reason") == "internal_protocol_mismatch",
                    "An attemptless old protocol request was admitted by a protocol-3 controller")
            observed.append({"route": route, "status": status, "code": error["code"], "reason": error["reason"]})
        require(self.journal(branch) == [] and before == self.metadata(
            f"SELECT count(*) FROM audit_event WHERE branch_id={branch['id']};"),
            "A rejected legacy request created an intent or audit event")
        json_file(self.report / "legacy-protocol-refusals.json", observed)
        self.record("valid attemptless legacy decision/outcome requests fail closed without an intent or audit event")

    def boundaries(self, branch, credentials):
        with Probe(self, "audit-empty", credentials) as probe:
            check_count(probe, "BEGIN", 0)
            require(probe.sql("SELECT id FROM parents WHERE id=100", "read").get("rows") == [[100]], "Read-only transaction failed")
            check_count(probe, "ROLLBACK", 0)
        require(self.journal(branch) == [], "Pure reads or an empty transaction created an audit attempt")
        with self.wire(branch) as client:
            for sql, count in (("BEGIN", 0), ("SAVEPOINT before_write", 0), (self.insert(740), 1),
                               ("ROLLBACK TO SAVEPOINT before_write", 0), (self.insert(741), 1), ("COMMIT", 0)):
                self.count(client, sql, count)
        require(self.native_count(branch, 740) == 0 and self.native_count(branch, 741) == 1,
                "Savepoint rollback or outer commit changed business facts")
        rows = self.settled(branch, 1)
        require(rows[0]["decisions"] == 2 and rows[0]["outcome"] == "committed", "Savepoint split the native attempt or outcome")
        if self.family != "postgresql":
            with self.wire(branch) as client:
                for sql, count in (("BEGIN", 0), (self.insert(742), 1), ("BEGIN", 0),
                                   (self.insert(743), 1), ("ROLLBACK", 0),
                                   ("SET AUTOCOMMIT=0", 0), (self.insert(744), 1), ("SET AUTOCOMMIT=1", 0)):
                    self.count(client, sql, count)
            require([self.native_count(branch, key) for key in (742, 743, 744)] == [1, 0, 1], "An implicit MySQL commit was omitted or replayed")
            self.settled(branch, 4)
        self.record("one attempt spans savepoints; empty/read-only transactions create none; real implicit boundaries are audited")

    def generated(self, branch, credentials):
        before = len(self.journal(branch))
        with Probe(self, "audit-generated", credentials) as probe:
            first = generated_one(probe, self.family != "postgresql", "audit-generated-one")
            if self.family != "postgresql":
                require(probe.sql("SELECT LAST_INSERT_ID()", "read").get("rows") == [[first]], "Witness changed LAST_INSERT_ID()")
            second = generated_one(probe, self.family != "postgresql", "audit-generated-two")
        require(second > first, "Witness changed the generated ID allocator")
        require(self.native_count(branch, first) == self.native_count(branch, second) == 1, "Generated business result is not durable")
        self.settled(branch, before + 2)
        self.record("witness results preserve prepared generated IDs, RETURNING, LAST_INSERT_ID and next allocation")

    def native_error_recovery(self, branch, credentials):
        before = len(self.journal(branch))
        with Probe(self, "audit-native-statement-error", credentials) as probe:
            check_count(probe, "BEGIN", 0)
            check_count(probe, self.insert(746), 1)
            if self.family == "postgresql":
                check_count(probe, "SAVEPOINT recover_native", 0)
            rejected = probe.sql(self.insert(746))
            require(rejected.get("fg") is not None, "Native unique-key error was not preserved")
            if self.family == "postgresql":
                check_count(probe, "ROLLBACK TO SAVEPOINT recover_native", 0)
            check_count(probe, self.insert(747), 1)
            check_count(probe, "COMMIT", 0)
        rows = self.settled(branch, before + 1)
        require(rows[-1]["decisions"] == 3 and rows[-1]["outcome"] == "committed"
                and self.native_count(branch, 746) == self.native_count(branch, 747) == 1,
                "A native-error observation replaced prior valid transaction admission")
        self.record("native statement errors remain audited and preserve valid MySQL/PG-savepoint transaction commit")
        if self.family == "postgresql":
            with self.wire(branch) as client:
                client.query(b"BEGIN", b"T")
                client.query(self.insert(748).encode(), b"T")
                failed = client.raw.pg_query(client.socket, self.insert(748).encode())
                errors = [body for tag, body in failed if tag == b"E"]
                require(len(errors) == 1 and failed[-1] == (b"Z", b"E"), "Native duplicate did not abort the PostgreSQL transaction")
                client.raw.pg_error(errors[0], b"23505", b"FG-3001")
                messages = client.raw.pg_query(client.socket, b"COMMIT")
                require(messages == [(b"C", b"ROLLBACK\0"), (b"Z", b"I")],
                        "COMMIT in an aborted transaction inserted a witness or hid the native ROLLBACK")
            rows = self.settled(branch, before + 2)
            require(rows[-1]["outcome"] == "rolled_back" and self.native_count(branch, 748) == 0,
                    "An aborted COMMIT was audited as committed")
            self.record("PostgreSQL COMMIT in an aborted transaction returns native ROLLBACK and records truthful rollback without a witness")

    @staticmethod
    def order_insert(key, note="rpc-text"):
        return f"INSERT INTO orders (tenant_id,id,customer_id,note) VALUES (8,{key},10,'{note}')"

    def order_count(self, branch, key):
        return int(self.native(f"SELECT count(*) FROM {self.branch_relation(branch['id'], 'orders')} WHERE tenant_id=8 AND id={key};"))

    def auto_query(self, client, statement):
        if self.family == "postgresql":
            require(b"C" in client.query(statement.encode(), b"I"), "Autocommit Query did not complete")
        else:
            client.count(statement, 1)

    def autocommit_requests(self, branch, credentials):
        results = []
        for protocol, first in (("text", 820), ("extended" if self.family == "postgresql" else "prepared", 830)):
            before = len(self.journal(branch))
            with self.native_relay("observe") as relay:
                with self.wire(branch) as client:
                    self.auto_query(client, self.order_insert(first - 1, "rpc-warmup"))
                    if protocol == "prepared":
                        handle = client.prepare("INSERT INTO orders (tenant_id,id,customer_id,note) VALUES (8,?,10,'rpc-prepared')")
                    elif protocol == "extended":
                        client.parse(b"rpc_statement", b"INSERT INTO orders (tenant_id,id,customer_id,note) VALUES (8,$1,10,'rpc-extended')")
                    start = len(self.outcomes.calls)
                    counters = (relay.business_mutations, relay.prepared_executions, relay.witness_mutations,
                                relay.commits, relay.witness_syncs)
                    for key in range(first, first + 3):
                        if protocol == "prepared":
                            require(client.execute(handle, key)[:2] == b"\0\1", "Prepared autocommit changed its native affected count")
                        elif protocol == "extended":
                            body = (b"rpc_portal\0rpc_statement\0" + struct.pack("!HHH", 1, 1, 1)
                                    + struct.pack("!IqH", 8, key, 0))
                            client.send(b"B", body)
                            client.expect(b"2", b"")
                            client.execute(b"rpc_portal")
                            client.send(b"H")
                            require(self.order_count(branch, key) == 0, "Extended Execute/Flush committed before Sync")
                            client.sync()
                        else:
                            self.auto_query(client, self.order_insert(key))
                    calls = self.outcomes.calls[start:]
                    expected = [f"/internal/v1/branches/{branch['id']}/{suffix}"
                                for suffix in ("audit/decisions", "write-fence", "audit/outcome")] * 3
                    require(calls == expected, "Normal warmed autocommit did not use exactly decision/fence/outcome per transaction")
                rows = self.settled(branch, before + 4)
                require(all(row["outcome"] == "committed" and row["decisions"] == row["outcomes"] == 1 for row in rows[-3:]),
                        "Normal prepared/text/extended commits lost a unique durable attempt")
                business = relay.prepared_executions - counters[1] if protocol == "prepared" else relay.business_mutations - counters[0]
                native_commits = relay.commits - counters[3]
                native_syncs = relay.witness_syncs - counters[4]
                business_rows = [self.order_count(branch, key) for key in range(first, first + 3)]
                results.append({"protocol": protocol, "transactions": 3, "control_requests": len(calls),
                                "native_business_executions": business,
                                "witnesses": relay.witness_mutations - counters[2],
                                "native_commit_commands": native_commits, "native_witness_syncs": native_syncs,
                                "native_business_rows": business_rows,
                                "journal_outcomes": [row["outcome"] for row in rows[-3:]],
                                "unique_decisions_and_outcomes": True})
                json_file(self.report / "autocommit-three-requests.json", results)
                require(business == relay.witness_mutations - counters[2] == 3
                        and native_commits == (0 if protocol == "extended" else 3)
                        and native_syncs == (3 if protocol == "extended" else 0)
                        and business_rows == [1, 1, 1],
                        "Normal autocommit resent native work, omitted witnesses, or changed native business facts")
            with Probe(self, "rpc-typed-" + protocol, credentials) as observer:
                note = "rpc-text" if protocol == "text" else "rpc-" + protocol
                require(observer.sql(f"SELECT tenant_id,id,note FROM orders WHERE tenant_id=8 AND id>={first} AND id<{first + 3} ORDER BY id", "read").get("rows")
                        == [[8, key, note] for key in range(first, first + 3)], "Autocommit protocol changed the typed frontend business result")
        json_file(self.report / "autocommit-three-requests.json", results)
        self.record("text and prepared/extended autocommit use exactly three RPCs with unique audits, native commits, witnesses and typed results")

    def refused_fence(self, branch):
        before = len(self.journal(branch))
        with self.native_relay("observe") as relay:
            with self.wire(branch) as client:
                self.auto_query(client, self.order_insert(839, "fence-warmup"))
                start = len(self.outcomes.calls)
                self.outcomes.after_decision = lambda: self.set_policy("dev", 50000, bps=10000, floor=100)
                try:
                    statement = self.order_insert(840, "must-roll-back")
                    if self.family == "postgresql":
                        response = client.raw.pg_query(client.socket, statement.encode())
                        errors = [body for tag, body in response if tag == b"E"]
                        require(len(errors) == 1 and response[-1] == (b"Z", b"I"), "A refused final fence lost PostgreSQL rollback framing")
                        client.raw.pg_error(errors[0], b"42501", b"FG-5001")
                        client.query(b"SELECT 1")
                    else:
                        response = client.query(statement)
                        json_file(self.report / "refused-final-fence-wire.json", {
                            "error_packet": response[:1] == b"\xff",
                            "errno": int.from_bytes(response[1:3], "little"),
                            "sqlstate": response[4:9].decode("ascii", errors="replace"),
                            "expected_forkget_code": "FG-5001", "contains_expected_code": b"FG-5001" in response})
                        client.raw.mysql_error(response, 1142, b"42000", b"FG-5001")
                    require(self.outcomes.after_decision is None, "The real post-decision policy revision cut did not run")
                finally:
                    self.outcomes.after_decision = None
                calls = self.outcomes.calls[start:]
                require(Counter(path.rsplit("/", 1)[-1] for path in calls) == Counter({"decisions": 1, "write-fence": 1, "outcome": 1}),
                        "A refused final fence retried admission or used a stale auxiliary authorization path")
            rows = self.settled(branch, before + 2)
            refused = rows[-1]
            relation = self.branch_relation(branch["id"], "_fg_txn_witness")
            require(refused["outcome"] == "rolled_back" and refused["decisions"] == refused["outcomes"] == 1
                    and self.order_count(branch, 840) == 0
                    and self.native(f"SELECT count(*) FROM {relation} WHERE attempt_id='{refused['id']}';") == "0",
                    "A post-decision authority change committed business data or a witness")
            json_file(self.report / "refused-final-fence.json", {"policy_changed_after_real_decision": True,
                "control_requests": len(calls), "business_rows": 0, "durable_witness_rows": 0,
                "unique_rolled_back_outcome": True, "native_commits_including_warmup": relay.commits})
        self.record("a real policy change after durable decision refuses the single final fence and rolls back native business/witness state")

    def error_only_commit_lease(self, branch):
        evidence = []
        for outage in (False, True):
            before = len(self.journal(branch))
            original = self.native(f"SELECT * FROM {self.branch_relation(branch['id'], 'parents')} WHERE id=100;")
            with self.native_relay("observe") as relay:
                with self.wire(branch) as client:
                    self.auto_query(client, self.order_insert(850 + int(outage), "error-only-warmup"))
                    counters = (relay.witness_mutations, relay.commits)
                    start = len(self.outcomes.calls)
                    self.count(client, "BEGIN")
                    if self.family == "postgresql":
                        client.query(b"SAVEPOINT before_error", b"T")
                        response = client.raw.pg_query(client.socket, self.insert(100).encode())
                        errors = [body for tag, body in response if tag == b"E"]
                        require(len(errors) == 1 and response[-1] == (b"Z", b"E"), "The error-only PostgreSQL transaction did not fail natively")
                        client.raw.pg_error(errors[0], b"23505", b"FG-3001")
                        client.query(b"ROLLBACK TO SAVEPOINT before_error", b"T")
                    else:
                        client.raw.mysql_error(client.query(self.insert(100)), 1062, b"23000", b"FG-3001")
                    if outage:
                        self.outcomes.lease_blocked.set()
                    try:
                        if not outage:
                            self.count(client, "COMMIT")
                        elif self.family == "postgresql":
                            response = client.raw.pg_query(client.socket, b"COMMIT")
                            errors = [body for tag, body in response if tag == b"E"]
                            require(len(errors) == 1 and b"FG-1004" in errors[0] and response[-1] == (b"Z", b"E"),
                                    "The error-only PostgreSQL COMMIT skipped its unavailable observer lease")
                        else:
                            response = client.query("COMMIT")
                            require(response[:1] == b"\xff" and b"FG-1004" in response,
                                    "The error-only MySQL COMMIT skipped its unavailable observer lease")
                    finally:
                        self.outcomes.lease_blocked.clear()
                    if outage and self.family == "postgresql":
                        client.query(b"ROLLBACK")
                    calls = self.outcomes.calls[start:]
                    require(Counter(path.rsplit("/", 1)[-1] for path in calls) == Counter({"decisions": 1, "lease": 1, "outcome": 1}),
                            "Error-only commit fabricated a successful admission or omitted its fresh observer lease")
                rows = self.settled(branch, before + 2)
                attempt = rows[-1]
                expected = "rolled_back" if outage else "committed"
                require(attempt["outcome"] == expected and attempt["decisions"] == attempt["outcomes"] == 1
                        and relay.witness_mutations - counters[0] == 1 and relay.commits - counters[1] == int(not outage)
                        and original == self.native(f"SELECT * FROM {self.branch_relation(branch['id'], 'parents')} WHERE id=100;")
                        and self.metadata("SELECT payload->>'verdict' FROM audit_event WHERE event_type='policy_decision' "
                                          f"AND payload->>'attempt_id'='{attempt['id']}';") == "native_error",
                        "Error-only observer semantics changed native business facts or fabricated a writer admission")
                if outage:
                    require(self.native(f"SELECT count(*) FROM {self.branch_relation(branch['id'], '_fg_txn_witness')} WHERE attempt_id='{attempt['id']}';") == "0",
                            "An unavailable observer lease committed its diagnostic witness")
                evidence.append({"lease_unavailable": outage, "outcome": expected, "fresh_observer_lease_requests": 1,
                                 "writer_fence_requests": 0, "native_commits": relay.commits - counters[1],
                                 "witness_inserts": 1, "business_unchanged": True, "decision_verdict": "native_error"})
        json_file(self.report / "error-only-commit-lease.json", evidence)
        self.record("error-only MySQL and recovered PostgreSQL savepoint transactions retain a fresh observer lease; outage rolls back without fabricated admission")

    def delivery(self, branch, credentials):
        before = len(self.journal(branch))
        self.outcomes.drop_next.set()
        with Probe(self, "audit-ack-loss", credentials) as probe:
            check_count(probe, self.insert(750), 1)
            require(self.outcomes.dropped.wait(5), "Real durable outcome ACK was not dropped")
            durable = self.settled(branch, before + 1)[-1]
            require(durable["outcome"] == "committed" and self.native_count(branch, 750) == 1,
                    "Dropping a real ACK lost its already durable native commit or audit outcome")
            wait_until("lost ACK delivery retry clears backpressure", lambda:
                       not self.proxy_audit_health()["protected_writes_paused"], seconds=15)
            acknowledgments = [ack for ack in self.outcomes.acks if ack["attempt_id"] == durable["id"]]
            require(acknowledgments and all(ack["outcome"] == "committed" and ack["audit_event_id"] > 0 for ack in acknowledgments)
                    and len({ack["audit_event_id"] for ack in acknowledgments}) == 1,
                    "Lost outcome ACK retry did not retain the same unique durable acknowledgment")
            check_count(probe, self.insert(751), 1)
        self.settled(branch, before + 2)
        require(self.native_count(branch, 750) == self.native_count(branch, 751) == 1, "Outcome redelivery retried a business mutation")
        self.outcomes.blocked.set()
        try:
            with Probe(self, "audit-delivery-unavailable", credentials) as probe:
                check_count(probe, self.insert(752), 1)
                pending = self.journal(branch)
                require(len(pending) == before + 3 and pending[-1]["outcome"] is None,
                        "Undelivered known commit lost its durable pending intent")
                require(self.native_count(branch, 752) == 1 and self.witness_count(branch) >= 1,
                        "Known native success has no same-transaction recovery witness")
                status, body = self.request("GET", f"/v1/branches/{branch['id']}/status", self.owner_tokens[OWNER_A])
                require(status == 200, "Pending audit status is unavailable to its owner")
                visible = json.loads(body)
                audit = visible.get("audit", {})
                json_file(self.report / "audit-delivery-pending-status.json", visible)
                require(audit.get("pending_delivery", 0) >= 1 and audit.get("cleanup_blocked") is True,
                        "Durable audit delivery pending is invisible or permits physical cleanup")
                require(all(secret not in body.decode() for secret in self.secret.values()) and b"INSERT INTO" not in body,
                        "Pending audit status exposes credentials or SQL")
                denied = probe.sql(self.insert(753))
                require(denied.get("fg") is not None and self.native_count(branch, 753) == 0,
                        "Audit delivery outage did not apply write backpressure")
        finally:
            self.outcomes.blocked.clear()
        wait_until("known commit delivery retry clears backpressure", lambda:
                   not self.proxy_audit_health()["protected_writes_paused"], seconds=15)
        # The delivery worker retries audit transport only, then new work resumes.
        with Probe(self, "audit-delivery-recovery", credentials) as probe:
            check_count(probe, self.insert(754), 1)
        self.settled(branch, before + 4)
        self.record("known native success survives unavailable audit delivery; duplicate ACK delivery is unique and pending applies backpressure")

    def preparation_gate(self, branch, credentials):
        before = {table: self.native(f"SELECT * FROM {self.branch_relation(branch['id'], table)} ORDER BY "
                  + ("tenant_id,id;" if table == "orders" else "id;")) for table in ("parents", "children", "orders")}
        identity = self.metadata(f"SELECT generation_id||':'||status FROM branch WHERE id={branch['id']};")
        self.metadata(f"UPDATE branch SET audit_witness_ready=FALSE WHERE id={branch['id']};")
        try:
            with self.native_relay("observe") as relay:
                with Probe(self, "unprepared-still-readable", credentials) as probe:
                    require(probe.sql("SELECT id FROM parents WHERE id=741", "read").get("rows") == [[741]],
                            "An unprepared branch lost read access to retained business data")
                with self.wire(branch) as client:
                    if self.family == "postgresql":
                        result = client.raw.pg_query(client.socket, self.insert(755).encode())
                        errors = [body for tag, body in result if tag == b"E"]
                        require(len(errors) == 1 and b"audit_storage_unprepared" in errors[0],
                                "Unprepared PostgreSQL write omitted its preparation reason")
                    else:
                        result = client.query(self.insert(755))
                        require(result[0] == 0xff and b"audit_storage_unprepared" in result,
                                "Unprepared MySQL write omitted its preparation reason")
                require(relay.business_mutations == 0 and self.native_count(branch, 755) == 0,
                        "An unprepared protected write reached native execution")
        finally:
            # The matched proxy proves that all native application sessions are
            # gone; keep its observer/control endpoint available for preparation.
            original = self.base_env
            self.base_env = original | {"FG_PROXY_CONTROL_URL": self.drain_url,
                                        "FG_INTERNAL_TOKEN": self.secret["internal"],
                                        "FG_BACKEND_DSN": self.dsn("p2_service", self.secret["service"],
                                                                  self.native_port, self.backend_database)}
            try:
                self.generation_command("audit-witness-only-prepare", "audit", "prepare")
            finally:
                self.base_env = original
        after = {table: self.native(f"SELECT * FROM {self.branch_relation(branch['id'], table)} ORDER BY "
                 + ("tenant_id,id;" if table == "orders" else "id;")) for table in ("parents", "children", "orders")}
        require(before == after and identity == self.metadata(f"SELECT generation_id||':'||status FROM branch WHERE id={branch['id']};"),
                "Witness-only preparation rebuilt a copy or changed retained business state/identity")
        require(self.metadata(f"SELECT audit_witness_ready FROM branch WHERE id={branch['id']};") == "t",
                "Witness preparation did not enable the same branch")
        self.record("unprepared branch remains readable and rejects writes before native; operator preparation preserves branch/data identity")

    def commit_cut(self, mode, key):
        branch, _ = self.create("audit-" + mode)
        with self.native_relay(mode) as relay:
            with self.wire(branch) as client:
                self.count(client, "BEGIN")
                self.count(client, self.insert(key), 1)
                if self.family == "postgresql":
                    client.send(b"Q", b"COMMIT\0")
                else:
                    client.raw.mysql_write(client.socket, 0, b"\x03COMMIT")
                require(relay.commit.wait(8) and relay.witness.is_set(), "Commit cut did not follow an actual witness insertion")
                if mode == "after-commit":
                    require(relay.withheld.wait(8), "Native COMMIT success was not withheld")
                    require(self.native_count(branch, key) == 1 and self.witness_count(branch) == 1,
                            "Lost commit response has no independently visible business row and witness")
                    require(self.journal(branch)[0]["outcome"] is None, "Audit was finalized before the native response")
                    relay.lose_commit_reply()
                try:
                    if self.family == "postgresql":
                        client.raw.pg_read(client.socket)
                    else:
                        client.raw.mysql_read(client.socket, 1)
                    raise RuntimeError("Unknown COMMIT returned a fabricated native response")
                except (OSError, EOFError):
                    pass
            rows = self.settled(branch, 1)
            # Native quiescence alone precedes MySQL's final outcome send. This
            # unique cut branch is finished: drain waits for registration Drop,
            # then health proves delivery retries have consumed their ACKs.
            status, _ = p6.p5.p34.p2.http("POST", self.drain_url + f"/internal/v1/branches/{branch['id']}/drain",
                                         self.secret["internal"], timeout=20)
            require(status == 204, "The cut branch did not finish its session audit delivery before test shutdown")
            wait_until("cut delivery retries finished before test shutdown", lambda:
                       not self.proxy_audit_health()["protected_writes_paused"], seconds=15)
        fact = rows[0]["resolution"] or rows[0]["outcome"]
        expected = "committed" if mode == "after-commit" else "rolled_back"
        require(fact == expected and self.native_count(branch, key) == int(expected == "committed"),
                "Quiescent native witness recovery disagrees with durable business data")
        require(relay.commits == 1 and relay.business_mutations == 1,
                "An uncertain result caused another native business mutation or COMMIT")
        json_file(self.report / (mode + ".json"), {"journal": rows, "business_rows": self.native_count(branch, key),
                  "commits_forwarded_or_cut": relay.commits, "business_mutations": relay.business_mutations,
                  "private_frames": relay.private_frames, "pre_shutdown_branch_drain": 204})
        self.drop(OWNER_A, branch["id"])
        self.record(f"{mode}: SQL witness recovery determines {expected} without business replay and preserves one outcome")

    def same_epoch_recovery(self, mode, orphan_key, live_key):
        suffix = "rollback" if mode == "pause-before-commit" else "commit"
        expected = "rolled_back" if suffix == "rollback" else "committed"
        orphan, _ = self.create("audit-current-orphan-" + suffix)
        healthy, _ = self.create("audit-current-live-" + suffix)
        evidence = {"expected_fact": expected, "proxy_or_control_restart": False, "forced_drain": False,
                    "proof_window": "after relay installation through recovery and subsequent writes"}
        with self.native_relay(mode) as relay:
            identity = self.runtime_identity()
            with self.wire(healthy) as live:
                self.count(live, "BEGIN")
                self.count(live, self.insert(live_key), 1)
                self.outcomes.blocked.set()
                self.outcomes.status_blocked.set()
                try:
                    with self.wire(orphan) as client:
                        self.count(client, "BEGIN")
                        self.count(client, self.insert(orphan_key), 1)
                        if self.family == "postgresql":
                            client.send(b"Q", b"COMMIT\0")
                        else:
                            client.raw.mysql_write(client.socket, 0, b"\x03COMMIT")
                        require(relay.commit.wait(8) and relay.witness.is_set(), "The current-epoch cut did not reach its witness/commit boundary")
                        if mode == "after-commit":
                            require(relay.withheld.wait(8), "The current-epoch native COMMIT reply was not withheld")
                        pending = self.journal(orphan)[0]
                        require(pending["outcome"] is None and not pending["sealed"]
                                and pending["session_id"].startswith(identity["epoch"] + ":")
                                and self.native_alive(pending["native_session_id"]) == 1,
                                "The live current-epoch attempt was sealed or lost its pending intent")
                        skipped = self.audit_reconcile("same-epoch-live-" + suffix)
                        require(skipped["active_skipped"] >= 2 and not self.journal(healthy)[0]["sealed"]
                                and not self.journal(orphan)[0]["sealed"],
                                "Default reconciliation sealed a healthy live transaction")
                        evidence["live_pending_before_cut"] = pending
                        evidence["live_reconcile"] = skipped
                        if mode == "pause-before-commit":
                            relay.release.set()
                        else:
                            relay.lose_commit_reply()
                        try:
                            if self.family == "postgresql":
                                client.raw.pg_read(client.socket)
                            else:
                                client.raw.mysql_read(client.socket, 1)
                            raise RuntimeError("A cut current-epoch commit returned a fabricated native response")
                        except (OSError, EOFError):
                            pass
                    attempt = pending["id"]
                    unknown_requests = lambda: [request for request in list(self.outcomes.requests)
                        if request["attempt_id"] == attempt and request["outcome"] == "unknown"]
                    wait_until("blocked unknown outcome transport", lambda: unknown_requests(), seconds=10)
                    wait_until("closed native orphan session", lambda: self.native_alive(pending["native_session_id"]) == 0, seconds=10)
                    require(self.proxy_audit_health()["protected_writes_paused"], "An undelivered unknown outcome did not pause protected writes")
                    evidence["closed_reconcile"] = self.audit_reconcile("same-epoch-closed-" + suffix)
                    recovered = self.settled(orphan, 1)[0]
                    require(recovered["outcome"] == expected and recovered["resolution"] is None
                            and recovered["sealed"] and self.native_count(orphan, orphan_key) == int(expected == "committed"),
                            "A closed same-epoch intent did not obtain the correct primary native fact")
                    require(not self.journal(healthy)[0]["sealed"] and self.journal(healthy)[0]["outcome"] is None
                            and self.native_count(healthy, live_key) == 0,
                            "Orphan recovery sealed or committed the unrelated healthy transaction")
                    sent_before = len(unknown_requests())
                    require(self.proxy_audit_health()["protected_writes_paused"], "The blocked status transport prematurely cleared the unknown delivery")
                    self.outcomes.status_blocked.clear()
                    wait_until("proved unknown delivery clears in the same epoch", lambda:
                               not self.proxy_audit_health()["protected_writes_paused"], seconds=15)
                    require(len(unknown_requests()) == sent_before and any(
                        status.get("resolved") and (status.get("ack") or {}).get("attempt_id") == attempt
                        and status["ack"]["outcome"] == expected for status in list(self.outcomes.status_acks)),
                        "A recovered primary fact did not clear the pending Unknown through status alone")
                    require(relay.business_mutations == 2 and relay.commits == 1 and relay.witness_mutations == 1,
                            "Current-epoch outcome recovery resent business DML or a commit")
                    evidence["recovered_primary"] = recovered
                    evidence["unknown_outcome_requests"] = sent_before
                    evidence["native_session_closed"] = True
                    relay.mode = "observe"
                finally:
                    relay.release.set()
                    self.outcomes.blocked.clear()
                    self.outcomes.status_blocked.clear()
                self.count(live, "COMMIT")
                self.count(live, "BEGIN")
                self.count(live, self.insert(live_key + 20), 1)
                self.count(live, "COMMIT")
            require(identity == self.runtime_identity(), "Current-epoch recovery restarted a proxy/controller or changed its epoch")
            require(self.native_count(healthy, live_key) == self.native_count(healthy, live_key + 20) == 1
                    and relay.business_mutations == relay.commits == relay.witness_mutations == 3,
                    "The healthy transaction or subsequent fresh write was lost or replayed")
            evidence.update({"runtime_identity": identity, "healthy_journal": self.settled(healthy, 2),
                             "business_mutations": relay.business_mutations, "commits": relay.commits,
                             "witness_mutations": relay.witness_mutations,
                             "protected_writes_resumed": not self.proxy_audit_health()["protected_writes_paused"]})
        json_file(self.report / ("same-epoch-" + suffix + ".json"), evidence)
        self.drop(OWNER_A, orphan["id"])
        self.drop(OWNER_A, healthy["id"])
        self.record(f"same epoch: closed orphan proves {expected}; pending Unknown clears through status, live transaction stays unsealed and commits without business replay")

    def pg_extended(self):
        branch, _ = self.create("audit-extended")
        with self.native_relay("observe") as relay:
            with self.wire(branch) as client:
                # User names deliberately equal the internal names before mapping.
                client.parse(b"_fg_witness_s", b"SELECT 1")
                client.parse(b"business_write", self.insert(760).encode())
                client.bind(b"_fg_witness_p", b"business_write")
                client.execute(b"_fg_witness_p")
                client.send(b"H")
                require(self.native_count(branch, 760) == 0 and self.witness_count(branch) == 0,
                        "Extended Execute/Flush committed before the application's Sync")
                require(self.journal(branch)[0]["outcome"] is None, "Extended transaction finalized before Sync")
                client.sync()
                require(self.native_count(branch, 760) == 1, "Final Sync failed to commit the business row")
                client.bind(b"_fg_witness_p", b"_fg_witness_s")
                client.execute(b"_fg_witness_p", read=True)
                client.sync()
                client.query(b"BEGIN", b"T")
                client.query(self.insert(762).encode(), b"T")
                client.parse(b"prepared_commit", b"COMMIT")
                require(len(relay.private_frames) == 6, "Preparing COMMIT inserted a witness before the commit boundary")
                client.query(self.insert(763).encode(), b"T")
                client.bind(b"commit_portal", b"prepared_commit")
                client.execute(b"commit_portal")
                client.sync()
                require(self.native_count(branch, 762) == self.native_count(branch, 763) == 1,
                        "A prepared COMMIT failed after intervening admitted writes")
            require(relay.private_frames == list("PBECCH") * 2, "Private witness sent Query/Sync or leaked protocol replies")
        self.settled(branch, 2)
        self.drop(OWNER_A, branch["id"])
        self.record("PostgreSQL implicit extended Flush stays uncommitted; private named witness preserves user names and final Sync")

    def pg_blocked_witness_recovery(self):
        branch, credentials = self.create("audit-blocked-witness")
        evidence = {"lock_mode": "ACCESS EXCLUSIVE", "recovery_limit_seconds": 20,
                    "business_retry": False, "proxy_or_control_restart_in_proof": False}
        with self.native_relay("after-commit") as relay:
            identity = self.runtime_identity()
            self.outcomes.blocked.set()
            self.outcomes.status_blocked.set()
            try:
                with self.wire(branch) as client:
                    client.query(b"BEGIN", b"T")
                    client.query(self.insert(790).encode(), b"T")
                    client.send(b"Q", b"COMMIT\0")
                    require(relay.commit.wait(8) and relay.withheld.wait(8), "The DDL-lock case did not lose a real COMMIT reply")
                    require(self.native_count(branch, 790) == self.witness_count(branch) == 1,
                            "The withheld COMMIT did not durably commit its business row and witness")
                    pending = self.journal(branch)[0]
                    require(pending["outcome"] is None, "The blocked witness attempt already had a durable outcome")
                    with self.pg_witness_ddl_lock(branch) as lock_pid:
                        relay.lose_commit_reply()
                        try:
                            client.raw.pg_read(client.socket)
                            raise RuntimeError("A withheld native COMMIT returned a fabricated response")
                        except (OSError, EOFError):
                            pass
                        wait_until("blocked DDL old native session closed", lambda:
                                   self.native_alive(pending["native_session_id"]) == 0, seconds=10)
                        wait_until("blocked DDL unknown outcome pending", lambda: any(
                            request["attempt_id"] == pending["id"] and request["outcome"] == "unknown"
                            for request in list(self.outcomes.requests)), seconds=10)
                        started = time.monotonic()
                        report = self.audit_reconcile("blocked-witness-reconcile")
                        elapsed = time.monotonic() - started
                        unknown = self.journal(branch)[0]
                        require(elapsed < 20 and report["retained_unknown"] >= 1
                                and unknown["id"] == pending["id"] and unknown["outcome"] == "unknown"
                                and unknown["resolution"] is None and not unknown["witness_collected"]
                                and unknown["outcomes"] == 1 and self.native_count(branch, 790) == 1,
                                "Blocked native evidence hung, inferred absence, or discarded the committed witness")
                        evidence.update({"lock_backend_pid": lock_pid, "blocked_reconcile": report,
                                         "blocked_elapsed_seconds": elapsed, "unknown_while_locked": unknown})
                self.audit_reconcile("released-witness-reconcile")
                resolved = self.settled(branch, 1)[0]
                require(resolved["id"] == pending["id"] and resolved["outcome"] == "unknown"
                        and resolved["resolution"] == "committed" and resolved["resolutions"] == resolved["outcomes"] == 1,
                        "Releasing the DDL lock did not append one truthful committed resolution to the same attempt")
                self.outcomes.status_blocked.clear()
                wait_until("resolved DDL unknown delivery clears", lambda:
                           not self.proxy_audit_health()["protected_writes_paused"], seconds=15)
                require(relay.business_mutations == relay.commits == relay.witness_mutations == 1,
                        "Blocked native evidence recovery resent business DML or COMMIT")
                evidence["resolved_after_unlock"] = resolved
                relay.mode = "observe"
            finally:
                self.outcomes.blocked.clear()
                self.outcomes.status_blocked.clear()
            with Probe(self, "audit-after-ddl-unlock", credentials) as probe:
                check_count(probe, self.insert(791), 1)
            require(identity == self.runtime_identity() and self.native_count(branch, 790) == self.native_count(branch, 791) == 1
                    and relay.business_mutations == relay.commits == relay.witness_mutations == 2,
                    "DDL-lock recovery restarted a runtime, replayed old work, or blocked a subsequent fresh write")
            evidence.update({"runtime_identity": identity, "journal": self.settled(branch, 2),
                             "business_mutations": relay.business_mutations, "commits": relay.commits,
                             "witness_mutations": relay.witness_mutations})
        json_file(self.report / "blocked-witness-recovery.json", evidence)
        self.drop(OWNER_A, branch["id"])
        self.record("PostgreSQL blocked witness evidence returns bounded Unknown, retains its marker, then resolves the same committed attempt after unlock without business replay")

    def pg_cancel_witness(self):
        branch, _ = self.create("audit-cancel-witness")
        with self.native_relay("pause-witness") as relay:
            raw = self.raw_module()
            connection, cancel_key = self.raw_connection(raw, (OWNER_A, branch["name"]))
            with connection:
                client = pg_review.Session(raw, connection)
                client.query(b"BEGIN", b"T")
                client.query(self.insert(761).encode(), b"T")
                client.send(b"Q", b"COMMIT\0")
                require(relay.witness.wait(8), "COMMIT did not reach the private witness")
                require(self.native_count(branch, 761) == 0, "Witness preparation committed business data")
                with raw.connect(self.proxy_port) as cancellation:
                    cancellation.sendall(struct.pack("!II", 16, 80877102) + cancel_key)
                try:
                    require(relay.cancel_seen.wait(8), "CancelRequest did not reach the active native witness boundary")
                finally:
                    relay.release.set()
                client.error(b"57014", b"FG-5003")
                client.expect(b"Z", b"E")
                client.query(b"ROLLBACK")
                client.query(b"SELECT 1")
        rows = self.settled(branch, 1)
        require(rows[0]["outcome"] == "rolled_back" and self.native_count(branch, 761) == 0,
                "Cancellation committed a witness/business row or lost the rollback audit")
        self.drop(OWNER_A, branch["id"])
        self.record("PostgreSQL cancellation during the private witness rolls back and preserves normal failed-transaction recovery")

    def verify_binaries(self):
        expected = self.call("observed-git-head", ["git", "rev-parse", "HEAD"])
        revisions = {name: self.call("revision-" + name, [self.executable(name), "--revision"])
                     for name in ("fg-control", "fg-proxy")}
        hashes = {}
        for name in revisions:
            digest = hashlib.sha256()
            with Path(self.executable(name)).open("rb") as binary:
                for chunk in iter(lambda: binary.read(1024 * 1024), b""):
                    digest.update(chunk)
            hashes[name] = digest.hexdigest()
        available = all(revision != "unavailable" for revision in revisions.values())
        state = getattr(self, "suite_source_state", "unavailable")
        json_file(self.report / "binaries.json", {"profile": "release", "revisions": revisions,
                  "sha256": hashes, "revision_available": available,
                  "observed_git_head": expected, "source_state": state,
                  "source_dirty": state == "dirty" if state != "unavailable" else None,
                  "source_binding": "embedded_revision" if available else "unavailable_revision_file_hashes_only"})
        require(len(expected) == 40 and all(char in "0123456789abcdef" for char in expected)
                and all(revision == expected for revision in revisions.values()),
                "SQL audit requires control/proxy embedded revisions equal to the observed Git HEAD; rebuild both binaries")

    def execute(self):
        self.verify_binaries()
        self.start_deployment()
        self.generation_command("audit-refresh-v2", "refresh", "--snapshot", "v2", cooldown=0)
        self.set_policy("dev", 50000, bps=10000, floor=100)
        branch, credentials = self.create("audit-boundaries")
        self.legacy_protocol(branch)
        self.boundaries(branch, credentials)
        self.autocommit_requests(branch, credentials)
        self.refused_fence(branch)
        self.error_only_commit_lease(branch)
        self.native_error_recovery(branch, credentials)
        self.generated(branch, credentials)
        self.delivery(branch, credentials)
        self.preparation_gate(branch, credentials)
        json_file(self.report / "boundaries.json", self.journal(branch))
        self.drop(OWNER_A, branch["id"])
        self.commit_cut("before-commit", 770)
        self.commit_cut("after-commit", 771)
        self.same_epoch_recovery("pause-before-commit", 780, 781)
        self.same_epoch_recovery("after-commit", 782, 783)
        if self.family == "postgresql":
            self.pg_blocked_witness_recovery()
            self.pg_extended()
            self.pg_cancel_witness()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=("mysql", "postgresql", "tidb", "all"), default="all")
    parser.add_argument("--report-dir", type=Path, required=True)
    args = parser.parse_args()
    args.report_dir.mkdir(parents=True, exist_ok=False)
    started = datetime.now(UTC)
    revision, state = p6.p5.p34.p2.git_state()
    AuditRun.suite_source_state = state
    results = {}
    for engine in (("mysql", "postgresql", "tidb") if args.engine == "all" else (args.engine,)):
        results[engine] = p6.p5.p34.run_engine(engine, args.report_dir,
            f"fgsqlaudit-{started:%H%M%S}-{os.getpid()}", AuditRun)
    json_file(args.report_dir / "report.json", {"status": "passed" if all(result["status"] == "passed" for result in results.values()) else "failed",
        "source_revision": revision, "source_state": state, "engines": results,
        "started_at": started.isoformat(), "finished_at": datetime.now(UTC).isoformat()})
    return 0 if all(result["status"] == "passed" for result in results.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
