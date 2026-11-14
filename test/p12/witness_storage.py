#!/usr/bin/env python3
"""Exercise native witness preparation, exact privileges and untrusted history."""

import argparse
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import re
import select
import socket
import subprocess
import sys
import time
from threading import Event, local
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import sql_audit
from run_p2 import OWNER_A, json_file, require, wait_until
from write_cases import Probe, check_count


def clone_tidb_witness(definition, source, target, branch_id):
    # Only this fixture's already-verified witness is cloned. TiDB preserves
    # CHECK names across RENAME/LIKE although they remain unique per schema.
    prefix = "CREATE TABLE `" + source + "` ("
    require(definition.startswith(prefix), "Unexpected native witness CREATE definition")
    definition = "CREATE TABLE `" + target + "` (" + definition[len(prefix):]
    index = 0

    def renamed(match):
        nonlocal index
        index += 1
        return match[1] + f"`p12_clone_{int(branch_id)}_{index}`" + match[2]

    definition = re.sub(r"(?m)^(\s*CONSTRAINT )`[a-zA-Z0-9_]+`( CHECK\s*\()", renamed, definition)
    require(index == 1, "Valid native witness must have exactly one named CHECK before cloning")
    return definition


def remove_tidb_witness_primary_key(definition):
    lines = definition.splitlines()
    primary = [line for line in lines if line.lstrip().startswith("PRIMARY KEY (`attempt_id`)")]
    require(len(primary) == 1 and primary[0].rstrip().endswith(","), "Unexpected native witness primary-key definition")
    return "\n".join(line for line in lines if line != primary[0])


class NativeProbe(Probe):
    """Reuse the SQLx oracle with an explicitly scoped native role and TLS."""

    def __init__(self, run, label, role):
        self.run, self.label, self.pending, self.process = run, label, False, None
        accounts = {"service": ("p2_service", "service"), "collector": ("p2_gc", "collector"),
                    "root": ("root", "native")}
        require(role in accounts, "Unexpected privilege-test identity")
        user, secret = accounts[role]
        environment = run.base_env | {
            "FG_WRITE_PROBE_URL": run.dsn(user, run.secret[secret], run.native_port, run.backend_database),
            "FG_WRITE_PROBE_CA": str(run.certs / "backend-ca.pem"),
        }
        self.process = subprocess.Popen([run.executable("fg-write-probe")], cwd=ROOT,
            env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1)
        try:
            require(self.line() == "ready", f"{label}: native TLS oracle did not connect")
        except Exception:
            self.close()
            raise


class ExecutedFrames(sql_audit.CommandFrames):
    def mysql_command(self):
        result = super().mysql_command()
        self.executed = result[1] if result else None
        return result

    def postgres_command(self):
        result = super().postgres_command()
        self.executed = result[1] if result else None
        return result


class WitnessDropRelay(sql_audit.NativeRelay):
    """Lose the first exact native witness DROP reply, retaining original frames."""

    def __init__(self, run, branch):
        super().__init__(run, "witness-drop")
        schema, prefix = run.branch_namespace(branch["id"])
        self.relation = sql_audit.p6.p5.p34.p2.data.table(run.engine, schema, prefix + "_fg_txn_witness").encode()
        self.business = [sql_audit.p6.p5.p34.p2.data.table(run.engine, schema, prefix + table).encode()
                         for table in ("parents", "children", "orders")]
        self.armed = Event()
        self.armed.set()
        self.dropped = Event()
        self.drop_executions = self.business_executions = self.missing_witness_reads = 0

    def observe(self, sql):
        if sql is None:
            return False
        target = sql in (b"DROP TABLE IF EXISTS " + self.relation,
                         b"DROP TABLE IF EXISTS " + self.relation + b";")
        with self.lock:
            if target:
                self.drop_executions += 1
                if self.armed.is_set():
                    self.armed.clear()
                    return True
            if sql.startswith((b"INSERT ", b"UPDATE ", b"DELETE ")) and any(table in sql for table in self.business):
                self.business_executions += 1
            if self.dropped.is_set() and sql.startswith(b"SELECT ") and self.relation in sql:
                self.missing_witness_reads += 1
        return False

    def drop_response(self, frame, command_complete):
        if self.run.family == "postgresql":
            require(frame[:1] != b"E", "The intercepted native witness DROP failed")
            if frame[:1] == b"C":
                require(frame[5:] == b"DROP TABLE\0", "Unexpected native witness DROP command tag")
                command_complete = True
            if frame[:1] == b"Z":
                require(command_complete and frame[5:] == b"I", "Native witness DROP did not finish its transaction")
                return command_complete, True
            return command_complete, False
        require(frame[4:5] != b"\xff", "The intercepted native witness DROP failed")
        return command_complete, frame[4:5] == b"\0"

    def forward(self, client, server):
        startup = self.run.family == "postgresql"
        commands = ExecutedFrames(self.run.family)
        withholding = False
        command_complete = False
        try:
            while not self.done.is_set():
                readable = [stream for stream in (client, server) if stream.pending()]
                if not readable:
                    readable, _, _ = select.select([client, server], [], [], .05)
                for source in readable:
                    if self.run.family == "postgresql":
                        width = 4 if source is client and startup else 5
                        header = sql_audit.read_exact(source, width)
                        length = int.from_bytes(header[-4:], "big")
                        require(4 <= length <= 1024 * 1024, "Unexpected native DROP protocol frame size")
                        frame = header + sql_audit.read_exact(source, length - 4)
                        if source is client:
                            startup = False
                    else:
                        header = sql_audit.read_exact(source, 4)
                        length = int.from_bytes(header[:3], "little")
                        require(length <= 1024 * 1024, "Unexpected native DROP protocol frame size")
                        frame = header + sql_audit.read_exact(source, length)
                    if source is client:
                        commands.scan(frame)
                        withholding = self.observe(commands.executed) or withholding
                        server.sendall(frame)
                    elif withholding:
                        command_complete, success = self.drop_response(frame, command_complete)
                        if success:
                            self.dropped.set()
                    else:
                        client.sendall(frame)
        except OSError:
            return
        except (ValueError, sql_audit.p6.p5.p34.p2.Failure) as error:
            self.errors.append(type(error).__name__)


class CollectorLockRelay(sql_audit.NativeRelay):
    """Pause an exact witness DELETE before forwarding its original command."""

    def __init__(self, run, branch):
        super().__init__(run, "collector-lock")
        require(run.family in ("mysql", "tidb"), "Collector lock relay requires the MySQL native protocol")
        schema, prefix = run.branch_namespace(branch["id"])
        self.relation = sql_audit.p6.p5.p34.p2.data.table(run.engine, schema, prefix + "_fg_txn_witness").encode()
        self.at_delete = Event()
        self.continue_delete = Event()
        self.delete_complete = Event()
        self.collector_closed = Event()
        self.collector_id = None
        self.admin_ids = set()
        self.collector_began = self.collector_read_header = False
        self.admin_before_collector_lock = False
        self.delete_executions = self.delete_successes = self.commit_successes = 0
        self.business_executions = 0
        self.later_delete_connections = 0
        self.pause_started = None
        self.connection_state = local()
        self.socket_options = []

    def __exit__(self, error, *_):
        self.continue_delete.set()
        super().__exit__(error)

    @staticmethod
    def packet(stream):
        header = sql_audit.read_exact(stream, 4)
        size = int.from_bytes(header[:3], "little")
        require(size <= 1024 * 1024, "Unexpected collector protocol frame size")
        return header + sql_audit.read_exact(stream, size)

    def start_tls(self, client, server):
        client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        with self.lock:
            self.socket_options.append({"downstream_tcp_nodelay": client.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY),
                                        "upstream_tcp_nodelay": server.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)})
        greeting = self.packet(server)
        body = greeting[4:]
        end = body.index(b"\0", 1)
        require(len(body) >= end + 5, "Native greeting omitted its connection identity")
        self.connection_state.native_id = int.from_bytes(body[end + 1:end + 5], "little")
        client.sendall(greeting)
        server.sendall(self.packet(client))

    def classify(self, sql):
        if sql is None:
            return None
        if sql.startswith(b"DELETE FROM " + self.relation + b" WHERE attempt_id <> '' AND attempt_id IN ("):
            return "delete"
        if sql == b"BEGIN":
            return "begin"
        if sql == b"COMMIT":
            return "commit"
        header_guard = b"SELECT attempt_id FROM " + self.relation + b" WHERE attempt_id=''"
        if self.run.family == "mysql":
            header_guard += b" FOR UPDATE"
        if sql == header_guard:
            return "lock"
        if sql.startswith(b"SELECT ") and b" FROM " + self.relation + b" WHERE attempt_id = ''" in sql:
            return "header"
        return sql_audit.mutation_kind(sql, self.run.family)

    @staticmethod
    def connection_state_for(native_id):
        return SimpleNamespace(native_id=native_id, role=None, statements={}, preparing=None, pending=None)

    def observe_collector(self, connection, executing):
        kind = connection.pending
        if executing and kind == "begin":
            self.collector_began = True
        if executing and kind == "lock":
            self.collector_read_header = True
        if kind == "delete" and not self.at_delete.is_set():
            self.collector_id = connection.native_id
            self.pause_started = time.monotonic()
            self.at_delete.set()
            require(self.continue_delete.wait(15), "Collector DELETE pause was not released")
        elif kind == "delete" and connection.native_id != self.collector_id:
            self.later_delete_connections += 1
            # Keep a later legitimate pass from erasing this failure's evidence.
            self.done.wait(15)
            return False
        if executing and kind == "delete":
            self.delete_executions += 1
        if executing and kind == "business":
            self.business_executions += 1
        return True

    def observe_client(self, connection, frame):
        body = frame[4:]
        if connection.role is None:
            require(len(body) > 32, "Native TLS login omitted its account")
            account = body[32:].split(b"\0", 1)[0]
            connection.role = ("collector" if account == b"p2_gc" else "admin"
                               if account == sql_audit.p6.p5.p34.ADMIN.encode() else "other")
        if frame[3] != 0 or not body:
            return True
        executing = False
        if body[0] in (3, 22):
            connection.pending = self.classify(body[1:])
            executing = body[0] == 3
            if body[0] == 22:
                connection.preparing = connection.pending
        elif body[0] == 23 and len(body) >= 5:
            connection.pending = connection.statements.get(body[1:5])
            executing = True
        else:
            connection.pending = None
        if connection.role == "admin" and connection.pending == "header":
            with self.lock:
                if not self.collector_read_header:
                    self.admin_before_collector_lock = True
                self.admin_ids.add(connection.native_id)
        if connection.role == "collector":
            return self.observe_collector(connection, executing)
        return True

    def observe_server(self, connection, frame):
        body = frame[4:]
        if connection.preparing is not None and frame[3] == 1:
            if body[:1] == b"\0":
                require(len(body) >= 12, "Native PREPARE_OK omitted its handle")
                connection.statements[body[1:5]] = connection.preparing
            connection.preparing = None
        elif connection.role == "collector" and frame[3] == 1 and body[:1] == b"\0":
            if connection.pending == "delete":
                self.delete_successes += 1
                self.delete_complete.set()
            elif connection.pending == "commit":
                self.commit_successes += 1

    def forward(self, client, server):
        connection = self.connection_state_for(self.connection_state.native_id)
        try:
            while not self.done.is_set():
                readable = [stream for stream in (client, server) if stream.pending()]
                if not readable:
                    readable, _, _ = select.select([client, server], [], [], .05)
                for source in readable:
                    frame = self.packet(source)
                    if source is client:
                        if not self.observe_client(connection, frame):
                            return
                        server.sendall(frame)
                    else:
                        self.observe_server(connection, frame)
                        client.sendall(frame)
        except OSError:
            return
        except (ValueError, sql_audit.p6.p5.p34.p2.Failure) as error:
            self.errors.append(type(error).__name__)
        finally:
            if connection.native_id == self.collector_id:
                self.collector_closed.set()


class WitnessRun(sql_audit.AuditRun):
    def __init__(self, *arguments):
        super().__init__(*arguments)
        # Docker's bind-mounted shell must be LF even from a Windows checkout.
        directory = self.certs.parent / "witness-compose"
        directory.mkdir()
        for name in ("compose.yml", "engine.sh"):
            (directory / name).write_text((ROOT / "test/p2" / name).read_text(),
                                           encoding="utf-8", newline="\n")
        self.compose_command = ["docker", "compose", "--project-name", self.project,
                                "--file", str(directory / "compose.yml")]
        self.base_env |= {"FG_PROXY_CONTROL_URL": self.drain_url,
                          "FG_INTERNAL_TOKEN": self.secret["internal"]}
        self.observations = {"scope": "disposable native storage; no external deployment", "shape_cases": []}

    def legacy_migration(self):
        # Full LF/CRLF metadata migration histories have separate native tests.
        # This suite exercises a retained branch with unprepared native storage.
        pass

    def start_databases(self):
        super().start_databases()
        self.base_env["FG_BACKEND_DSN"] = self.dsn("p2_service", self.secret["service"], self.native_port,
                                                self.backend_database)

    def dump_native_state(self):
        json_file(self.report / "witness-storage-partial.json", self.observations)
        super().dump_native_state()

    def identity(self, branch):
        relation = self.branch_relation(branch["id"], "_fg_txn_witness")
        value = self.native(f"SELECT CONCAT(format_version,'|',deployment_id,'|',branch_id,'|',"
                            f"generation_id,'|',storage_incarnation) FROM {relation} WHERE attempt_id='';")
        version, deployment, branch_id, generation_id, incarnation = value.split("|")
        return {"format_version": int(version), "deployment_id": deployment,
                "branch_id": int(branch_id), "generation_id": int(generation_id), "storage_incarnation": incarnation}

    def snapshot(self, branch):
        return {table: self.native(f"SELECT * FROM {self.branch_relation(branch['id'], table)} ORDER BY "
                    + ("tenant_id,id;" if table == "orders" else "id;"))
                for table in ("parents", "children", "orders")}

    def witness_ready(self, branch):
        return self.metadata(f"SELECT audit_witness_ready::int FROM branch WHERE id={branch['id']};") == "1"

    def operator(self, label, *arguments, succeeds=True):
        environment = self.base_env | {
            "FG_META_DSN": self.dsn("postgres", self.secret["meta"], self.metadata_port, "forkget_meta", "postgresql"),
            "FG_META_CA": str(self.certs / "backend-ca.pem"),
            "FG_BACKEND_GC_DSN": self.dsn("p2_gc", self.secret["collector"], self.native_port, self.backend_database),
            "FG_BACKEND_CA": str(self.certs / "backend-ca.pem"),
            "FG_INTERNAL_TOKEN": self.secret["internal"], "FG_PROXY_CONTROL_URL": self.drain_url,
        }
        return self.call(label, [self.executable("fg-control"), "audit", *arguments], env=environment,
                         succeeds=succeeds, log=True, timeout=90)

    def permissions(self, branch):
        relation = self.branch_relation(branch["id"], "_fg_txn_witness")
        header = self.identity(branch)
        attempt = "f" * 32 + ":999:1"
        insert = (f"INSERT INTO {relation} VALUES ({header['format_version']},'{header['deployment_id']}',"
                  f"{header['branch_id']},{header['generation_id']},'{header['storage_incarnation']}',"
                  f"'{attempt}','1')")
        errors = {}
        with NativeProbe(self, "witness-native-service", "service") as probe:
            check_count(probe, "BEGIN", 0)
            check_count(probe, insert, 1)
            check_count(probe, "ROLLBACK", 0)
            for name, sql in (("select", f"SELECT * FROM {relation}"),
                              ("delete", f"DELETE FROM {relation} WHERE attempt_id='{attempt}'"),
                              ("update", f"UPDATE {relation} SET native_session='2' WHERE attempt_id='{attempt}'")):
                result = probe.sql(sql)
                require(result.get("sqlstate") in ("42501", "42000"), f"Service unexpectedly has witness {name}")
                errors["service-" + name] = {key: result.get(key) for key in ("errno", "sqlstate")}
        with NativeProbe(self, "witness-native-collector", "collector") as probe:
            require(probe.sql(f"SELECT count(*) FROM {relation} WHERE attempt_id=''", "read").get("rows") == [[1]],
                    "Collector lacks SELECT on the trusted header")
            check_count(probe, f"DELETE FROM {relation} WHERE attempt_id='{attempt}'", 0)
            check_count(probe, "BEGIN", 0)
            denied = probe.sql(insert)
            check_count(probe, "ROLLBACK", 0)
            require(denied.get("sqlstate") in ("42501", "42000"), "Collector unexpectedly has witness INSERT")
            errors["collector-insert"] = {key: denied.get(key) for key in ("errno", "sqlstate")}
        require(self.native(f"SELECT count(*) FROM {relation} WHERE attempt_id='{attempt}';") == "0",
                "Privilege probes persisted an unassociated marker")
        self.observations["native_privilege_errors"] = errors
        self.record("native TLS service has INSERT only; collector has SELECT/DELETE and cannot INSERT; probes leave no marker")

    def upgrade(self, branch, credentials):
        with Probe(self, "retained-business-data", credentials) as probe:
            check_count(probe, self.insert(810), 1)
        self.stop("control")
        before = self.snapshot(branch)
        registration = self.metadata(f"SELECT generation_id||':'||status FROM branch WHERE id={branch['id']};")
        relation = self.branch_relation(branch["id"], "_fg_txn_witness")
        # Represent the earlier storage contract without rebuilding any
        # user table. There are no pending facts when removing this test marker.
        require(all(row["outcome"] is not None for row in self.journal(branch)), "Upgrade fixture has pending audit evidence")
        self.metadata(f"UPDATE branch SET audit_witness_ready=FALSE,audit_witness_version=0,"
                      f"audit_witness_incarnation=NULL WHERE id={branch['id']};")
        self.native(f"DROP TABLE {relation};")
        self.generation_command("prepare-retained-native-storage", "audit", "prepare")
        require(self.witness_ready(branch), "Witness-only upgrade did not prepare the retained branch")
        require(self.snapshot(branch) == before and self.metadata(
            f"SELECT generation_id||':'||status FROM branch WHERE id={branch['id']};") == registration,
            "Witness preparation rebuilt business tables or changed branch identity")
        self.observations["legacy_registration_fixture"] = True
        self.record("witness-only preparation of retained unprepared native registration preserves exact business rows and branch identity")

    def rename(self, source, target):
        if self.family == "postgresql":
            self.native(f"ALTER TABLE {source} RENAME TO {target.rsplit('.',1)[1]};")
        else:
            self.native(f"RENAME TABLE {source} TO {target};")

    def malformed(self, branch, name, mutate):
        relation = self.branch_relation(branch["id"], "_fg_txn_witness")
        saved = self.branch_relation(branch["id"], "_fg_saved_witness")
        before = self.snapshot(branch)
        self.metadata(f"UPDATE branch SET audit_witness_ready=FALSE WHERE id={branch['id']};")
        self.rename(relation, saved)
        try:
            if self.family == "postgresql":
                clone = f"CREATE TABLE {relation} (LIKE {saved} INCLUDING ALL);"
            elif self.family == "tidb":
                schema, prefix = self.branch_namespace(branch["id"])
                source = prefix + "_fg_saved_witness"
                observed, definition = self.native(f"SHOW CREATE TABLE {saved};").split("\t", 1)
                require(observed == source, "Native witness definition names a different table")
                clone = "USE " + schema + "; " + clone_tidb_witness(definition, source,
                    prefix + "_fg_txn_witness", branch["id"]) + ";"
            else:
                clone = f"CREATE TABLE {relation} LIKE {saved};"
            self.native(clone + f" INSERT INTO {relation} SELECT * FROM {saved};")
            if self.family == "postgresql":
                self.native(f"ALTER TABLE {relation} OWNER TO {sql_audit.p6.p5.p34.ADMIN};")
            self.generation_command("validate-witness-clone-" + name, "audit", "prepare")
            require(self.witness_ready(branch), "The valid native clone failed before fault injection: " + name)
            self.metadata(f"UPDATE branch SET audit_witness_ready=FALSE WHERE id={branch['id']};")
            mutate(relation)
            self.generation_command("reject-witness-" + name, "audit", "prepare", succeeds=False)
            require(not self.witness_ready(branch), "Invalid witness was marked prepared: " + name)
            require(self.snapshot(branch) == before, "Rejected witness shape changed business data: " + name)
            self.observations["shape_cases"].append({"case": name, "result": "rejected", "business_unchanged": True})
        finally:
            self.native(f"DROP TABLE IF EXISTS {relation};")
            if self.family == "postgresql":
                schema = relation.split(".", 1)[0]
                self.native(f"DROP FUNCTION IF EXISTS {schema}.p12_witness_trigger();")
            self.rename(saved, relation)
            self.generation_command("restore-valid-witness-" + name, "audit", "prepare")
            require(self.witness_ready(branch), "Restored valid native witness did not prepare")

    def wrong_shapes(self, branch):
        if self.family == "postgresql":
            self.malformed(branch, "unlogged", lambda table: self.native(f"ALTER TABLE {table} SET UNLOGGED;"))
        elif self.family == "mysql":
            self.malformed(branch, "myisam", lambda table: self.native(f"ALTER TABLE {table} ENGINE=MyISAM;"))
        else:
            self.observations["shape_cases"].append({"case": "nontransactional-engine", "result": "not_applicable", "reason": "TiDB has no alternate MyISAM table engine"})
        def remove_pk(table):
            if self.family == "postgresql":
                constraint = self.native(f"SELECT conname FROM pg_constraint WHERE conrelid='{table}'::regclass AND contype='p';")
                require(constraint and constraint.replace("_", "").isalnum(), "Unexpected native PK identifier")
                self.native(f"ALTER TABLE {table} DROP CONSTRAINT {constraint};")
            elif self.family == "tidb":
                # TiDB cannot drop a clustered primary key. Replace only the
                # disposable witness clone with the same full native definition
                # minus its PK; the saved valid witness and business rows stay intact.
                schema, prefix = self.branch_namespace(branch["id"])
                observed, definition = self.native(f"SHOW CREATE TABLE {table};").split("\t", 1)
                require(observed == prefix + "_fg_txn_witness", "Native PK fault addressed a different witness")
                broken = remove_tidb_witness_primary_key(definition)
                saved = self.branch_relation(branch["id"], "_fg_saved_witness")
                self.native(f"DROP TABLE {table}; USE {schema}; {broken}; INSERT INTO {table} SELECT * FROM {saved};")
            else:
                self.native(f"ALTER TABLE {table} DROP PRIMARY KEY;")
        self.malformed(branch, "missing-primary-key", remove_pk)
        self.malformed(branch, "wrong-column-length", lambda table: self.native(
            f"ALTER TABLE {table} ALTER COLUMN native_session TYPE VARCHAR(127);" if self.family == "postgresql"
            else f"ALTER TABLE {table} MODIFY native_session VARCHAR(127) NOT NULL;"))
        self.malformed(branch, "wrong-header", lambda table: self.native(
            f"UPDATE {table} SET native_session='tampered' WHERE attempt_id='';"))
        self.malformed(branch, "extra-check", lambda table: self.native(
            f"ALTER TABLE {table} ADD CONSTRAINT p12_extra_check CHECK(branch_id>0);"))
        if self.family == "postgresql":
            self.malformed(branch, "extra-not-valid-check", lambda table: self.native(
                f"ALTER TABLE {table} ADD CONSTRAINT p12_extra_check CHECK(attempt_id='') NOT VALID;"))
        elif self.family == "mysql":
            self.malformed(branch, "extra-not-enforced-check", lambda table: self.native(
                f"ALTER TABLE {table} ADD CONSTRAINT p12_extra_check CHECK(attempt_id='') NOT ENFORCED;"))
        if self.family != "tidb":
            def add_trigger(table):
                if self.family == "postgresql":
                    schema = table.split(".", 1)[0]
                    self.native(f"CREATE FUNCTION {schema}.p12_witness_trigger() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NEW; END$$; "
                        f"CREATE TRIGGER p12_witness_guard BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION {schema}.p12_witness_trigger();")
                else:
                    self.native(f"CREATE TRIGGER {table.split('.',1)[0]}.p12_witness_guard BEFORE INSERT ON {table} FOR EACH ROW SET NEW.native_session=NEW.native_session;")
            self.malformed(branch, "trigger", add_trigger)
        else:
            self.observations["shape_cases"].append({"case": "trigger", "result": "not_applicable", "reason": "TiDB does not implement triggers"})
        self.record("native wrong engine/logging, primary key, column length, trusted header, extra CHECK and supported trigger cases reject preparation")

    def hidden(self, branch, credentials):
        binding = self.binding(OWNER_A, branch)
        require(all(not table["logical_table"].startswith("_fg_") for table in binding["tables"]), "Witness leaked into the registered business catalog")
        with Probe(self, "hidden-witness-query", credentials) as probe:
            refused = probe.sql("SELECT attempt_id FROM _fg_txn_witness", "read")
            require(refused.get("fg") == "FG-2003", "User SQL can address the internal witness")
        status, raw = self.request("GET", f"/v1/branches/{branch['id']}/diff", self.owner_tokens[OWNER_A])
        require(status == 200 and "_fg_txn_witness" not in raw.decode(), "Witness leaked into native row diff")
        output = self.certs.parent / "witness-hidden.jsonl"
        environment = self.base_env | {"FG_CONTROL_URL": self.control_url, "FG_OWNER_TOKEN": self.owner_tokens[OWNER_A]}
        self.call("export-business-only", [self.executable("forkget"), "export", "--id", str(branch["id"]), "--output", str(output)], env=environment, timeout=90)
        require("_fg_txn_witness" not in output.read_text(), "Witness leaked into a typed business export")
        self.record("private witness remains inaccessible to user SQL and absent from catalog, native diff and typed export")

    @staticmethod
    def root_scalar(probe, sql):
        rows = probe.sql(sql, "read").get("rows")
        require(isinstance(rows, list) and len(rows) == 1 and len(rows[0]) == 1,
                "Root fault observation did not return one native scalar")
        return rows[0][0]

    @staticmethod
    def diagnostic_rows(probe, sql):
        value = probe.sql(sql, "read")
        if "rows" in value:
            return {"available": True, "rows": value["rows"]}
        return {"available": False, "errno": value.get("errno"), "sqlstate": value.get("sqlstate")}

    def gc_lock_diagnostics(self, branch, label):
        if self.family != "tidb":
            return
        relation = self.branch_relation(branch["id"], "_fg_txn_witness")
        schema, prefix = self.branch_namespace(branch["id"])
        quoted = sql_audit.p6.p5.p34.p2.data.table(self.engine, schema, prefix + "_fg_txn_witness")
        observation = {"label": label, "branch_id": branch["id"],
                       "scope": "owned fixture collector/admin sessions and this witness; no SQL text, key values or digests"}
        with NativeProbe(self, "gc-lock-diagnostic", "root") as probe:
            phase = (f"LOCATE('{quoted}',INFO)>0 OR LOCATE('{relation}',INFO)>0")
            observation["sessions"] = self.diagnostic_rows(probe,
                "SELECT CAST(ID AS SIGNED),CAST(TIME AS SIGNED),"
                "CASE WHEN USER='p2_gc' THEN 'collector' ELSE 'admin' END,"
                "CASE WHEN COMMAND='Sleep' THEN 'idle' WHEN STATE LIKE '%lock%' THEN 'lock_wait' "
                "WHEN STATE LIKE '%transaction%' THEN 'transaction' ELSE 'other' END,"
                f"CASE WHEN INFO IS NULL THEN 'idle' WHEN ({phase}) AND LOCATE('FOR UPDATE',INFO)>0 THEN 'header_lock' "
                f"WHEN ({phase}) AND INFO LIKE 'SELECT attempt_id FROM %' THEN 'transactional_header_guard' "
                f"WHEN ({phase}) AND INFO LIKE 'DELETE %' THEN 'witness_delete' "
                f"WHEN ({phase}) AND INFO LIKE 'SELECT %' THEN 'witness_identity_read' "
                f"WHEN ({phase}) AND INFO LIKE 'SHOW CREATE TABLE %' THEN 'witness_definition' "
                "WHEN INFO='COMMIT' THEN 'commit' WHEN INFO='BEGIN' THEN 'begin' ELSE 'other_native_command' END "
                "FROM information_schema.PROCESSLIST WHERE USER IN ('p2_gc','"
                + sql_audit.p6.p5.p34.ADMIN + "') ORDER BY ID")
            columns = {}
            for table in ("TIDB_TRX", "DATA_LOCK_WAITS", "METADATA_LOCK_INFO"):
                value = self.diagnostic_rows(probe, "SELECT UPPER(COLUMN_NAME) FROM information_schema.COLUMNS "
                    f"WHERE TABLE_SCHEMA='information_schema' AND UPPER(TABLE_NAME)='{table}'")
                columns[table] = {row[0] for row in value.get("rows", [])}
            sessions = [row[0] for row in observation["sessions"].get("rows", [])]
            if {"ID", "START_TIME", "STATE", "SESSION_ID"} <= columns["TIDB_TRX"] and sessions:
                identifiers = ",".join(str(int(value)) for value in sessions)
                waiting = "CAST(WAITING_START_TIME AS CHAR)" if "WAITING_START_TIME" in columns["TIDB_TRX"] else "NULL"
                observation["transactions"] = self.diagnostic_rows(probe,
                    f"SELECT CAST(ID AS CHAR),CAST(START_TIME AS CHAR),CAST(SESSION_ID AS SIGNED),{waiting},"
                    "CASE WHEN STATE='LockWaiting' THEN 'lock_waiting' WHEN STATE='Running' THEN 'running' "
                    "WHEN STATE='Idle' THEN 'idle' WHEN STATE='Committing' THEN 'committing' "
                    "WHEN STATE='RollingBack' THEN 'rolling_back' ELSE 'other' END "
                    f"FROM information_schema.TIDB_TRX WHERE SESSION_ID IN ({identifiers})")
            else:
                observation["transactions"] = {"available": False, "reason": "view_shape_or_sessions_unavailable"}
            table_id = self.root_scalar(probe, "SELECT CAST(TIDB_TABLE_ID AS SIGNED) FROM information_schema.TABLES "
                f"WHERE TABLE_SCHEMA='{schema}' AND TABLE_NAME='{prefix}_fg_txn_witness'")
            if {"TRX_ID", "CURRENT_HOLDING_TRX_ID", "KEY_INFO"} <= columns["DATA_LOCK_WAITS"]:
                observation["lock_waits"] = self.diagnostic_rows(probe,
                    "SELECT CAST(TRX_ID AS CHAR),CAST(CURRENT_HOLDING_TRX_ID AS CHAR) "
                    "FROM information_schema.DATA_LOCK_WAITS "
                    f"WHERE CAST(JSON_UNQUOTE(JSON_EXTRACT(KEY_INFO,'$.table_id')) AS UNSIGNED)={int(table_id)}")
            else:
                observation["lock_waits"] = {"available": False, "reason": "view_shape_unavailable"}
            if {"JOB_ID", "SESSION_ID", "DB_NAME", "TABLE_NAME"} <= columns["METADATA_LOCK_INFO"]:
                observation["metadata_lock_waits"] = self.diagnostic_rows(probe,
                    "SELECT CAST(JOB_ID AS SIGNED),CAST(SESSION_ID AS SIGNED) FROM information_schema.METADATA_LOCK_INFO "
                    f"WHERE DB_NAME='{schema}' AND TABLE_NAME='{prefix}_fg_txn_witness'")
            else:
                observation["metadata_lock_waits"] = {"available": False, "reason": "view_shape_unavailable"}
            observation["native_witness_rows"] = self.root_scalar(probe,
                f"SELECT COUNT(*) FROM {relation} WHERE attempt_id<>''")
            observation["header_rows"] = self.root_scalar(probe,
                f"SELECT COUNT(*) FROM {relation} WHERE attempt_id=''")
        rows = self.journal(branch)
        observation["journal"] = [{key: row[key] for key in ("outcome", "resolution", "witness_collected", "decisions", "outcomes")}
                                   for row in rows]
        self.observations.setdefault("collector_lock_diagnostics", []).append(observation)
        json_file(self.report / "collector-lock-diagnostics.json", self.observations["collector_lock_diagnostics"])
        return observation

    def lock_fault_ddl(self, branch):
        schema, prefix = self.branch_namespace(branch["id"])
        relation = self.branch_relation(branch["id"], "_fg_txn_witness")
        quote = sql_audit.p6.p5.p34.p2.data.table
        sentinel = quote(self.engine, schema, f"p12_gc_canary_{branch['id']}")
        trigger = quote(self.engine, schema, f"p12_gc_trigger_{branch['id']}")
        if self.family == "mysql":
            self.native(f"CREATE TABLE {sentinel} (id INT NOT NULL) ENGINE=MyISAM;")
            return {"statement": f"CREATE TRIGGER {trigger} BEFORE DELETE ON {relation} "
                                  f"FOR EACH ROW INSERT INTO {sentinel} VALUES (1)",
                    "restore": f"DROP TRIGGER IF EXISTS {trigger}; DROP TABLE {sentinel};",
                    "sentinel": sentinel, "table": prefix + "_fg_txn_witness", "schema": schema}
        require(self.native("SELECT @@GLOBAL.tidb_enable_metadata_lock;") == "1",
                "TiDB collector fault requires real native metadata locking")
        return {"statement": f"ALTER TABLE {relation} ADD COLUMN p12_gc_lock_probe INT NULL",
                "restore": f"ALTER TABLE {relation} DROP COLUMN p12_gc_lock_probe;",
                "sentinel": None, "table": prefix + "_fg_txn_witness", "schema": schema}

    def cut_collector_connections(self, operator, relay, ddl):
        require(relay.at_delete.wait(8), "Native collector did not reach its exact witness DELETE")
        require(relay.collector_began and relay.collector_read_header and not relay.admin_before_collector_lock
                and len(relay.admin_ids) == 1,
                "Collector did not own its transaction/header lock before independent admin attestation")
        admin_id = next(iter(relay.admin_ids))
        require(admin_id != relay.collector_id, "Attestation and destructive collector share a connection")
        require(self.root_scalar(operator, f"SELECT COUNT(*) FROM {relay.relation.decode()} WHERE attempt_id<>''") == 1,
                "Collector cut lacks a retained native witness")
        granted = None
        if self.family == "mysql":
            granted = self.root_scalar(operator, "SELECT COUNT(*) FROM performance_schema.metadata_locks m "
                "JOIN performance_schema.threads t ON t.THREAD_ID=m.OWNER_THREAD_ID "
                f"WHERE t.PROCESSLIST_ID={relay.collector_id} AND m.OBJECT_SCHEMA='{ddl['schema']}' "
                f"AND m.OBJECT_NAME='{ddl['table']}' AND m.LOCK_STATUS='GRANTED'")
            require(granted > 0, "The destructive collector has no granted lock on its exact witness")
        check_count(operator, f"KILL CONNECTION {admin_id}", 0)
        admin_present = self.root_scalar(operator, f"SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE ID={admin_id}")
        require(admin_present == 0, "The owned native administrator survived KILL CONNECTION")
        return {"collector_session_id": relay.collector_id, "killed_admin_session_id": admin_id,
                "killed_admin_still_present": admin_present,
                "collector_granted_metadata_locks": granted,
                "collector_guard_kind": "select_for_update" if self.family == "mysql" else "transactional_mdl_read",
                "collector_begin_and_header_lock_before_attestation": True}

    def queue_collector_ddl(self, operator, ddl_probe, context):
        ddl_id = self.root_scalar(ddl_probe, "SELECT CONNECTION_ID()")
        ddl_probe.send(context["statement"])
        wait_until("actual witness DDL is running", lambda: self.root_scalar(operator,
            f"SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE ID={ddl_id} AND INFO IS NOT NULL") == 1,
            seconds=2)
        require(not ddl_probe.readable(.1), "Concurrent witness DDL bypassed the collector's own transaction lock")
        return ddl_id

    def collector_lock_case(self, kill_collector):
        branch, credentials = self.create("collector-loss-" + ("collector" if kill_collector else "admin"))
        context = self.lock_fault_ddl(branch)
        original_admin = self.base_env["FG_BRANCH_ADMIN_DSN"]
        database = sql_audit.p6.p5.p34.MYSQL_WRITE_SCHEMA
        ddl_finished = False
        self.stop("control")
        relay = None
        evidence = {"kill_collector": kill_collector, "engine": self.engine, "phase": "starting"}
        self.observations.setdefault("collector_lock_loss", []).append(evidence)
        try:
            with CollectorLockRelay(self, branch) as relay:
                self.base_env["FG_BRANCH_ADMIN_DSN"] = self.dsn(sql_audit.p6.p5.p34.ADMIN,
                    self.secret["branch_admin"], relay.port, database)
                with NativeProbe(self, "collector-cut-root", "root") as operator, NativeProbe(
                        self, "collector-cut-ddl", "root") as ddl_probe:
                    self.start_control_through(relay)
                    with Probe(self, "collector-cut-committed-business", credentials) as probe:
                        check_count(probe, self.insert(860), 1)
                    evidence |= self.cut_collector_connections(operator, relay, context)
                    require(len(self.journal(branch)) == 1 and not self.journal(branch)[0]["witness_collected"],
                            "Metadata marked witness collection before the native DELETE/COMMIT boundary")
                    evidence["phase"] = "admin_killed_collector_lock_held"
                    evidence["ddl_session_id"] = self.queue_collector_ddl(operator, ddl_probe, context)
                    evidence["phase"] = "concurrent_ddl_blocked"
                    if kill_collector:
                        if self.family == "tidb":
                            evidence["collector_transaction_before_kill"] = self.diagnostic_rows(operator,
                                "SELECT CAST(ID AS CHAR),CAST(START_TIME AS CHAR),CAST(SESSION_ID AS SIGNED) "
                                f"FROM information_schema.TIDB_TRX WHERE SESSION_ID={relay.collector_id}")
                        check_count(operator, f"KILL CONNECTION {relay.collector_id}", 0)
                        collector_present = self.root_scalar(operator,
                            f"SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE ID={relay.collector_id}")
                        require(collector_present == 0, "The owned native collector survived KILL CONNECTION")
                        evidence["killed_collector_still_present"] = collector_present
                        if self.family == "tidb":
                            evidence["collector_transaction_after_kill"] = self.diagnostic_rows(operator,
                                "SELECT CAST(ID AS CHAR),CAST(START_TIME AS CHAR),CAST(SESSION_ID AS SIGNED) "
                                f"FROM information_schema.TIDB_TRX WHERE SESSION_ID={relay.collector_id}")
                        require(ddl_probe.readable(2), "Witness DDL stayed blocked after both owned lock sessions died")
                        require(ddl_probe.receive().get("affected") == 0, "Concurrent native witness DDL did not complete")
                        ddl_finished = True
                    evidence["delete_pause_ms"] = (time.monotonic() - relay.pause_started) * 1000
                    relay.continue_delete.set()
                    evidence["phase"] = "original_delete_released"
                    if kill_collector:
                        require(relay.collector_closed.wait(3), "The killed collector silently changed its native connection")
                        self.stop("control")
                        row = self.journal(branch)[0]
                        require(not row["witness_collected"] and self.witness_count(branch) == 1,
                                "A dead collector executed cleanup or marked its retained witness collected")
                        require(relay.delete_executions == relay.delete_successes == relay.commit_successes == 0,
                                "The killed collector retried DELETE/COMMIT on a fresh native connection")
                    else:
                        require(relay.delete_complete.wait(3), "The surviving collector did not execute its original DELETE")
                        wait_until("collector commit acknowledged before metadata mark", lambda:
                                   self.journal(branch)[0]["witness_collected"], seconds=3)
                        require(ddl_probe.readable(2), "Witness DDL remained blocked after collector COMMIT")
                        require(ddl_probe.receive().get("affected") == 0, "Native DDL failed after the collector released its lock")
                        ddl_finished = True
                        self.stop("control")
                        require(relay.delete_executions == relay.delete_successes == relay.commit_successes == 1
                                and self.witness_count(branch) == 0,
                                "Surviving collector omitted or retried native DELETE/COMMIT")
                    sentinel_rows = (self.root_scalar(operator, f"SELECT COUNT(*) FROM {context['sentinel']}")
                                     if context["sentinel"] else None)
                    require(sentinel_rows in (None, 0), "Concurrent DELETE trigger caused a nontransactional native side effect")
                    rows = self.journal(branch)
                    require(len(rows) == 1 and rows[0]["outcome"] == "committed"
                            and rows[0]["decisions"] == rows[0]["outcomes"] == 1
                            and self.native_count(branch, 860) == 1 and relay.business_executions == 0,
                            "Collector lock loss changed the committed fact or replayed business DML")
                    evidence |= {"concurrent_ddl_blocked_after_admin_loss": True,
                        "ddl_completed_after_collector_release": True,
                        "native_delete_executions": relay.delete_executions,
                        "native_delete_successes": relay.delete_successes,
                        "native_commit_successes": relay.commit_successes,
                        "metadata_witness_collected": rows[0]["witness_collected"],
                        "retained_witness_rows": self.witness_count(branch), "myisam_sentinel_rows": sentinel_rows,
                        "later_delete_connections_held": relay.later_delete_connections,
                        "business_dml_retries": relay.business_executions, "unique_committed_outcome": True,
                        "phase": "verified"}
                    if kill_collector:
                        diagnosis = self.gc_lock_diagnostics(branch, "killed_collector_before_shape_restore")
                        if self.family == "tidb":
                            require(diagnosis["lock_waits"] == {"available": True, "rows": []},
                                    "A dead TiDB collector left a pessimistic witness-header lock wait")
                            evidence["no_pessimistic_header_lock_wait_after_kill"] = True
                json_file(self.report / "collector-lock-loss.json", self.observations["collector_lock_loss"])
        finally:
            if relay is not None:
                relay.continue_delete.set()
                evidence["final_observed_counters"] = {"delete_executions": relay.delete_executions,
                    "delete_successes": relay.delete_successes, "commit_successes": relay.commit_successes,
                    "business_executions": relay.business_executions,
                    "later_delete_connections_held": relay.later_delete_connections}
                evidence["observer_socket_options"] = relay.socket_options
            json_file(self.report / "collector-lock-loss.json", self.observations["collector_lock_loss"])
            self.stop("control")
            self.base_env["FG_BRANCH_ADMIN_DSN"] = original_admin
            if self.family == "mysql" or ddl_finished:
                self.native(context["restore"])
            recovery_started = time.monotonic()
            self.start_control()
        if kill_collector:
            try:
                wait_until("fresh safe recovery collects the retained witness", lambda:
                           self.journal(branch)[0]["witness_collected"], seconds=10)
                evidence["fresh_recovery_elapsed_ms"] = (time.monotonic() - recovery_started) * 1000
                evidence["fresh_recovery_witness_collected"] = True
                if self.family == "tidb":
                    self.gc_lock_diagnostics(branch, "fresh_recovery_succeeded_within_10_second_wait")
            except sql_audit.p6.p5.p34.p2.Failure:
                evidence["fresh_recovery_witness_collected"] = False
                self.gc_lock_diagnostics(branch, "fresh_recovery_failed_after_10_seconds")
                raise
            finally:
                json_file(self.report / "collector-lock-loss.json", self.observations["collector_lock_loss"])
        self.drop(OWNER_A, branch["id"])
        self.record("collector-owned native lock survives admin loss and blocks concurrent DDL; collector loss retains evidence without DELETE, metadata mark or business retry")

    def gc_interruption(self):
        branch, credentials = self.create("witness-gc-interruption")
        with Probe(self, "gc-durable-native-fact", credentials) as probe:
            check_count(probe, self.insert(830), 1)
        journal = self.settled(branch, 1)
        require(journal[0]["outcome"] == "committed" and self.native_count(branch, 830) == 1,
                "GC interruption lacks a genuinely committed and durably acknowledged fact")
        wait_until("completed witness collected before GC cut", lambda: self.journal(branch)[0]["witness_collected"])
        journal = self.journal(branch)
        # Reclaim intentionally seals the acknowledged attempts; every other
        # journal field, including outcome and event counts, must stay exact.
        reclaimed_journal = [dict(row, sealed=True) for row in journal]
        before = self.snapshot(branch)
        self.stop("control")
        original_admin = self.base_env["FG_BRANCH_ADMIN_DSN"]
        database = self.backend_database if self.family == "postgresql" else sql_audit.p6.p5.p34.MYSQL_WRITE_SCHEMA
        try:
            with WitnessDropRelay(self, branch) as relay:
                self.base_env["FG_BRANCH_ADMIN_DSN"] = self.dsn(sql_audit.p6.p5.p34.ADMIN,
                    self.secret["branch_admin"], relay.port, database)
                self.start_control_through(relay)
                requested = self.cli(OWNER_A, "drop", "--id", str(branch["id"]))
                require(requested["id"] == branch["id"] and requested["status"] in ("dropping", "dropped"),
                        "GC interruption requested a different branch")
                require(relay.dropped.wait(10), "Native witness DROP did not complete at the injected reply boundary")
                # The server has dropped the witness, but its success frame never
                # reaches the controller. Stop only our process before cleanup continues.
                process = self.processes.pop("control")
                process.kill()
                process.wait(timeout=10)
                state = json.loads(self.metadata(f"""SELECT jsonb_build_object(
                    'status',b.status,'reclaim_started',b.audit_storage_reclaim_started,
                    'witness_ready',b.audit_witness_ready,'pending',
                    (SELECT count(*) FROM audit_attempt a WHERE a.branch_id=b.id AND forkget_audit_pending(a)))::text
                    FROM branch b WHERE id={branch['id']};"""))
                json_file(self.report / "gc-interrupted-state.json", state)
                require(state == {"status": "dropping", "reclaim_started": True, "witness_ready": False, "pending": 0},
                        "Interrupted physical GC did not preserve its durable reclaim gate")
                schema, prefix = self.branch_namespace(branch["id"])
                witness_exists = self.native("SELECT count(*) FROM information_schema.tables "
                    f"WHERE table_schema='{schema}' AND table_name='{prefix}_fg_txn_witness';")
                require(witness_exists == "0" and self.snapshot(branch) == before,
                        "GC cut was not between the real witness DROP and business-object removal")
                require(self.journal(branch) == reclaimed_journal, "GC interruption changed the acknowledged native fact")
                json_file(self.report / "gc-interrupted-state.json", state | {
                    "witness_exists": False, "business_rows_unchanged": True,
                    "journal_before": journal, "journal_after": reclaimed_journal})
                self.start_control_through(relay)
                self.wait_dropped(OWNER_A, branch["id"])
                require(not self.branch_storage_exists(branch["id"]) and self.journal(branch) == reclaimed_journal,
                        "Restarted GC replayed business data or failed to reclaim the owned branch")
                require(relay.drop_executions >= 2 and relay.business_executions == relay.missing_witness_reads == 0,
                        "GC restart attested the absent witness, replayed DML, or skipped idempotent witness cleanup")
                self.observations["gc_interruption"] = {"branch_id": branch["id"], "cut": "native witness DROP succeeded; original success reply withheld; own controller killed",
                    "interrupted": state, "business_rows_unchanged_at_cut": True, "final_status": "dropped",
                    "witness_drop_executions": relay.drop_executions, "business_dml_executions": relay.business_executions,
                    "missing_witness_reads": relay.missing_witness_reads, "durable_journal_unchanged": True}
        finally:
            self.base_env["FG_BRANCH_ADMIN_DSN"] = original_admin
            self.stop("control")
            self.start_control()
        self.record("physical witness DROP with lost ACK and controller crash resumes from durable reclaim gate without missing-witness attestation or business replay")

    def start_control_through(self, relay):
        native_port = self.native_port
        try:
            # Collector and administrator must retain one authoritative endpoint.
            self.native_port = relay.port
            self.start_control()
        finally:
            self.native_port = native_port

    def untrusted_restore(self, branch, credentials):
        old = self.identity(branch)["storage_incarnation"]
        self.outcomes.blocked.set()
        try:
            with Probe(self, "untrusted-pending-fact", credentials) as probe:
                check_count(probe, self.insert(820), 1)
            pending = [row for row in self.journal(branch) if row["outcome"] is None]
            require(len(pending) == 1, "Untrusted-history fixture lacks one genuine pending native fact")
            attempt = pending[0]["id"]
            require(self.native_count(branch, 820) == 1, "Pending fact has no durable native business row")
            self.stop("control")
            self.stop("proxy")
            before_restore = self.snapshot(branch)
            # Simulate native PITR losing witness history with both processes
            # stopped. Invalidation must precede any new controller's recovery.
            self.native(f"DELETE FROM {self.branch_relation(branch['id'], '_fg_txn_witness')} WHERE attempt_id<>'';")
            require(not self.processes and self.snapshot(branch) == before_restore,
                    "Restore fault did not preserve business rows with services offline")
            self.operator("invalidate-untrusted-history", "invalidate-storage", "--id", str(branch["id"]), "--operator", "p12-fixture")
            invalidated = self.metadata(f"SELECT audit_storage_invalidated::int||':'||audit_witness_ready::int FROM branch WHERE id={branch['id']};")
            row = next(row for row in self.journal(branch) if row["id"] == attempt)
            self.observations["untrusted_restore"] = {"attempt_id": attempt, "offline_state": invalidated,
                "offline_journal": row, "business_unchanged": self.snapshot(branch) == before_restore}
            require(invalidated == "1:0" and row["outcome"] == "unknown" and row["resolution"] is None
                    and self.snapshot(branch) == before_restore and not self.processes,
                    "Offline invalidation trusted lost history, changed business data, or started a new process")
        finally:
            self.outcomes.blocked.clear()
        self.start_control()
        self.start_proxy()
        with Probe(self, "untrusted-retained-read-only", credentials) as probe:
            require(probe.sql("SELECT id FROM parents WHERE id=820", "read").get("rows") == [[820]],
                    "The unprepared restored branch lost read access to retained data")
            require(probe.sql(self.insert(822)).get("fg") == "FG-5001", "Unprepared restored storage allowed a write")
        self.operator("reconcile-untrusted-history", "reconcile")
        row = next(row for row in self.journal(branch) if row["id"] == attempt)
        require(row["outcome"] == "unknown" and row["resolution"] is None, "Lost native history fabricated rollback or commit proof")
        self.generation_command("normal-prepare-untrusted-refused", "audit", "prepare", succeeds=False)
        replace = ("audit", "prepare", "--replace-untrusted", "--id", str(branch["id"]), "--operator", "p12-fixture")
        self.generation_command("replace-before-ack-refused", *replace, succeeds=False)
        self.operator("acknowledge-durable-unknown", "acknowledge-unknown", "--attempt", attempt, "--operator", "p12-fixture")
        self.generation_command("normal-prepare-after-ack-refused", "audit", "prepare", succeeds=False)
        before = self.snapshot(branch)
        # Even complete loss of an already invalidated witness cannot turn the
        # ordinary upgrade command into permission to establish a new history.
        self.native(f"DROP TABLE {self.branch_relation(branch['id'], '_fg_txn_witness')};")
        self.generation_command("normal-prepare-missing-untrusted-refused", "audit", "prepare", succeeds=False)
        require(not self.witness_ready(branch) and self.snapshot(branch) == before,
                "Ordinary preparation silently replaced missing untrusted native storage")
        self.generation_command("replace-only-untrusted-witness", *replace)
        require(self.witness_ready(branch) and self.identity(branch)["storage_incarnation"] != old, "Explicit replacement did not create a new ready storage incarnation")
        require(self.snapshot(branch) == before, "Witness replacement rebuilt or changed business data")
        row = next(row for row in self.journal(branch) if row["id"] == attempt)
        retained = self.metadata(f"SELECT (retention_ack_event_id IS NOT NULL)::int FROM audit_attempt WHERE attempt_id='{attempt}';")
        require(row["outcome"] == "unknown" and row["resolution"] is None and retained == "1", "Operator acknowledgment rewrote unknown native history")
        with Probe(self, "new-incarnation-new-write", credentials) as probe:
            check_count(probe, self.insert(821), 1)
        require(self.native_count(branch, 820) == self.native_count(branch, 821) == 1, "Storage recovery lost existing data or rejected fresh protected work")
        self.observations["untrusted_restore"] = {"attempt_id": attempt, "historical_outcome": "unknown", "operator_acknowledged": True,
            "fault": "simulated native witness history loss while both services stopped; offline invalidation precedes new controller recovery",
            "offline_invalidation": True, "unprepared_read_preserved": True, "unprepared_write_refused": True,
            "missing_untrusted_witness_requires_explicit_replacement": True,
            "new_incarnation": self.identity(branch)["storage_incarnation"], "business_unchanged": True}
        self.record("offline invalidation after simulated native history loss preserves unknown and retained reads, refuses unprepared writes, requires acknowledgment and explicit witness replacement")

    def execute(self):
        self.verify_binaries()
        self.start_deployment()
        self.generation_command("witness-refresh-v2", "refresh", "--snapshot", "v2", cooldown=0)
        self.set_policy("dev", 50000, bps=10000, floor=100)
        branch, credentials = self.create("witness-storage")
        self.generation_command("verify-normal-native-witness", "audit", "prepare")
        require(self.witness_ready(branch), "Valid native witness failed strict preparation")
        self.permissions(branch)
        self.upgrade(branch, credentials)
        self.wrong_shapes(branch)
        self.start_control()
        self.hidden(branch, credentials)
        self.untrusted_restore(branch, credentials)
        self.drop(OWNER_A, branch["id"])
        require(not self.branch_storage_exists(branch["id"]), "Resolved storage left branch-native evidence after drop")
        if self.family in ("mysql", "tidb"):
            self.collector_lock_case(False)
            self.collector_lock_case(True)
        self.gc_interruption()
        json_file(self.report / "witness-storage.json", self.observations)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=("mysql", "postgresql", "tidb", "all"), default="all")
    parser.add_argument("--report-dir", type=Path, required=True)
    args = parser.parse_args()
    args.report_dir.mkdir(parents=True, exist_ok=False)
    started = datetime.now(UTC)
    revision, state = sql_audit.p6.p5.p34.p2.git_state()
    WitnessRun.suite_source_state = state
    results = {}
    for engine in (("mysql", "postgresql", "tidb") if args.engine == "all" else (args.engine,)):
        results[engine] = sql_audit.p6.p5.p34.run_engine(engine, args.report_dir,
            f"fgwitness-{started:%H%M%S}-{os.getpid()}", WitnessRun)
    json_file(args.report_dir / "report.json", {"status": "passed" if all(result["status"] == "passed" for result in results.values()) else "failed",
        "source_revision": revision, "source_state": state, "engines": results,
        "started_at": started.isoformat(), "finished_at": datetime.now(UTC).isoformat()})
    return 0 if all(result["status"] == "passed" for result in results.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
