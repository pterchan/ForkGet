#!/usr/bin/env python3
"""Real standalone MongoDB audit fault cuts over verified TLS; no business retries."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime
from http.client import HTTPConnection
import importlib.util
import json
import os
from pathlib import Path
import secrets
import select
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
from threading import Event
from types import SimpleNamespace
import time
from urllib.parse import urlsplit
import urllib.error
import urllib.request

import pymongo
from bson import BSON, SON

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import sql_audit
from run_p2 import json_file, require, wait_until

OBSERVATION_FIELDS = {"state", "matched", "modified", "inserted", "deleted", "upserted", "error_count", "native_code"}


class AuditRelay(sql_audit.ControlRelay):
    """Fault only real audit responses, retaining their complete metadata facts."""

    def __init__(self, run):
        super().__init__(run, lambda *_args: False)
        self.block_outcome = Event()
        self.block_status = Event()
        self.hold_arm = Event()
        self.arm_seen = Event()
        self.release_arm = Event()
        self.drop_step = None
        self.cuts = 0

    def forward(self, handler):
        try:
            request = self.request_body(handler)
            blocked = ((self.block_outcome.is_set() and handler.path.endswith("/audit/outcome"))
                       or (self.block_status.is_set() and handler.path.endswith("/audit/status")))
            if blocked:
                status, body, content_type = 503, b"", "application/json"
            else:
                origin = urlsplit(self.run.control_url)
                headers = {key: value for key, value in handler.headers.items()
                           if key.lower() not in {"host", "content-length", "transfer-encoding", "connection"}}
                headers["Content-Length"] = str(len(request))
                with closing(HTTPConnection(origin.hostname, origin.port, timeout=60)) as upstream:
                    upstream.request(handler.command, handler.path, body=request, headers=headers)
                    response = upstream.getresponse()
                    status, body = response.status, response.read()
                    content_type = response.getheader("Content-Type", "application/json")
            if status == 200 and handler.path.endswith("/audit/mongo-step"):
                ordinal = json.loads(body)["armed_step"]
                cut = self.drop_step == ordinal
                if self.hold_arm.is_set() and ordinal == 1:
                    self.arm_seen.set()
                    require(self.release_arm.wait(40), "The armed native-send cut was not released")
                    cut = True
                if cut:
                    self.cuts += 1
                    handler.close_connection = True
                    try:
                        handler.connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        # This exact injected ACK is also allowed to lose its
                        # downstream socket when the real drain already closed it.
                        pass
                    return
            handler.send_response(status)
            handler.send_header("Content-Type", content_type)
            handler.send_header("Content-Length", str(len(body)))
            handler.end_headers()
            handler.wfile.write(body)
        except (OSError, ValueError, RuntimeError) as error:
            self.errors.append(type(error).__name__)
            handler.close_connection = True


class MongoRelay(sql_audit.NativeRelay):
    """Preserve actual Mongo wire frames, cutting only a selected complete ACK."""

    def __init__(self, run):
        super().__init__(run, "mongo-audit")
        self.target = None
        self.drop_ack = Event()
        self.ack_seen = Event()
        self.release_ack = Event()
        self.native_writes = 0
        self.last_reply = None

    def start_tls(self, _client, _server):
        # Mongo starts TLS immediately; the inherited connection verifies both legs.
        return

    @staticmethod
    def document(frame):
        if int.from_bytes(frame[12:16], "little", signed=True) != 2013:
            return None
        require(frame[20:21] == b"\0", "Unexpected native Mongo document section")
        size = int.from_bytes(frame[21:25], "little", signed=True)
        require(size >= 5 and size + 21 == len(frame), "Native Mongo reply is not one complete document")
        return BSON(frame[21:]).decode()

    def forward(self, client, server):
        outstanding = set()
        buffers = {client: bytearray(), server: bytearray()}
        wants_write = set()
        try:
            while not self.done.is_set():
                readable = [stream for stream in (client, server)
                            if stream not in wants_write and stream.pending()]
                if not readable:
                    readable, writable, _ = select.select(
                        [stream for stream in (client, server) if stream not in wants_write],
                        list(wants_write), [], .05)
                    readable += writable
                for source in readable:
                    buffer = buffers[source]
                    length = 16 if len(buffer) < 16 else int.from_bytes(buffer[:4], "little", signed=True)
                    require(16 <= length <= 16 * 1024 * 1024, "Unexpected native Mongo frame size")
                    previous_timeout = source.gettimeout()
                    try:
                        # TLS control records can make select readable without
                        # application bytes. Never block the opposite direction.
                        source.setblocking(False)
                        try:
                            data = source.recv(min(length - len(buffer), 65536))
                        except ssl.SSLWantReadError:
                            wants_write.discard(source)
                            continue
                        except ssl.SSLWantWriteError:
                            wants_write.add(source)
                            continue
                    finally:
                        source.settimeout(previous_timeout)
                    wants_write.discard(source)
                    if not data:
                        return
                    buffer.extend(data)
                    if len(buffer) < 16:
                        continue
                    length = int.from_bytes(buffer[:4], "little", signed=True)
                    require(16 <= length <= 16 * 1024 * 1024, "Unexpected native Mongo frame size")
                    if len(buffer) < length:
                        continue
                    frame = bytes(buffer)
                    buffer.clear()
                    header = frame[:16]
                    document = self.document(frame)
                    if source is client:
                        if document is not None:
                            verb = next(iter(document), "")
                            target = (document.get("$db"), document.get(verb))
                            if verb in ("insert", "update", "delete") and target == self.target:
                                with self.lock:
                                    self.native_writes += 1
                                outstanding.add(int.from_bytes(header[4:8], "little", signed=True))
                        server.sendall(frame)
                    else:
                        correlation = int.from_bytes(header[8:12], "little", signed=True)
                        if correlation in outstanding:
                            require(document is not None, "Native Mongo ACK omitted its full document")
                            outstanding.remove(correlation)
                            with self.lock:
                                self.last_reply = frame[21:]
                            if self.drop_ack.is_set():
                                self.drop_ack.clear()
                                self.ack_seen.set()
                                require(self.release_ack.wait(30), "The real native ACK cut was not released")
                                return
                        client.sendall(frame)
        except OSError:
            return
        except (ValueError, sql_audit.p6.p5.p34.p2.Failure) as error:
            self.errors.append(type(error).__name__)


READINESS_BUDGET_SECONDS = 30
READINESS_PROBE_SECONDS = 1
READINESS_RETRY_SECONDS = .1


def poll_process_readiness(context):
    observation = {"stage": context.name, "pid": context.process.pid,
                   "build_revision": context.revision, "outcome": "pending", "exception_type": None}
    try:
        code = context.process.poll()
        if code is not None:
            observation.update(outcome="process_exited", exit_code=code)
        require(code is None, context.name + " exited before readiness")
        remaining = context.deadline - time.monotonic()
        if remaining <= 0:
            observation["outcome"] = "deadline"
            return False
        with urllib.request.urlopen(context.url, timeout=min(READINESS_PROBE_SECONDS, remaining)) as response:
            observation["status"] = response.status
        completed = time.monotonic()
        ready = observation["status"] == 204 and completed <= context.deadline
        observation["outcome"] = "ready" if ready else "deadline" if completed > context.deadline else "pending"
        return ready
    except (urllib.error.URLError, TimeoutError) as error:
        observation["exception_type"] = type(error).__name__
        return False
    except Exception as error:
        observation["exception_type"] = type(error).__name__
        raise
    finally:
        observation["elapsed_ms"] = (time.monotonic() - context.started) * 1000
        context.observations.append(observation)
        json_file(context.report / "readiness.json", context.observations)


def wait_process_readiness(context):
    while time.monotonic() < context.deadline:
        if poll_process_readiness(context):
            return
        remaining = context.deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(READINESS_RETRY_SECONDS, remaining))
    require(False, "Timed out: " + context.name + " readiness")


class MongoRun:
    verify_binaries = sql_audit.AuditRun.verify_binaries

    def __init__(self, report):
        self.report = report
        self.bin_dir = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")) / "release"
        self.suite_source_state = sql_audit.p6.p5.p34.p2.git_state()[1]
        self.processes, self.checks = {}, []
        self.secret = {name: secrets.token_hex(24) for name in ("mongo", "postgres", "mysql", "service", "collector", "owner", "internal", "frontend")}
        self.environment = {key: value for key, value in os.environ.items() if not key.startswith("FG_")}
        self.private_note = "private-bson-canary-" + secrets.token_hex(12)
        self.temporary = tempfile.TemporaryDirectory(prefix="forkget-p12-mongo-", dir=Path.home())
        self.work = Path(self.temporary.name)
        self.project = "fgp12audit-" + str(os.getpid()) + "-" + secrets.token_hex(4)
        self.clients = []

    def executable(self, name):
        return self.bin_dir / name

    def safe(self, value):
        for secret in (*self.secret.values(), self.private_note):
            value = value.replace(secret, "[redacted]")
        return value

    def call(self, label, arguments, env=None, **_options):
        result = subprocess.run([str(value) for value in arguments], cwd=ROOT, env=env or self.environment,
                                capture_output=True, text=True, timeout=120)
        (self.report / (label + ".log")).write_text(self.safe(result.stdout + result.stderr))
        require(result.returncode == 0, label + " failed; see sanitized log")
        return result.stdout.strip()

    def binary(self, label, executable, *arguments):
        raw = self.call(label, [self.executable(executable), *arguments])
        if executable == "fg-control" and arguments[0] in ("migrate", "bootstrap", "refresh"):
            return None
        return json.loads(raw) if raw else None

    def metadata(self, query):
        return self.p2.psql("postgres", query)

    def request(self, method, path, body=None, internal=False):
        token = self.secret["internal" if internal else "owner"]
        base = self.drain_url if internal else self.control_url
        request = urllib.request.Request(base + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()

    def record(self, label, evidence):
        json_file(self.report / (label + ".json"), evidence)
        self.checks.append(label)
        print("[PASS] mongodb: " + label, flush=True)

    def start(self, name):
        env = dict(self.environment)
        if name == "proxy":
            env["FG_CONTROL_URL"] = self.audit.url
            env["FG_BACKEND_DSN"] = f"mongodb://fg_service:{self.secret['service']}@127.0.0.1:{self.relay.port}/admin"
        output = (self.report / (name + ".log")).open("ab")
        try:
            self.processes[name] = subprocess.Popen([self.executable("fg-" + name), *(["serve"] if name == "control" else [])],
                cwd=ROOT, env=env, stdout=output, stderr=subprocess.STDOUT)
        finally:
            output.close()
        url = self.control_url if name == "control" else self.drain_url
        path = "/health/ready" if name == "control" else "/healthz"
        if not hasattr(self, "readiness_observations"):
            self.readiness_observations = []
        started = time.monotonic()
        wait_process_readiness(SimpleNamespace(name=name, process=self.processes[name], url=url + path,
            revision=self.process_revision(name), started=started, deadline=started + READINESS_BUDGET_SECONDS,
            observations=self.readiness_observations, report=self.report))

    def process_revision(self, name):
        if getattr(self, "old", False):
            revisions = self.baseline.revisions
        else:
            revisions = json.loads((self.report / "binaries.json").read_text())["revisions"]
        revision = revisions["fg-" + name]
        require(isinstance(revision, str) and len(revision) == 40
                and all(character in "0123456789abcdef" for character in revision),
                "Readiness requires the selected process's full preflight build revision")
        return revision

    def stop(self, name):
        process = self.processes.pop(name, None)
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=8)

    def client(self, branch):
        uri = f"mongodb://alice:{self.secret['frontend']}@127.0.0.1:{self.proxy_port}/{branch['name']}?authSource=admin&directConnection=true"
        client = pymongo.MongoClient(uri, tls=True, tlsCAFile=str(self.certs / "ca.pem"),
            serverSelectionTimeoutMS=5000, socketTimeoutMS=15000, retryReads=False, retryWrites=False, maxPoolSize=1)
        self.clients.append(client)
        return client

    def branch(self, name, legacy=False):
        if legacy:
            self.metadata("INSERT INTO branch(name,class,generation_id,created_by,expires_at,status,access,layout,read_strategy) "
                f"SELECT '{name}','dev',id,'alice',clock_timestamp()+interval '1 hour','active','read_write','sparse_delta','merge' "
                "FROM generation WHERE status='active' AND engine='mongodb';")
            raw = self.metadata(f"SELECT id FROM branch WHERE name='{name}';")
            branch = {"id": int(raw), "name": name}
        else:
            branch = self.binary("fork-" + name, "forkget", "fork", name, "--write")
            wait_until("native Mongo branch activation", lambda: self.metadata(f"SELECT status FROM branch WHERE id={branch['id']}") == "active")
        return branch

    def journal(self, branch):
        value = self.metadata(f"""SELECT COALESCE(jsonb_agg(jsonb_build_object(
            'id',a.attempt_id,'outcome',a.outcome,'payload',a.outcome_payload,'late',a.late_payload,
            'sealed',a.sealed,'quiescent',a.quiescence_confirmed,'armed',a.armed_step,
            'steps',(SELECT COALESCE(jsonb_agg(jsonb_build_object('step',s.step,'observation',s.observation) ORDER BY s.step),'[]'::jsonb)
                     FROM audit_mongo_step s WHERE s.attempt_id=a.attempt_id)) ORDER BY a.created_at),'[]'::jsonb)::text
            FROM audit_attempt a WHERE a.branch_id={branch['id']};""")
        rows = json.loads(value)
        require(self.private_note not in value, "Audit metadata exposed a private BSON value")
        for row in rows:
            observations = [payload.get("mongo") for payload in (row["payload"], row["late"]) if payload]
            observations.extend(step["observation"] for step in row["steps"] if step["observation"])
            for observation in observations:
                require(set(observation) <= OBSERVATION_FIELDS, "Mongo audit stored a native document or error message")
                require(all(value is None or isinstance(value, int) for key, value in observation.items() if key != "state"),
                        "Mongo audit observation contains a nonnumeric native fact")
        return rows

    def paused(self):
        status, body = self.request("GET", "/internal/v1/audit-health", internal=True)
        require(status == 200, "Proxy write-delivery health was unavailable")
        return json.loads(body)["protected_writes_paused"]

    def reconcile(self, label):
        return self.binary(label, "fg-control", "audit", "reconcile")

    def setup(self):
        self.verify_binaries()
        ports = []
        for _ in range(5):
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                ports.append(listener.getsockname()[1])
        pg, self.native_port, control, self.proxy_port, drain = ports
        self.control_url, self.drain_url = f"http://127.0.0.1:{control}", f"http://127.0.0.1:{drain}"
        os.environ.update(COMPOSE_PROJECT_NAME=self.project, MONGO_PORT=str(self.native_port), POSTGRES_PORT=str(pg),
            FG_TEST_MYSQL_ROOT_PASSWORD=self.secret["mysql"], FG_TEST_POSTGRES_PASSWORD=self.secret["postgres"],
            FG_TEST_MONGO_ROOT_PASSWORD=self.secret["mongo"])
        for key in ("FG_TRANSPORT_TEST_HOST", "FG_MANAGED_BACKEND_HOST"):
            os.environ.pop(key, None)
        spec = importlib.util.spec_from_file_location("p12_mongo_fixture", ROOT / "test/p2/mongo.py")
        self.p2 = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.p2)
        self.p2.COMPOSE = ["docker", "compose", "--project-name", self.project, "--file", str(ROOT / "test/local/docker-compose.yml")]
        self.p2.configure_tls(self.report)
        self.certs = Path(self.p2.TLS_DIRECTORY.name)
        for source, target in (("server.pem", "native.pem"), ("server.key", "native.key"), ("ca.pem", "backend-ca.pem")):
            shutil.copyfile(self.certs / source, self.certs / target)
        self.p2.run(self.p2.COMPOSE + ["up", "-d", "mongo", "postgres"])
        self.p2.wait_healthy("mongo-7")
        self.p2.wait_healthy("postgres-16")
        uri = f"mongodb://root:{self.secret['mongo']}@127.0.0.1:{self.native_port}/admin?directConnection=true"
        self.native = pymongo.MongoClient(uri, tls=True, tlsCAFile=str(self.certs / "ca.pem"), serverSelectionTimeoutMS=5000)
        for user, key in (("fg_service", "service"), ("fg_gc", "collector")):
            self.native.admin.command("createUser", user, pwd=self.secret[key], roles=[])
        self.environment.update(FG_META_DSN=f"postgres://fg_test:{self.secret['postgres']}@127.0.0.1:{pg}/postgres",
            FG_BACKEND_ADMIN_DSN=uri.split("?")[0], FG_BACKEND_GC_DSN=f"mongodb://fg_gc:{self.secret['collector']}@127.0.0.1:{self.native_port}/admin",
            FG_BACKEND_DSN=f"mongodb://fg_service:{self.secret['service']}@127.0.0.1:{self.native_port}/admin",
            FG_BACKEND_CA=str(self.certs / "ca.pem"), FG_BACKEND_SERVICE_USER="fg_service", FG_BACKEND_GC_USER="fg_gc",
            FG_REFRESH_COOLDOWN_SECONDS="0", FG_INTERNAL_TOKEN=self.secret["internal"],
            FG_CONTROL_ACCOUNTS=json.dumps([{"user": "alice", "token": self.secret["owner"], "expires_at": 9999999999, "policy_admin": True}]),
            FG_CONTROL_LISTEN=f"127.0.0.1:{control}", FG_PROXY_CONTROL_URL=self.drain_url, FG_CONTROL_URL=self.control_url, FG_OWNER_TOKEN=self.secret["owner"],
            FG_LISTEN_MONGO=f"127.0.0.1:{self.proxy_port}", FG_PROXY_CONTROL_LISTEN=f"127.0.0.1:{drain}",
            FG_TLS_CERT=str(self.certs / "server.pem"), FG_TLS_KEY=str(self.certs / "server.key"),
            FG_FRONTEND_ACCOUNTS=json.dumps([{"user": "alice", "password": self.secret["frontend"], "expires_at": 9999999999}]),
            FG_STATE_DIR=str(self.work / "private-state"))
        for label, arguments in (("migrate", ("migrate",)), ("bootstrap", ("bootstrap",)), ("refresh", ("refresh", "--snapshot", "v2"))):
            self.binary(label, "fg-control", *arguments)
        self.audit = AuditRelay(self)
        self.audit.__enter__()
        self.relay = MongoRelay(self)
        self.relay.__enter__()
        self.start("control")
        self.start("proxy")
        status, body = self.request("GET", "/v1/policies/dev")
        require(status == 200, "Mongo default policy was unavailable")
        status, _body = self.request("PUT", "/v1/policies/dev", {"expected_version": json.loads(body)["version"],
            "max_transaction_rows": 1000, "table_limit_bps": 10000, "small_table_floor": 100, "approval_after_rows": None})
        require(status == 200, "Mongo fixture policy refused its finite small batches")

    def cleanup(self):
        relay_errors = []
        for client in self.clients:
            client.close()
        for name in ("proxy", "control"):
            self.stop(name)
        if hasattr(self, "native"):
            self.native.close()
        for name in ("audit", "relay"):
            if hasattr(self, name):
                relay = getattr(self, name)
                if name == "audit":
                    relay.release_arm.set()
                else:
                    relay.release_ack.set()
                try:
                    relay.__exit__(None, None, None)
                except Exception as error:
                    relay_errors.append({"relay": name, "error": type(error).__name__, "observed_errors": relay.errors})
        if hasattr(self, "p2"):
            result = self.p2.run(self.p2.COMPOSE + ["down", "--volumes", "--remove-orphans", "--timeout", "5"], check=False)
            (self.report / "cleanup.log").write_text(self.safe(result.stdout + result.stderr))
            remaining = subprocess.check_output(["docker", "ps", "-aq", "--filter", "label=com.docker.compose.project=" + self.project], text=True).splitlines()
            volumes = subprocess.check_output(["docker", "volume", "ls", "-q", "--filter", "label=com.docker.compose.project=" + self.project], text=True).splitlines()
            networks = subprocess.check_output(["docker", "network", "ls", "-q", "--filter", "label=com.docker.compose.project=" + self.project], text=True).splitlines()
            json_file(self.report / "cleanup.json", {"project": self.project, "exit_code": result.returncode,
                "remaining_owned_containers": len(remaining), "remaining_owned_volumes": len(volumes), "remaining_owned_networks": len(networks)})
            require(result.returncode == 0 and not remaining and not volumes and not networks, "Owned Mongo services or volumes remain")
            self.p2.TLS_DIRECTORY.cleanup()
        self.temporary.cleanup()
        json_file(self.report / "relay-cleanup.json", {"errors": relay_errors})
        require(not relay_errors, "The native fault relay recorded an unexpected failure; owned services were cleaned")

    def select_target(self, branch, legacy=False):
        self.relay.target = (("fg_g2", self.metadata("SELECT delta_table FROM catalog_table WHERE generation_id=2 AND logical_table='orders'"))
                             if legacy else (f"fg_b{branch['id']}", "orders"))
        self.relay.last_reply = None
        self.relay.native_writes = 0

    def closed_unknown(self, branch):
        def recovered():
            rows = self.journal(branch)
            return rows if rows and rows[-1]["outcome"] == "unknown" and rows[-1]["sealed"] and rows[-1]["quiescent"] else None
        return wait_until("standalone unknown after real native quiescence", recovered, seconds=30)

    def drop(self, branch):
        self.binary("drop-" + branch["name"], "forkget", "drop", "--id", str(branch["id"]))
        wait_until("Mongo branch cleanup", lambda: self.metadata(f"SELECT status FROM branch WHERE id={branch['id']}") == "dropped")

    def duplicate_batches(self):
        for ordered in (True, False):
            branch = self.branch("audit-ordered" if ordered else "audit-unordered")
            self.select_target(branch)
            client = self.client(branch)
            documents = [{"_id": 500, "note": self.private_note}, {"_id": 1}, {"_id": 501, "note": self.private_note}]
            reply = client[branch["name"]].command(SON([("insert", "orders"), ("documents", documents), ("ordered", ordered)]))
            require(BSON.encode(reply) == self.relay.last_reply, "The client did not receive the real native write reply")
            expected = 1 if ordered else 2
            require(reply["n"] == expected and [(error["index"], error["code"]) for error in reply["writeErrors"]] == [(1, 11000)],
                    "Native ordered/unordered duplicate-key semantics changed")
            observed = self.native[f"fg_b{branch['id']}"].orders.count_documents({"_id": {"$in": [500, 501]}})
            require(observed == expected and self.relay.native_writes == 1, "Partial native batch changed the wrong documents or was retried")
            rows = self.journal(branch)
            observation = rows[0]["payload"]["mongo"]
            require(len(rows) == 1 and rows[0]["armed"] == 1 and rows[0]["outcome"] == "unknown"
                    and observation["state"] == "acknowledged_with_errors" and observation["inserted"] == expected
                    and observation["error_count"] == 1, "Partial native reply was audited as full success or rollback")
            client.close()
            self.record("ordered-native-duplicate" if ordered else "unordered-native-duplicate",
                {"branch_id": branch["id"], "original_native_reply_preserved": True, "native_inserted": observed,
                 "error_index": 1, "native_code": 11000, "journal": rows, "native_commands": self.relay.native_writes})
            self.drop(branch)

    def lost_native_ack(self):
        branch = self.branch("audit-lost-native-ack")
        self.select_target(branch)
        self.relay.ack_seen.clear()
        self.relay.release_ack.clear()
        self.relay.drop_ack.set()
        self.audit.block_outcome.set()
        self.audit.block_status.set()
        client = self.client(branch)
        try:
            with ThreadPoolExecutor(max_workers=1) as workers:
                operation = workers.submit(client[branch["name"]].orders.insert_one, {"_id": 510, "note": self.private_note})
                require(self.relay.ack_seen.wait(10), "The fault did not intercept a real native write ACK")
                rows = self.journal(branch)
                require(len(rows) == 1 and rows[0]["armed"] == 1 and rows[0]["outcome"] is None
                        and self.native[f"fg_b{branch['id']}"].orders.count_documents({"_id": 510}) == 1,
                        "Native ACK loss lacks a durable pre-intent, arm or actual mutation")
                self.reconcile("reconcile-live-native-ack")
                require(self.journal(branch)[0]["outcome"] is None, "Recovery fabricated an outcome while the service socket was live")
                requested = self.binary("request-drop-pending-native-ack", "forkget", "drop", "--id", str(branch["id"]))
                status, visible = self.request("GET", f"/v1/branches/{branch['id']}/status")
                require(status == 200, "Pending native delivery was not visible during requested GC")
                audit = json.loads(visible).get("audit", {})
                require(requested["status"] == "dropping" and audit.get("pending_delivery", 0) >= 1
                        and audit.get("cleanup_blocked") is True and self.journal(branch)[0]["outcome"] is None
                        and self.native[f"fg_b{branch['id']}"].orders.count_documents({"_id": 510}) == 1,
                        "GC erased a real native fact before quiescence and durable unknown delivery")
                pending_gc = {"branch_status": requested["status"], "pending_delivery": audit["pending_delivery"],
                    "cleanup_blocked": audit["cleanup_blocked"], "native_document_count": 1}
                self.relay.release_ack.set()
                try:
                    operation.result(timeout=15)
                    raise RuntimeError("The driver received success after its real native ACK was discarded")
                except pymongo.errors.PyMongoError:
                    pass
            client.close()
            rows = self.closed_unknown(branch)
            require(rows[0]["payload"]["mongo"]["state"] == "unknown" and self.relay.native_writes == 1,
                    "Lost native ACK became rollback, full success or a native business retry")
        finally:
            self.relay.release_ack.set()
            client.close()
            self.audit.block_outcome.clear()
            self.audit.block_status.clear()
        wait_until("unknown delivery retained durably", lambda: not self.paused(), seconds=15)
        wait_until("pending native ACK branch reclaimed after unknown", lambda: self.metadata(f"SELECT status FROM branch WHERE id={branch['id']}") == "dropped")
        events = json.loads(self.metadata(f"SELECT jsonb_agg(jsonb_build_object('id',id,'event',event_type) ORDER BY id)::text FROM audit_event WHERE branch_id={branch['id']} AND event_type IN ('policy_outcome','branch_dropped')"))
        require([event["event"] for event in events] == ["policy_outcome", "branch_dropped"],
                "Native evidence was reclaimed before the durable unknown outcome")
        self.record("lost-native-ack-unknown", {"branch_id": branch["id"], "journal": self.journal(branch),
            "pending_gc": pending_gc, "native_commands": self.relay.native_writes, "durable_outcome_before_gc": events})

    def late_observation(self):
        branch = self.branch("audit-late-partial")
        self.select_target(branch)
        client = self.client(branch)
        self.audit.block_outcome.set()
        self.audit.block_status.set()
        try:
            reply = client[branch["name"]].command(SON([("insert", "orders"),
                ("documents", [{"_id": 520, "note": self.private_note}, {"_id": 1}, {"_id": 521}]), ("ordered", True)]))
            require(BSON.encode(reply) == self.relay.last_reply and reply["n"] == 1, "Unavailable audit delivery changed the real partial native reply")
            require(self.paused() and self.journal(branch)[0]["outcome"] is None, "Missing outcome delivery did not apply global write backpressure")
            client.close()
            rows = self.closed_unknown(branch)
            require(rows[0]["payload"]["mongo"]["state"] == "unknown" and rows[0]["late"] is None,
                    "Recovery prematurely invented the unavailable native observation")
        finally:
            client.close()
            self.audit.block_outcome.clear()
            self.audit.block_status.clear()
        def late():
            rows = self.journal(branch)
            return rows if rows[0]["late"] is not None and not self.paused() else None
        rows = wait_until("immutable late partial observation delivery", late, seconds=20)
        require(rows[0]["outcome"] == "unknown" and rows[0]["payload"]["mongo"]["state"] == "unknown"
                and rows[0]["late"]["mongo"]["state"] == "acknowledged_with_errors"
                and rows[0]["late"]["mongo"]["inserted"] == 1 and rows[0]["late"]["mongo"]["error_count"] == 1,
                "Late delivery rewrote original unknown history or lost actual partial counts")
        require(self.relay.native_writes == 1, "Audit delivery recovery retried a native business operation")
        self.record("late-partial-observation", {"branch_id": branch["id"], "journal": rows,
            "original_native_reply_preserved": True, "protected_writes_resumed": True, "native_commands": self.relay.native_writes})
        self.drop(branch)

    def legacy_arm_loss(self):
        branch = self.branch("audit-legacy-step", legacy=True)
        self.select_target(branch, legacy=True)
        self.audit.drop_step = 2
        client = self.client(branch)
        try:
            try:
                client[branch["name"]].orders.insert_many([{"_id": 530, "note": self.private_note}, {"_id": 531}], ordered=True)
                raise RuntimeError("A lost next-arm ACK returned complete command success")
            except pymongo.errors.PyMongoError:
                pass
        finally:
            self.audit.drop_step = None
            client.close()
        rows = self.journal(branch)
        require(len(rows) == 1 and rows[0]["armed"] == 2 and rows[0]["outcome"] == "unknown"
                and len(rows[0]["steps"]) == 2 and rows[0]["steps"][0]["observation"]["state"] == "acknowledged"
                and rows[0]["steps"][1]["observation"]["state"] == "unknown" and self.relay.native_writes == 1,
                "Lost next-arm ACK reused prior ACK, lost its prefix, or sent the next native mutation")
        collection = self.native[self.relay.target[0]][self.relay.target[1]]
        require(collection.count_documents({"_fg_branch": branch["id"], "_doc._id": 530}) == 1
                and collection.count_documents({"_fg_branch": branch["id"], "_doc._id": 531}) == 0,
                "Legacy partial prefix differs from actual native delta documents")
        self.record("legacy-next-arm-ack-loss", {"branch_id": branch["id"], "journal": rows, "native_commands": self.relay.native_writes})
        self.drop(branch)

    def capture_and_drain(self):
        branch = self.branch("audit-capture-arm-cut")
        self.select_target(branch)
        self.audit.arm_seen.clear()
        self.audit.release_arm.clear()
        self.audit.hold_arm.set()
        client = self.client(branch)
        try:
            with ThreadPoolExecutor(max_workers=1) as workers:
                write = workers.submit(client[branch["name"]].orders.insert_one, {"_id": 540, "note": self.private_note})
                require(self.audit.arm_seen.wait(10), "The capture cut lacks its real durable arm ACK")
                require(self.journal(branch)[0]["outcome"] is None and self.relay.native_writes == 0,
                        "The pre-native capture cut already dispatched a native mutation")
                status, artifact = self.request("GET", f"/v1/branches/{branch['id']}/export")
                require(status == 200, "The admitted Mongo capture did not complete after draining its armed writer")
                require(len(artifact) <= 1024 * 1024, "The finite capture fixture unexpectedly exceeded one MiB")
                records = [json.loads(line) for line in artifact.splitlines()]
                require(records[0].get("record") == "header" and records[-1].get("record") == "end"
                        and records[-1].get("value", {}).get("complete") is True,
                        "Capture published an incomplete artifact")
                try:
                    write.result(timeout=10)
                    raise RuntimeError("A drained writer continued through its held arm acknowledgment")
                except pymongo.errors.PyMongoError:
                    pass
                self.audit.release_arm.set()
            client.close()
            rows = self.closed_unknown(branch)
            require(self.relay.native_writes == 0 and self.native[f"fg_b{branch['id']}"].orders.count_documents({"_id": 540}) == 0,
                    "Capture/drain permitted native mutation after closing the old writer")
            require(self.metadata(f"SELECT capture_active::int FROM branch WHERE id={branch['id']}") == "0", "Capture left its durable fence held")
        finally:
            self.audit.hold_arm.clear()
            self.audit.release_arm.set()
            client.close()
        self.drop(branch)
        events = json.loads(self.metadata(f"SELECT jsonb_agg(jsonb_build_object('id',id,'event',event_type) ORDER BY id)::text FROM audit_event WHERE branch_id={branch['id']} AND event_type IN ('policy_outcome','branch_dropped')"))
        require([event["event"] for event in events] == ["policy_outcome", "branch_dropped"], "GC removed native evidence before durable unknown delivery")
        self.record("capture-drain-before-native", {"branch_id": branch["id"], "journal": rows,
            "complete_capture": True, "native_commands": self.relay.native_writes, "durable_outcome_before_gc": events})

    def unacknowledged_refusals(self):
        branch = self.branch("audit-unacknowledged")
        self.select_target(branch)
        client = self.client(branch)
        try:
            try:
                client[branch["name"]].command({"insert": "orders", "documents": [{"_id": 550}], "writeConcern": {"w": 0}})
                raise RuntimeError("Explicit unacknowledged command was silently upgraded to acknowledged")
            except pymongo.errors.PyMongoError:
                pass
            unacknowledged = client[branch["name"]].get_collection("orders", write_concern=pymongo.WriteConcern(w=0))
            try:
                result = unacknowledged.insert_one({"_id": 551})
                require(not result.acknowledged, "An unacknowledged driver operation was silently upgraded")
            except pymongo.errors.ConnectionFailure:
                pass
            time.sleep(.2)
        finally:
            client.close()
        require(self.journal(branch) == [] and self.relay.native_writes == 0
                and self.native[f"fg_b{branch['id']}"].orders.count_documents({"_id": {"$in": [550, 551]}}) == 0,
                "w:0/moreToCome created an intent, arm or actual native write")
        self.record("unacknowledged-pre-native-refusal", {"branch_id": branch["id"], "attempts": 0, "native_commands": 0})
        self.drop(branch)

    def execute(self):
        self.setup()
        self.duplicate_batches()
        self.lost_native_ack()
        self.late_observation()
        self.legacy_arm_loss()
        self.capture_and_drain()
        self.unacknowledged_refusals()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir", type=Path, required=True)
    options = parser.parse_args()
    report = options.report_dir.resolve()
    report.mkdir(parents=True, exist_ok=False)
    run = MongoRun(report)
    errors, cleaned = [], False
    try:
        run.execute()
    except Exception as error:
        if isinstance(error, pymongo.errors.PyMongoError):
            # Driver error details may contain a complete original document.
            code = getattr(error, "code", None)
            errors.append(type(error).__name__ + (f" native_code={code}" if isinstance(code, int) else ""))
        else:
            errors.append(run.safe(type(error).__name__ + ": " + str(error)))
    finally:
        try:
            run.cleanup()
            cleaned = True
        except Exception as error:
            errors.append(run.safe("cleanup " + type(error).__name__ + ": " + str(error)))
    json_file(report / "report.json", {"suite": "p12-native-mongo-audit", "status": "failed" if errors else "passed",
        "qualification": "development source focused native regression", "transport": "verified_tls", "checks": run.checks,
        "errors": errors, "cleaned_up": cleaned, "finished_at": datetime.now(UTC).isoformat()})
    for error in errors:
        print("[FAIL] mongodb: " + error, flush=True)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
