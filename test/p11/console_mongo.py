"""Disposable TLS MongoDB fixture for the packaged console browser tests."""

from datetime import UTC, datetime
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import tempfile
import uuid

import pymongo
from bson import Int64

import run_p2 as p2


class MongoConsole:
    engine = "mongodb"

    def __init__(self, report, state, shared_port=None):
        self.report, self.state = report, state
        self.certs = state / "certs"
        self.secret = {name: secrets.token_hex(24) for name in
            ("native", "service", "collector", "internal", "alice_token", "bob_token", "alice_password")}
        self.owner_tokens = {p2.OWNER_A: self.secret["alice_token"], p2.OWNER_B: self.secret["bob_token"]}
        self.frontend_passwords = {p2.OWNER_A: self.secret["alice_password"]}
        self.containers, self.processes, self.clients, self.cases = [], [], [], []
        self.control_port, self.proxy_port, self.drain_port = p2.free_ports(3)
        self.control_port = shared_port or self.control_port
        self.control_url = f"http://127.0.0.1:{self.control_port}"

    def executable(self, name):
        return Path(os.environ.get("CARGO_TARGET_DIR", p2.ROOT / "target")) / "debug" / name

    def safe(self, value):
        for secret in self.secret.values():
            value = value.replace(secret, "[redacted]")
        return value

    def record(self, label):
        self.cases.append(label)
        print("[PASS] mongodb: " + label, flush=True)

    def command(self, *args, check=True, **kwargs):
        result = subprocess.run([str(arg) for arg in args], capture_output=True, text=True, timeout=180, **kwargs)
        p2.require(not check or result.returncode == 0, "Owned Mongo console fixture operation failed")
        return result

    def request(self, method, path, token=None, body=None):
        return p2.http(method, self.control_url + path, token, body, timeout=10)

    def api(self, method, path, body=None):
        status, raw = self.request(method, path, self.owner_tokens[p2.OWNER_A], body)
        p2.require(200 <= status < 300, f"Disposable console API returned HTTP {status}")
        return json.loads(raw) if raw else None

    def setup(self):
        p2.build_certs(self.certs)
        self.certs.chmod(0o755)
        combined = self.certs / "mongod.pem"
        combined.write_bytes((self.certs / "native.pem").read_bytes() + (self.certs / "native.key").read_bytes())
        combined.chmod(0o644)
        suffix = uuid.uuid4().hex[:12]
        metadata_name, native_name = "fg-console-meta-" + suffix, "fg-console-mongo-" + suffix
        self.containers.append(metadata_name)
        self.command("docker", "run", "--detach", "--rm", "--name", metadata_name,
                     "-e", "POSTGRES_HOST_AUTH_METHOD=trust", "-p", "127.0.0.1::5432", "postgres:16.14")
        self.containers.append(native_name)
        self.command("docker", "run", "--detach", "--rm", "--name", native_name,
                     "-e", "MONGO_INITDB_ROOT_USERNAME=root", "-e", "MONGO_INITDB_ROOT_PASSWORD=" + self.secret["native"],
                     "-v", f"{self.certs}:/certs:ro", "-p", "127.0.0.1::27017", "mongo:7.0.48",
                     "mongod", "--auth", "--bind_ip_all", "--tlsMode", "requireTLS", "--tlsCertificateKeyFile",
                     "/certs/mongod.pem", "--tlsCAFile", "/certs/backend-ca.pem", "--tlsAllowConnectionsWithoutCertificates")
        def port(name, number):
            return int(self.command("docker", "inspect", "--format",
                '{{(index (index .NetworkSettings.Ports "' + str(number) + '/tcp") 0).HostPort}}', name).stdout.strip())
        metadata_port, native_port = port(metadata_name, 5432), port(native_name, 27017)
        p2.wait_until("console metadata readiness", lambda: self.command("docker", "exec", metadata_name,
            "pg_isready", "-U", "postgres", check=False).returncode == 0, seconds=60)
        native = pymongo.MongoClient(host="127.0.0.1", port=native_port, username="root", password=self.secret["native"],
            authSource="admin", directConnection=True, tls=True, tlsCAFile=str(self.certs / "backend-ca.pem"),
            serverSelectionTimeoutMS=500)
        self.clients.append(native)
        def ready():
            try:
                return native.admin.command("ping")["ok"] == 1
            except pymongo.errors.PyMongoError:
                return False
        p2.wait_until("console Mongo TLS readiness", ready, seconds=60)
        for name, secret in (("fg_service", "service"), ("fg_gc", "collector")):
            native.admin.command("createUser", name, pwd=self.secret[secret], roles=[])
        def dsn(user, password):
            return f"mongodb://{user}:{password}@127.0.0.1:{native_port}/admin"
        accounts = [{"user": p2.OWNER_A, "token": self.owner_tokens[p2.OWNER_A], "expires_at": 9999999999,
                     "policy_admin": True},
                    {"user": p2.OWNER_B, "token": self.owner_tokens[p2.OWNER_B], "expires_at": 9999999999,
                     "approver_for": [p2.OWNER_A]}]
        self.environment = {key: value for key, value in os.environ.items() if not key.startswith("FG_")}
        self.environment.update(FG_META_DSN=f"postgresql://postgres@127.0.0.1:{metadata_port}/postgres",
            FG_BACKEND_ADMIN_DSN=dsn("root", self.secret["native"]), FG_BACKEND_DSN=dsn("fg_service", self.secret["service"]),
            FG_BACKEND_GC_DSN=dsn("fg_gc", self.secret["collector"]), FG_BACKEND_SERVICE_USER="fg_service", FG_BACKEND_GC_USER="fg_gc",
            FG_BACKEND_CA=str(self.certs / "backend-ca.pem"), FG_TLS_CERT=str(self.certs / "frontend.pem"),
            FG_TLS_KEY=str(self.certs / "frontend.key"), FG_CONTROL_ACCOUNTS=json.dumps(accounts),
            FG_FRONTEND_ACCOUNTS=json.dumps([{"user": p2.OWNER_A, "password": self.frontend_passwords[p2.OWNER_A], "expires_at": 9999999999}]),
            FG_INTERNAL_TOKEN=self.secret["internal"], FG_CONTROL_LISTEN=f"127.0.0.1:{self.control_port}",
            FG_CONTROL_URL=self.control_url, FG_PROXY_CONTROL_URL=f"http://127.0.0.1:{self.drain_port}",
            FG_PROXY_CONTROL_LISTEN=f"127.0.0.1:{self.drain_port}", FG_LISTEN_MONGO=f"127.0.0.1:{self.proxy_port}",
            FG_REFRESH_COOLDOWN_SECONDS="0", FG_STATE_DIR=str(self.state / "private-state"),
            FG_CONSOLE_DIR=str(p2.ROOT / "apps/console/build"))
        for action in (("migrate",), ("bootstrap",), ("refresh", "--snapshot", "v2")):
            result = self.command(self.executable("fg-control"), *action, env=self.environment, check=False)
            (self.report / (action[0] + ".log")).write_text(self.safe(result.stdout + result.stderr))
            p2.require(result.returncode == 0, "Console Mongo operator setup failed")
        for name, args in (("control", ["fg-control", "serve"]), ("proxy", ["fg-proxy"])):
            with (self.report / (name + ".log")).open("w") as output:
                self.processes.append(subprocess.Popen([str(self.executable(args[0])), *args[1:]],
                    env=self.environment, stdout=output, stderr=subprocess.STDOUT))
        p2.wait_until("console Mongo control", lambda: self.request("GET", "/health/ready")[0] == 204)
        p2.wait_until("console Mongo proxy", lambda: p2.http("GET", f"http://127.0.0.1:{self.drain_port}/healthz")[0] == 204)
        policy = self.api("GET", "/v1/policies/dev")
        self.api("PUT", "/v1/policies/dev", {"expected_version": policy["version"], "max_transaction_rows": 50000,
                                             "table_limit_bps": None, "approval_after_rows": None})

    def branch(self, name, write=False):
        branch = self.api("POST", "/v1/branches", {"name": name, "mode": "native_write" if write else "read_only"})
        p2.wait_until("console Mongo branch", lambda: self.api("GET", f"/v1/branches/{branch['id']}")["status"] == "active")
        return branch

    def client(self, branch):
        client = pymongo.MongoClient(host="127.0.0.1", port=self.proxy_port, username=p2.OWNER_A,
            password=self.frontend_passwords[p2.OWNER_A], authSource="admin", directConnection=True, retryWrites=False,
            tls=True, tlsCAFile=str(self.certs / "frontend-ca.pem"), serverSelectionTimeoutMS=5000)
        self.clients.append(client)
        return client

    def execute(self, node, browser):
        self.setup()
        readonly = self.branch("console-readonly")
        client = self.client(readonly)
        p2.require(client[readonly["name"]].orders.find_one({"_id": Int64(1)}) is not None, "Default Mongo branch could not read")
        try:
            client[readonly["name"]].orders.update_one({"_id": Int64(1)}, {"$set": {"note": "must-not-commit"}})
            raise p2.Failure("Default Mongo console branch admitted a write")
        except pymongo.errors.OperationFailure as error:
            p2.require("FG-5001" in str(error), "Read-only Mongo refusal lost its policy category")
        branch = self.branch("console-live", write=True)
        client = self.client(branch)
        p2.require(client[branch["name"]].orders.update_one({"_id": Int64(1)}, {"$set": {"note": "console-verified"}}).modified_count == 1,
                   "Console Mongo change was not committed")
        self.record("Verified TLS frontend/backend, default read-only refusal and writable BSON change use independent branch pools")
        browser(self, branch, node)
        for item in (branch, readonly):
            self.api("DELETE", f"/v1/branches/{item['id']}")
            p2.wait_until("console Mongo cleanup", lambda: self.api("GET", f"/v1/branches/{item['id']}")["status"] == "dropped")

    def cleanup(self):
        for process in self.processes:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        for client in self.clients:
            client.close()
        unconfirmed = []
        for name in reversed(self.containers):
            self.command("docker", "rm", "--force", "--volumes", name, check=False)
            observed = self.command("docker", "container", "ls", "--all", "--filter",
                "name=^" + name + "$", "--format", "{{.ID}}", check=False)
            if observed.returncode != 0 or observed.stdout.strip():
                unconfirmed.append(name)
        p2.require(not unconfirmed, "Console fixture cleanup could not confirm all owned containers absent")


def run(report_root, node, browser, control_port):
    report = report_root / f"mongodb-{datetime.now(UTC):%Y%m%dT%H%M%S}-{os.getpid()}"
    report.mkdir(parents=True)
    errors = []
    cleaned = False
    with tempfile.TemporaryDirectory(prefix="fg-console-mongo-") as temporary:
        runner = MongoConsole(report, Path(temporary), control_port(node))
        try:
            runner.execute(node, browser)
        except Exception as error:
            errors.append(runner.safe(str(error)))
        finally:
            try:
                runner.cleanup()
                cleaned = True
            except Exception as error:
                errors.append(runner.safe(str(error)))
    revision, state = p2.git_state()
    p2.json_file(report / "report.json", {"status": "failed" if errors else "passed", "engine": "mongodb",
        "source_revision": revision, "source_state": state, "checks": runner.cases, "errors": errors, "cleaned_up": cleaned})
    print(json.dumps({"engine": "mongodb", "errors": errors, "cleaned_up": cleaned, "report": str(report)}), flush=True)
    return int(bool(errors))
