"""Run the catalog-backed branch suite on disposable, loopback-only services."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import platform
import secrets
import select
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

sys.dont_write_bytecode = True

from corpus import write_corpus
import data


ROOT = Path(__file__).resolve().parents[2]
SUITE = ROOT / "test/p2"
OWNER_A = "p2_alice"
OWNER_B = "p2_bob"
EXPIRED = "p2_expired"
API = build_opener(ProxyHandler({}))
CONTROL_SETTINGS = (
    "FG_META_", "FG_BACKEND_", "FG_CONTROL_", "FG_PROXY_", "FG_DIFF_", "FG_LISTEN_", "FG_TLS_",
    "FG_INTERNAL_TOKEN", "FG_OWNER_TOKEN", "FG_FRONTEND_ACCOUNTS", "FG_BRANCH_",
    "FG_GITHUB_", "FG_CI_", "FG_DRYRUN_", "FG_MANAGED_", "FG_REFRESH_",
)


class Failure(RuntimeError):
    pass


def require(condition, label):
    if not condition:
        raise Failure(label)


def json_file(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def wait_until(label, predicate, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if value := predicate():
            return value
        time.sleep(0.1)
    raise Failure(f"Timed out: {label}")


def free_ports(count):
    listeners = []
    try:
        for _ in range(count):
            listener = socket.socket()
            listeners.append(listener)
            listener.bind(("127.0.0.1", 0))
        return [listener.getsockname()[1] for listener in listeners]
    finally:
        for listener in listeners:
            listener.close()


def build_certs(directory):
    directory.mkdir(mode=0o700)
    extensions = directory / "extensions.cnf"
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,DNS:native,IP:127.0.0.1\n"
        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n",
        encoding="utf-8",
    )
    for authority, services in (("backend", ("native", "metadata")), ("frontend", ("frontend",))):
        ca = directory / f"{authority}-ca.pem"
        key = directory / f"{authority}-ca.key"
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
                "-subj", f"/CN=Forkget P2 {authority} CA", "-keyout", key, "-out", ca,
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-addext", "subjectKeyIdentifier=hash",
                "-addext", "authorityKeyIdentifier=keyid:always")
        for index, service in enumerate(services, 1):
            csr = directory / f"{service}.csr"
            openssl("req", "-newkey", "rsa:2048", "-nodes", "-sha256", "-subj", "/CN=localhost",
                    "-keyout", directory / f"{service}.key", "-out", csr)
            openssl("x509", "-req", "-sha256", "-days", "1", "-in", csr,
                    "-CA", ca, "-CAkey", key, "-set_serial", str(index), "-extfile", extensions,
                    "-out", directory / f"{service}.pem")
            csr.unlink()
        key.unlink()


def openssl(*arguments):
    result = subprocess.run(["openssl", *arguments], cwd=ROOT, capture_output=True, timeout=30)
    require(result.returncode == 0, "OpenSSL could not issue the disposable TLS certificates")


def http(method, url, token=None, body=None, *, timeout=3):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    payload = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        payload = json.dumps(body).encode()
    request = Request(url, data=payload, headers=headers, method=method)
    try:
        with API.open(request, timeout=timeout) as response:
            return response.status, response.read()
    except HTTPError as error:
        return error.code, error.read()
    except (URLError, TimeoutError, ConnectionError):
        return 0, b""


# Per-engine suite settings. "family" selects the wire/SQL shape: TiDB shares
# the MySQL family but serves the tidb:// backend scheme and needs its own
# client transport and CHECK-enforcement setup.
ENGINE_SETTINGS = {
    "mysql": {"image": "mysql:8.0.43", "internal_port": 3306, "cli_engine": "mysql",
              "backend_scheme": "mysql", "frontend_scheme": "mysql", "family": "mysql",
              "backend_database": "forkget_delta", "listen_key": "FG_LISTEN_MYSQL",
              "version": "8.0.43"},
    "postgresql": {"image": "postgres:16.14", "internal_port": 5432, "cli_engine": "postgres",
                   "backend_scheme": "postgresql", "frontend_scheme": "postgresql",
                   "family": "postgresql", "backend_database": "p2_native",
                   "listen_key": "FG_LISTEN_PG", "version": "16.14"},
    "tidb": {"image": "pingcap/tidb:v8.5.8", "internal_port": 4000, "cli_engine": "tidb",
             "backend_scheme": "tidb", "frontend_scheme": "mysql", "family": "tidb",
             "backend_database": "forkget_delta", "listen_key": "FG_LISTEN_MYSQL",
             "version": "v8.5.8"},
}


class EngineRun:
    def __init__(self, engine, report, workspace, certs, run_id):
        self.engine = engine
        self.settings = ENGINE_SETTINGS[engine]
        self.family = self.settings["family"]
        self.report = report
        self.certs = certs
        self.corpus = workspace / "corpus"
        self.cases = []
        self.differential = []
        self.processes = {}
        self.compose_started = False
        self.engine_version = None
        self.secret = {name: secrets.token_hex(24) for name in (
            "native", "meta", "service", "collector", "metadata_control", "reference",
            "alice_password", "bob_password", "expired_password", "alice_token", "bob_token",
            "expired_token", "internal",
        )}
        self.owner_tokens = {OWNER_A: self.secret["alice_token"], OWNER_B: self.secret["bob_token"]}
        self.frontend_passwords = {
            OWNER_A: self.secret["alice_password"], OWNER_B: self.secret["bob_password"],
            EXPIRED: self.secret["expired_password"],
        }
        self.expires = int(time.time()) + 3_600
        self.control_port, self.proxy_port, self.drain_port = free_ports(3)
        self.control_url = f"http://127.0.0.1:{self.control_port}"
        self.drain_url = f"http://127.0.0.1:{self.drain_port}"
        self.image = self.settings["image"]
        self.internal_port = self.settings["internal_port"]
        self.cli_engine = self.settings["cli_engine"]
        self.scheme = self.settings["backend_scheme"]
        self.frontend_scheme = self.settings["frontend_scheme"]
        self.backend_database = self.settings["backend_database"]
        self.listen_key = self.settings["listen_key"]
        self.base_env = {key: value for key, value in os.environ.items() if not key.startswith(CONTROL_SETTINGS)}
        self.base_env |= {"FG_BACKEND_SERVICE_USER": "p2_service", "FG_BACKEND_GC_USER": "p2_gc"}
        self.compose_env = self.base_env | {
            "P2_NATIVE_IMAGE": self.image, "P2_NATIVE_PORT": str(self.internal_port),
            "P2_ENGINE": engine, "P2_CERT_DIR": str(certs),
            "P2_ADMIN_PASSWORD": self.secret["native"], "P2_META_PASSWORD": self.secret["meta"],
        }
        self.project = f"{run_id}-{engine}"
        self.compose_command = ["docker", "compose", "--project-name", self.project,
                                "--file", str(SUITE / "compose.yml")]
        target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
        self.bin_dir = (ROOT / target / "debug").resolve()
        self.base_env["FG_STATE_DIR"] = str(workspace / "private-replay-state")
        json_file(self.report / "safe-endpoint-ports.json", {
            "host": "127.0.0.1", "control_port": self.control_port,
            "proxy_port": self.proxy_port, "proxy_control_port": self.drain_port,
        })

    def record(self, label):
        self.cases.append(label)
        print(f"[PASS] {self.engine}: {label}", flush=True)

    def safe(self, value):
        for token in self.secret.values():
            value = value.replace(token, "[redacted]")
        return value

    def call(self, label, command, env=None, stdin=None, timeout=30, log=False, succeeds=True):
        try:
            result = subprocess.run(command, cwd=ROOT, env=env if env is not None else self.base_env,
                                    input=stdin, capture_output=True, text=True,
                                    errors="surrogateescape", timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise Failure(f"{label} did not complete ({type(error).__name__})") from None
        okay = (result.returncode == 0) == succeeds
        if log or not okay:
            details = self.safe(result.stdout + result.stderr)
            (self.report / f"{label}.log").write_text(details, encoding="utf-8", errors="backslashreplace")
        if not okay:
            raise Failure(f"{label} returned {result.returncode}; see {label}.log")
        return result.stdout.strip()

    def compose(self, label, *arguments, **kwargs):
        return self.call(label, self.compose_command + list(arguments), env=self.compose_env, **kwargs)

    def executable(self, name):
        return self.bin_dir / name

    def dsn(self, user, password, port, database, scheme=None):
        return f"{scheme or self.scheme}://{user}:{password}@127.0.0.1:{port}/{database}"

    def prepare_native_engine(self):
        """Fresh-engine setup that must precede any credentialed DSN.

        Fresh TiDB starts with a passwordless root: pin the deployment secret
        before any DSN exists, then enable CHECK enforcement, which the
        branch-table and generated-key checks rely on.
        """
        if self.family != "tidb":
            return
        # TiDB ignores MYSQL_DATABASE; the suite's default schema is created
        # here alongside the credential and CHECK prerequisites.
        self.native_setup(
            "CREATE DATABASE IF NOT EXISTS p2_native;\n"
            f"ALTER USER 'root'@'%' IDENTIFIED BY '{self.secret['native']}';\n"
            "SET GLOBAL tidb_enable_check_constraint = ON;\n"
            "SET GLOBAL tidb_enable_metadata_lock = ON;\n")
        require(self.native("SELECT @@GLOBAL.tidb_enable_check_constraint;") == "1",
                "TiDB CHECK enforcement did not activate")
        require(self.native("SELECT @@GLOBAL.tidb_enable_metadata_lock;") == "1",
                "TiDB metadata locking did not activate")

    def native_setup(self, sql):
        """One-time TiDB setup against the passwordless fresh root."""
        # -i keeps stdin attached; the SQL arrives on the client's stdin.
        client = ["docker", "run", "-i", "--rm", "--network", f"{self.project}_default",
                  "-v", f"{self.certs}:/certs:ro",
                  "mysql:8.0.43", "mysql", "--no-defaults", "--protocol=TCP",
                  f"--host=native", f"--port={self.settings['internal_port']}",
                  "--user=root", "--ssl-mode=VERIFY_IDENTITY",
                  "--ssl-ca=/certs/backend-ca.pem", "--batch", "--skip-column-names"]
        return self.call("native-setup", client, env=self.compose_env, stdin=sql, timeout=60)

    def native(self, sql, database=None, *, timeout=30):
        if self.family == "postgresql":
            command = self.psql_command()
            return self.compose("native-sql", "exec", "-T", "native", "sh", "-c", command,
                                "sh", database or "p2_native", stdin=sql, timeout=timeout)
        if self.family == "mysql":
            command = ('MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql --no-defaults --protocol=TCP '
                       '--host=127.0.0.1 --user=root --ssl-mode=VERIFY_IDENTITY '
                       '--ssl-ca=/certs/backend-ca.pem --batch --skip-column-names '
                       '--raw --binary-as-hex --database="$1"')
            return self.compose("native-sql", "exec", "-T", "native", "sh", "-c", command,
                                "sh", database or "p2_native", stdin=sql, timeout=timeout)
        # The TiDB image ships no MySQL client; run one on the project network.
        # -i keeps stdin attached; the SQL arrives on the client's stdin.
        client = ["docker", "run", "-i", "--rm", "--network", f"{self.project}_default",
                  "-v", f"{self.certs}:/certs:ro",
                  "-e", f"MYSQL_PWD={self.secret['native']}",
                  "mysql:8.0.43", "mysql", "--no-defaults", "--protocol=TCP",
                  "--host=native", f"--port={self.settings['internal_port']}",
                  "--user=root", "--ssl-mode=VERIFY_IDENTITY",
                  "--ssl-ca=/certs/backend-ca.pem", "--batch", "--skip-column-names",
                  "--raw", "--binary-as-hex",
                  f"--database={database or 'p2_native'}"]
        return self.call("native-sql", client, env=self.compose_env, stdin=sql, timeout=timeout)

    @staticmethod
    def psql_command():
        return ('PGPASSWORD="$POSTGRES_PASSWORD" PGSSLMODE=verify-full '
                'PGSSLROOTCERT=/certs/backend-ca.pem exec psql -XqAt --set=ON_ERROR_STOP=1 '
                '--host=127.0.0.1 --username=postgres --dbname="$1"')

    def metadata(self, sql):
        return self.compose("metadata-sql", "exec", "-T", "metadata", "sh", "-c", self.psql_command(),
                            "sh", "forkget_meta", stdin=sql)

    def start(self, label, binary, arguments, env):
        log = self.report / f"{label}.log"
        with log.open("ab") as output:
            process = subprocess.Popen([self.executable(binary), *arguments], cwd=ROOT, env=env,
                                       stdout=output, stderr=subprocess.STDOUT)
        self.processes[label] = process
        return process

    def stop(self, label):
        process = self.processes.pop(label, None)
        if process is None or process.poll() is not None:
            return
        try:
            process.send_signal(signal.SIGINT)
            process.wait(timeout=5)
        except ProcessLookupError:
            return
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    def ready(self, label, url, process):
        def is_ready():
            if process.poll() is not None:
                if label == "control":
                    try:
                        self.control_startup_diagnostics(process.returncode)
                    except OSError:
                        pass
                raise Failure(f"{label} exited {process.returncode}; see {label}.log")
            return http("GET", url)[0] == 204
        wait_until(f"{label} readiness", is_ready)

    def control_startup_diagnostics(self, returncode):
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", self.control_port))
                bind_errno = 0
            except OSError as error:
                bind_errno = error.errno
        try:
            state = Path(self.base_env["FG_STATE_DIR"]).lstat()
            directory = {"exists": True, "mode": oct(stat.S_IMODE(state.st_mode)),
                         "is_directory": stat.S_ISDIR(state.st_mode),
                         "uid": state.st_uid, "gid": state.st_gid}
        except OSError as error:
            directory = {"stat_errno": error.errno}
        json_file(self.report / "control-startup-failure.json", {
            "process_returncode": returncode, "observed_at": datetime.now(UTC).isoformat(),
            "host": "127.0.0.1", "port": self.control_port,
            "bind_probe_errno": bind_errno, "state_directory": directory,
        })

    def native_roles(self):
        for user, secret in (("p2_service", "service"), ("p2_gc", "collector"), ("p2_ref", "reference")):
            password = self.secret[secret]
            if self.family in ("mysql", "tidb"):
                self.native(f"CREATE USER '{user}'@'%' IDENTIFIED WITH caching_sha2_password BY '{password}' REQUIRE SSL;")
            else:
                self.native(f"CREATE ROLE {user} LOGIN PASSWORD '{password}';")

    def metadata_role(self):
        self.metadata(f"""
            CREATE ROLE p2_meta_control LOGIN PASSWORD '{self.secret['metadata_control']}';
            GRANT USAGE ON SCHEMA public TO p2_meta_control;
            GRANT SELECT ON generation, catalog_table, catalog_column TO p2_meta_control;
            GRANT SELECT, INSERT ON branch TO p2_meta_control;
            GRANT UPDATE (status,expires_at,lease_version,lease_renewed_at,lifecycle_phase,lifecycle_reason,lifecycle_updated_at,capture_active,capture_version,storage_preflight) ON branch TO p2_meta_control;
            GRANT SELECT, INSERT ON audit_event, policy_version TO p2_meta_control;
            GRANT SELECT, INSERT, UPDATE ON audit_attempt, audit_mongo_step TO p2_meta_control;
            GRANT UPDATE (audit_witness_version,audit_witness_incarnation,audit_witness_ready,audit_storage_invalidated,audit_storage_reclaim_started) ON branch TO p2_meta_control;
            GRANT SELECT, INSERT ON policy_approval TO p2_meta_control;
            GRANT UPDATE (state) ON policy_approval TO p2_meta_control;
            GRANT SELECT ON policy_proxy_epoch TO p2_meta_control;
            GRANT UPDATE (epoch) ON policy_proxy_epoch TO p2_meta_control;
            GRANT SELECT, INSERT, UPDATE ON github_source TO p2_meta_control;
            GRANT SELECT ON replay_deployment TO p2_meta_control;
            GRANT SELECT ON snapshot_job TO p2_meta_control;
            GRANT UPDATE(storage_preflight) ON snapshot_job TO p2_meta_control;
            GRANT SELECT,INSERT,UPDATE ON branch_budget_revision,budget_request,budget_grant TO p2_meta_control;
            GRANT SELECT,INSERT,UPDATE ON replay_job TO p2_meta_control;
            GRANT USAGE ON SEQUENCE replay_job_id_seq TO p2_meta_control;
            GRANT USAGE ON SEQUENCE budget_request_id_seq,budget_grant_id_seq TO p2_meta_control;
            GRANT USAGE ON SEQUENCE branch_id_seq, audit_event_id_seq, policy_approval_id_seq TO p2_meta_control;
        """)

    def migrations_and_bootstrap(self):
        admin = "postgres" if self.family == "postgresql" else "root"
        deployment = self.base_env | {
            "FG_BACKEND_CA": str(self.certs / "backend-ca.pem"),
            "FG_META_CA": str(self.certs / "backend-ca.pem"),
            "FG_META_DSN": self.dsn("postgres", self.secret["meta"], self.metadata_port, "forkget_meta", "postgresql"),
            "FG_BACKEND_ADMIN_DSN": self.dsn(admin, self.secret["native"], self.native_port, "p2_native"),
        }
        migration_dir = ROOT / "crates/fg-meta/migrations"
        expected_migrations = str(len(list(migration_dir.glob("*.sql"))))
        for run in ("first", "repeat"):
            self.call(f"migrate-{run}", [self.executable("fg-control"), "migrate"], env=deployment, log=True)
            require(self.metadata("SELECT count(*) FROM _sqlx_migrations WHERE success;") == expected_migrations,
                    "Expected all forward migrations to succeed")
        self.record("forward-and-repeat-migrations")
        self.metadata_role()
        self.native_roles()
        stale = self.create_interrupted_generation()
        self.verify_unsafe_role_refusal(deployment)
        self.call("bootstrap", [self.executable("fg-control"), "bootstrap"], env=deployment, log=True)
        self.call("bootstrap-existing-generation", [self.executable("fg-control"), "bootstrap"],
                  env=deployment, log=True, succeeds=False)
        require(self.metadata("SELECT count(*) FROM generation WHERE status='active';") == "1",
                "Bootstrap must leave one ready generation")
        active_id = int(self.metadata("SELECT id FROM generation WHERE status='active';"))
        require(active_id > stale["id"] and self.metadata(
            f"SELECT status FROM generation WHERE id={stale['id']};") == "failed",
            "Bootstrap did not retire its interrupted generation")
        require(self.native(f"SELECT count(*) FROM information_schema.schemata WHERE schema_name='{stale['schema']}';") == "0",
                "Bootstrap left an interrupted native generation schema")
        require(self.native(f"SELECT count(*) FROM information_schema.tables WHERE table_schema='forkget_delta' AND table_name='{stale['delta']}';") == "0",
                "Bootstrap left an interrupted native delta table")
        self.record("native-generation-bootstrap")
        self.record("interrupted-bootstrap-removes-owned-partial-objects")

    def verify_unsafe_role_refusal(self, deployment):
        if self.family in ("mysql", "tidb"):
            grant = "GRANT INSERT ON *.* TO 'p2_service'@'%';"
            revoke = "REVOKE INSERT ON *.* FROM 'p2_service'@'%';"
        else:
            grant = "ALTER ROLE p2_service CREATEDB;"
            revoke = "ALTER ROLE p2_service NOCREATEDB;"
        self.native(grant)
        try:
            self.call("bootstrap-unsafe-role", [self.executable("fg-control"), "bootstrap"],
                      env=deployment, log=True, succeeds=False)
            require(self.metadata("SELECT count(*) FROM generation WHERE status='active';") == "0",
                    "Bootstrap activated a generation with an overprivileged service role")
            details = (self.report / "bootstrap-unsafe-role.log").read_text(encoding="utf-8")
            require("privilege" in details.lower(), "Unsafe role bootstrap did not fail on privilege validation")
        finally:
            self.native(revoke)
        self.record("overprivileged-native-role-refused-before-activation")

    def create_interrupted_generation(self):
        stale_id = int(self.metadata(f"""
            INSERT INTO generation (engine, status, native_claimed)
              VALUES ('{self.engine}', 'importing', true) RETURNING id;
        """))
        table_id = int(self.metadata(f"""
            INSERT INTO catalog_table (generation_id, logical_schema, logical_table, base_table)
              VALUES ({stale_id}, 'app', 'partial_seed', 'partial_seed') RETURNING id;
        """))
        self.metadata(f"""
            INSERT INTO catalog_column (table_id, ordinal, name, data_type, is_nullable, key_ordinal)
              VALUES ({table_id}, 1, 'id', 'bigint', false, 1);
        """)
        schema = f"fg_g{stale_id}"
        delta = f"_d_g{stale_id}_t{table_id}"
        delta_charset = ("" if self.family == "postgresql"
                        else " CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci")
        self.native(f"""
            CREATE SCHEMA {data.identifier(self.engine, schema)};
            CREATE SCHEMA forkget_delta{delta_charset};
            CREATE TABLE {data.table(self.engine, schema, 'partial_seed')} (id BIGINT PRIMARY KEY);
            CREATE TABLE {data.table(self.engine, 'forkget_delta', delta)} (id BIGINT PRIMARY KEY);
        """)
        return {"id": stale_id, "schema": schema, "delta": delta}

    def policy_account(self, user):
        return {}

    def start_control(self):
        accounts = [dict(user=user, token=token, expires_at=self.expires, **self.policy_account(user))
                    for user, token in self.owner_tokens.items()]
        accounts.append(dict(user=EXPIRED, token=self.secret["expired_token"], expires_at=1))
        environment = self.base_env | {
            "FG_META_DSN": self.dsn("p2_meta_control", self.secret["metadata_control"], self.metadata_port,
                                    "forkget_meta", "postgresql"),
            "FG_META_CA": str(self.certs / "backend-ca.pem"),
            "FG_BACKEND_GC_DSN": self.dsn("p2_gc", self.secret["collector"], self.native_port,
                                         self.backend_database),
            "FG_BACKEND_CA": str(self.certs / "backend-ca.pem"),
            "FG_CONTROL_ACCOUNTS": json.dumps(accounts),
            "FG_INTERNAL_TOKEN": self.secret["internal"],
            "FG_CONTROL_LISTEN": f"127.0.0.1:{self.control_port}",
            "FG_PROXY_CONTROL_URL": self.drain_url,
        }
        control = self.start("control", "fg-control", ["serve"], environment)
        self.ready("control", self.control_url + "/health/ready", control)

    def verify_readiness_diagnostics(self):
        log_path = self.report / "control.log"

        def verify_outage(component):
            log_start = log_path.stat().st_size
            status, raw = http("GET", self.control_url + "/health/ready", timeout=8)
            require(status == 503, f"{component} outage did not fail readiness")
            problem = json.loads(raw)
            require(problem.get("code") == "FG-1004" and problem.get("component") == component,
                    f"{component} readiness failure did not identify its dependency")
            logs = log_path.read_bytes()[log_start:].decode("utf-8")
            diagnostics = [json.loads(line).get("fields", {})
                           for line in logs.splitlines() if line.startswith("{")]
            require(any(entry.get("component", "").lower() == component for entry in diagnostics),
                    f"{component} readiness failure did not write a component diagnostic")
            text = raw.decode("utf-8") + log_path.read_text(encoding="utf-8")
            require(all(secret not in text for secret in self.secret.values()),
                    f"{component} readiness response or logs exposed a generated credential")
            json_file(self.report / f"readiness-{component}.json", problem)

        self.metadata("REVOKE SELECT ON generation FROM p2_meta_control;")
        try:
            verify_outage("metadata")
        finally:
            self.metadata("GRANT SELECT ON generation TO p2_meta_control;")
        self.ready("control", self.control_url + "/health/ready", self.processes["control"])
        reject = ("ALTER USER 'p2_gc'@'%' ACCOUNT LOCK;" if self.family in ("mysql", "tidb")
                  else "ALTER ROLE p2_gc NOLOGIN;")
        restore = ("ALTER USER 'p2_gc'@'%' ACCOUNT UNLOCK;" if self.family in ("mysql", "tidb")
                   else "ALTER ROLE p2_gc LOGIN;")
        self.native(reject)
        try:
            verify_outage("native")
        finally:
            self.native(restore)
        self.ready("control", self.control_url + "/health/ready", self.processes["control"])
        self.record("readiness-identifies-metadata-and-native-outages-with-safe-diagnostics")

    def start_proxy(self):
        accounts = [dict(user=user, password=password, expires_at=1 if user == EXPIRED else self.expires)
                    for user, password in self.frontend_passwords.items()]
        environment = self.base_env | {
            "FG_BACKEND_DSN": self.dsn("p2_service", self.secret["service"], self.native_port,
                                      self.backend_database),
            "FG_BACKEND_CA": str(self.certs / "backend-ca.pem"),
            "FG_FRONTEND_ACCOUNTS": json.dumps(accounts),
            "FG_CONTROL_URL": self.control_url, "FG_INTERNAL_TOKEN": self.secret["internal"],
            "FG_PROXY_CONTROL_LISTEN": f"127.0.0.1:{self.drain_port}",
            self.listen_key: f"127.0.0.1:{self.proxy_port}",
            "FG_TLS_CERT": str(self.certs / "frontend.pem"),
            "FG_TLS_KEY": str(self.certs / "frontend.key"),
        }
        proxy = self.start("proxy", "fg-proxy", [], environment)
        self.ready("proxy", self.drain_url + "/healthz", proxy)

    def cli(self, owner, *arguments):
        environment = self.base_env | {"FG_CONTROL_URL": self.control_url,
                                       "FG_OWNER_TOKEN": self.owner_tokens[owner]}
        output = self.call(f"cli-{arguments[0]}", [self.executable("forkget"), *arguments], env=environment)
        return json.loads(output)

    def request(self, method, path, token=None, body=None):
        return http(method, self.control_url + path, token, body)

    def binding(self, owner, branch):
        status, raw = self.request("POST", "/internal/v1/resolve", self.secret["internal"],
                                   {"principal": owner, "branch": branch["name"]})
        require(status == 200, "Control could not resolve the persisted branch binding")
        value = json.loads(raw)
        require(value["id"] == branch["id"] and value["generation_id"] == branch["generation_id"],
                "Resolver changed the branch identity")
        return value

    def merge_fixture(self, owner, name):
        """Represent a legacy sparse branch whose native delta is seeded below."""
        require(owner in (OWNER_A, OWNER_B) and name in ("p2-alpha", "p2-beta", "p5-sparse-alpha", "p5-sparse-beta"),
                "Unexpected legacy fixture identity")
        branch_id = int(self.metadata(f"""
            INSERT INTO branch(name,class,generation_id,created_by,expires_at,status,access,layout,read_strategy)
            SELECT '{name}','dev',id,'{owner}',statement_timestamp()+interval '24 hours',
                   'active','read_only','sparse_delta','merge'
            FROM generation WHERE status='active' AND engine='{self.engine}' RETURNING id;
        """))
        status, raw = self.request("GET", f"/v1/branches/{branch_id}", self.owner_tokens[owner])
        require(status == 200, "The legacy fixture was not visible to its owner")
        return json.loads(raw)

    def diff_env(self, owner, branch, password=None, ca=None):
        if self.family == "postgresql":
            ref_key, proxy_key = "FG_DIFF_PG_REF_URL", "FG_DIFF_PG_CAND_URL"
            reference = self.dsn("p2_ref", self.secret["reference"], self.native_port, "p2_native")
        else:
            ref_key, proxy_key = (("FG_DIFF_MYSQL_REF_URL", "FG_DIFF_MYSQL_CAND_URL")
                                  if self.family == "mysql" else
                                  ("FG_DIFF_TIDB_REF_URL", "FG_DIFF_TIDB_CAND_URL"))
            # sqlx only parses mysql://, so the TiDB reference stays on the
            # wire scheme while backend DSNs use tidb://.
            reference = self.dsn("p2_ref", self.secret["reference"], self.native_port, "app",
                                 scheme="mysql")
        candidate = self.dsn(owner, password or self.frontend_passwords[owner], self.proxy_port,
                             branch, scheme=self.frontend_scheme)
        return self.base_env | {
            ref_key: reference,
            proxy_key: candidate,
            "FG_DIFF_REF_CA": str(self.certs / "backend-ca.pem"),
            "FG_DIFF_PROXY_CA": str(ca or self.certs / "frontend-ca.pem"),
        }

    def session_args(self, action, expected_fg=None):
        arguments = [self.executable("fg-diff"), "session", "--engine", self.cli_engine, "--action", action]
        if expected_fg is not None:
            arguments.extend(["--expected-fg", expected_fg])
        return arguments

    def session(self, label, action, owner, branch, expected_fg=None, **settings):
        self.call(label, self.session_args(action, expected_fg), env=self.diff_env(owner, branch, **settings), log=True)

    def hold(self, action, owner, branch):
        process = subprocess.Popen(self.session_args(action), cwd=ROOT, env=self.diff_env(owner, branch),
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True)
        self.processes[action] = process
        readable, _, _ = select.select([process.stdout], [], [], 12)
        if not (bool(readable) and process.stdout.readline().strip() == "ready"):
            output, error = process.communicate(timeout=5)
            (self.report / f"{action}.log").write_text(self.safe(output + error),
                                                       encoding="utf-8", errors="backslashreplace")
            raise Failure(f"{action} could not start its prepared transaction")

    def finish_hold(self, action):
        process = self.processes[action]
        try:
            output, error = process.communicate("continue\n", timeout=12)
        except subprocess.TimeoutExpired:
            raise Failure(f"{action} did not complete") from None
        (self.report / f"{action}.log").write_text(self.safe(output + error), encoding="utf-8")
        require(process.returncode == 0, f"{action} did not observe the expected connection state")
        del self.processes[action]

    def branch_probe(self, branch):
        """One persistent fg-write-probe session on a branch.

        Query-level lifecycle tests ride it: the proxy must refuse commands
        on an already-open connection the moment a local branch guarantee
        (TTL cutoff, drain) trips, without waiting for the GC sweep.
        """
        url = self.dsn(OWNER_A, self.frontend_passwords[OWNER_A], self.proxy_port,
                       branch["name"], scheme=self.frontend_scheme)
        process = subprocess.Popen(
            [self.executable("fg-write-probe")], cwd=ROOT,
            env=self.base_env | {"FG_WRITE_PROBE_URL": url,
                                 "FG_WRITE_PROBE_CA": str(self.certs / "frontend-ca.pem")},
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        readable, _, _ = select.select([process.stdout], [], [], 12)
        if not (bool(readable) and process.stdout.readline().strip() == "ready"):
            process.kill()
            raise Failure("the branch probe session did not start")
        return process

    def probe_query(self, process, sql):
        process.stdin.write(json.dumps({"op": "read", "sql": sql}) + "\n")
        process.stdin.flush()
        readable, _, _ = select.select([process.stdout], [], [], 12)
        if not readable:
            raise Failure("the branch probe session stopped answering queries")
        return json.loads(process.stdout.readline())

    def wait_dropped(self, owner, branch_id):
        def is_dropped():
            status, raw = self.request("GET", f"/v1/branches/{branch_id}", self.owner_tokens[owner])
            return status == 200 and json.loads(raw)["status"] == "dropped"
        wait_until(f"branch {branch_id} cleanup", is_dropped)

    def drop(self, owner, branch_id):
        branch = self.cli(owner, "drop", "--id", str(branch_id))
        require(branch["id"] == branch_id and branch["status"] in {"dropping", "dropped"},
                "Drop returned a different branch or invalid lifecycle state")
        self.wait_dropped(owner, branch_id)

    def test_owner_and_expiry(self, alpha, beta, canary):
        alice = self.cli(OWNER_A, "list")
        bob = self.cli(OWNER_B, "list")
        json_file(self.report / "owner-list-alice.json", alice)
        json_file(self.report / "owner-list-bob.json", bob)
        require(len(alice) == 2 and {row["id"] for row in alice} == {canary["id"], alpha["id"]}
                and all(row["created_by"] == OWNER_A for row in alice),
                "Alice list did not contain exactly her active and dropped branches")
        require(next(row for row in alice if row["id"] == canary["id"])["status"] == "dropped",
                "Alice list did not retain the dropped canary lifecycle state")
        require(len(bob) == 1 and {row["id"] for row in bob} == {beta["id"]}
                and all(row["created_by"] == OWNER_B for row in bob),
                "Bob list did not contain exactly his branch")
        for method in ("GET", "DELETE"):
            require(self.request(method, f"/v1/branches/{alpha['id']}", self.owner_tokens[OWNER_B])[0] == 404,
                    "Owner API leaked another branch")
        require(self.request("GET", "/v1/branches", self.secret["expired_token"])[0] == 401,
                "Expired owner token was accepted")
        for label, owner, branch, code, kwargs in (
            ("wrong-password", OWNER_A, alpha["name"], "FG-1002", {"password": "deliberately-wrong"}),
            ("forged-user", "not-an-account", alpha["name"], "FG-1002", {"password": "deliberately-wrong"}),
            ("unauthorized-branch", OWNER_B, alpha["name"], "FG-2003", {}),
            ("unknown-branch", OWNER_A, "not-created", "FG-2003", {}),
            ("missing-branch", OWNER_A, "", "FG-2003", {}),
            ("expired-account", EXPIRED, alpha["name"], "FG-1002", {}),
            ("wrong-ca", OWNER_A, alpha["name"], None, {"ca": self.certs / "backend-ca.pem"}),
        ):
            self.session(label, "reject", owner, branch, expected_fg=code, **kwargs)
        short = self.cli(OWNER_A, "fork", "p2-short", "--ttl-seconds", "5")
        # The barrier's held session closes when the TTL trips: after the
        # wait its next statement re-verifies with the control plane and is
        # refused, which is exactly what finish_hold requires.
        self.hold("hold-closed", OWNER_A, short["name"])
        probe = self.branch_probe(short)
        # Orders is the one v1 fixture table every generation catalog
        # registers (parents/children arrive with the v2 refresh).
        before = self.probe_query(probe, "SELECT tenant_id, id FROM orders WHERE tenant_id=1 AND id=1")
        require(before.get("rows") == [[1, 1]], f"The probe query failed before expiry: {before}")
        wait_until("branch TTL", lambda: self.metadata(
            f"SELECT (expires_at <= clock_timestamp())::int FROM branch WHERE id={short['id']};") == "1", 8)
        expired = self.probe_query(probe, "SELECT tenant_id, id FROM orders WHERE tenant_id=1 AND id=1")
        require(expired.get("fg") == "FG-2003",
                f"An expired branch stayed queryable on an open session: {expired}")
        self.session("expired-branch", "reject", OWNER_A, short["name"], expected_fg="FG-2003")
        self.finish_hold("hold-closed")
        probe.kill()
        self.drop(OWNER_A, short["id"])
        self.record("owner-authentication-and-branch-expiry")

    def test_concurrent_fork(self):
        request = {"name": "p2-race", "class": "dev", "ttl_seconds": 60}
        token = self.owner_tokens[OWNER_A]
        for invalid in (request | {"class": "unknown"}, request | {"ttl_seconds": 86401},
                        request | {"name": "mysql"}):
            require(self.request("POST", "/v1/branches", token, invalid)[0] == 400,
                    "The owner API accepted an unsupported class, TTL, or reserved name")
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: self.request("POST", "/v1/branches", token, request), range(2)))
        require(sorted(status for status, _ in results) == [201, 409], "Concurrent fork did not produce one conflict")
        branch = next(json.loads(raw) for status, raw in results if status == 201)
        self.drop(OWNER_A, branch["id"])
        self.record("concurrent-live-name-conflict")

    def prepare_data(self, binding, alpha, beta):
        data.seed_delta(self.engine, self.native, binding, alpha["id"], beta["id"])
        data.prepare_reference(self.engine, self.native)
        if self.family in ("mysql", "tidb"):
            self.native("GRANT SELECT ON app.* TO 'p2_ref'@'%';")
            grants = self.native("SHOW GRANTS FOR 'p2_service'@'%';")
            require("GRANT SELECT ON" in grants and all(word not in grants for word in ("INSERT", "UPDATE", "DELETE", "ALL PRIVILEGES")),
                    "The native MySQL proxy account has unexpected write privileges")
        else:
            self.native("GRANT USAGE ON SCHEMA app TO p2_ref; GRANT SELECT ON ALL TABLES IN SCHEMA app TO p2_ref;")
            for entry in binding["tables"]:
                for relation in (data.table(self.engine, entry["base_schema"], entry["base_table"]),
                                 data.table(self.engine, entry["delta_schema"], entry["delta_table"])):
                    allowed = self.native(f"SELECT has_table_privilege('p2_service','{relation}','SELECT'), has_table_privilege('p2_service','{relation}','INSERT,UPDATE,DELETE');")
                    require(allowed == "t|f", "The native PostgreSQL proxy account has unexpected write privileges")
        self.record("separate-read-only-native-roles")

    def compare(self, binding, alpha, beta):
        write_corpus(self.corpus, binding)
        expected = data.snapshot(self.engine, self.native, binding)
        for label, owner, branch in (("alpha", OWNER_A, alpha), ("beta", OWNER_B, beta)):
            data.materialize_reference(self.engine, self.native, label)
            existing = set(self.report.glob("*/report.json"))
            self.call(f"differential-{label}", [self.executable("fg-diff"), "run", "--mode", "reference-vs-proxy",
                      "--engine", self.cli_engine, "--tag", f"p2-{label}", "--corpus", self.corpus,
                      "--report-root", self.report], env=self.diff_env(owner, branch["name"]), timeout=90, log=True)
            added = set(self.report.glob("*/report.json")) - existing
            require(len(added) == 1, "A differential run did not produce one fresh report")
            path = added.pop()
            observations = json.loads(path.read_text(encoding="utf-8"))
            require(observations["mode"] == "reference_vs_proxy" and observations["failed"] == 0,
                    "Differential evidence is missing or contains failed cases")
            refused = sum("-refuse-" in item["id"] for item in observations["cases"])
            self.differential.append({"branch": label, "reads": observations["passed"] - refused,
                                      "refusals": refused, "report": str(path.parent.relative_to(self.report))})
            self.session(f"prepare-{label}", "probe", owner, branch["name"])
            require(data.snapshot(self.engine, self.native, binding) == expected,
                    "Reference comparison or refusal changed candidate base or delta rows")
            self.record(f"branch-{label}-reference-vs-proxy-and-prepared")

    def test_outage_and_recovery(self, binding, alpha):
        self.hold("hold-closed", OWNER_A, alpha["name"])
        self.stop("control")
        self.session("control-outage-new-session", "reject", OWNER_A, alpha["name"], expected_fg="FG-1004")
        self.finish_hold("hold-closed")
        self.start_control()
        require(any(row["id"] == alpha["id"] and row["status"] == "active"
                    for row in self.cli(OWNER_A, "list")), "Control restart lost active branch metadata")
        self.record("control-outage-fails-closed-and-restart-preserves-ids")
        baseline = data.snapshot(self.engine, self.native, binding)
        recovering = self.cli(OWNER_A, "fork", "p2-recovery")
        orders = self.seed_witness(binding, recovering["id"])
        self.gc_privilege("REVOKE", orders)
        dropping = self.cli(OWNER_A, "drop", "--id", str(recovering["id"]))
        require(dropping["status"] == "dropping", "Drop completed before native cleanup")
        wait_until("GC permission failure", lambda: self.gc_attempt_failed(recovering["id"]), 10)
        self.stop("control")
        require(self.metadata(f"SELECT status FROM branch WHERE id={recovering['id']};") == "dropping",
                "Interrupted drop did not persist its state")
        require(any(data.snapshot(self.engine, self.native, binding, recovering["id"])[1::2]),
                "GC failure unexpectedly removed the denied delta rows")
        self.gc_privilege("GRANT", orders)
        self.start_control()
        self.wait_dropped(OWNER_A, recovering["id"])
        require(data.snapshot(self.engine, self.native, binding) == baseline,
                "Resumed cleanup did not preserve the independent branch data")
        self.record("interrupted-drop-resumes-after-restart")

    def gc_attempt_failed(self, branch_id):
        for line in (self.report / "control.log").read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            fields = event.get("fields", {})
            if (fields.get("branch_id") == branch_id
                    and fields.get("message") == "branch remains dropping"
                    and fields.get("reason") == "native_connection_or_operation_failed"):
                return self.metadata(
                    f"SELECT (status='dropping' AND lifecycle_phase='cleanup_retry' "
                    f"AND lifecycle_reason='native_connection_or_operation_failed')::int "
                    f"FROM branch WHERE id={branch_id};") == "1"
        return False

    def seed_witness(self, binding, branch_id):
        entry = next(entry for entry in binding["tables"] if entry["logical_table"] == "orders")
        base = data.table(self.engine, entry["base_schema"], entry["base_table"])
        delta = data.table(self.engine, entry["delta_schema"], entry["delta_table"])
        self.native(f"""
            INSERT INTO {delta} (_fg_branch,_fg_op,tenant_id,id,customer_id,amount,note,payload)
              SELECT {int(branch_id)},'U',tenant_id,id,customer_id,amount,note,payload
              FROM {base} WHERE tenant_id=1 AND id=2;
        """)
        return delta

    def gc_privilege(self, action, table):
        principal = "p2_gc" if self.family == "postgresql" else "'p2_gc'@'%'"
        direction = "TO" if action == "GRANT" else "FROM"
        self.native(f"{action} DELETE ON {table} {direction} {principal};")

    def test_drop(self, binding, alpha, beta):
        beta_before = data.snapshot(self.engine, self.native, binding, beta["id"])
        self.hold("hold-closed", OWNER_A, alpha["name"])
        self.hold("hold-open", OWNER_B, beta["name"])
        self.drop(OWNER_A, alpha["id"])
        self.finish_hold("hold-closed")
        self.finish_hold("hold-open")
        alpha_after = data.snapshot(self.engine, self.native, binding, alpha["id"])
        require(all(not rows for rows in alpha_after[1::2]), "Dropped branch still has native delta rows")
        require(data.snapshot(self.engine, self.native, binding, beta["id"]) == beta_before,
                "Drop changed the base or another branch's delta rows")
        self.session("dropped-branch", "reject", OWNER_A, alpha["name"], expected_fg="FG-2003")
        replacement = self.cli(OWNER_A, "fork", alpha["name"])
        require(replacement["id"] != alpha["id"], "Reused branch name retained the old immutable ID")
        self.seed_witness(binding, replacement["id"])
        replacement_before = data.snapshot(self.engine, self.native, binding, replacement["id"])
        self.drop(OWNER_A, alpha["id"])
        require(data.snapshot(self.engine, self.native, binding, replacement["id"]) == replacement_before,
                "Stale drop changed the replacement branch's native rows")
        self.session("replacement-prepared", "probe", OWNER_A, replacement["name"])
        self.drop(OWNER_A, replacement["id"])
        self.drop(OWNER_B, beta["id"])
        self.record("drop-drain-isolation-and-immutable-name-reuse")

    def execute(self):
        self.compose_started = True
        self.compose("compose-up", "up", "--detach", "--wait", "--wait-timeout", "120", timeout=150, log=True)
        self.native_port = int(self.compose("native-port", "port", "native", str(self.internal_port)).rpartition(":")[2])
        self.metadata_port = int(self.compose("metadata-port", "port", "metadata", "5432").rpartition(":")[2])
        self.prepare_native_engine()
        self.engine_version = self.native("SELECT VERSION();")
        require(self.settings["version"] in self.engine_version, "Unexpected native engine version")
        self.migrations_and_bootstrap()
        self.start_control()
        self.verify_readiness_diagnostics()
        self.start_proxy()
        canary = self.cli(OWNER_A, "fork", "p2-base-only")
        require(canary["access"] == "read_only" and canary["read_strategy"] == "base_only",
                "A new SQL read-only branch did not select the immutable base path")
        self.drop(OWNER_A, canary["id"])
        alpha = self.merge_fixture(OWNER_A, "p2-alpha")
        beta = self.merge_fixture(OWNER_B, "p2-beta")
        require(alpha["id"] != beta["id"] and alpha["generation_id"] == beta["generation_id"],
                "Fork did not allocate distinct IDs in the active generation")
        self.test_owner_and_expiry(alpha, beta, canary)
        self.test_concurrent_fork()
        binding = self.binding(OWNER_A, alpha)
        self.prepare_data(binding, alpha, beta)
        self.compare(binding, alpha, beta)
        self.test_outage_and_recovery(binding, alpha)
        self.test_drop(binding, alpha, beta)

    def cleanup(self):
        try:
            for label in list(self.processes):
                self.stop(label)
        finally:
            if self.compose_started:
                self.compose("compose-down", "down", "--volumes", "--remove-orphans", "--timeout", "5",
                             timeout=40, log=True)
                project = f"label=com.docker.compose.project={self.project}"
                for listing in (["ps", "-aq"], ["network", "ls", "-q"], ["volume", "ls", "-q"]):
                    remaining = self.call("compose-residuals", ["docker", *listing, "--filter", project])
                    require(not remaining, "Disposable Compose project still has resources")
                self.compose_started = False


def git_state():
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True)
    if revision.returncode != 0:
        return None, "unavailable"
    status = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True)
    dirty = "dirty" if status.stdout.strip() else "clean"
    return revision.stdout.strip(), dirty if status.returncode == 0 else "unavailable"


def interrupt(_signal, _frame):
    raise KeyboardInterrupt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("engine", choices=("mysql", "postgresql", "tidb", "all"), nargs="?", default="all")
    selected = parser.parse_args().engine
    engines = ("mysql", "postgresql", "tidb") if selected == "all" else (selected,)
    started = datetime.now(UTC)
    run_id = f"fgp2-{started:%H%M%S}-{os.getpid()}"
    report_root = Path(os.environ.get("FG_P2_REPORT_ROOT", ROOT / "test/reports")).resolve()
    report = report_root / f"{started:%Y%m%d}-p2-branches-{started:%H%M%S}-{os.getpid()}"
    report.mkdir(parents=True)
    results = {}
    interrupted = False
    signal.signal(signal.SIGTERM, interrupt)
    for engine in engines:
        engine_report = report / engine
        engine_report.mkdir()
        print(f"Running P2 {engine}; reports: {engine_report}", flush=True)
        with tempfile.TemporaryDirectory(prefix=f"{run_id}-") as temporary:
            workspace = Path(temporary)
            certs = workspace / "certs"
            runner = EngineRun(engine, engine_report, workspace, certs, run_id)
            errors = []
            try:
                build_certs(certs)
                runner.execute()
            except KeyboardInterrupt:
                errors.append("Run interrupted")
                interrupted = True
            except (Failure, OSError, ValueError, KeyError, IndexError) as error:
                errors.append(runner.safe(str(error)))
            finally:
                try:
                    runner.cleanup()
                except (Failure, OSError, subprocess.TimeoutExpired) as error:
                    errors.append(runner.safe(str(error)))
            results[engine] = {"status": "failed" if errors else "passed", "image": runner.image,
                               "version": runner.engine_version, "passed_cases": runner.cases,
                               "differential": runner.differential, "errors": errors,
                               "cleaned_up": not runner.compose_started}
            for error in errors:
                print(f"[FAIL] {engine}: {error}", flush=True)
        if interrupted:
            break
    passed = all(result["status"] == "passed" for result in results.values())
    status = "interrupted" if interrupted else ("passed" if passed else "failed")
    json_file(report / "report.json", {"status": status, "mode": "reference_vs_proxy", "engines": results,
                                      "started_at": started.isoformat(), "finished_at": datetime.now(UTC).isoformat()})
    revision, source_state = git_state()
    json_file(report / "env.json", {"run_kind": "local", "source_revision": revision, "source_state": source_state,
                                   "host": platform.system(), "architecture": platform.machine(),
                                   "metadata_image": "postgres:16.14"})
    summary = ["# P2 local branch integration", "", f"Overall result: {status}.", ""]
    for engine, result in results.items():
        summary.append(f"- {engine}: {result['status']}, {len(result['passed_cases'])} lifecycle and suite checks.")
        for item in result["differential"]:
            summary.append(
                f"  - [{item['branch']}]({engine}/{item['report']}/summary.md): "
                f"{item['reads']} reads and {item['refusals']} exact SQL refusals."
            )
        summary.extend(f"  - {error}" for error in result["errors"])
    summary.extend(["", "The per-engine directories contain native differential reports and lifecycle logs.", ""])
    (report / "summary.md").write_text("\n".join(summary), encoding="utf-8")
    print(f"P2 report: {report}", flush=True)
    return 130 if interrupted else (0 if status == "passed" else 1)


if __name__ == "__main__":
    raise SystemExit(main())
