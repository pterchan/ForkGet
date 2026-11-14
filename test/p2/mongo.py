#!/usr/bin/env python3
"""MongoDB branch suite: the full production chain -
compose engines, metadata migrations, mongo generation bootstrap, control
serve, proxy serve, CLI fork - then a real pymongo driver proves merged
reads, policy-gated delta capture, base immutability, branch isolation,
the budget refusal path, typed refusals, and drop cleanup.

The suite needs docker (test/local compose), the repository binaries
(cargo build runs it through make p2-test) and a python venv with pymongo
for the driver oracle; without pymongo the suite records the skip and
still proves the lifecycle through the CLI and mongod state.

Usage: python3 test/p2/mongo.py [report_root]
"""
import json
import os
import secrets
import socket
import signal
import subprocess
import sys
import time
import tempfile
import urllib.request
from urllib.parse import unquote, urlsplit
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BINS = (Path(os.environ.get("CARGO_TARGET_DIR", REPO / "target")) / "debug").resolve()
os.environ["PATH"] = str(BINS) + os.pathsep + os.environ.get("PATH", "")
COMPOSE = ["docker", "compose", "-f", str(REPO / "test/local/docker-compose.yml")]
META_DB_PREFIX = "fg_p2_mongo_"
def frontend_ports():
    listeners=[]
    try:
        for _ in range(3):
            listener=socket.socket()
            listener.bind(("127.0.0.1",0))
            listeners.append(listener)
        return [listener.getsockname()[1] for listener in listeners]
    finally:
        for listener in listeners:listener.close()

FRONTEND_PORT, CONTROL_PORT, PROXY_CONTROL_PORT = frontend_ports()
MONGO_PORT = int(os.environ.get("MONGO_PORT", "27027"))
POSTGRES_PORT = int(os.environ.get("POSTGRES_PORT", "55432"))
BRANCH_USER = "alice"
STEP_TIMEOUT = 60
DRIVER_TLS = {}
FRONTEND_HOST = "127.0.0.1"
TLS_DIRECTORY = None
PRIVATE_RELAY = None
BACKEND_HOST = "127.0.0.1"
BACKEND_PORT = MONGO_PORT


def log(step, detail=""):
    print(f"[mongo-suite] {step}: {detail}", flush=True)


def run(command, env=None, check=True, timeout=STEP_TIMEOUT):
    if TLS_DIRECTORY and command[:4] == ["docker", "exec", "fg-mongo-7", "mongosh"]:
        command = command[:4] + ["--tls", "--tlsCAFile", "/certs/ca.pem"] + command[4:]
    if command[:2]==["docker","exec"] and command[2] in ("fg-mongo-7","fg-postgres-16"):
        service="mongo" if command[2]=="fg-mongo-7" else "postgres"
        command=command[:2]+[container(service)]+command[3:]
    result = subprocess.run(
        command, env=env, cwd=REPO, capture_output=True, text=True, timeout=timeout
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"fixture command failed ({result.returncode}): {Path(str(command[0])).name}; inspect the suite phase"
        )
    return result


def sanitized_phase_output(value, environment, known_secrets):
    """Retain safe control diagnostics without argv, DSNs or credentials."""
    redactions = {secret for secret in known_secrets if secret}
    for name, setting in environment.items():
        if not setting:
            continue
        if any(part in name.upper() for part in ("PASSWORD", "PASSWD", "TOKEN", "SECRET", "DSN", "ACCOUNTS")):
            redactions.add(setting)
        if name.endswith(("_DSN", "_URL")):
            try:
                password = urlsplit(setting).password
            except ValueError:
                password = None
            if password:
                redactions.update((password, unquote(password)))
        if name in ("FG_CONTROL_ACCOUNTS", "FG_FRONTEND_ACCOUNTS"):
            try:
                accounts = json.loads(setting)
            except (TypeError, ValueError):
                continue
            if isinstance(accounts, list):
                for account in accounts:
                    if isinstance(account, dict):
                        redactions.update(secret for key in ("password", "token")
                                          if isinstance(secret := account.get(key), str) and secret)
    for secret in tuple(redactions):
        # Structured child diagnostics can escape a credential instead of
        # emitting its literal form. Cover both JSON Unicode encodings.
        redactions.update(json.dumps(secret, ensure_ascii=ascii_only)[1:-1]
                          for ascii_only in (False, True))
    for secret in sorted(redactions, key=len, reverse=True):
        value = value.replace(secret, "[redacted]")
    return value

def container(service):
    value=subprocess.check_output(COMPOSE+["ps","-q",service],cwd=REPO,text=True).strip()
    if not value:raise RuntimeError(f"The suite's {service} container is unavailable")
    return value


def configure_tls(artifacts):
    """Disposable CA/key material stays outside the report tree."""
    global COMPOSE, DRIVER_TLS, FRONTEND_HOST, TLS_DIRECTORY, PRIVATE_RELAY, BACKEND_HOST, BACKEND_PORT
    hostname = os.environ.get("FG_TRANSPORT_TEST_HOST")
    if hostname is not None:
        sys.path.insert(0, str(REPO / "test/p7"))
        from transport_cases import PrivateRelay, private_host
        # Use the same DNS identity and strict RFC1918 checks as SQL transport.
        # Persist failed endpoint selection before issuing certificates or DDL.
        hostname, address = private_host(artifacts)
    TLS_DIRECTORY = tempfile.TemporaryDirectory(prefix="forkget-mongo-tls-")
    directory = Path(TLS_DIRECTORY.name)
    directory.chmod(0o755)
    sans = "IP:127.0.0.1,DNS:localhost"
    if hostname is not None:
        FRONTEND_HOST = address
        sans += f",DNS:{hostname},IP:{address}"
        os.environ["FG_MANAGED_BACKEND_HOST"] = hostname
        PRIVATE_RELAY = PrivateRelay(address, MONGO_PORT)
        PRIVATE_RELAY.__enter__()
        BACKEND_HOST, BACKEND_PORT = hostname, PRIVATE_RELAY.server_address[1]
    for name in ("ca", "wrong-ca"):
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", f"/CN=Forkget {name}", "-keyout", str(directory / f"{name}.key"),
             "-out", str(directory / f"{name}.pem"), "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
    run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=Forkget fixture",
         "-keyout", str(directory / "server.key"), "-out", str(directory / "server.csr")])
    (directory / "server.ext").write_text(f"subjectAltName={sans}\nextendedKeyUsage=serverAuth\n"
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
    run(["openssl", "x509", "-req", "-in", str(directory / "server.csr"), "-CA", str(directory / "ca.pem"),
         "-CAkey", str(directory / "ca.key"), "-set_serial", "1", "-days", "1",
         "-extfile", str(directory / "server.ext"), "-out", str(directory / "server.pem")])
    (directory / "mongod.pem").write_bytes((directory / "server.pem").read_bytes() + (directory / "server.key").read_bytes())
    (directory / "mongod.pem").chmod(0o644)
    override = directory / "compose.json"
    override.write_text(json.dumps({"services": {"mongo": {
        "command": ["mongod", "--auth", "--bind_ip_all", "--tlsMode", "requireTLS",
                    "--tlsCertificateKeyFile", "/certs/mongod.pem", "--tlsCAFile", "/certs/ca.pem",
                    "--tlsAllowConnectionsWithoutCertificates"],
        "volumes": [f"{directory}:/certs:ro"],
        "healthcheck": {"test": ["CMD-SHELL", "mongosh --tls --tlsCAFile /certs/ca.pem -u root -p \"$$MONGO_INITDB_ROOT_PASSWORD\" --quiet --eval 'db.runCommand({ping:1}).ok' | grep -q 1"]},
    }}}))
    COMPOSE = COMPOSE + ["-f", str(override)]
    DRIVER_TLS = {"tls": True, "tlsCAFile": str(directory / "ca.pem")}
    os.environ.update(FG_BACKEND_CA=str(directory / "ca.pem"),
                      FG_TLS_CERT=str(directory / "server.pem"), FG_TLS_KEY=str(directory / "server.key"))


def load_env():
    """Secrets come from test/local/.env first, then the process environment
    (the CI jobs define the same variables)."""
    env_file = REPO / "test/local/.env"
    values = {}
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if "=" in line and not line.strip().startswith("#"):
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
    for key in ("FG_TEST_MONGO_ROOT_PASSWORD", "FG_TEST_POSTGRES_PASSWORD"):
        values[key] = os.environ.get(key) or values.get(key, "")
        if not values[key]:
            raise RuntimeError(f"{key} is missing; source test/local/.env first")
    return values


def psql(meta_db, sql):
    return run(
        ["docker", "exec", "fg-postgres-16", "psql", "-U", "fg_test", "-d", meta_db, "-tAc", sql]
    ).stdout.strip()


def wait_healthy(service):
    deadline = time.time() + 90
    while time.time() < deadline:
        result = run(
            ["docker", "inspect", "-f", "{{.State.Health.Status}}", container(service.rsplit("-",1)[0])],
            check=False,
        )
        if result.stdout.strip() == "healthy":
            return
        time.sleep(2)
    raise RuntimeError(f"{service} never became healthy")


def driver_python():
    """A python with pymongo available: FG_SUITE_PYTHON, a repo-local venv,
    or a fresh venv next to the suite artifacts."""
    candidate = os.environ.get("FG_SUITE_PYTHON")
    if candidate and subprocess.run(
        [candidate, "-c", "import pymongo"], capture_output=True
    ).returncode == 0:
        return candidate
    venv = REPO / "target/p2-mongo-venv"
    python = venv / "bin/python"
    if not python.exists():
        log("venv", "creating a pymongo venv for the driver oracle")
        run([sys.executable, "-m", "venv", str(venv)], timeout=120)
        pip = venv / "bin/pip"
        run([str(pip), "install", "--quiet", "pymongo"], timeout=180)
    return str(python)


def driver_steps(python, proxy_port, mongo_password, base_db):
    """Everything the real pymongo driver proves through the proxy."""
    steps = []

    def step(name, script):
        result = run(
            [python, "-c", script],
            timeout=STEP_TIMEOUT,
            check=False,
        )
        steps.append(
            {
                "step": name,
                "ok": result.returncode == 0,
                "stdout": result.stdout.strip()[-2000:],
                "stderr": result.stderr.strip()[-2000:],
            }
        )
        log(f"driver {name}", "ok" if result.returncode == 0 else result.stderr[-500:])
        return result.returncode == 0

    uri = (
        f"mongodb://{BRANCH_USER}:branch-alice-pw@{FRONTEND_HOST}:{proxy_port}/alpha"
        "?authSource=admin&directConnection=true"
    )
    beta_uri = (
        f"mongodb://{BRANCH_USER}:branch-alice-pw@{FRONTEND_HOST}:{proxy_port}/beta"
        "?authSource=admin&directConnection=true"
    )
    base_uri = (
        f"mongodb://root:{mongo_password}@127.0.0.1:{MONGO_PORT}/{base_db}"
        "?authSource=admin&directConnection=true"
    )
    scripts = {
        "authentication_and_owner_isolation": f"""
import pymongo
for account, password, expected in [('alice', 'wrong-password', 'Authentication'), ('bob', 'branch-bob-pw', 'FG-2003')]:
    client = pymongo.MongoClient(f'mongodb://{{account}}:{{password}}@{FRONTEND_HOST}:{proxy_port}/alpha?authSource=admin&directConnection=true', serverSelectionTimeoutMS=5000, **{DRIVER_TLS!r})
    try:
        client.alpha.orders.find_one()
        raise AssertionError('unauthorized principal read another owner branch')
    except pymongo.errors.OperationFailure as error:
        assert (error.code == 18 if account == 'alice' else expected in str(error)), error
    finally:
        client.close()
""",
        "legacy_hello_and_op_msg": f"""
import socket, ssl, struct, bson
connection = socket.create_connection(({FRONTEND_HOST!r}, {proxy_port}), timeout=5)
if {bool(DRIVER_TLS)!r}:
    connection = ssl.create_default_context(cafile={DRIVER_TLS.get('tlsCAFile')!r}).wrap_socket(connection, server_hostname={FRONTEND_HOST!r})
def exchange(opcode, body):
    connection.sendall(struct.pack('<iiii', 16+len(body), 19, 0, opcode)+body)
    def receive(size):
        data = b''
        while len(data) < size:
            chunk = connection.recv(size-len(data))
            assert chunk, 'truncated wire response'
            data += chunk
        return data
    header = struct.unpack('<iiii', receive(16))
    assert header[2] == 19, header
    return header[3], receive(header[0]-16)
hello = bson.BSON.encode({{'hello': 1}})
opcode, body = exchange(2004, struct.pack('<i', 0)+b'admin.$cmd'+bytes([0])+struct.pack('<ii', 0, -1)+hello)
assert opcode == 1 and struct.unpack('<iqii', body[:20]) == (0, 0, 0, 1), (opcode, body)
assert bson.BSON(body[20:]).decode()['maxWireVersion'] == 21
opcode, body = exchange(2013, struct.pack('<i', 0)+bytes([0])+bson.BSON.encode({{'hello': 1, '$db': 'admin'}}))
assert opcode == 2013 and bson.BSON(body[5:]).decode()['ok'] == 1
opcode, body = exchange(2004, struct.pack('<i', 0)+b'alpha.$cmd'+bytes([0])+struct.pack('<ii', 0, -1)+bson.BSON.encode({{'find': 'orders'}}))
assert opcode == 2013 and bson.BSON(body[5:]).decode()['code'] == 20
connection.close()
""",
        "service_cannot_mutate_base": f"""
import pymongo
client = pymongo.MongoClient("mongodb://fg_service:svc-local-pw@127.0.0.1:{MONGO_PORT}/fg_g2?authSource=admin&directConnection=true", serverSelectionTimeoutMS=5000, **{DRIVER_TLS!r})
try:
    client.get_default_database().orders.update_one({{"_id": 1}}, {{"$set": {{"note": "forbidden"}}}})
    raise AssertionError("service account can mutate the immutable generation")
except pymongo.errors.OperationFailure as error:
    assert error.code == 13, error
client.close()
""",
        "read_base": f"""
import pymongo
client = pymongo.MongoClient({uri!r}, serverSelectionTimeoutMS=5000, **{DRIVER_TLS!r})
db = client.alpha
assert db.list_collection_names() == ["orders", "customers", "parents", "children"], (
    db.list_collection_names()
)
assert db.orders.count_documents({{}}) == 4
assert db.customers.count_documents({{}}) == 3
client.close()
""",
        "capture_and_merge": f"""
import pymongo
client = pymongo.MongoClient({uri!r}, serverSelectionTimeoutMS=5000, **{DRIVER_TLS!r})
db = client.alpha
db.orders.insert_one({{"_id": 100, "tenant_id": 1, "customer_id": 10, "amount": 7.25, "note": "suite"}})
db.orders.update_one({{"_id": 2}}, {{"$set": {{"note": "alpha-edited"}}}})
db.orders.delete_one({{"_id": 3}})
assert sorted(d["_id"] for d in db.orders.find()) == [1, 2, 4, 100]
assert db.orders.find_one({{"_id": 2}})["note"] == "alpha-edited"
client.close()
""",
        "base_immutable": f"""
import pymongo
client = pymongo.MongoClient({base_uri!r}, serverSelectionTimeoutMS=5000, **{DRIVER_TLS!r})
base = client.get_default_database()
assert base.orders.count_documents({{}}) == 4, "base row count changed"
assert base.orders.find_one({{"_id": 1}})["note"] == "base-v2-one", "base document mutated"
client.close()
""",
        "branch_isolation": f"""
import pymongo
beta = pymongo.MongoClient({beta_uri!r}, serverSelectionTimeoutMS=5000, **{DRIVER_TLS!r})
assert sorted(d["_id"] for d in beta.beta.orders.find()) == [1, 2, 3, 4]
assert beta.beta.orders.find_one({{"_id": 2}})["note"] == "base-two"
beta.close()
""",
        "duplicate_identity_refused": f"""
import pymongo
client = pymongo.MongoClient({uri!r}, serverSelectionTimeoutMS=5000, **{DRIVER_TLS!r})
try:
    client.alpha.orders.insert_one({{"_id": 1, "note": "conflict"}})
    raise AssertionError("duplicate insert was accepted")
except (pymongo.errors.BulkWriteError, pymongo.errors.DuplicateKeyError) as failure:
    code = getattr(failure, "code", None) or failure.details["writeErrors"][0]["code"]
    assert code == 11000, code
client.close()
""",
        "escape_hatch_refused": f"""
import pymongo
client = pymongo.MongoClient({uri!r}, serverSelectionTimeoutMS=5000, **{DRIVER_TLS!r})
try:
    list(client.alpha.orders.aggregate([{{"$out": "elsewhere"}}]))
    raise AssertionError("$out was admitted")
except pymongo.errors.OperationFailure as failure:
    assert "FG-2002" in str(failure), failure
client.close()
""",
    }
    for name, script in scripts.items():
        step(name, script)
        if not steps[-1]["ok"]:
            return steps
    return steps


def control_request(path, method, token, body=None):
    request = urllib.request.Request(
        f"http://127.0.0.1:{CONTROL_PORT}{path}",
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"{method} {path} -> {error.code}: {error.read().decode()[:200]}") from None


def main():
    started = datetime.now(timezone.utc)
    secrets_token = secrets.token_hex(12)
    meta_db = f"{META_DB_PREFIX}{int(time.time())}"
    report_root = os.environ.get("FG_P2_MONGO_REPORT_ROOT")
    artifacts = Path(
        sys.argv[1]
        if len(sys.argv) > 1
        else (
            Path(report_root)
            / f"p2-mongo-{started:%H%M%S}-{os.getpid()}"
            if report_root
            else REPO / "target" / "p2-mongo-evidence"
            / f"{started:%Y%m%d}-p2-mongo-{started:%H%M%S}-{os.getpid()}"
        )
    )
    artifacts.mkdir(parents=True, exist_ok=True)
    secrets_map = load_env()

    def phase(label, command, environment):
        result = run(command, env=environment, check=False)
        diagnostic = sanitized_phase_output(result.stdout + result.stderr, environment,
                                             [*secrets_map.values(), secrets_token])
        # Save the child result before refusing the phase. A failed run cannot
        # reconstruct stderr that a prior fixture already discarded.
        (artifacts / (label + ".log")).write_text(diagnostic)
        if result.returncode != 0:
            raise RuntimeError(f"fixture {label} failed ({result.returncode}); inspect {label}.log")
        return result

    if os.environ.get("FG_MONGO_TEST_TLS") == "1":
        configure_tls(artifacts)

    log("compose", "starting mongo and postgres")
    run(COMPOSE + ["up", "-d", "mongo", "postgres"])
    wait_healthy("mongo-7")
    wait_healthy("postgres-16")

    meta_password = secrets_map["FG_TEST_POSTGRES_PASSWORD"]
    mongo_password = secrets_map["FG_TEST_MONGO_ROOT_PASSWORD"]
    run(
        [
            "docker", "exec", "fg-postgres-16", "psql", "-U", "fg_test", "-d", "postgres",
            "-c", f"DROP DATABASE IF EXISTS {meta_db}",
        ]
    )
    run(
        [
            "docker", "exec", "fg-postgres-16", "psql", "-U", "fg_test", "-d", "postgres",
            "-c", f"CREATE DATABASE {meta_db}",
        ]
    )
    meta_dsn = f"postgres://fg_test:{meta_password}@127.0.0.1:{POSTGRES_PORT}/{meta_db}"
    admin_dsn = f"mongodb://root:{mongo_password}@{BACKEND_HOST}:{BACKEND_PORT}/admin"
    gc_dsn = f"mongodb://fg_gc:gc-local-pw@{BACKEND_HOST}:{BACKEND_PORT}/admin"

    base_uri = (
        f"mongodb://root:{mongo_password}@127.0.0.1:{MONGO_PORT}/fg_g2"
        "?authSource=admin&directConnection=true"
    )
    # The deployment grant recipe creates the service and collector accounts;
    # the suite provisions them idempotently (fresh containers have root only).
    run(
        [
            "docker", "exec", "fg-mongo-7", "mongosh", "-u", "root", "-p", mongo_password,
            "--quiet", "--eval",
            "const admin = db.getSiblingDB('admin');"
            "try { admin.createUser({user: 'fg_service', pwd: 'svc-local-pw', roles: []}); }"
            "catch (e) { if (e.code !== 51003) throw e; }"
            "try { admin.createUser({user: 'fg_gc', pwd: 'gc-local-pw', roles: []}); }"
            "catch (e) { if (e.code !== 51003) throw e; }"
            "const role = admin.getRole('fg_service');"
            "if (role) { const privs = role.privileges || []; "
            "const kept = privs.filter(p => !(p.resource && p.resource.db && (p.resource.db.startsWith('fg_b') || p.resource.db.startsWith('fg_g')))); "
            "if (kept.length !== privs.length) { admin.updateRole('fg_service', { privileges: kept }); } }",
        ],
        timeout=60,
    )

    log("cleanup", "drop leftover forkget-owned databases from reused volumes")
    run(
        [
            "docker", "exec", "fg-mongo-7", "mongosh", "-u", "root", "-p", mongo_password,
            "--quiet", "--eval",
            "db.adminCommand({listDatabases: 1}).databases.map(d => d.name)"
            ".filter(n => n.startsWith('fg_g') || n.startsWith('fg_b') || n === 'forkget_delta')"
            ".forEach(n => db.getSiblingDB(n).dropDatabase())",
        ],
        timeout=120,
    )

    log("bootstrap", "migrate and bootstrap the mongo generation")
    env = {
        **os.environ,
        "FG_META_DSN": meta_dsn,
        "FG_BACKEND_ADMIN_DSN": admin_dsn,
        "FG_BACKEND_GC_DSN": gc_dsn,
        "FG_BACKEND_SERVICE_USER": "fg_service",
        "FG_BACKEND_GC_USER": "fg_gc",
        **({"FG_REFRESH_COOLDOWN_SECONDS": "0"} if not os.environ.get("FG_MANAGED_BACKEND_HOST") else {}),
    }
    phase("migrate", ["fg-control", "migrate"], env)
    bootstrap = phase("bootstrap", ["fg-control", "bootstrap"], env)
    assert '"engine":"mongodb"' in bootstrap.stdout + bootstrap.stderr, (
        "Mongo bootstrap omitted its engine confirmation; inspect bootstrap.log"
    )

    control_env = {
        **env,
        "FG_CONTROL_ACCOUNTS": json.dumps(
            [
                {
                    "user": BRANCH_USER,
                    "token": secrets_token,
                    "expires_at": 9999999999,
                    "policy_admin": True,
                },
                {"user": "bob", "token": secrets.token_hex(12), "expires_at": 9999999999, "policy_admin": False},
            ]
        ),
        "FG_INTERNAL_TOKEN": "suite-internal-token",
        "FG_CONTROL_LISTEN": f"127.0.0.1:{CONTROL_PORT}",
        "FG_PROXY_CONTROL_URL": f"http://127.0.0.1:{PROXY_CONTROL_PORT}",
    }
    proxy_env = {
        **control_env,
        "FG_BACKEND_DSN": f"mongodb://fg_service:svc-local-pw@{BACKEND_HOST}:{BACKEND_PORT}/admin",
        "FG_FRONTEND_ACCOUNTS": json.dumps(
            [
                {
                    "user": BRANCH_USER,
                    "password": "branch-alice-pw",
                    "expires_at": 9999999999,
                },
                {"user": "bob", "password": "branch-bob-pw", "expires_at": 9999999999},
            ]
        ),
        "FG_CONTROL_URL": f"http://127.0.0.1:{CONTROL_PORT}",
        "FG_PROXY_CONTROL_LISTEN": f"127.0.0.1:{PROXY_CONTROL_PORT}",
        "FG_LISTEN_MONGO": f"{FRONTEND_HOST}:{FRONTEND_PORT}",
    }
    control = subprocess.Popen(
        ["fg-control", "serve"],
        env=control_env,
        cwd=REPO,
        stdout=open(artifacts / "control.log", "w"),
        stderr=subprocess.STDOUT,
    )
    proxy = subprocess.Popen(
        ["fg-proxy"],
        env=proxy_env,
        cwd=REPO,
        stdout=open(artifacts / "proxy.log", "w"),
        stderr=subprocess.STDOUT,
    )
    outcomes = {}

    def stop_processes():
        for process in (proxy, control):
            process.send_signal(signal.SIGTERM)
        for process in (proxy, control):
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()

    try:
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{PROXY_CONTROL_PORT}/healthz", timeout=2
                ) as response:
                    if response.status == 204:
                        break
            except Exception:
                time.sleep(0.5)
        else:
            raise RuntimeError("proxy never became healthy")

        cli_env = {
            **os.environ,
            "FG_CONTROL_URL": f"http://127.0.0.1:{CONTROL_PORT}",
            "FG_OWNER_TOKEN": secrets_token,
        }
        log("refresh v2", "write-capable snapshot before the write branch")
        env = {
            **os.environ,
            "FG_META_DSN": meta_dsn,
            "FG_BACKEND_ADMIN_DSN": admin_dsn,
            "FG_BACKEND_GC_DSN": gc_dsn,
            "FG_BACKEND_SERVICE_USER": "fg_service",
            "FG_BACKEND_GC_USER": "fg_gc",
            **({"FG_REFRESH_COOLDOWN_SECONDS": "0"} if not os.environ.get("FG_MANAGED_BACKEND_HOST") else {}),
        }
        refresh = phase("refresh-v2", ["fg-control", "refresh", "--snapshot", "v2"], env)
        assert '"snapshot":"v2"' in refresh.stdout + refresh.stderr, (
            "Mongo refresh omitted its snapshot confirmation; inspect refresh-v2.log"
        )
        orders_delta=psql(meta_db,"SELECT delta_table FROM catalog_table WHERE generation_id=2 AND logical_table='orders'")
        customers_delta=psql(meta_db,"SELECT delta_table FROM catalog_table WHERE generation_id=2 AND logical_table='customers'")

        log("fork", "legacy sparse-write alpha, default read-only beta, and native alpha-write")
        psql(meta_db, f"""
            INSERT INTO branch(name,class,generation_id,created_by,expires_at,status,access,layout,read_strategy)
            SELECT 'alpha','dev',id,'{BRANCH_USER}',statement_timestamp()+interval '24 hours',
                   'active','read_write','sparse_delta','merge'
            FROM generation WHERE status='active' AND engine='mongodb';
        """)
        run(["forkget", "fork", "beta"], env=cli_env)
        alpha_id=int(psql(meta_db,"SELECT id FROM branch WHERE name='alpha'"))
        beta_id=int(psql(meta_db,"SELECT id FROM branch WHERE name='beta'"))
        fork_write = run(
            ["forkget", "fork", "alpha-write", "--write", "--ttl-seconds", "3600"],
            env=cli_env,
            check=False,
        )
        assert fork_write.returncode == 0, fork_write.stdout[-400:] + fork_write.stderr[-400:]

        deadline = time.time() + 60
        write_state = ""
        while time.time() < deadline:
            write_state = psql(
                meta_db,
                "SELECT status || ':' || mode FROM branch WHERE name = 'alpha-write'",
            )
            if write_state == "active:native_write":
                break
            time.sleep(0.5)
        outcomes["write_branch_active"] = write_state == "active:native_write"
        write_id = int(psql(meta_db, "SELECT id FROM branch WHERE name = 'alpha-write'"))
        write_database = f"fg_b{write_id}"
        log("write branch provisioned", write_state)
        listing = run(["forkget", "list"], env=cli_env).stdout
        assert '"alpha"' in listing and '"beta"' in listing and '"alpha-write"' in listing

        # Keep the larger legacy write fixture independent of default floors.
        _,current_policy=control_request("/v1/policies/dev","GET",secrets_token)
        status, _ = control_request(
            "/v1/policies/dev",
            "PUT",
            secrets_token,
            {
                "expected_version": json.loads(current_policy)["version"],
                "max_transaction_rows": 50000,
                "table_limit_bps": 10000,
                "small_table_floor": 1,
                "approval_after_rows": None,
            },
        )
        assert status == 200, f"policy raise refused: {status}"

        python = driver_python()
        readonly = run([python, "-c", f"""
import pymongo
client = pymongo.MongoClient('mongodb://{BRANCH_USER}:branch-alice-pw@{FRONTEND_HOST}:{FRONTEND_PORT}/beta?authSource=admin&directConnection=true', serverSelectionTimeoutMS=5000, **{DRIVER_TLS!r})
before = list(client.beta.orders.find())
for operation in (
    lambda: client.beta.orders.insert_one({{'_id': 707, 'note': 'read-only-must-refuse'}}),
    lambda: client.beta.orders.update_one({{'_id': 1}}, {{'$set': {{'note': 'read-only-must-refuse'}}}}),
    lambda: client.beta.orders.delete_one({{'_id': 1}}),
):
    try:
        operation()
        raise AssertionError('a new default MongoDB branch accepted a write')
    except pymongo.errors.OperationFailure as error:
        assert 'FG-5001' in str(error), error
assert list(client.beta.orders.find()) == before
client.close()
"""], check=False)
        outcomes["default_read_only_refuses_all_writes"] = readonly.returncode == 0
        outcomes["driver_steps"] = driver_steps(python, FRONTEND_PORT, mongo_password, "fg_g2")
        outage = run([python, "-c", f"""
import os, signal, pymongo
client = pymongo.MongoClient('mongodb://{BRANCH_USER}:branch-alice-pw@{FRONTEND_HOST}:{FRONTEND_PORT}/alpha?authSource=admin&directConnection=true', serverSelectionTimeoutMS=5000, **{DRIVER_TLS!r})
assert client.alpha.orders.find_one({{'_id': 1}})
os.kill({control.pid}, signal.SIGSTOP)
try:
    try:
        client.alpha.orders.insert_one({{'_id': 622, 'note': 'must-not-commit'}})
        raise AssertionError('control outage admitted a write')
    except pymongo.errors.OperationFailure as error:
        assert 'FG-1004' in str(error), error
finally:
    os.kill({control.pid}, signal.SIGCONT)
client.close()
root = pymongo.MongoClient({base_uri!r}, serverSelectionTimeoutMS=5000, **{DRIVER_TLS!r})
assert root.get_default_database().get_collection({orders_delta!r}).count_documents({{'_doc._id': 622}}) == 0
root.close()
"""], check=False)
        outcomes["control_outage_write_closed"] = outage.returncode == 0
        run(["forkget", "fork", "ttl-canary", "--ttl-seconds", "5"], env=cli_env)
        ttl = run([python, "-c", f"""
import pymongo, time
client = pymongo.MongoClient('mongodb://{BRANCH_USER}:branch-alice-pw@{FRONTEND_HOST}:{FRONTEND_PORT}/ttl-canary?authSource=admin&directConnection=true', serverSelectionTimeoutMS=5000, **{DRIVER_TLS!r})
database = client.get_default_database()
assert database.orders.find_one({{'_id': 1}})
time.sleep(6)
try:
    database.orders.find_one({{'_id': 1}})
    raise AssertionError('expired session continued reading')
except pymongo.errors.OperationFailure as error:
    assert 'FG-2003' in str(error), error
except pymongo.errors.ConnectionFailure:
    pass
client.close()
"""], check=False)
        deadline = time.time() + 75
        while time.time() < deadline and psql(meta_db, "SELECT status FROM branch WHERE name='ttl-canary'") != "dropped":
            time.sleep(0.5)
        (artifacts / "ttl.log").write_text(ttl.stdout + ttl.stderr)
        outcomes["ttl_refuses_expired_session_and_cleans_branch"] = ttl.returncode == 0 and psql(meta_db, "SELECT status FROM branch WHERE name='ttl-canary'") == "dropped"

        # Materialized writable branch checks.
        _,current_policy=control_request("/v1/policies/dev","GET",secrets_token)
        control_request(
            "/v1/policies/dev",
            "PUT",
            secrets_token,
            {
                "expected_version": json.loads(current_policy)["version"],
                "max_transaction_rows": 50000,
                "table_limit_bps": 10000,
                "approval_after_rows": None,
            },
        )
        write_uri = (
            f"mongodb://{BRANCH_USER}:branch-alice-pw@{FRONTEND_HOST}:{FRONTEND_PORT}/alpha-write"
            "?authSource=admin&directConnection=true"
        )
        beta_uri = (
            f"mongodb://{BRANCH_USER}:branch-alice-pw@{FRONTEND_HOST}:{FRONTEND_PORT}/beta"
            "?authSource=admin&directConnection=true"
        )
        base_uri = (
            f"mongodb://root:{mongo_password}@127.0.0.1:{MONGO_PORT}/fg_g2"
            "?authSource=admin&directConnection=true"
        )

        log("write branch provision", "collections cloned with generation counts")
        provision = run(
            [
                python,
                "-c",
                f"""
import pymongo, os
root = os.environ["FG_TEST_MONGO_ROOT_PASSWORD"]
proxy = pymongo.MongoClient({write_uri!r}, serverSelectionTimeoutMS=5000, **{DRIVER_TLS!r})
write_db = proxy.get_database("alpha-write")
assert write_db.orders.count_documents({{}}) == 4
assert write_db.customers.count_documents({{}}) == 3
base = pymongo.MongoClient(
    "mongodb://root:" + root + "@127.0.0.1:{MONGO_PORT}/fg_g2"
    "?authSource=admin&directConnection=true",
    serverSelectionTimeoutMS=5000, **{DRIVER_TLS!r},
)
assert base.get_default_database().orders.count_documents({{}}) == 4
assert base.get_database({write_database!r}).orders.count_documents({{}}) == 4
proxy.close()
base.close()
""",
            ],
            check=False,
            env={**os.environ, "FG_TEST_MONGO_ROOT_PASSWORD": mongo_password},
        )
        outcomes["write_branch_provisioned"] = provision.returncode == 0
        log("provision", "ok" if outcomes["write_branch_provisioned"] else (provision.stdout + provision.stderr)[-900:])

        log("native writes", "insert/update/delete on the materialized copy")
        native = run(
            [
                python,
                "-c",
                f"""
import pymongo
client = pymongo.MongoClient({write_uri!r}, serverSelectionTimeoutMS=5000, **{DRIVER_TLS!r})
db = client.get_database("alpha-write")
db.orders.insert_one({{"_id": 100, "tenant_id": 1, "customer_id": 10, "amount": 9.5, "note": "native"}})
db.orders.update_one({{"_id": 2}}, {{"$set": {{"note": "write-branch-edited"}}}})
db.orders.delete_one({{"_id": 3}})
assert sorted(d["_id"] for d in db.orders.find()) == [1, 2, 4, 100]
try:
    db.orders.update_many({{}}, {{"$set": {{"note": "x"}}}})
    raise AssertionError("multi was admitted")
except pymongo.errors.OperationFailure as failure:
    assert "FG-2002" in str(failure), failure
client.close()
""",
            ],
            check=False,
        )
        outcomes["native_writes"] = native.returncode == 0
        log("native writes", "ok" if outcomes["native_writes"] else (native.stdout + native.stderr)[-900:])

        log("write isolation", "read branch stays on its own view; base immutable")
        isolation = run(
            [
                python,
                "-c",
                f"""
import pymongo, os
root = os.environ["FG_TEST_MONGO_ROOT_PASSWORD"]
beta = pymongo.MongoClient({beta_uri!r}, serverSelectionTimeoutMS=5000, **{DRIVER_TLS!r})
assert sorted(d["_id"] for d in beta.beta.orders.find()) == [1, 2, 3, 4]
assert beta.beta.orders.find_one({{"_id": 2}})["note"] == "base-two"
beta.close()
base = pymongo.MongoClient(
    "mongodb://root:" + root + "@127.0.0.1:{MONGO_PORT}/fg_g2"
    "?authSource=admin&directConnection=true",
    serverSelectionTimeoutMS=5000, **{DRIVER_TLS!r},
)
generation = base.get_default_database()
assert generation.orders.find_one({{"_id": 1}})["note"] == "base-v2-one"
assert sorted(d["_id"] for d in generation.orders.find()) == [1, 2, 3, 4]
base.close()
""",
            ],
            check=False,
            env={**os.environ, "FG_TEST_MONGO_ROOT_PASSWORD": mongo_password},
        )
        outcomes["write_isolation"] = isolation.returncode == 0
        log("write isolation", "ok" if outcomes["write_isolation"] else isolation.stderr[-400:])

        log("rowdiff", "forkget diff on the materialized branch")
        diff_out = artifacts / "diff-alpha-write.json"
        diff = run(
            [
                "forkget",
                "diff",
                "alpha-write",
                "--output",
                str(diff_out),
            ],
            env=cli_env,
            check=False,
        )
        diff_ok = diff.returncode == 0 and diff_out.exists()
        changes_report = json.loads(diff_out.read_text()) if diff_ok else {"tables": []}
        changed = sum(len(t.get("changes", [])) for t in changes_report.get("tables", []))
        outcomes["rowdiff_native_write"] = diff_ok and changes_report.get("native_write") is True
        outcomes["rowdiff_changes_seen"] = changed == 3
        log(
            "rowdiff",
            f"ok={outcomes['rowdiff_native_write']} changes={changed}",
        )

        log("budget restore", "tight share then over-budget write branch refusal")
        _,current_policy=control_request("/v1/policies/dev","GET",secrets_token)
        control_request(
            "/v1/policies/dev",
            "PUT",
            secrets_token,
            {
                "expected_version": json.loads(current_policy)["version"],
                "max_transaction_rows": 50000,
                "table_limit_bps": 1000,
                "approval_after_rows": None,
            },
        )
        tight = run(
            [
                python,
                "-c",
                f"""
import pymongo
client = pymongo.MongoClient({write_uri!r}, serverSelectionTimeoutMS=5000, **{DRIVER_TLS!r})
try:
    client.get_database("alpha-write").orders.insert_many(
        [{{"_id": 900, "note": "x"}}, {{"_id": 901, "note": "y"}}]
    )
    raise AssertionError("over-budget write was admitted")
except pymongo.errors.OperationFailure as failure:
    assert "FG-5002" in str(failure), failure
client.close()
""",
            ],
            check=False,
        )
        outcomes["write_budget_refusal"] = tight.returncode == 0
        log("write budget", "ok" if outcomes["write_budget_refusal"] else (tight.stdout + tight.stderr)[-900:])

        log("drop", "read alpha then the write branch")
        run(["forkget", "drop", "alpha"], env=cli_env)
        run(["forkget", "drop", "alpha-write"], env=cli_env)
        deadline = time.time() + 20
        write_gone = ""
        while time.time() < deadline:
            write_gone = psql(
                meta_db,
                "SELECT status FROM branch WHERE name = 'alpha-write'",
            )
            if write_gone == "dropped":
                break
            time.sleep(0.5)
        outcomes["write_branch_dropped"] = write_gone == "dropped"

        purge = run(
            [
                python,
                "-c",
                f"""
import pymongo
client = pymongo.MongoClient({base_uri!r}, serverSelectionTimeoutMS=5000, **{DRIVER_TLS!r})
names = client.list_database_names()
assert {write_database!r} not in names, f"branch database survived the drop: {{names}}"
role = client.admin.command("rolesInfo", "fg_service", showPrivileges=True)["roles"][0]
assert all(p.get("resource", {{}}).get("db") != {write_database!r} for p in role["privileges"])
client.close()
""",
            ],
            check=False,
            env={**os.environ, "FG_TEST_MONGO_ROOT_PASSWORD": mongo_password},
        )
        outcomes["branch_db_removed"] = purge.returncode == 0
        log("branch db removal", "ok" if outcomes["branch_db_removed"] else purge.stderr[-400:])
        log("drop", "beta follows")
        run(["forkget", "drop", "beta"], env=cli_env)
        deadline = time.time() + 15
        while time.time() < deadline:
            beta_state = psql(meta_db, "SELECT status FROM branch WHERE name = 'beta'")
            if beta_state == "dropped":
                break
            time.sleep(0.5)
        outcomes["beta_dropped"] = beta_state == "dropped"
        purge = run(
            [
                python,
                "-c",
                "import pymongo\n"
                f"client = pymongo.MongoClient({base_uri!r}, serverSelectionTimeoutMS=5000, **{DRIVER_TLS!r})\n"
                "base = client.get_default_database()\n"
                f'orders_delta = base.get_collection({orders_delta!r})\n'
                f'assert orders_delta.count_documents({{"_fg_branch": {alpha_id}}}) == 0, "alpha delta survived"\n'
                f'assert base.get_collection({customers_delta!r}).count_documents({{"_fg_branch": {beta_id}}}) == 0, "beta never wrote"\n'
                "client.close()\n",
            ],
            check=False,
        )
        outcomes["delta_purged_on_drop"] = purge.returncode == 0
        log("delta purge", "ok" if outcomes["delta_purged_on_drop"] else purge.stderr[-400:])
        legacy_grant = run([python, "-c", f"""
import pymongo, subprocess, os
client = pymongo.MongoClient({base_uri!r}, serverSelectionTimeoutMS=5000, **{DRIVER_TLS!r})
role = client.admin.command('rolesInfo', 'fg_service', showPrivileges=True)['roles'][0]
try:
    client.admin.command('grantPrivilegesToRole', 'fg_service', privileges=[{{'resource': {{'db': 'fg_g2', 'collection': ''}}, 'actions': ['insert']}}])
    result = subprocess.run(['fg-control', 'serve'], env=os.environ, capture_output=True, text=True, timeout=15)
    assert result.returncode != 0 and 'unsafe MongoDB generation-wide writes' in result.stderr, result.stderr
finally:
    client.admin.command('updateRole', 'fg_service', privileges=role['privileges'])
    client.close()
"""], env=control_env, check=False)
        outcomes["legacy_unsafe_grants_refused"] = legacy_grant.returncode == 0
        (artifacts / "legacy-grants.log").write_text(legacy_grant.stdout + legacy_grant.stderr)
        if TLS_DIRECTORY:
            outcomes.update(tls_negative_cases(proxy_env, proxy, artifacts))
    finally:
        if control.poll() is None:
            control.send_signal(signal.SIGCONT)
        stop_processes()

    audit = psql(
        meta_db,
        "SELECT event_type, payload->>'kind', payload->>'verdict', payload->>'outcome' "
        "FROM audit_event WHERE event_type IN ('policy_decision','policy_outcome') ORDER BY id",
    )
    (artifacts / "audit.txt").write_text(audit)
    assert "insert|allowed" in audit.replace(" ", ""), audit[-400:]

    passed = all(
        value for key, value in outcomes.items() if isinstance(value, bool)
    ) and all(step["ok"] for step in outcomes.get("driver_steps", []))
    report = {
        "suite": "p2-mongo",
        "date_utc": started.isoformat(),
        "meta_db": meta_db,
        "outcomes": outcomes,
        "passed": passed,
        "transport": "verified_tls" if DRIVER_TLS else "loopback_plaintext",
        "source_revision": run(["git", "rev-parse", "HEAD"]).stdout.strip(),
    }
    (artifacts / "report.json").write_text(json.dumps(report, indent=2))
    summary = [
        "# P2 MongoDB branch suite",
        "",
        f"- date_utc: {started.isoformat()}",
        f"- meta_db: {meta_db}",
        f"- passed: {passed}",
        "",
        "## Outcomes",
    ]
    for key, value in outcomes.items():
        summary.append(f"- {key}: {value}")
    (artifacts / "summary.md").write_text("\n".join(summary) + "\n")
    log("result", f"passed={passed} report={artifacts}")
    if not passed:
        sys.exit(1)


def tls_negative_cases(proxy_env, proxy, artifacts):
    import ssl
    outcomes = {}
    ca = str(Path(TLS_DIRECTORY.name) / "ca.pem")
    wrong_ca = str(Path(TLS_DIRECTORY.name) / "wrong-ca.pem")
    for name, trust, hostname in (("frontend_wrong_ca", wrong_ca, FRONTEND_HOST),
                                   ("frontend_wrong_hostname", ca, "wrong.example.internal")):
        try:
            with socket.create_connection((FRONTEND_HOST, FRONTEND_PORT), timeout=5) as connection:
                ssl.create_default_context(cafile=trust).wrap_socket(connection, server_hostname=hostname)
            outcomes[name] = False
        except ssl.SSLCertVerificationError:
            outcomes[name] = True
    try:
        with socket.create_connection((FRONTEND_HOST, FRONTEND_PORT), timeout=5) as connection:
            connection.sendall(b"plaintext is refused")
            response = connection.recv(32)
            outcomes["frontend_plaintext_refused"] = response == b"" or response[:2] == bytes([21, 3])
    except ConnectionResetError:
        outcomes["frontend_plaintext_refused"] = True
    proxy.terminate()
    proxy.wait(timeout=10)
    invalid = {"backend_wrong_ca": proxy_env | {"FG_BACKEND_CA": wrong_ca}}
    wrong_host = os.environ.get("FG_MONGO_TEST_WRONG_HOST")
    if wrong_host:
        selected = os.environ["FG_MANAGED_BACKEND_HOST"]
        invalid["backend_wrong_hostname"] = proxy_env | {
            "FG_MANAGED_BACKEND_HOST": wrong_host,
            "FG_BACKEND_DSN": proxy_env["FG_BACKEND_DSN"].replace(selected, wrong_host),
        }
    for name, env in invalid.items():
        result = run(["fg-proxy"], env=env, check=False, timeout=25)
        (artifacts / f"{name}.log").write_text(result.stdout + result.stderr)
        outcomes[name] = result.returncode != 0 and "FG-1004" in result.stderr
    return outcomes


if __name__ == "__main__":
    main()
