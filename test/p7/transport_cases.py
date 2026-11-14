"""Exercise managed transport on a disposable deployment through a private interface."""

import importlib.util
from ipaddress import IPv4Address, IPv4Network, ip_address
import json
import os
from pathlib import Path
import re
from select import select
import socket
from socketserver import BaseRequestHandler, ThreadingTCPServer
from threading import Thread

P6 = Path(__file__).resolve().parents[1] / "p6" / "run.py"
spec = importlib.util.spec_from_file_location("transport_p6", P6)
p6 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p6)
from run_p2 import OWNER_A, free_ports, json_file, openssl, require

RFC1918 = tuple(IPv4Network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def canonical_hostname(value):
    hostname = value.removesuffix(".").lower()
    if not hostname or len(hostname) > 253:
        return None
    try:
        ip_address(hostname)
    except ValueError:
        pass
    else:
        return None
    if any(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is None
           for label in hostname.split(".")):
        return None
    if hostname in {"localhost", "localhost.localdomain"} or hostname.endswith(".localhost"):
        return None
    return hostname


def private_host(report):
    selected = os.environ.get("FG_TRANSPORT_TEST_HOST", socket.gethostname())
    endpoint = {"hostname": selected, "resolved_ips": [], "validated": False}
    json_file(report / "transport-endpoint.json", endpoint)
    hostname = canonical_hostname(selected)
    require(hostname is not None,
            "Set FG_TRANSPORT_TEST_HOST to a nonliteral DNS hostname of this host's private interface")
    endpoint["hostname"] = hostname
    addresses = sorted({entry[4][0] for entry in socket.getaddrinfo(hostname, 0, type=socket.SOCK_STREAM)})
    endpoint["resolved_ips"] = addresses
    json_file(report / "transport-endpoint.json", endpoint)
    require(len(addresses) == 1, "The test hostname must resolve to exactly one private IPv4 address")
    address, = addresses
    parsed = ip_address(address)
    require(isinstance(parsed, IPv4Address) and any(parsed in network for network in RFC1918),
            "The test hostname must resolve exclusively to RFC1918 IPv4, never loopback or public addresses")
    endpoint["validated"] = True
    json_file(report / "transport-endpoint.json", endpoint)
    return hostname, address


def issue_certificate(certs, service, sans, trust):
    ca, key = (certs / f"transport-{service}-ca.{extension}" for extension in ("pem", "key"))
    config, csr = (certs / f"transport-{service}.{extension}" for extension in ("cnf", "csr"))
    config.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                      f"extendedKeyUsage=serverAuth\nsubjectAltName={sans}\n", encoding="utf-8")
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
            "-subj", f"/CN=Forkget managed {service} fixture CA", "-keyout", key, "-out", ca,
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    openssl("req", "-newkey", "rsa:2048", "-nodes", "-sha256", "-subj", "/CN=localhost",
            "-keyout", certs / f"{service}.key", "-out", csr)
    openssl("x509", "-req", "-sha256", "-days", "1", "-in", csr, "-CA", ca, "-CAkey", key,
            "-set_serial", "1", "-extfile", config, "-out", certs / f"{service}.pem")
    with trust.open("ab") as file:
        file.write(ca.read_bytes())
    key.unlink()
    csr.unlink()


class RelayHandler(BaseRequestHandler):
    def handle(self):
        if self.client_address[0] != self.server.server_address[0]:
            return
        try:
            with socket.create_connection(("127.0.0.1", self.server.native_port), timeout=5) as backend:
                backend.settimeout(None)
                endpoints = {self.request: backend, backend: self.request}
                while True:
                    readable, _, _ = select(list(endpoints), [], [], 10)
                    for endpoint in readable:
                        chunk = endpoint.recv(65536)
                        if not chunk:
                            return
                        endpoints[endpoint].sendall(chunk)
        except OSError:
            return


class PrivateRelay(ThreadingTCPServer):
    daemon_threads = True

    def __init__(self, ip, native_port):
        super().__init__((ip, 0), RelayHandler)
        self.native_port = native_port
        self.worker = Thread(target=self.serve_forever, daemon=True)

    def __enter__(self):
        self.worker.start()
        return self

    def __exit__(self, *_):
        self.shutdown()
        self.server_close()
        self.worker.join(timeout=5)


class EngineRun(p6.p5.EngineRun):
    def dsn(self, user, password, port, database, scheme=None):
        dsn = super().dsn(user, password, port, database, scheme)
        if port == self.native_port:
            dsn = dsn.replace(f"@127.0.0.1:{port}/", f"@{self.hostname}:{self.relay_port}/")
        return dsn

    def native(self, sql, database=None, *, timeout=30):
        if self.family == "mysql":
            command = ('MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql --no-defaults --protocol=TCP '
                       '--host=localhost --user=root --ssl-mode=VERIFY_IDENTITY '
                       '--ssl-ca=/certs/backend-ca.pem --batch --skip-column-names '
                       '--raw --binary-as-hex --database="$1"')
        elif self.family == "postgresql":
            command = self.psql_command().replace("--host=127.0.0.1", "--host=localhost")
        else:
            return super().native(sql, database, timeout=timeout)
        return self.compose("native-sql", "exec", "-T", "native", "sh", "-c", command,
                            "sh", database or "p2_native", stdin=sql, timeout=timeout)

    def execute(self):
        self.hostname, self.private_ip = private_host(self.report)
        issue_certificate(self.certs, "native", f"DNS:localhost,DNS:native,DNS:{self.hostname}", self.certs / "backend-ca.pem")
        issue_certificate(self.certs, "frontend", f"IP:127.0.0.1,IP:{self.private_ip}", self.certs / "frontend-ca.pem")
        self.base_env |= {"FG_MANAGED_BACKEND_HOST": self.hostname, "FG_BACKEND_SERVICE_USER": "p2_service"}
        self.compose_started = True
        self.compose("compose-up", "up", "--detach", "--wait", "--wait-timeout", "120", timeout=150, log=True)
        self.native_port = int(self.compose("native-port", "port", "native", str(self.internal_port)).rpartition(":")[2])
        self.metadata_port = int(self.compose("metadata-port", "port", "metadata", "5432").rpartition(":")[2])
        with PrivateRelay(self.private_ip, self.native_port) as relay:
            self.relay_port = relay.server_address[1]
            self.prepare_native_engine()
            self.engine_version = self.native("SELECT VERSION();")
            self.migrations_and_bootstrap()
            self.generation_command("managed-refresh", "refresh", "--snapshot", "v2")
            self.start_control()
            self.positive()
            self.stop("proxy")
            self.negative()

    def proxy_env(self):
        accounts = [dict(user=user, password=password, expires_at=self.expires)
                    for user, password in self.frontend_passwords.items() if user in self.owner_tokens]
        return self.base_env | {
            "FG_BACKEND_DSN": self.dsn("p2_service", self.secret["service"], self.native_port, self.backend_database),
            "FG_BACKEND_CA": str(self.certs / "backend-ca.pem"),
            "FG_FRONTEND_ACCOUNTS": json.dumps(accounts), "FG_CONTROL_URL": self.control_url,
            "FG_INTERNAL_TOKEN": self.secret["internal"],
            "FG_PROXY_CONTROL_LISTEN": f"127.0.0.1:{self.drain_port}",
            self.listen_key: f"{self.private_ip}:{self.proxy_port}",
            "FG_TLS_CERT": str(self.certs / "frontend.pem"), "FG_TLS_KEY": str(self.certs / "frontend.key"),
        }

    def positive(self):
        proxy = self.start("proxy", "fg-proxy", [], self.proxy_env())
        self.ready("proxy", self.drain_url + "/healthz", proxy)
        directory = self.certs.parent
        manifest = directory / "managed-dryrun.json"
        manifest.write_text(json.dumps({"changes": ["INSERT INTO parents (id,tenant_id,code) VALUES (7170,8,'managed-tls')"]}))
        proxy_dsn = super().dsn(OWNER_A, self.frontend_passwords[OWNER_A], self.proxy_port, "unused")
        proxy_dsn = proxy_dsn.replace("@127.0.0.1:", f"@{self.private_ip}:")
        environment = self.base_env | {"FG_CONTROL_URL": self.control_url,
            "FG_OWNER_TOKEN": self.owner_tokens[OWNER_A], "FG_DRYRUN_PROXY_DSN": proxy_dsn,
            "FG_DRYRUN_PROXY_CA": str(self.certs / "frontend-ca.pem"), "FG_MANAGED_FRONTEND_HOST": self.private_ip}
        arguments = [self.executable("forkget"), "dryrun", "--engine", self.engine,
                     "--manifest", str(manifest), "--output", str(directory / "managed-report.json")]
        invalid = environment.copy()
        invalid.pop("FG_MANAGED_FRONTEND_HOST")
        self.call("managed-dryrun-opt-in-required", arguments, env=invalid, succeeds=False)
        result = json.loads(self.call("managed-dryrun", arguments, env=environment))
        require(result["status"] == "passed" and result["cleanup"] == "dropped",
                "Managed private frontend or native observation did not complete dry-run cleanup")
        self.record("Managed DNS/TLS, private SQL frontend, branch write/diff and observed cleanup")

    def negative(self):
        valid = self.proxy_env()
        local = valid | {self.listen_key: f"127.0.0.1:{self.proxy_port}",
                         "FG_BACKEND_DSN": super().dsn("p2_service", self.secret["service"], self.native_port, self.backend_database)}
        local.pop("FG_MANAGED_BACKEND_HOST")
        cases = {
            "private-without-opt-in": local | {self.listen_key: valid[self.listen_key]},
            "wildcard-frontend": valid | {self.listen_key: f"0.0.0.0:{self.proxy_port}"},
            "public-frontend": valid | {self.listen_key: f"8.8.8.8:{self.proxy_port}"},
            "private-drain": valid | {"FG_PROXY_CONTROL_LISTEN": f"{self.private_ip}:{self.drain_port}"},
            "public-backend": valid | {"FG_MANAGED_BACKEND_HOST": "8.8.8.8"},
            "mismatched-dsn": valid | {"FG_BACKEND_DSN": local["FG_BACKEND_DSN"]},
            "mismatched-role": valid | {"FG_BACKEND_SERVICE_USER": "p2_gc"},
            "gc-as-service": valid | {"FG_BACKEND_GC_USER": "p2_service"},
            "wrong-certificate-name": local,
            "wrong-backend-ca": valid | {"FG_BACKEND_CA": str(self.certs / "frontend-ca.pem")},
        }
        for label, environment in cases.items():
            self.call(label, [self.executable("fg-proxy")], env=environment, succeeds=False, timeout=10, log=True)
            detail = (self.report / f"{label}.log").read_text()
            expected = "FG-1004" if label in {"wrong-certificate-name", "wrong-backend-ca"} else "Invalid or missing"
            require(expected in detail, f"Unexpected rejection path for {label}")
        self.negative_control()
        self.record("Managed transport rejects wrong hostname/CA, public or wildcard bind, private control/drain and role conflicts")

    def negative_control(self):
        environment = self.base_env | {
            "FG_META_DSN": self.dsn("p2_meta_control", self.secret["metadata_control"], self.metadata_port,
                                    "forkget_meta", "postgresql"),
            "FG_META_CA": str(self.certs / "backend-ca.pem"), "FG_BACKEND_CA": str(self.certs / "backend-ca.pem"),
            "FG_BACKEND_GC_DSN": self.dsn("p2_gc", self.secret["collector"], self.native_port, self.backend_database),
            "FG_CONTROL_LISTEN": f"{self.private_ip}:{self.control_port}",
        }
        self.call("private-control", [self.executable("fg-control"), "serve"],
                  env=environment, succeeds=False, timeout=10, log=True)
        require("FG_CONTROL_LISTEN must be loopback" in (self.report / "private-control.log").read_text(),
                "Managed transport allowed the control listener to leave loopback")


if __name__ == "__main__":
    raise SystemExit(p6.run_profile("transport", "Managed private transport fixture", EngineRun))
