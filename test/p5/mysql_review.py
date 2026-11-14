"""Verify audited MySQL exits and affected rows on disposable TLS connections."""

from contextlib import contextmanager
import json
import select
from socketserver import BaseRequestHandler, ThreadingTCPServer
import ssl
import struct
from threading import Event, Thread
import time

from run_p2 import OWNER_A, require, wait_until
from write_cases import Probe


class Client:
    def __init__(self, run, branch, found_rows=False):
        self.raw = run.raw_module()
        self.socket = self.raw.mysql_connect(
            run.frontend_passwords[OWNER_A].encode(), port=run.proxy_port,
            user=OWNER_A.encode(), branch=branch["name"].encode(),
            cafile=run.certs / "frontend-ca.pem", found_rows=found_rows,
        )

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.socket.close()

    def command(self, payload):
        self.raw.mysql_write(self.socket, 0, payload)
        return self.raw.mysql_read(self.socket, 1)

    def query(self, sql):
        return self.command(b"\x03" + sql.encode())

    def count(self, sql, expected):
        require(self.query(sql)[:2] == bytes([0, expected]), "Unexpected MySQL affected count")

    def prepare(self, sql):
        reply = self.command(b"\x16" + sql.encode())
        require(len(reply) == 12 and reply[0] == 0, "MySQL write Prepare failed")
        require(struct.unpack("<HH", reply[5:9]) == (0, 1), "MySQL Prepare metadata differs")
        self.raw.mysql_read(self.socket, 2)
        require(self.raw.mysql_read(self.socket, 3)[0] == 0xFE, "MySQL Prepare metadata did not end")
        return reply[1:5]

    def execute(self, handle, key):
        return self.command(b"\x17" + handle + struct.pack("<BI", 0, 1)
                            + b"\0\1\x08\0" + struct.pack("<q", key))

    def closed(self):
        try:
            self.raw.read_exact(self.socket, 1)
        except (EOFError, ConnectionResetError):
            return True
        return False


def insert(key):
    return f"INSERT INTO parents (id,tenant_id,code) VALUES ({key},8,'review-{key}')"


def outcomes(run, branch):
    path = f"/v1/branches/{branch['id']}/audit?event_type=policy_outcome&limit=100"
    status, body = run.request("GET", path, run.owner_tokens[OWNER_A])
    require(status == 200, "MySQL outcome audit was unavailable")
    return json.loads(body)["events"]


def expect_outcome(run, branch, before, expected, key, committed):
    events = wait_until("native transaction outcome", lambda: (
        current if len(current := outcomes(run, branch)) > before else None))
    require(len(events) == before + 1 and events[-1]["payload"]["outcome"] == expected,
            "The MySQL transaction was missing its unique native outcome")
    relation = run.branch_relation(branch["id"], "parents")
    require(run.native(f"SELECT count(*) FROM {relation} WHERE id={key};") == str(int(committed)),
            "The native row state disagrees with the transaction outcome")


def found_rows(run, branch):
    for index, enabled in enumerate((False, True)):
        key = 650 + index
        with Client(run, branch, enabled) as client:
            client.count(insert(key), 1)
            client.count(f"UPDATE parents SET label='changed' WHERE id={key}", 1)
            client.count(f"UPDATE parents SET label='changed' WHERE id={key}", int(enabled))
            client.count("UPDATE parents SET label='miss' WHERE id=699", 0)
            handle = client.prepare("UPDATE parents SET label='prepared' WHERE id=?")
            for target, affected in ((699, 0), (key, 1), (key, int(enabled))):
                require(client.execute(handle, target)[:2] == bytes([0, affected]),
                        "MySQL prepared write changed the negotiated affected count")
            client.count("BEGIN", 0)
            client.count(f"UPDATE parents SET label='rollback' WHERE id={key}", 1)
            client.raw.mysql_error(client.execute(handle, key), 1644, b"45000", b"FG-5002")
            client.raw.mysql_error(client.query("SELECT 1"),1644,b"45000",b"FG-5001")
            client.raw.mysql_error(client.query("COMMIT"),1644,b"45000",b"FG-5001")
            client.count("ROLLBACK",0)
        relation = run.branch_relation(branch["id"], "parents")
        require(run.native(f"SELECT label FROM {relation} WHERE id={key};") == "prepared",
                "MySQL budget refusal preserved a previous change")
    run.record("Both MySQL affected-row modes preserve text/prepared counts and charge matched rows")


def closed_transactions(run, branch):
    for index, action in enumerate(("disconnect", "long-data", "quit", "commit", "begin", "autocommit")):
        key = 660 + index
        before = len(outcomes(run, branch))
        committed = action in {"commit", "begin", "autocommit"}
        with Client(run, branch) as client:
            client.count("SET AUTOCOMMIT=0" if action == "autocommit" else "BEGIN", 0)
            client.count(insert(key), 1)
            if action == "long-data":
                handle = client.prepare("UPDATE parents SET label='unexecuted' WHERE id=?")
                client.raw.mysql_error(client.command(b"\x18" + handle + b"\0\0test"),
                                       1235, b"42000", b"FG-2002")
                require(client.closed(), "MySQL long-data refusal left the session open")
            elif action == "quit":
                client.raw.mysql_write(client.socket, 0, b"\x01")
                require(client.closed(), "MySQL QUIT left the session open")
            elif committed:
                statement = {"commit": "COMMIT", "begin": "BEGIN", "autocommit": "SET AUTOCOMMIT=1"}[action]
                client.count(statement, 0)
        expect_outcome(run, branch, before, "committed" if committed else "rolled_back", key, committed)
    run.record("MySQL EOF, QUIT, active refusal and explicit or implicit native commit are audited once")


def expired_session(run, branch):
    before = len(outcomes(run, branch))
    expiry = run.expires
    run.stop("proxy")
    try:
        deadline = int(time.time()) + 6
        run.expires = deadline
        run.start_proxy()
        with Client(run, branch) as client:
            client.count("BEGIN", 0)
            client.count(insert(666), 1)
            time.sleep(max(0, deadline - time.time() + 0.05))
            client.raw.mysql_error(client.query("SELECT 1"), 1045, b"28000", b"FG-1002")
            require(client.closed(), "Expired MySQL session remained open")
        expect_outcome(run, branch, before, "rolled_back", 666, False)
    finally:
        run.expires = expiry
        run.stop("proxy")
        run.start_proxy()
    run.record("MySQL authorization expiry closes the native transaction and records rollback")


@contextmanager
def native_commit_reply(run, raw):
    """Withhold a native success packet only in the disposable local deployment."""
    server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_tls.load_cert_chain(run.certs / "native.pem", run.certs / "native.key")
    client_tls = ssl.create_default_context(cafile=run.certs / "backend-ca.pem")
    withheld = Event()
    backend_port = run.native_port

    def packet(stream):
        header = raw.read_exact(stream, 4)
        return header + raw.read_exact(stream, int.from_bytes(header[:3], "little"))

    class Handler(BaseRequestHandler):
        def handle(self):
            try:
                with raw.connect(backend_port) as upstream:
                    self.request.settimeout(8)
                    self.request.sendall(packet(upstream))
                    upstream.sendall(packet(self.request))
                    with client_tls.wrap_socket(upstream, server_hostname="localhost") as native:
                        with server_tls.wrap_socket(self.request, server_side=True) as proxy:
                            self.forward(proxy, native)
            except (EOFError, OSError):
                pass

        @staticmethod
        def forward(proxy, native):
            while True:
                ready = [stream for stream in (proxy, native) if stream.pending()]
                if not ready:
                    ready, _, _ = select.select([proxy, native], [], [], 8)
                if not ready:
                    return
                for source in ready:
                    frame = packet(source)
                    destination = native if source is proxy else proxy
                    destination.sendall(frame)
                    if source is proxy and frame[3:] == b"\0\x03COMMIT":
                        if packet(native)[4:5] == b"\0":
                            withheld.set()
                        return

    with ThreadingTCPServer(("127.0.0.1", 0), Handler) as server:
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        try:
            yield server.server_address[1], withheld
        finally:
            server.shutdown()
            thread.join(timeout=5)


def unknown_commit(run, branch):
    before = len(outcomes(run, branch))
    run.stop("proxy")
    backend_port = run.native_port
    try:
        with native_commit_reply(run, run.raw_module()) as (relay_port, withheld):
            try:
                run.native_port = relay_port
                run.start_proxy()
                run.native_port = backend_port
                with Client(run, branch) as client:
                    client.count("BEGIN", 0)
                    client.count(insert(667), 1)
                    client.raw.mysql_write(client.socket, 0, b"\x03COMMIT")
                    require(withheld.wait(8) and client.closed(), "Native COMMIT loss was not witnessed")
                expect_outcome(run, branch, before, "unknown", 667, True)
            finally:
                run.stop("proxy")
    finally:
        run.native_port = backend_port
        run.start_proxy()
    run.record("MySQL native COMMIT response loss is audited as unknown and independently durable")


def drained_transaction(run, branch, generation_lock):
    before = len(outcomes(run, branch))
    with Client(run, branch) as client, Probe(run, "hold-review-collect", metadata=True) as lock:
        lock.sql(f"SELECT pg_advisory_lock({generation_lock})", "read")
        client.count("BEGIN", 0)
        client.count(insert(668), 1)
        status, _ = run.request("DELETE", f"/v1/branches/{branch['id']}", run.owner_tokens[OWNER_A])
        require(status == 202 and client.closed(), "MySQL branch drain did not close the open write")
        expect_outcome(run, branch, before, "rolled_back", 668, False)
    run.wait_dropped(OWNER_A, branch["id"])
    require(len(outcomes(run, branch)) == before + 1, "MySQL branch cleanup duplicated the audit")
    run.record("MySQL branch drain rolls back before physical cleanup and keeps one audit result")


def run_cases(run, branch, generation_lock):
    found_rows(run, branch)
    audited, _ = run.create("p5-mysql-audit-exits")
    closed_transactions(run, audited)
    expired_session(run, audited)
    unknown_commit(run, audited)
    drained_transaction(run, audited, generation_lock)
