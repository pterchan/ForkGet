"""Verify PostgreSQL handle limits and rollback through the local TLS proxy."""

from contextlib import contextmanager

from run_p2 import require
from write_cases import Probe

HANDLE_CAPACITY = 256
READ = b"SELECT 1"
BOUNDARY_KEY = 550
CAPACITY_KEY = 551
POLICY_KEYS = (552, 553)
SAVEPOINT_KEYS = (554, 555)
READ_ROW = b"\0\x01\0\0\0\x011"


def insert(key):
    return f"INSERT INTO parents (id,tenant_id,code) VALUES ({key},8,'review-{key}')".encode()


def parse_body(name, sql):
    return name + b"\0" + sql + b"\0" * 3


def bind_body(portal, statement):
    return portal + b"\0" + statement + b"\0" * 7


def execute_body(portal):
    return portal + b"\0" * 5


class Session:
    def __init__(self, raw, socket):
        self.raw = raw
        self.socket = socket

    def send(self, tag, body=b""):
        self.raw.pg_send(self.socket, tag, body)

    def expect(self, tag, body=None):
        actual, received = self.raw.pg_read(self.socket)
        require(actual == tag, f"Expected PostgreSQL frame {tag!r}, received {actual!r}")
        require(body is None or received == body, f"Unexpected PostgreSQL frame body for {tag!r}")
        return received

    def parse(self, name, sql=READ):
        self.send(b"P", parse_body(name, sql))
        self.expect(b"1", b"")

    def bind(self, portal, statement):
        self.send(b"B", bind_body(portal, statement))
        self.expect(b"2", b"")

    def execute(self, portal, read=False):
        self.send(b"E", execute_body(portal))
        if read:
            self.expect(b"D", READ_ROW)
        self.expect(b"C")

    def close(self, kind, name):
        self.send(b"C", kind + name + b"\0")
        self.expect(b"3", b"")

    def query(self, sql, state=b"I"):
        messages = self.raw.pg_query(self.socket, sql)
        require(messages[-1] == (b"Z", state) and all(tag != b"E" for tag, _ in messages),
                "Simple query did not reach the expected transaction state")
        return self.raw.pg_tags(messages)

    def sync(self, state=b"I"):
        self.send(b"S")
        self.expect(b"Z", state)

    def error(self, sqlstate, code):
        self.raw.pg_error(self.expect(b"E"), sqlstate, code)


@contextmanager
def session(run, branch):
    raw = run.raw_module()
    socket, _ = run.raw_connection(raw, branch)
    with socket:
        yield Session(raw, socket)


def name_boundaries(run, branch):
    suffix = "é".encode()
    statement = b"s" * 61 + suffix
    portal = b"p" * 61 + suffix
    with session(run, branch) as client:
        client.parse(statement)
        client.send(b"D", b"S" + statement + b"\0")
        client.expect(b"t", b"\0\0")
        client.expect(b"T")
        client.bind(portal, statement)
        client.send(b"D", b"P" + portal + b"\0")
        client.expect(b"T")
        client.execute(portal, read=True)
        client.close(b"P", portal)
        client.close(b"S", statement)
        client.sync()

    cases = (
        (b"P", parse_body(statement + b"x", insert(BOUNDARY_KEY))),
        (b"B", bind_body(portal + b"x", statement)),
        (b"B", bind_body(portal, statement + b"x")),
        (b"E", execute_body(portal + b"x")),
        (b"D", b"P" + portal + b"x\0"),
        (b"D", b"S" + statement + b"x\0"),
        (b"C", b"P" + portal + b"x\0"),
        (b"C", b"S" + statement + b"x\0"),
    )
    for tag, body in cases:
        with session(run, branch) as client:
            if tag != b"P":
                client.parse(statement, insert(BOUNDARY_KEY))
            if tag in (b"E", b"D", b"C"):
                client.bind(portal, statement)
            client.send(tag, body)
            client.error(b"08P01", b"FG-1003")
    require_no_writes(run, branch, (BOUNDARY_KEY,))
    run.record("PostgreSQL enforces the native 63-byte limit in every handle field")


def long_session(run, branch):
    with session(run, branch) as client:
        client.parse(b"before_loop")
        client.sync()
        for _ in range(4097):
            require(client.query(READ) == b"TDCZ", "A long session lost its simple-query response")
        client.bind(b"after_loop", b"before_loop")
        client.execute(b"after_loop", read=True)
        client.sync()
        require(client.query(b"ROLLBACK") == b"CZ", "An engine notice reached the client")
    run.record("PostgreSQL reuses a prepared statement after 4,097 queries and suppresses native notices")


def statement_capacity(run, branch):
    with session(run, branch) as client:
        for index in range(HANDLE_CAPACITY):
            client.parse(f"statement_{index}".encode())
        client.parse(b"")
        client.parse(b"")
        client.send(b"P", parse_body(b"over_capacity", READ))
        client.error(b"54000", b"FG-1006")
        client.sync()
        client.close(b"S", b"statement_0")
        client.parse(b"after_close")
        client.bind(b"", b"after_close")
        client.execute(b"", read=True)
        client.sync()
        client.query(b"DEALLOCATE ALL")
        client.parse(b"after_deallocate")
        client.sync()
    run.record("PostgreSQL bounds named statements and releases capacity after Close and DEALLOCATE ALL")


def portal_capacity(run, branch):
    with session(run, branch) as client:
        client.parse(b"read_statement")
        client.parse(b"write_statement", insert(CAPACITY_KEY))
        client.bind(b"pending_write", b"write_statement")
        client.execute(b"pending_write")
        for index in range(HANDLE_CAPACITY - 1):
            client.bind(f"portal_{index}".encode(), b"read_statement")
        client.bind(b"", b"read_statement")
        client.bind(b"", b"read_statement")
        client.close(b"P", b"portal_0")
        client.bind(b"after_close", b"read_statement")
        client.send(b"B", bind_body(b"over_capacity", b"read_statement"))
        client.error(b"54000", b"FG-1006")
        client.sync()
        client.bind(b"after_sync", b"read_statement")
        client.execute(b"after_sync", read=True)
        client.sync()
    require_no_writes(run, branch, (CAPACITY_KEY,))
    run.record("PostgreSQL portal capacity preserves Sync rollback and releases handles after Close and transaction end")


def prepare_policy_writes(client, keys):
    for statement, key in zip((b"first", b"second"), keys, strict=True):
        client.parse(statement, insert(key))
        client.bind(statement, statement)


def policy_recovery(run, branch):
    with session(run, branch) as client:
        client.parse(b"_fg_abort")
        prepare_policy_writes(client, POLICY_KEYS)
        client.execute(b"first")
        client.send(b"E", execute_body(b"second"))
        client.error(b"54000", b"FG-5002")
        client.sync()
        client.bind(b"client_portal", b"_fg_abort")
        client.execute(b"client_portal", read=True)
        client.sync()
    require_no_writes(run, branch, POLICY_KEYS)
    run.record("PostgreSQL guarded abort preserves a client statement named _fg_abort")


def savepoint_recovery(run, branch):
    with session(run, branch) as client:
        client.query(b"BEGIN", b"T")
        prepare_policy_writes(client, SAVEPOINT_KEYS)
        client.query(b"SAVEPOINT review_point", b"T")
        client.query(b"ROLLBACK TO SAVEPOINT review_point", b"T")
        client.execute(b"first")
        client.send(b"E", execute_body(b"second"))
        client.error(b"54000", b"FG-5002")
    require_no_writes(run, branch, SAVEPOINT_KEYS)
    run.record("PostgreSQL savepoint rollback preserves earlier portal policy mappings and rolls back denied writes")


def require_no_writes(run, branch, keys):
    witnesses = ",".join(map(str, keys))
    with Probe(run, "pg-handle-witness", branch) as probe:
        result = probe.sql(f"SELECT id FROM parents WHERE id IN ({witnesses})", "read")
        require(result.get("rows") == [], "A rejected PostgreSQL handle operation committed a write")


def run_cases(run, branch):
    name_boundaries(run, branch)
    long_session(run, branch)
    statement_capacity(run, branch)
    portal_capacity(run, branch)
    policy_recovery(run, branch)
    savepoint_recovery(run, branch)
