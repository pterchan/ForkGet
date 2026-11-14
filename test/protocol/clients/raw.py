"""Exercise wire behavior that a high-level driver normally hides."""

import base64
import hashlib
import hmac
import os
import platform
import secrets
import select
import socket
import ssl
import struct
import sys
import time

MYSQL_PORT = 13306
PG_PORT = 15432
MYSQL_FRAGMENT = 0xFFFFFF
PG_SSL = 80877103
PG_CANCEL = 80877102
PG_VERSION_3 = 3 << 16
USER = b"p1_user"
BRANCH = b"p1-fixture"
ROWS = b"SELECT id, payload FROM fixture_items ORDER BY id"


def connect(port):
    return socket.create_connection(("127.0.0.1", port), timeout=8)


def tls(stream):
    context = ssl.create_default_context(cafile="/p1-tls/frontend-ca.pem")
    return context.wrap_socket(stream, server_hostname="localhost")


def read_exact(stream, size):
    data = bytearray()
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        if not chunk:
            raise EOFError("protocol stream ended")
        data.extend(chunk)
    return bytes(data)


def mysql_read(stream, sequence):
    header = read_exact(stream, 4)
    assert header[3] == sequence, "MySQL packet sequence"
    return read_exact(stream, int.from_bytes(header[:3], "little"))


def mysql_write(stream, sequence, payload):
    stream.sendall(len(payload).to_bytes(3, "little") + bytes([sequence]) + payload)


def mysql_connect(password, *, port=MYSQL_PORT, user=USER, branch=BRANCH, cafile=None, found_rows=False):
    stream = connect(port)
    hello = mysql_read(stream, 0)
    assert hello[0] == 10, "MySQL protocol version"
    version_end = hello.index(0, 1)
    capability_start = version_end + 14
    lower = int.from_bytes(hello[capability_start:capability_start + 2], "little")
    upper = int.from_bytes(hello[capability_start + 5:capability_start + 7], "little")
    advertised = lower | (upper << 16)
    forbidden = (1 << 5) | (1 << 16) | (1 << 26)
    assert advertised & forbidden == 0, "MySQL must omit compression and multi-statements"
    flags = (1 << 3) | (1 << 9) | (1 << 11) | (1 << 15) | (1 << 19)
    if found_rows:
        assert advertised & (1 << 1), "MySQL CLIENT_FOUND_ROWS advertised"
        flags |= 1 << 1
    header = struct.pack("<IIB23x", flags, 32 * 1024 * 1024, 45)
    mysql_write(stream, 1, header)
    if cafile is None:
        stream = tls(stream)
    else:
        context = ssl.create_default_context(cafile=cafile)
        stream = context.wrap_socket(stream, server_hostname="localhost")
    login = user + b"\0\x00" + branch + b"\0caching_sha2_password\0"
    mysql_write(stream, 2, header + login)
    assert mysql_read(stream, 3) == b"\x01\x04", "MySQL TLS full auth must be exercised"
    mysql_write(stream, 4, password + b"\0")
    assert mysql_read(stream, 5)[0] == 0, "MySQL full auth result"
    return stream


def mysql_error(body, number, state, forkget):
    assert body[:1] == b"\xff", "MySQL ERR packet"
    assert int.from_bytes(body[1:3], "little") == number, "MySQL numeric errno"
    assert body[3:9] == b"#" + state, "MySQL SQLSTATE"
    assert forkget in body[9:], "MySQL Forkget error code"


def mysql_prepared(stream, password):
    mysql_write(stream, 0, b"\x16SELECT id, payload FROM fixture_items WHERE id = ?")
    prepared = mysql_read(stream, 1)
    assert prepared[0] == 0 and len(prepared) == 12, "MySQL PREPARE_OK"
    handle, columns, parameters = struct.unpack("<IHH", prepared[1:9])
    assert (columns, parameters) == (2, 1), "MySQL prepared metadata counts"
    for sequence in range(2, 7):
        metadata = mysql_read(stream, sequence)
        if sequence in (3, 6):
            assert metadata[0] == 0xFE, "MySQL prepared metadata terminator"
        else:
            assert b"p1_native" not in metadata, "MySQL physical database metadata"

    native_handle = struct.pack("<I", handle)
    execute = b"\x17" + native_handle + struct.pack("<BI", 0, 1)
    with mysql_connect(password) as unrelated:
        mysql_write(unrelated, 0, execute)
        mysql_error(mysql_read(unrelated, 1), 1043, b"08S01", b"FG-1003")

    mysql_write(stream, 0, b"\x17" + native_handle + struct.pack("<BI", 1, 1))
    mysql_error(mysql_read(stream, 1), 1235, b"42000", b"FG-2002")
    mysql_write(stream, 0, execute)
    response = mysql_read(stream, 1)
    assert response[:1] == b"\xff" and b"FG-1005" in response, "Invalid native prepared bindings"
    mysql_write(stream, 0, b"\x1a" + native_handle)
    assert mysql_read(stream, 1)[0] == 0, "MySQL RESET native response"
    mysql_write(stream, 0, b"\x19" + native_handle)
    mysql_write(stream, 0, execute)
    mysql_error(mysql_read(stream, 1), 1043, b"08S01", b"FG-1003")


def mysql_savepoint(stream):
    for sql, affected in (
        (b"BEGIN", 0),
        (b"SAVEPOINT fixture_savepoint", 0),
        (b"INSERT INTO fixture_events (id) VALUES (1)", 1),
        (b"ROLLBACK TO SAVEPOINT fixture_savepoint", 0),
        (b"ROLLBACK", 0),
    ):
        mysql_write(stream, 0, b"\x03" + sql)
        response = mysql_read(stream, 1)
        assert response[:3] == bytes([0, affected, 0]), "MySQL native affected row count"
        status = int.from_bytes(response[3:5], "little")
        assert bool(status & 1) == (sql != b"ROLLBACK"), "MySQL native transaction state"


def mysql_tests(password):
    with connect(MYSQL_PORT) as stream:
        mysql_read(stream, 0)
        mysql_write(stream, 1, struct.pack("<IIB23x", 1 << 9, 0, 45))
        mysql_error(mysql_read(stream, 2), 1045, b"28000", b"FG-1002")
        print("case cleartext-connection-rejected PASS")
    with mysql_connect(password) as stream:
        mysql_write(stream, 0, b"\x04fixture_items\0")
        mysql_error(mysql_read(stream, 1), 1235, b"42000", b"FG-2002")
        mysql_write(stream, 0, b"\x03SELECT 1; SELECT 1")
        mysql_error(mysql_read(stream, 1), 1235, b"42000", b"FG-2002")
        mysql_write(stream, 0, b"\x02other-branch")
        mysql_error(mysql_read(stream, 1), 1044, b"42000", b"FG-2003")
        mysql_write(stream, 0, b"\x02" + BRANCH)
        assert mysql_read(stream, 1)[0] == 0, "Reaffirm the bound MySQL branch"
        print("case unsupported-capabilities-and-commands PASS")

        # An exact maximum-size fragment is followed by a zero-length packet.
        mysql_write(stream, 0, b"\x03" + b"X" * (MYSQL_FRAGMENT - 1))
        mysql_write(stream, 1, b"")
        mysql_error(mysql_read(stream, 2), 1235, b"42000", b"FG-2002")
        mysql_write(stream, 0, b"\x0e")
        assert mysql_read(stream, 1)[0] == 0, "MySQL PING after refusal"
        print("case exact-fragment-and-sequence-reset PASS")
        mysql_prepared(stream, password)
        print("case prepared-reset-close-and-session-ownership PASS")
        mysql_savepoint(stream)
        print("case mysql-native-transaction-status-and-savepoint PASS")

    with mysql_connect(password) as stream:
        mysql_write(stream, 8, b"\x0e")
        try:
            response = mysql_read(stream, 1)
        except (EOFError, ConnectionResetError):
            pass
        else:
            mysql_error(response, 1043, b"08S01", b"FG-1003")
            assert not stream.recv(1), "Malformed MySQL packet must close the session"
        print("case wrong-packet-sequence PASS")


def pg_read(stream):
    tag, length = struct.unpack("!cI", read_exact(stream, 5))
    assert 4 <= length <= 1024 * 1024, "PostgreSQL response length"
    return tag, read_exact(stream, length - 4)


def pg_send(stream, tag, body=b""):
    stream.sendall(tag + struct.pack("!I", len(body) + 4) + body)


def pg_auth_frame(stream, code):
    tag, body = pg_read(stream)
    assert tag == b"R" and body[:4] == struct.pack("!I", code), "PostgreSQL auth message"
    return body[4:]


def hmac_sha256(key, data):
    return hmac.digest(key, data, "sha256")


def scram(stream, password):
    mechanisms = pg_auth_frame(stream, 10)
    assert mechanisms == b"SCRAM-SHA-256\0\0", "Advertised SCRAM mechanisms"
    nonce = base64.b64encode(secrets.token_bytes(18))
    client_bare = b"n=" + USER + b",r=" + nonce
    client_first = b"n,," + client_bare
    pg_send(stream, b"p", b"SCRAM-SHA-256\0" + struct.pack("!I", len(client_first)) + client_first)
    server_first = pg_auth_frame(stream, 11)
    fields = dict(field.split(b"=", 1) for field in server_first.split(b","))
    server_nonce = fields[b"r"]
    assert server_nonce.startswith(nonce) and server_nonce != nonce, "SCRAM server nonce"
    salted = hashlib.pbkdf2_hmac("sha256", password, base64.b64decode(fields[b"s"]), int(fields[b"i"]))
    client_key = hmac_sha256(salted, b"Client Key")
    final_bare = b"c=biws,r=" + server_nonce
    auth_message = b",".join((client_bare, server_first, final_bare))
    signature = hmac_sha256(hashlib.sha256(client_key).digest(), auth_message)
    proof = bytes(left ^ right for left, right in zip(client_key, signature))
    pg_send(stream, b"p", final_bare + b",p=" + base64.b64encode(proof))
    server_signature = hmac_sha256(hmac_sha256(salted, b"Server Key"), auth_message)
    assert pg_auth_frame(stream, 12) == b"v=" + base64.b64encode(server_signature), "SCRAM server proof"


def pg_startup(branch):
    startup = struct.pack("!I", PG_VERSION_3) + b"user\0" + USER + b"\0"
    if branch is not None:
        startup += b"database\0" + branch + b"\0"
    startup += b"\0"
    return struct.pack("!I", len(startup) + 4) + startup


def pg_secure_stream():
    stream = connect(PG_PORT)
    stream.sendall(struct.pack("!II", 8, PG_SSL))
    assert read_exact(stream, 1) == b"S", "PostgreSQL TLS upgrade"
    return tls(stream)


def pg_connect(password):
    stream = pg_secure_stream()
    stream.sendall(pg_startup(BRANCH))
    scram(stream, password)
    assert pg_auth_frame(stream, 0) == b"", "PostgreSQL authentication result"
    key = None
    for tag, body in pg_until_ready(stream):
        if tag == b"K":
            key = body
    assert key is not None and len(key) == 8, "PostgreSQL session cancellation key"
    return stream, key


def pg_until_ready(stream):
    messages = []
    while True:
        tag, body = pg_read(stream)
        messages.append((tag, body))
        if tag == b"Z":
            return messages


def pg_query(stream, sql):
    pg_send(stream, b"Q", sql + b"\0")
    return pg_until_ready(stream)


def pg_tags(messages):
    return b"".join(tag for tag, _ in messages)


def pg_error(body, sqlstate, forkget):
    fields = {field[:1]: field[1:] for field in body.split(b"\0") if field}
    assert fields[b"C"] == sqlstate, "PostgreSQL SQLSTATE"
    assert forkget in fields[b"M"], "PostgreSQL Forkget error code"


def pg_portal(stream):
    pg_send(stream, b"P", b"named\0" + ROWS + b"\0\0\0")
    pg_send(stream, b"B", b"p\0named\0" + b"\0" * 6)
    pg_send(stream, b"D", b"Pp\0")
    pg_send(stream, b"E", b"p\0" + struct.pack("!I", 1))
    pg_send(stream, b"H")
    responses = [pg_read(stream) for _ in range(5)]
    assert pg_tags(responses) == b"12TDs", "PostgreSQL portal suspension"
    assert responses[3][1] == b"\0\x02\0\0\0\x011\xff\xff\xff\xff", "PostgreSQL NULL row"
    pg_send(stream, b"E", b"p\0" + struct.pack("!I", 0))
    pg_send(stream, b"S")
    assert pg_tags(pg_until_ready(stream)) == b"DDCZ", "PostgreSQL portal completion"


def pg_recover(stream):
    assert pg_query(stream, b"BEGIN")[-1] == (b"Z", b"T"), "PostgreSQL BEGIN status"
    savepoint = b"fixture_savepoint"
    assert pg_query(stream, b"SAVEPOINT " + savepoint)[-1] == (b"Z", b"T"), "Create savepoint"
    pg_send(stream, b"P", b"\0DROP TABLE fixture_items\0\0\0")
    pg_send(stream, b"B", b"\0\0" + b"\0" * 6)
    pg_send(stream, b"S")
    messages = pg_until_ready(stream)
    assert pg_tags(messages) == b"EZ", "Extended errors discard messages until Sync"
    pg_error(messages[0][1], b"0A000", b"FG-2002")
    assert messages[-1] == (b"Z", b"E"), "Rejected statement aborts transaction"
    assert pg_query(stream, b"ROLLBACK TO SAVEPOINT " + savepoint)[-1] == (b"Z", b"T"), (
        "Rollback to savepoint restores the transaction"
    )
    assert pg_tags(pg_query(stream, b"SELECT 1")) == b"TDCZ", "Recovered transaction accepts queries"
    assert pg_query(stream, b"ROLLBACK")[-1] == (b"Z", b"I"), "Rollback restores idle state"


def pg_cancel(key):
    with connect(PG_PORT) as stream:
        stream.sendall(struct.pack("!II", 16, PG_CANCEL) + key)
        assert not stream.recv(1), "CancelRequest has no reply"


def pg_cancel_tests(stream, key, other_key):
    pg_send(stream, b"Q", b"SELECT pg_sleep(30)\0")
    forged = key[:-1] + bytes([key[-1] ^ 0x80])
    pg_cancel(forged)
    pg_cancel(other_key)
    if pg_readable(stream, 0.15):
        assert pg_read(stream)[0] == b"T", "Forged or unrelated key affected the query"
    assert not pg_readable(stream, 0.15), "Forged or unrelated key affected the query"
    deadline = time.monotonic() + 4
    while not pg_readable(stream, 0.05):
        assert time.monotonic() < deadline, "Owned PostgreSQL cancellation timed out"
        pg_cancel(key)
    messages = pg_until_ready(stream)
    assert pg_tags(messages) in {b"EZ", b"TEZ"}, "Canceled query protocol response"
    pg_error(messages[-2][1], b"57014", b"FG-1005")
    assert pg_tags(pg_query(stream, b"SELECT 1")) == b"TDCZ", "Cancel must not affect the next query"


def pg_readable(stream, wait):
    return stream.pending() or select.select([stream], [], [], wait)[0]


def pg_tests(password):
    with connect(PG_PORT) as cleartext:
        cleartext.sendall(pg_startup(BRANCH))
        tag, body = pg_read(cleartext)
        assert tag == b"E", "Reject cleartext startup"
        pg_error(body, b"28P01", b"FG-1002")
        print("case cleartext-connection-rejected PASS")
    with pg_secure_stream() as missing_branch:
        missing_branch.sendall(pg_startup(None))
        scram(missing_branch, password)
        tag, body = pg_read(missing_branch)
        assert tag == b"E", "Reject startup without a branch after proving identity"
        pg_error(body, b"3D000", b"FG-2003")
        print("case authenticated-missing-branch-rejected PASS")
    with pg_secure_stream() as channel_bound:
        channel_bound.sendall(pg_startup(BRANCH))
        assert pg_auth_frame(channel_bound, 10) == b"SCRAM-SHA-256\0\0", "Advertised mechanisms"
        mechanism = b"SCRAM-SHA-256-PLUS\0"
        pg_send(channel_bound, b"p", mechanism + struct.pack("!I", 0))
        tag, body = pg_read(channel_bound)
        assert tag == b"E", "Reject unsupported channel binding"
        pg_error(body, b"28P01", b"FG-1002")
        print("case channel-binding-required-rejected PASS")
    stream, key = pg_connect(password)
    with stream:
        pg_portal(stream)
        print("case named-portal-suspend-and-resume PASS")
        pg_recover(stream)
        print("case policy-error-sync-and-transaction-recovery PASS")
        copy = pg_query(stream, b"COPY (" + ROWS + b") TO STDOUT")
        tags = pg_tags(copy)
        assert tags[:1] == b"H" and tags[-3:] == b"cCZ" and set(tags[1:-3]) == {ord("d")}, (
            "PostgreSQL COPY OUT response"
        )
        assert b"".join(body for tag, body in copy if tag == b"d") == (
            b"1\t\\N\n2\t\\\\x\n3\t\\\\x00ff41\n"
        ), "PostgreSQL COPY OUT values"
        print("case copy-out-protocol-and-values PASS")
        other, other_key = pg_connect(password)
        with other:
            pg_cancel_tests(stream, key, other_key)
        print("case owned-cancellation-and-spoof-rejection PASS")
        stream.sendall(b"Q" + struct.pack("!I", 0x7FFFFFFF))
        try:
            tag, body = pg_read(stream)
        except (EOFError, ConnectionResetError):
            pass
        else:
            assert tag == b"E", "PostgreSQL malformed length"
            pg_error(body, b"08P01", b"FG-1003")
            assert not stream.recv(1), "Malformed PostgreSQL frame must close the session"
        print("case oversized-frame PASS")


def main():
    engine, = sys.argv[1:]
    password = os.environ["FG_P1_FRONTEND_PASSWORD"].encode()
    print(f"version Python {platform.python_version()}")
    if engine in ("mysql", "tidb"):
        mysql_tests(password)
    elif engine == "postgresql":
        pg_tests(password)
    else:
        raise ValueError("expected mysql, postgresql or tidb")
    print(f"case {engine}-raw-wire PASS")


if __name__ == "__main__":
    main()
