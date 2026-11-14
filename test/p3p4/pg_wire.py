"""Cover PostgreSQL write behavior hidden behind the high-level driver."""

import importlib.util
from pathlib import Path
import ssl
import struct

from run_p2 import Failure, require


RAW_CLIENT = Path(__file__).resolve().parents[1] / "protocol" / "clients" / "raw.py"
STATEMENT = b"generated_abandon\0"
PORTAL = b"abandon\0"
ABANDONED_CODE = b"pg-abandoned-portal"
GENERATED_SQL = b"INSERT INTO parents (tenant_id, code, label) VALUES ($2, $1, $3) RETURNING id"


def abandon_generated_portal(run, branch, expected_id):
    """Confirm Bind alone leaves no row at the reserved ID or bound code."""
    owner, database = branch
    spec = importlib.util.spec_from_file_location("p34_pg_raw_client", RAW_CLIENT)
    raw = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(raw)
    raw.USER = owner.encode("ascii")
    context = ssl.create_default_context(cafile=run.certs / "frontend-ca.pem")
    try:
        with raw.connect(run.proxy_port) as plain:
            plain.sendall(struct.pack("!II", 8, raw.PG_SSL))
            require(raw.read_exact(plain, 1) == b"S", "PostgreSQL refused frontend TLS")
            with context.wrap_socket(plain, server_hostname="localhost") as stream:
                stream.sendall(raw.pg_startup(database.encode("ascii")))
                raw.scram(stream, run.frontend_passwords[owner].encode("ascii"))
                require(raw.pg_auth_frame(stream, 0) == b"", "PostgreSQL authentication failed")
                require(raw.pg_until_ready(stream)[-1] == (b"Z", b"I"), "Expected idle PostgreSQL startup")
                bind_and_close(raw, stream)
                sql = f"SELECT id FROM parents WHERE id={int(expected_id)} OR code='".encode("ascii")
                result = raw.pg_query(stream, sql + ABANDONED_CODE + b"'")
                require(raw.pg_tags(result) == b"TCZ" and result[1][1] == b"SELECT 0\0",
                        "Abandoning a generated portal created a row without Execute")
                extended_recovery(raw, stream)
                raw.pg_send(stream, b"X")
    except (AssertionError, EOFError) as error:
        raise Failure(f"PostgreSQL raw protocol probe: {error}") from error


def bind_and_close(raw, stream):
    raw.pg_send(stream, b"P", STATEMENT + GENERATED_SQL + b"\0" + struct.pack("!H", 0))
    raw.pg_send(stream, b"D", b"S" + STATEMENT)
    # All parameters use text format. The third value is SQL NULL.
    values = struct.pack("!i", len(ABANDONED_CODE)) + ABANDONED_CODE + struct.pack("!i", 1) + b"8"
    bind = PORTAL + STATEMENT + struct.pack("!HH", 0, 3) + values + struct.pack("!iH", -1, 0)
    raw.pg_send(stream, b"B", bind)
    raw.pg_send(stream, b"H")
    require(raw.pg_read(stream) == (b"1", b""), "Generated Parse did not complete")
    require(raw.pg_read(stream) == (b"t", struct.pack("!HIII", 3, 1043, 23, 1043)),
            "Generated ParameterDescription leaked the internal key or changed client types")
    require(raw.pg_read(stream)[0] == b"T", "Generated Describe did not return row metadata")
    require(raw.pg_read(stream) == (b"2", b""), "Generated Bind did not complete")
    raw.pg_send(stream, b"C", b"P" + PORTAL)
    raw.pg_send(stream, b"S")
    require(raw.pg_until_ready(stream) == [(b"3", b""), (b"Z", b"I")],
            "Abandoned generated portal did not close without executing")


def extended_recovery(raw, stream):
    for sql in (b"BEGIN", b"SAVEPOINT p34_wire"):
        require(raw.pg_query(stream, sql)[-1] == (b"Z", b"T"), "PostgreSQL transaction setup failed")
    raw.pg_send(stream, b"P", b"\0DROP TABLE parents\0\0\0")
    raw.pg_send(stream, b"B", b"\0" * 8)
    raw.pg_send(stream, b"S")
    replies = raw.pg_until_ready(stream)
    require(raw.pg_tags(replies) == b"EZ" and replies[-1] == (b"Z", b"E"),
            "PostgreSQL did not discard Bind and report the failed transaction after Sync")
    raw.pg_error(replies[0][1], b"0A000", b"FG-2002")
    require(raw.pg_query(stream, b"ROLLBACK TO SAVEPOINT p34_wire")[-1] == (b"Z", b"T"),
            "PostgreSQL savepoint did not recover the rejected Parse")
    require(raw.pg_query(stream, b"ROLLBACK")[-1] == (b"Z", b"I"), "PostgreSQL rollback did not restore idle")
