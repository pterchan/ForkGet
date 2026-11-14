import importlib.metadata
import os
import platform
import sys


HOST = "localhost"
USER = "p1_user"
BRANCH = "p1-fixture"
PASSWORD = os.environ["FG_P1_FRONTEND_PASSWORD"]
CA = "/p1-tls/frontend-ca.pem"
WRONG_CA = "/p1-tls/backend-ca.pem"
ROWS = [(1, None), (2, b""), (3, b"\x00\xffA")]
SELECT_ROWS = "SELECT id, payload FROM fixture_items ORDER BY id"
COUNT_EVENTS = "SELECT COUNT(*) FROM fixture_events"
INSERT_EVENT = "INSERT INTO fixture_events (id) VALUES (1)"
REFUSED_SQL = "DROP TABLE fixture_items"


def check(condition, case):
    if not condition:
        raise AssertionError(case)
    print(f"case {case} PASS")


def reject(operation, marker, case):
    try:
        operation()
    except Exception as error:
        if marker is not None and marker not in str(error):
            raise AssertionError(f"{case}: expected {marker}, received {error}") from error
        print(f"case {case} PASS")
    else:
        raise AssertionError(f"{case}: unexpectedly succeeded")


def reject_connection(connect, marker, case, **settings):
    def attempt():
        connection = connect(**settings)
        connection.close()

    reject(attempt, marker, case)


def query(connection, sql, params=None):
    with connection.cursor() as cursor:
        cursor.execute(sql, params)
        return list(cursor.fetchall())


def exec_sql(connection, sql):
    with connection.cursor() as cursor:
        cursor.execute(sql)


def normalize_rows(rows):
    return [(row[0], None if row[1] is None else bytes(row[1])) for row in rows]


def session_checks(connect, begin):
    connection = connect()
    try:
        check(query(connection, "SELECT 1") == [(1,)], "verified-tls-and-select")
        check(normalize_rows(query(connection, SELECT_ROWS)) == ROWS, "null-empty-bytes")
        reject(lambda: exec_sql(connection, REFUSED_SQL), "FG-2002", "unsupported-sql")
        exec_sql(connection, begin)
        exec_sql(connection, INSERT_EVENT)
        check(query(connection, COUNT_EVENTS) == [(1,)], "transaction-visibility")
        exec_sql(connection, "ROLLBACK")
        check(query(connection, COUNT_EVENTS) == [(0,)], "rollback")
        exec_sql(connection, begin)
        exec_sql(connection, INSERT_EVENT)
    finally:
        connection.close()
    connection = connect()
    try:
        check(query(connection, COUNT_EVENTS) == [(0,)], "disconnect-rollback")
    finally:
        connection.close()


def authentication_checks(connect):
    reject_connection(connect, "FG-1002", "wrong-password", password="wrong-password")
    reject_connection(connect, "FG-1002", "unknown-user", user="unknown-user")
    reject_connection(connect, "FG-2003", "unauthorized-branch", database="other-branch")
    reject_connection(connect, "certificate verify failed", "wrong-ca", ca=WRONG_CA)


def mysql_driver(driver):
    if driver == "pymysql":
        import pymysql

        connector = pymysql.connect
        package = "PyMySQL"
        options = {"connect_timeout": 5, "read_timeout": 5}
    else:
        import mysql.connector

        connector = mysql.connector.connect
        package = "mysql-connector-python"
        options = {"connection_timeout": 5, "use_pure": True}

    def connect(*, password=PASSWORD, database=BRANCH, user=USER, ca=CA):
        return connector(
            host=HOST,
            port=13306,
            user=user,
            password=password,
            database=database,
            ssl_ca=ca,
            ssl_verify_cert=True,
            ssl_verify_identity=True,
            charset="utf8mb4",
            autocommit=True,
            **options,
        )

    print(f"version {package} {importlib.metadata.version(package)} Python {platform.python_version()}")
    authentication_checks(connect)
    reject_connection(connect, "FG-2003", "missing-branch", database=None)
    session_checks(connect, "START TRANSACTION")
    if driver == "pymysql":
        mysql_savepoint(connect)
    else:
        mysql_prepared(connect)


def mysql_savepoint(connect):
    connection = connect()
    try:
        exec_sql(connection, "START TRANSACTION")
        exec_sql(connection, INSERT_EVENT)
        exec_sql(connection, "SAVEPOINT fixture_savepoint")
        exec_sql(connection, INSERT_EVENT)
        exec_sql(connection, "ROLLBACK TO SAVEPOINT fixture_savepoint")
        check(query(connection, COUNT_EVENTS) == [(1,)], "savepoint-rollback")
        exec_sql(connection, "RELEASE SAVEPOINT fixture_savepoint")
        exec_sql(connection, "ROLLBACK")
    finally:
        connection.close()


def mysql_prepared(connect):
    connection = connect()
    try:
        with connection.cursor(prepared=True) as cursor:
            statement = "SELECT id, payload FROM fixture_items WHERE id = %s"
            for row in ROWS:
                cursor.execute(statement, (row[0],))
                check(normalize_rows(cursor.fetchall()) == [row], f"prepared-reuse-{row[0]}")
            typed = "SELECT CAST(%s AS UNSIGNED), CAST(%s AS BINARY)"
            cursor.execute(typed, (None, b""))
            check(normalize_rows([cursor.fetchone()]) == [(None, b"")], "prepared-null-empty-bind")
            unsigned_max = (1 << 64) - 1
            cursor.execute(typed, (unsigned_max, b"\x00\xffA"))
            check(
                normalize_rows([cursor.fetchone()]) == [(unsigned_max, b"\x00\xffA")],
                "prepared-unsigned-bytes",
            )
            reject(
                lambda: cursor.execute(typed, (1,)),
                "Incorrect number of arguments",
                "incorrect-binding",
            )
    finally:
        connection.close()


def postgres_driver(driver):
    if driver == "psycopg2":
        import psycopg2
        from psycopg2 import extensions

        connector = psycopg2.connect
        package = "psycopg2-binary"
        libpq_version = extensions.libpq_version()
    else:
        import psycopg

        connector = psycopg.connect
        package = "psycopg"
        libpq_version = psycopg.pq.version()

    def connect(*, password=PASSWORD, database=BRANCH, user=USER, ca=CA):
        connection = connector(
            host=HOST,
            port=15432,
            user=user,
            password=password,
            dbname=database,
            sslmode="verify-full",
            sslrootcert=ca,
            gssencmode="disable",
            connect_timeout=5,
        )
        connection.autocommit = True
        return connection

    version = importlib.metadata.version(package)
    print(f"version {package} {version} libpq {libpq_version} Python {platform.python_version()}")
    authentication_checks(connect)
    session_checks(connect, "BEGIN")
    if driver == "psycopg":
        postgres_prepared(connect)


def postgres_prepared(connect):
    with connect() as connection:
        with connection.cursor() as cursor:
            statement = "SELECT id, payload FROM fixture_items WHERE id = %s"
            for row in ROWS:
                cursor.execute(statement, (row[0],), prepare=True)
                check(normalize_rows(cursor.fetchall()) == [row], f"prepared-reuse-{row[0]}")
            cursor.execute("BEGIN")
            try:
                cursor.execute("SELECT 1 / 0", prepare=True)
            except Exception as error:
                check(error.sqlstate == "22012" and "FG-1005" in str(error), "extended-error")
            else:
                raise AssertionError("division by zero unexpectedly succeeded")
            try:
                cursor.execute("SELECT 1")
            except Exception as error:
                check(error.sqlstate == "25P02", "failed-transaction")
            else:
                raise AssertionError("failed transaction unexpectedly admitted a query")
            cursor.execute("ROLLBACK")
            cursor.execute("SELECT 1")
            check(cursor.fetchone() == (1,), "extended-sync-recovery")
            cursor.execute(statement, (1,), prepare=True)
            check(normalize_rows(cursor.fetchall()) == [ROWS[0]], "prepared-after-rollback")
            copy_sql = "COPY (SELECT id, payload FROM fixture_items ORDER BY id) TO STDOUT"
            with cursor.copy(copy_sql) as copy:
                check(sum(1 for _ in copy) == 3, "copy-output")


if __name__ == "__main__":
    client = sys.argv[1]
    if client in {"pymysql", "connector-python"}:
        mysql_driver(client)
    elif client in {"psycopg2", "psycopg"}:
        postgres_driver(client)
    else:
        raise SystemExit("Unknown Python client")
