#!/bin/sh
set -eu

case "$FG_P1_BACKEND_PASSWORD" in
    ''|*[!0123456789abcdef]*) printf '%s\n' 'Expected a generated hex service password' >&2; exit 1 ;;
esac

# Two invocation modes share this script:
# - entrypoint hook (no argument) on MySQL and PostgreSQL;
# - one-shot compose init with the "tidb" argument, applying the fixture
#   over TCP because the TiDB image has no entrypoint hook.
mode=${1:-}
case "$mode" in
    "")
        case "$FG_PROTOCOL_ENGINE" in
            mysql|postgresql) ;;
            *) exit 0 ;;
        esac
        ;;
    mongodb)
        [ "$FG_PROTOCOL_ENGINE" = mongodb ] || exit 0
        ;;
    tidb)
        [ "$FG_PROTOCOL_ENGINE" = tidb ] || exit 0
        ;;
    # The mongo entrypoint sources this hook with mongod arguments in $@, so
    # any unexpected mode here is a sourced context: no-op and let the engine
    # dispatch below decide.
    *) ;;
esac

case "$FG_PROTOCOL_ENGINE" in
    mysql)
        MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql --no-defaults --protocol=socket \
            --user=root --database=p1_native <<SQL
CREATE TABLE fixture_items (id INT NOT NULL PRIMARY KEY, payload VARBINARY(32));
INSERT INTO fixture_items (id, payload) VALUES (1, NULL), (2, X''), (3, X'00FF41');
CREATE TABLE fixture_events (id INT NOT NULL);
CREATE USER 'p1_service'@'%' IDENTIFIED WITH caching_sha2_password BY '$FG_P1_BACKEND_PASSWORD' REQUIRE SSL;
GRANT SELECT ON p1_native.fixture_items TO 'p1_service'@'%';
GRANT SELECT, INSERT ON p1_native.fixture_events TO 'p1_service'@'%';
SQL
        ;;
    postgresql)
        psql -X --username "$POSTGRES_USER" --dbname p1_native --set=ON_ERROR_STOP=1 <<SQL
CREATE TABLE public.fixture_items (id integer PRIMARY KEY, payload bytea);
INSERT INTO public.fixture_items (id, payload) VALUES (1, NULL), (2, ''::bytea), (3, decode('00ff41', 'hex'));
CREATE TABLE public.fixture_events (id integer NOT NULL);
SET password_encryption = 'scram-sha-256';
CREATE ROLE p1_service LOGIN PASSWORD '$FG_P1_BACKEND_PASSWORD';
GRANT SELECT ON public.fixture_items TO p1_service;
GRANT SELECT, INSERT ON public.fixture_events TO p1_service;
SQL
        ;;
    mongodb)
        # One-shot init on the mongo image (mongosh ships in-image, so no
        # sidecar is needed): the mirror account the spike fixture maps the
        # frontend identity onto, plus the fixture collection.
        # The mongo entrypoint sources this hook, so no exec and no failure
        # may escape (it would kill the entrypoint shell and the container).
        mongosh --username root --password "$MYSQL_ROOT_PASSWORD" \
            --authenticationDatabase admin --quiet <<'MONGO' || true
try {
  const admin = db.getSiblingDB('admin');
  try {
    admin.createUser({user: 'p1_user', pwd: process.env.FG_P1_FRONTEND_PASSWORD, roles: [{role: 'readWrite', db: 'p1_native'}, {role: 'readWrite', db: 'p1-fixture'}]});
  } catch (e) { if (e.code !== 51003 && e.code !== 51002) throw e; }
  const fixture = db.getSiblingDB('p1-fixture').fixture_items;
  fixture.drop();
  fixture.insertMany([
    {_id: 1, payload: null},
    {_id: 2, payload: 'empty'},
    {_id: 3, payload: '00ff41'}
  ]);
} catch (error) {
  print('p1 fixture init error: ' + error);
}
MONGO
        ;;
    tidb)
        # Entry point for the compose init sidecar (the TiDB image has no
        # entrypoint hook). The sidecar shares the native network and runs
        # the statements through the MySQL client against the fresh root
        # (no password on a fresh volume; the pinned password on reuse).
        root_client() {
            mysql --no-defaults --protocol=TCP --host=127.0.0.1 \
                --port="${FG_P1_NATIVE_PORT:-4000}" --user=root "$@" 2>/dev/null ||
            MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql --no-defaults --protocol=TCP \
                --host=127.0.0.1 --port="${FG_P1_NATIVE_PORT:-4000}" --user=root "$@"
        }
        root_client <<SQL
CREATE DATABASE IF NOT EXISTS p1_native;
CREATE TABLE p1_native.fixture_items (id INT NOT NULL PRIMARY KEY, payload VARBINARY(32));
INSERT INTO p1_native.fixture_items (id, payload) VALUES (1, NULL), (2, X''), (3, X'00FF41');
CREATE TABLE p1_native.fixture_events (id INT NOT NULL);
CREATE USER 'p1_service'@'%' IDENTIFIED WITH caching_sha2_password BY '$FG_P1_BACKEND_PASSWORD' REQUIRE SSL;
GRANT SELECT ON p1_native.fixture_items TO 'p1_service'@'%';
GRANT SELECT, INSERT ON p1_native.fixture_events TO 'p1_service'@'%';
SET GLOBAL tidb_enable_check_constraint = ON;
ALTER USER 'root'@'%' IDENTIFIED BY '$MYSQL_ROOT_PASSWORD';
SQL
        ;;
esac
