#!/bin/sh
# Isolated frontend wire fixtures. Requires Docker Compose and OpenSSL.
set -eu
umask 077

case "${1:-all}" in
    mysql) engines=mysql ;;
    postgresql) engines=postgresql ;;
    tidb) engines=tidb ;;
    mongodb) engines=mongodb ;;
    all) engines='mysql postgresql tidb mongodb' ;;
    *) printf 'Usage: %s [mysql|postgresql|tidb|mongodb|all]\n' "$0" >&2; exit 2 ;;
esac
[ "$#" -le 1 ] || { printf 'Expected at most one engine argument\n' >&2; exit 2; }

suite=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH='' cd -- "$suite/../.." && pwd)
cd "$root"
run_id="$(date -u +%Y%m%d)-p1-protocol-$(date -u +%H%M%S)-$$"
report_root=${FG_PROTOCOL_REPORT_ROOT:-"$root/test/reports"}
mkdir -p "$report_root"
report="$(CDPATH='' cd -- "$report_root" && pwd)/$run_id"
mkdir "$report"
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
work=$(mktemp -d /tmp/forkget-p1.XXXXXXXX)
project_base="fgp1-$(date -u +%H%M%S)-$$"
project=

compose() {
    docker compose --project-name "$project" --file "$suite/compose.yml" "$@"
}

cleanup_project() {
    if [ -n "$project" ]; then
        compose down --volumes --remove-orphans --timeout 5 >> "$report/cleanup.log" 2>&1 || return 1
        project=
    fi
}

cleanup() {
    cleanup_project || printf 'Compose cleanup failed; see %s/cleanup.log\n' "$report" >&2
    rm -rf -- "$work"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM

command -v openssl >/dev/null
command -v python3 >/dev/null
docker compose version --short > "$report/compose-version.txt"
docker info --format '{{.ServerVersion}}' > "$report/docker-version.txt"

export FG_PROTOCOL_CERT_DIR="$work"
export FG_PROTOCOL_FRONTEND_PASSWORD="$(openssl rand -hex 32)"
export FG_PROTOCOL_BACKEND_PASSWORD="$(openssl rand -hex 32)"
export FG_PROTOCOL_ADMIN_PASSWORD="$(openssl rand -hex 32)"

issue_certificates() {
    authority=$1
    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
        -subj "/CN=Forkget P1 $authority test CA" \
        -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
        -keyout "$work/$authority-ca.key" -out "$work/$authority-ca.pem"
    openssl req -newkey rsa:2048 -nodes -sha256 -subj /CN=localhost \
        -keyout "$work/$authority.key" -out "$work/$authority.csr"
    openssl x509 -req -sha256 -days 1 -in "$work/$authority.csr" \
        -CA "$work/$authority-ca.pem" -CAkey "$work/$authority-ca.key" -CAcreateserial \
        -extfile "$work/extensions.cnf" -out "$work/$authority.pem"
    rm -f "$work/$authority-ca.key" "$work/$authority-ca.srl" "$work/$authority.csr"
}

cat > "$work/extensions.cnf" <<'CERT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
CERT
issue_certificates frontend > "$report/certificates.log" 2>&1
issue_certificates backend >> "$report/certificates.log" 2>&1

configure() {
    export FG_PROTOCOL_ENGINE="$1"
    export FG_PROTOCOL_EXEC_TARGET=native
    case "$1" in
        mysql)
            export FG_PROTOCOL_NATIVE_IMAGE=mysql:8.0.43
            export FG_PROTOCOL_LISTEN_PORT=13306
            ;;
        postgresql)
            export FG_PROTOCOL_NATIVE_IMAGE=postgres:16.14
            export FG_PROTOCOL_LISTEN_PORT=15432
            ;;
        tidb)
            export FG_PROTOCOL_NATIVE_IMAGE=pingcap/tidb:v8.5.8
            export FG_PROTOCOL_LISTEN_PORT=13306
            export FG_P1_NATIVE_PORT=4000
            # Sessions and health run through the mysql-client sidecar because
            # the TiDB image carries no client.
            export FG_PROTOCOL_EXEC_TARGET=client
            ;;
        mongodb)
            export FG_PROTOCOL_NATIVE_IMAGE=mongo:7.0.48
            export FG_PROTOCOL_LISTEN_PORT=28017
            export FG_P1_NATIVE_PORT=27017
            # The mongo image ships mongosh: one-shot init runs in it and the
            # health/observation calls stay native without a sidecar.
            export FG_PROTOCOL_INIT_IMAGE=mongo:7.0.48
            export FG_PROTOCOL_INIT_ARG=mongodb
            export FG_PROTOCOL_EXEC_TARGET=native
            ;;
    esac
    project="$project_base-$1"
}

driver_names() {
    case "$1" in
        mysql|tidb) printf '%s\n' mysql-cli connector-j pymysql go-sql-driver connector-python raw ;;
        postgresql) printf '%s\n' psql psycopg2 psycopg pgx pgjdbc raw ;;
        mongodb) printf '%s\n' pymongo ;;
    esac
}

driver() {
    case "$1" in
        # mysql-cli runs in the client sidecar (TiDB has no client);
        # psql runs in the native PostgreSQL container as before.
        mysql-cli) compose exec -T client sh /suite/clients/cli.sh "$FG_PROTOCOL_ENGINE" ;;
        psql) compose exec -T native sh /suite/clients/cli.sh "$FG_PROTOCOL_ENGINE" ;;
        pymongo) compose run --rm --no-deps -T --entrypoint python python /suite/mongo_probe.py ;;
        connector-j|pgjdbc) compose run --rm --no-deps -T java "$FG_PROTOCOL_ENGINE" ;;
        pymysql|connector-python|psycopg2|psycopg) compose run --rm --no-deps -T python "$1" ;;
        go-sql-driver|pgx) compose run --rm --no-deps -T go "$FG_PROTOCOL_ENGINE" ;;
        raw) compose run --rm --no-deps -T --entrypoint python python /suite/raw.py "$FG_PROTOCOL_ENGINE" ;;
    esac
}

record() {
    printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$report/rows.tsv"
    printf '%s %s %s\n' "$3" "$1" "$2"
}

observe_rollback() {
    attempt=0
    while [ "$attempt" -lt 10 ]; do
        remaining=$(compose exec -T "$FG_PROTOCOL_EXEC_TARGET" sh /suite/native.sh observe) || return 1
        case "$remaining" in
            0:0) printf '%s\n' 'case native-independent-rollback PASS'; return 0 ;;
            0:*) sleep 1 ;;
            *) break ;;
        esac
        attempt=$((attempt + 1))
    done
    printf 'Native observer expected zero fixture events and other service sessions, saw %s\n' "$remaining" >&2
    return 1
}

run_driver() {
    driver_failed=0
    driver "$1" || driver_failed=1
    observe_rollback || driver_failed=1
    return "$driver_failed"
}

block_engine() {
    for client in $(driver_names "$1"); do
        record "$1" "$client" blocked "$2"
    done
}

run_engine() {
    engine=$1
    configure "$engine"
    startup_log="$engine-startup.log"
    if ! compose up --no-build --detach --wait --wait-timeout 150 native client fixture > "$report/$startup_log" 2>&1; then
        compose logs --no-color native fixture >> "$report/$startup_log" 2>&1 || true
        block_engine "$engine" "$startup_log"
        cleanup_project || true
        return 1
    fi
    if ! compose exec -T "$FG_PROTOCOL_EXEC_TARGET" sh /suite/native.sh health > "$report/$engine-native-version.txt" 2>&1; then
        block_engine "$engine" "$engine-native-version.txt"
        cleanup_project || true
        return 1
    fi
    failed=0
    for client in $(driver_names "$engine"); do
        log="$engine-$client.log"
        if run_driver "$client" > "$report/$log" 2>&1; then
            record "$engine" "$client" passed "$log"
        else
            record "$engine" "$client" failed "$log"
            failed=1
        fi
    done
    compose logs --no-color native fixture > "$report/$engine-services.log" 2>&1 || failed=1
    cleanup_project || failed=1
    return "$failed"
}

: > "$report/rows.tsv"
status=0
configure "$(printf '%s\n' "$engines" | cut -d ' ' -f 1)"
if compose build fixture python go java > "$report/build.log" 2>&1; then
    project=
    for selected in $engines; do
        run_engine "$selected" || status=1
        if [ -n "$project" ]; then
            break
        fi
    done
else
    project=
    for selected in $engines; do
        block_engine "$selected" build.log
    done
    status=1
fi

finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
python3 "$suite/report.py" "$report" "$started" "$finished" "$status" "$engines" || status=1
printf 'Protocol fixture report: %s\n' "$report"
exit "$status"
