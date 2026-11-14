#!/bin/sh
set -eu

expect() {
    case_name=$1
    wanted=$2
    shift 2
    actual=$("$@")
    if [ "$actual" != "$wanted" ]; then
        printf 'case %s expected <%s>, received <%s>\n' "$case_name" "$wanted" "$actual" >&2
        return 1
    fi
    printf 'case %s PASS\n' "$case_name"
}

refuse() {
    case_name=$1
    marker=$2
    shift 2
    if output=$("$@" 2>&1); then
        printf 'case %s unexpectedly succeeded\n' "$case_name" >&2
        return 1
    fi
    case "$output" in
        *"$marker"*) printf 'case %s PASS\n' "$case_name" ;;
        *) printf 'case %s expected %s, received %s\n' "$case_name" "$marker" "$output" >&2; return 1 ;;
    esac
}

mysql_query() {
    MYSQL_PWD="${CLIENT_PASSWORD:-$FG_P1_FRONTEND_PASSWORD}" mysql --no-defaults \
        --protocol=TCP --host=localhost --port="${CLIENT_PORT:-13306}" --user=p1_user \
        --connect-timeout=5 --ssl-mode=VERIFY_IDENTITY \
        --ssl-ca="${CLIENT_CA:-/p1-tls/frontend-ca.pem}" --batch --skip-column-names "$@"
}

postgres_query() {
    PGPASSWORD="${CLIENT_PASSWORD:-$FG_P1_FRONTEND_PASSWORD}" PGSSLMODE=verify-full \
        PGSSLROOTCERT="${CLIENT_CA:-/p1-tls/frontend-ca.pem}" PGCONNECT_TIMEOUT=5 \
        PGGSSENCMODE=disable psql -XAt -h localhost -p 15432 -U p1_user \
        --set=ON_ERROR_STOP=1 "$@"
}

branch=p1-fixture
insert='INSERT INTO fixture_events (id) VALUES (1)'
count='SELECT COUNT(*) FROM fixture_events'
case "$1" in
    mysql|tidb)
        printf 'version %s\n' "$(mysql --version)"
        expect verified-tls-and-select 1 mysql_query --database="$branch" -e 'SELECT 1'
        CLIENT_PASSWORD=wrong-password refuse wrong-password FG-1002 mysql_query --database="$branch" -e 'SELECT 1'
        refuse unauthorized-branch FG-2003 mysql_query --database=other-branch -e 'SELECT 1'
        refuse missing-branch FG-2003 mysql_query -e 'SELECT 1'
        CLIENT_CA=/p1-tls/backend-ca.pem refuse wrong-ca 'SSL connection error' mysql_query --database="$branch" -e 'SELECT 1'
        refuse unsupported-sql FG-2002 mysql_query --database="$branch" -e 'DROP TABLE fixture_items'
        mysql_query --database="$branch" -e "START TRANSACTION; $insert"
        expect disconnect-rollback 0 mysql_query --database="$branch" -e "$count"
        ;;
    postgresql)
        printf 'version %s\n' "$(psql --version)"
        expect verified-tls-and-select 1 postgres_query -d "$branch" -c 'SELECT 1'
        CLIENT_PASSWORD=wrong-password refuse wrong-password FG-1002 postgres_query -d "$branch" -c 'SELECT 1'
        refuse unauthorized-branch FG-2003 postgres_query -d other-branch -c 'SELECT 1'
        CLIENT_CA=/p1-tls/backend-ca.pem refuse wrong-ca 'certificate verify failed' postgres_query -d "$branch" -c 'SELECT 1'
        refuse unsupported-sql FG-2002 postgres_query -d "$branch" -c 'DROP TABLE fixture_items'
        postgres_query -d "$branch" -c BEGIN -c "$insert"
        expect disconnect-rollback 0 postgres_query -d "$branch" -c "$count"
        ;;
esac
